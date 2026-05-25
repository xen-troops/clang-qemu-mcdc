from elftools.elf.elffile import ELFFile
from elftools.dwarf.descriptions import (describe_DWARF_expr,
                                         set_global_machine_arch)
from elftools.dwarf.locationlists import (LocationEntry, LocationExpr,
                                          LocationParser, LocationLists)
from elftools.dwarf.lineprogram import LineProgram, LineState
from elftools.dwarf.dwarfinfo import DWARFInfo
from elftools.dwarf.die import DIE
from elftools.dwarf.dwarf_expr import DWARFExprParser, DWARFExprOp
from mcdc_tool_definitions import CodeLoc, SAST, BoolExpression, BoolVar, NonBoolExpression, NonBoolVar, \
    FCall, ASTEntry, MemberExpr, SizeOf, CCast, IntLiteral, StringLiteral, ConditionalOp, ArraySubscript
import pickle
import sys
from typing import Optional
from pprint import pprint
import capstone

SUBPROGRAMS: dict[int, DwarfSubProgram] = {}

class DwarfSubProgram:
    def __init__(self, name: str, die: DIE, addr: int):
        self.name = name
        self.die = die
        self.addr = addr

class DwarfLoc:

    def __init__(self, fname: str, lp_state: LineState):
        self.fname = fname
        self.lp_state = lp_state

    def __repr__(self) -> str:
        return f"<DwarfLoc: {self.fname, self.lp_state}>"


def parse_locs(dwarfinfo) -> list[DwarfLoc]:
    ret: list[LineState] = list()
    for CU in dwarfinfo.iter_CUs():
        lp: LineProgram = dwarfinfo.line_program_for_CU(CU)
        fnames = [x["DW_LNCT_path"].decode() for x in lp["file_names"]]
        lp_entries = lp.get_entries()
        for lp_entry in lp_entries:
            if lp_entry.state:
                state = lp_entry.state
                ret.append(DwarfLoc(fnames[state.file], state))
    return ret


def find_dw_loc(dwarf_locs: list[DwarfLoc],
                loc: CodeLoc) -> Optional[DwarfLoc]:

    for dw_loc in dwarf_locs:
        if dw_loc.fname == loc.file and dw_loc.lp_state.line == loc.line:
            return dw_loc

    return None


def find_dw_loc_end(dwarf_locs: list[DwarfLoc],
                    loc: CodeLoc) -> Optional[DwarfLoc]:

    for idx, dw_loc in enumerate(reversed(dwarf_locs)):
        if dw_loc.fname == loc.file and dw_loc.lp_state.line == loc.line:
            return dwarf_locs[idx + 1]

    return None


def get_addr_range_for_expr(dwarf_locs: list[DwarfLoc],
                            expr: BoolExpression) -> (int, int):
    code_range = expr.ast.range
    if not code_range:
        raise Exception(f"No code range for {expr}: {expr.loc}")
    dw_loc = find_dw_loc(dwarf_locs, code_range.begin)
    dw_loc_end = find_dw_loc_end(dwarf_locs, code_range.end)
    if not dw_loc:
        raise Exception(f"Can't find DWARF location for {expr}: {expr.loc}")
    if not dw_loc_end:
        raise Exception(
            f"Can't find DWARF END location for {expr}: {expr.loc}")
    return dw_loc.lp_state.address, dw_loc_end.lp_state.address
  #  return dw_loc_end.lp_entry.address, dw_loc.lp_entry.address


def get_code_for_range(elffile: ELFFile, start, end):
    for sect in elffile.iter_sections():
        if sect["sh_type"] != "SHT_PROGBITS":
            continue
        sect_start = sect["sh_addr"]
        sect_len = sect["sh_size"]
        if start < sect_start or start > sect_start + sect_len:
            continue
        if end > sect_start + sect_len:
            sect_name = elffile._get_section_name(sect.header)
            raise Exception(
                f"Section {sect_name} holds beginning of range ({start:x}, {end:x})  but not end"
            )
        return sect.data()[start - sect_start:end - sect_start]


class DWVariable:

    def __init__(self, name: str, loc_expr: DWARFExprOp, fname: str, line: int,
                 cu):
        self.name = name
        self.loc_expr = loc_expr
        self.fname = fname
        self.line = line
        self.cu = cu

    def __repr__(self) -> str:
        return f"<DWVariable: {self.name} at {self.fname}:{self.line}>"


def process_function(die: DIE, loc_parser, expr_parser,
                     fnames: list[str]) -> list[DWVariable]:
    ret = []

    SUBPROGRAMS[die.offset] = DwarfSubProgram(die.attributes["DW_AT_name"].value.decode(), die, die.offset)
    for child in die.iter_children():
        child: DIE
        if child.tag in ("DW_TAG_formal_parameter", "DW_TAG_variable"):
            name = child.attributes["DW_AT_name"].value.decode()
            fname = child.attributes["DW_AT_decl_file"].value
            line = child.attributes["DW_AT_decl_line"].value
            if not "DW_AT_location" in child.attributes:
                #TODO: Inlined functions
#                pprint(child.attributes)
                continue
            parsed_loc = loc_parser.parse_from_attribute(
                child.attributes["DW_AT_location"], die.cu["version"], die)
            if isinstance(parsed_loc, LocationExpr):
                loc_expr = parsed_loc.loc_expr
            else:
                # TODO: Need to proces the whole list
                loc_expr = parsed_loc[0].loc_expr
                # for entity in parsed_loc:
                #     print(entity, type(entity))
                # raise NotImplementedError()
            loc = expr_parser.parse_expr(loc_expr)
#            print(f"{name} at {fname}:{line}", loc)
            ret.append(DWVariable(name, loc[0], fnames[fname], line, die.cu))
        if child.tag == "DW_TAG_inlined_subroutine":
            process_inlined_function(child, loc_parser, expr_parser)
    return ret

def process_inlined_function(die: DIE, loc_parser, expr_parser):
    print(f"Processing inlined function {die.attributes['DW_AT_abstract_origin']}")
    func = SUBPROGRAMS[die.attributes['DW_AT_abstract_origin'].value]
    pprint(func.__dict__)
    print(die)
    pass

def process_cus(dwarfinfo: DWARFInfo) -> list[DWVariable]:
    location_lists = dwarfinfo.location_lists()
    loc_parser = LocationParser(location_lists)
    expr_parser = DWARFExprParser(dwarfinfo.structs)
    ret = []
    for CU in dwarfinfo.iter_CUs():
        lp: LineProgram = dwarfinfo.line_program_for_CU(CU)
        fnames = [x["DW_LNCT_path"].decode() for x in lp["file_names"]]
        for die in CU.get_top_DIE().iter_children():
            if die.tag == "DW_TAG_subprogram":
#                print(die)
                ret.extend(
                    process_function(die, loc_parser, expr_parser, fnames))
    return ret

def find_expr_for_loc(dw_loc: DwarfLoc, expr_list: list[SAST]):
    fname = dw_loc.fname
    line = dw_loc.lp_state.line
    col = dw_loc.lp_state.column

    for expr in expr_list:
        if expr.loc.file != fname:
            continue
        if line < expr.loc_range.begin.line or line > expr.loc_range.end.line:
            continue
        if col < expr.loc_range.begin.col or col > expr.loc_range.end.col:
            continue
        return expr
    return None

def process_elf(fname: str, expressions: list[SAST]):
    f = open(fname, "rb")
    elffile = ELFFile(f)
    if not elffile.has_dwarf_info():
        raise Exception("We need elf file with debugging information!")
    dwarfinfo = elffile.get_dwarf_info()
    set_global_machine_arch(elffile.get_machine_arch())
    dwarf_locs = parse_locs(dwarfinfo)
    dis = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)
    dis.detail = True
    variables = process_cus(dwarfinfo)
    print(variables)
    ret: list[TracePoint] = []
    start_loc: DwarfLoc = None
    found_expr: SAST = None
    for loc in dwarf_locs:
        cur_expr = find_expr_for_loc(loc, expressions)
        if not cur_expr and not found_expr:
            continue
        if not found_expr:
            found_expr = cur_expr
            start_loc = loc
            continue
        if cur_expr != found_expr:
            # We have found the whole range for that expr: start_loc - prev_loc
            start_addr = start_loc.lp_state.address
            # Probably a hack, but somethimes dwarf data is a bit murky...
            end_addr = loc.lp_state.address + 16
            data = get_code_for_range(elffile, start_addr, end_addr)
            print(f"Found addr range 0x{start_addr:x} 0x{end_addr:x} for {found_expr}")
            if not data:
                raise Exception(
                    f"Can't get data for range {start:x}, {end:x}, expr: {decision} at {decision.loc}"
                )
            ret.append(
                match_bool_expr(found_expr, list(dis.disasm(data, start_addr)),
                                variables))
            if cur_expr:
                found_expr = cur_expr
                start_loc = loc
                continue

    # Old code that works by iterating over expressions
    # for expr in expressions:
    #     for decision in expr.get_decisions():
    #         (start, end) = get_addr_range_for_expr(dwarf_locs, decision)
    #         if end < start:
    #             print(
    #                 f"TODO: skipping expr at {decision.loc} because of inverted range: 0x{start:x},0x{end:x}"
    #             )
    #             continue
    #         data = get_code_for_range(elffile, start, end)
    #         if not data:
    #             raise Exception(
    #                 f"Can't get data for range {start:x}, {end:x}, expr: {decision} at {decision.loc}"
    #             )
    #         ret.append(
    #             match_bool_expr(decision, list(dis.disasm(data, start)),
    #                             variables))
    #         # for instr in dis.disasm(data, start):
    #         #     print(instr)
    #         #     pass
    # pprint(ret)

def find_variable(variables: list[DWVariable], name: str, fname: str,
                  line: int):
    # TODO: Handle lexigraphical scope

    for v in reversed(variables):
        if v.name != name:
            continue
        if v.fname != fname:
            continue
        if v.line > line:
            continue
        #print(f"Looked for {name} at {fname}:{line} ==> found {v}")
        return v
    raise Exception(f"Can't find variable {name} referenced at {fname}:{line}")

def get_variable_at_loc(func_die: DIE, name: str, fname: str,
                  line: int):
    # TODO: Handle lexigraphical scope

    for v in reversed(variables):
        if v.name != name:
            continue
        if v.fname != fname:
            continue
        if v.line > line:
            continue
        #print(f"Looked for {name} at {fname}:{line} ==> found {v}")
        return v
    raise Exception(f"Can't find variable {name} referenced at {fname}:{line}")


class MatchError(Exception):

    def __init__(self, msg):
        return super().__init__(msg)


def match_instr_reg_operand(instr: capstone.CsInsn, idx: int, reg: str):
    if idx >= len(instr.operands):
        raise MatchError(
            f"Tried to match {idx}'th operand, but op has only {len(instr.operands)} operands"
        )
    if instr.operands[idx].type != capstone.arm64_const.ARM64_OP_REG:
        raise MatchError(
            f"{idx}'th operand is not a register: {instr.operands[idx].type}")
    if instr.reg_name(instr.operands[idx].reg)[1:] != reg[1:]:
        raise MatchError(
            f"{idx}'th register is not one that we expect: {instr.reg_name(instr.operands[idx].reg)} != {reg}"
        )


def get_instr_reg_operand(instr: capstone.CsInsn, idx: int) -> str:
    if idx >= len(instr.operands):
        raise MatchError(
            f"Tried to match {idx}'th operand, but op has only {len(instr.operands)} operands"
        )
    if instr.operands[idx].type != capstone.arm64_const.ARM64_OP_REG:
        raise MatchError(
            f"{idx}'th operand is not a register: {instr.operands[idx].type}")
    return instr.reg_name(instr.operands[idx].reg)


def match_instr_const_operand(instr: capstone.CsInsn, idx: int, value: int):
    if idx >= len(instr.operands):
        raise MatchError(
            f"Tried to match {idx}'th operand, but op has only {len(instr.operands)} operands"
        )
    if instr.operands[idx].type != capstone.arm64_const.ARM64_OP_IMM:
        raise MatchError(
            f"{idx}'th operand is not an immediate: {instr.operands[idx].type}"
        )
    if instr.operands[idx].value.imm != value:
        raise MatchError(
            f"{idx}'th immediate is not one that we expect: {instr.operands[idx].value.imm} != {value}"
        )


def match_instr_mem_operand(instr: capstone.CsInsn, idx: int, base_reg: str,
                            offset: str):
    if idx >= len(instr.operands):
        raise MatchError(
            f"Tried to match {idx}'th operand, but op has only {len(instr.operands)} operands"
        )
    operand = instr.operands[idx]
    if operand.type != capstone.arm64_const.ARM64_OP_MEM:
        raise MatchError(
            f"{idx}'th operand is not an memory op: {operand.type}")

    if instr.reg_name(operand.value.mem.base) != base_reg:
        raise MatchError(
            f"{idx}'th reg does not match: {instr.reg_name(operand.value.mem.base)} != {base_reg}"
        )

    if offset and operand.value.mem.disp != offset:
        raise MatchError(
            f"Offset for memory op does not match: {operand.value.mem.disp} != {offset}"
        )


def match_instr_read_mem_operand(instr: capstone.CsInsn, idx: int,
                                 base_reg: str, offset: str):
    if not instr.mnemonic.startswith("ld"):
        raise MatchError(f"Expected ld[us] found {instr.mnemonic}")

    if idx >= len(instr.operands):
        raise MatchError(
            f"Tried to match {idx}'th operand, but op has only {len(instr.operands)} operands"
        )
    operand = instr.operands[idx]
    if operand.type != capstone.arm64_const.ARM64_OP_MEM:
        raise MatchError(
            f"{idx}'th operand is not an memory op: {operand.type}")

    if instr.reg_name(operand.value.mem.base) != base_reg:
        raise MatchError(
            f"{idx}'th reg does not match: {instr.reg_name(operand.value.mem.base)} != {base_reg}"
        )

    if offset and operand.value.mem.disp != offset:
        raise MatchError(
            f"Offset for memory op does not match: {operand.value.mem.disp} != {offset}"
        )


def match_branch_isntr(instr: capstone.CsInsn, mnemonic: str):
    if instr.mnemonic != mnemonic:
        raise MatchError(f"Expected {mnemonic} found {instr.mnemonic}")


def match_sub_instr(instr: capstone.CsInsn, target_reg, const):
    if instr.mnemonic != "subs":
        raise MatchError(f"Expected opcode 'subs' found {instr.mnemonic}")


#    match_instr_reg_operand(instr, 0, target_reg)
#    match_instr_reg_operand(instr, 1, target_reg)
    match_instr_const_operand(instr, 2, const)


class TracePoint:

    def __init__(self, addr: int, check_for: str, bool_expr: BoolExpression):
        self.addr = addr
        self.check_for = check_for
        self.bool_expr = bool_expr

    def __repr__(self) -> str:
        return f"<TracePoint( 0x{self.addr:06x} ?{self.check_for} for {self.bool_expr} )>"


class MatchState:

    def __init__(self,
                 instr_idx: int,
                 target_reg: str = None,
                 partial: bool = False):
        self.instr_idx = instr_idx
        self.target_reg = target_reg
        self.partial = partial

    def __repr__(self) -> str:
        return f"<MatchState(at={self.instr_idx} partial={self.partial} target_reg={self.target_reg})>"


def match_bool_expr(expr: BoolExpression, instructions: list[capstone.CsInsn],
                    variables: list[DWVariable]):

    def fuzzy_matcher(func):

        def result(arg1, state: MatchState):
            if not state.partial:
                return func(arg1, state)
            offset = state.instr_idx
            while offset < min(offset + 10, len(instructions)):
                try:
                    return func(
                        arg1,
                        MatchState(offset, state.target_reg, state.partial))
                except MatchError as e:
                    print(f"   Got exception: {e}")
                    offset += 1
            raise MatchError(f"Fuzzy matching failed for {state}")

        return result

    def match_optional_store(state: MatchState) -> MatchState:
        if instructions[state.instr_idx].mnemonic == "mov" and instructions[
                state.instr_idx + 1].mnemonic == "str":
            state.instr_idx += 2
        return state

    ret: list[TracePoint] = []

    @fuzzy_matcher
    def handle_operand(operand: SAST, state: MatchState):
        match operand:
            case BoolVar() | NonBoolVar():
                print(f"Handling variable '{operand}'")
                v = find_variable(variables, operand.name, operand.loc.file,
                                  operand.loc.line)
                if v.loc_expr.op_name == "DW_OP_fbreg":
                    target_reg = "fp"
                    offset = v.loc_expr.args[0]
                else:
                    raise Exception(f"Unknown var op {v.loc_expr.op_name}")
                instr = instructions[state.instr_idx]
                match_instr_read_mem_operand(instr, 1, target_reg, offset)
                print(f"  Found read at 0x{instr.address:x}")
                return MatchState(state.instr_idx + 1,
                                  instr.reg_name(instr.operands[0].reg))
            case IntLiteral():
                print(
                    f"Handling int const '{operand.value}' for reg {state.target_reg}"
                )
                match_sub_instr(instructions[state.instr_idx],
                                state.target_reg, operand.value)
                return MatchState(state.instr_idx + 1, state.target_reg)
            case BoolExpression():
                print("Handling bool expr")
                return recurse(operand, state)
            case ArraySubscript():
                new_state = handle_operand(operand.array, state)
                return MatchState(new_state.instr_idx + 1,
                                  new_state.target_reg, True)
            case CCast():
                new_state = handle_operand(operand.casted, state)
                return MatchState(new_state.instr_idx + 1,
                                  new_state.target_reg, False)
            case MemberExpr():
                # Just do the fuzzy matching and hope for best
                state.partial = True
                return state
            case _:
                raise Exception(
                    f"Don't know what to do with operand {operand}")

    @fuzzy_matcher
    def recurse(e: BoolExpression, state: MatchState) -> MatchState:
        print(f"Recurse, handling {e} at {e.loc}")
        assert isinstance(e, BoolExpression)
        match e.op:
            case BoolExpression.OP_EQ | BoolExpression.OP_XOR:
                print(f"EQ: op1: {e.a} op2: {e.b}")
                new_state = handle_operand(e.a, state)
                new_state = match_optional_store(new_state)
                print(f"EQ handled state1: {new_state}")
                new_state = handle_operand(e.b, new_state)
                print(f"EQ handled state2: {new_state}")
                idx = new_state.instr_idx
                # Optional write to variable
                if instructions[idx].mnemonic in ("str", "stur"):
                    idx += 1
                if instructions[idx].mnemonic == "cset":
                    pass
                elif instructions[idx].mnemonic == "b.eq":
                    match_branch_isntr(instructions[idx], "b.eq")
                    match_branch_isntr(instructions[idx + 1], "b")
                else:
                    match_branch_isntr(instructions[idx], "b.ne")
                    match_branch_isntr(instructions[idx + 1], "b")
                ret.append(
                    TracePoint(instructions[idx].address, "'EQ FLAG(TODO)'",
                               e))
                return MatchState(idx + 2)
            case BoolExpression.OP_OR:
                print("Handling OR")
                new_state = handle_operand(e.a, state)
                new_state = match_optional_store(new_state)
                if instructions[new_state.instr_idx].mnemonic == "tbnz":
                    match_branch_isntr(instructions[new_state.instr_idx + 1],
                                       "b")
                    ret.append(
                        TracePoint(instructions[new_state.instr_idx].address,
                                   "'NOT ZERO FLAG (TODO)'", e.a))
                    new_state.instr_idx += 2
                elif instructions[new_state.instr_idx].mnemonic == "tbz":
                    match_branch_isntr(instructions[new_state.instr_idx + 1],
                                       "b")
                    ret.append(
                        TracePoint(instructions[new_state.instr_idx].address,
                                   "'ZERO FLAG (TODO)'", e.a))
                    new_state.instr_idx += 2
                new_state = handle_operand(e.b, new_state)
                if isinstance(e.b, BoolVar):
                    if instructions[new_state.instr_idx].mnemonic == "tbz":
                        match_branch_isntr(instructions[new_state.instr_idx + 1],
                                           "b")
                        ret.append(
                            TracePoint(instructions[new_state.instr_idx].address,
                                       "'ZERO FLAG (TODO)'", e.b))
                        new_state.instr_idx += 2
                    elif instructions[new_state.instr_idx].mnemonic == "tbnz":
                        match_branch_isntr(instructions[new_state.instr_idx + 1],
                                           "b")
                        ret.append(
                            TracePoint(instructions[new_state.instr_idx].address,
                                       "'NOT ZERO FLAG (TODO)'", e.b))
                        new_state.instr_idx += 2
                return new_state
            case BoolExpression.OP_AND:
                new_state = handle_operand(e.a, state)
                new_state = match_optional_store(new_state)
                if instructions[new_state.instr_idx].mnemonic == "tbz":
                    match_branch_isntr(instructions[new_state.instr_idx + 1],
                                       "b")
                    ret.append(
                        TracePoint(instructions[new_state.instr_idx].address,
                                   "'ZERO FLAG (TODO)'", e.a))
                    new_state.instr_idx += 2
                elif instructions[new_state.instr_idx].mnemonic == "tbnz":
                    match_branch_isntr(instructions[new_state.instr_idx + 1],
                                       "b")
                    ret.append(
                        TracePoint(instructions[new_state.instr_idx].address,
                                   "'NOT ZERO FLAG (TODO)'", e.a))
                    new_state.instr_idx += 2

                new_state = handle_operand(e.b, new_state)
                if isinstance(e.b, BoolVar):
                    if instructions[new_state.instr_idx].mnemonic == "tbz":
                        match_branch_isntr(instructions[new_state.instr_idx + 1],
                                           "b")
                        ret.append(
                            TracePoint(instructions[new_state.instr_idx].address,
                                       "'ZERO FLAG (TODO)'", e.b))
                        new_state.instr_idx += 2
                    elif instructions[new_state.instr_idx].mnemonic == "tbnz":
                        match_branch_isntr(instructions[new_state.instr_idx + 1],
                                           "b")
                        ret.append(
                            TracePoint(instructions[new_state.instr_idx].address,
                                       "'NOT ZERO FLAG (TODO)'", e.b))
                        new_state.instr_idx += 2
                #     # Need to handle last variable
                return new_state
            case BoolExpression.OP_NOT:
                new_state = handle_operand(e.a, state)
                return new_state
            case BoolExpression.OP_LT:
                new_state = handle_operand(e.a, state)
                new_state = match_optional_store(new_state)
                new_state = handle_operand(e.b, new_state)
                if instructions[new_state.instr_idx].mnemonic == "b.lt":
                    match_branch_isntr(instructions[new_state.instr_idx + 1],
                                       "b")
                    ret.append(
                        TracePoint(instructions[new_state.instr_idx].address,
                                   "'LT FLAG(TODO)'", e))
                elif instructions[new_state.instr_idx].mnemonic == "b.ge":
                    match_branch_isntr(instructions[new_state.instr_idx + 1],
                                       "b")
                    ret.append(
                        TracePoint(instructions[new_state.instr_idx].address,
                                   "'GE FLAG INVERSE(TODO)'", e))
                else:
                    raise MatchError(
                        f"Expected b.lt or b.ge, but found {instructions[new_state.instr_idx].mnemonic}"
                    )
                return MatchState(new_state.instr_idx + 2)
            case BoolExpression.OP_GT:
                new_state = handle_operand(e.a, state)
                new_state = match_optional_store(new_state)
                new_state = handle_operand(e.b, new_state)
                match_branch_isntr(instructions[new_state.instr_idx], "b.le")
                match_branch_isntr(instructions[new_state.instr_idx + 1], "b")
                ret.append(
                    TracePoint(instructions[new_state.instr_idx].address,
                               "'LE FLAG(TODO)'", e))
                return MatchState(new_state.instr_idx + 2)
            case _:
                raise Exception(f"Don't know what to do with {e} ({e.op})")

    assert (type(expr) == BoolExpression)
    # Try to find matching expression taking into account that it can be not
    # at the beginning of a line
    # TODO: Remove min, this is only for debugging
    recurse(expr, MatchState(0, partial=True))
    pprint(ret)
    return ret


#    for expr in expressions:
#        loc = expr.loc
#        locations.


def load_mcdc_data() -> list[SAST]:
    with open("mcdc.pickle", "rb") as f:
        expressions: SAST = pickle.load(f)
        return expressions


def main():
    mcdc_data = load_mcdc_data()
    #    process_elf("~/work/xen/xen/xen-syms")
    process_elf(sys.argv[1], mcdc_data)


if __name__ == "__main__":
    main()
