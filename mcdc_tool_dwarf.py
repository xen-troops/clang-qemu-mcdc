from elftools.elf.elffile import ELFFile
from elftools.elf.sections import SymbolTableSection
from elftools.dwarf.descriptions import (describe_DWARF_expr,
                                         set_global_machine_arch)
from elftools.dwarf.locationlists import (LocationEntry, LocationExpr,
                                          LocationParser, LocationLists)
from elftools.dwarf.lineprogram import LineProgram, LineState
from elftools.dwarf.dwarfinfo import DWARFInfo
from elftools.dwarf.die import DIE
from elftools.dwarf.compileunit import CompileUnit
from elftools.dwarf.dwarf_expr import DWARFExprParser, DWARFExprOp
from mcdc_tool_definitions import CodeLoc, SAST, BoolExpression, BoolVar, NonBoolExpression, NonBoolVar, \
    FCall, ASTEntry, MemberExpr, SizeOf, CCast, IntLiteral, StringLiteral, ArraySubscript
import pickle
import sys
from typing import Optional
from pprint import pprint
import capstone
from mcdc_tool_capstone_helper import aarch64_reg_name
import os
import logging
import traceback
import functools

log = logging.getLogger(__name__)
log.setLevel(logging.DEBUG)

#Tracing/debugging facilities
def null_trace(prefix: str, msg: str):
    pass

def log_trace(prefix: str, msg: str):
    trace = traceback.extract_stack(limit=2)
    p = f"[{prefix}][{trace[0].name}:{trace[0].lineno}]"
    log.debug(f"{p:32}|{msg}")


TRACE_EXPR_LOCATOR = functools.partial(log_trace, "ExprLocator")
TRACE_CU = functools.partial(log_trace, "HandleCU")
TRACE_MATCH = functools.partial(log_trace, "Match")


class DwarfInlinedFunc:

    def __init__(self, name: str, die: DIE, low_addr: int, high_addr: int):
        self.name = name
        self.die = die
        self.low_addr = low_addr
        self.high_addr = high_addr

    def __repr__(self) -> str:
        return f"<DwarfInlinedFunc {self.name}: {hex(self.low_addr)} - {hex(self.high_addr)}>"


class DwarfLoc:

    def __init__(self, fname: str, lp_state: LineState):
        self.fname = fname
        self.lp_state = lp_state

    def __repr__(self) -> str:
        return f"<DwarfLoc: {self.fname, self.lp_state}>"


def parse_locs(cu) -> list[DwarfLoc]:
    ret: list[LineState] = list()
    lp: LineProgram = cu.dwarfinfo.line_program_for_CU(cu)
    fnames = [x["DW_LNCT_path"].decode() for x in lp["file_names"]]
    lp_entries = lp.get_entries()
    for lp_entry in lp_entries:
        if lp_entry.state:
            state = lp_entry.state
            ret.append(DwarfLoc(fnames[state.file], state))
    return ret


def get_code_for_range(elffile: ELFFile, start, end):
    for sect in elffile.iter_sections():
        if sect["sh_type"] != "SHT_PROGBITS":
            continue
        sect_start = sect["sh_addr"]
        sect_len = sect["sh_size"]
        if start < sect_start or start > sect_start + sect_len:
            continue
        if end > sect_start + sect_len:
            # HACK: caller adds 16 bytes, remove these here
            end -= 16
        if end > sect_start + sect_len:
            sect_name = elffile._get_section_name(sect.header)
            raise Exception(
                f"Section {sect_name} holds beginning of range ({start:x}, {end:x})  but not end"
            )
        return sect.data()[start - sect_start:end - sect_start + 4]


class DWVariable:

    def __init__(self, name: str, loc_expr: DWARFExprOp, frame_base: str):
        self.name = name
        self.loc_expr = loc_expr
        self.frame_base = frame_base

    def __repr__(self) -> str:
        return f"<DWVariable: {self.name} at {self.loc_expr} (with FB {self.frame_base})>"


class ExprTraceInfo:

    def __init__(self, expr: SAST, tp: list[TracePoint]):
        self.expr = expr
        self.trace_points = tp

    def format(self):
        ret = f"; {self.expr.loc_range}\n"
        ret += f"{self.expr.uuid}:" + ",".join(
            (hex(t.addr) for t in self.trace_points)) + "\n"
        return ret

    def __str__(self):
        return f"<ExprTraceInfo for expr at {self.expr.loc_range} with {len(self.tp)} trace points>"


def _find_expr_for_loc(dw_loc: DwarfLoc,
                       expr_list: list[SAST],
                       ignored: SAST = None):
    fname = dw_loc.fname
    line = dw_loc.lp_state.line
    col = dw_loc.lp_state.column

    for expr in expr_list:
        if expr.loc.file != fname or expr == ignored:
            continue
        if line < expr.loc_range.begin.line or line > expr.loc_range.end.line:
            continue
        if (line == expr.loc_range.begin.line
                and col < expr.loc_range.begin.col) or (
                    line == expr.loc_range.end.line
                    and col > expr.loc_range.end.col):
            continue
        return expr
    return None


def _find_last_loc_for_expr(expr: SAST, locs: list[DwarfLoc],
                            start_idx: int) -> int:
    last_line = expr.loc_range.end.line
    last_col = expr.loc_range.end.col
    for idx in range(start_idx - 1, len(locs)):
        loc = locs[idx]
        if (loc.lp_state.line == last_line and loc.lp_state.column
                >= last_col) or loc.lp_state.line >= last_line:
            return idx
    raise Exception(
        "How it is possible that we found start for expression, but can't find an end?"
    )


def _collect_inlines(cu: CompileUnit) -> list[DwarfInlinedFunc]:

    def _process_dies(die: DIE) -> list[DwarfInlinedFunc]:
        ret = []
        for child in die.iter_children():
            if child.tag == "DW_TAG_inlined_subroutine":
                func_info = cu.dwarfinfo.get_DIE_from_refaddr(
                    child.attributes["DW_AT_abstract_origin"].value)
                low_pc = child.attributes["DW_AT_low_pc"].value
                high_pc = child.attributes["DW_AT_high_pc"].value
                if child.attributes["DW_AT_high_pc"].form == "DW_FORM_data4":
                    high_pc += low_pc - 4
                if not "DW_AT_name" in func_info.attributes:
                    # Some internal compiller stuff?
                    continue
                ret.append(
                    DwarfInlinedFunc(
                        func_info.attributes["DW_AT_name"].value.decode(), die,
                        low_pc, high_pc))
            if child.has_children:
                ret.extend(_process_dies(child))
        return ret

    return _process_dies(cu.get_top_DIE())


def _addr_inside_inline(inlines: list[DwarfInlinedFunc], addr: int) -> bool:
    return any((addr >= inline.low_addr and addr <= inline.high_addr
                for inline in inlines))


class ExprAddressData:

    def __init__(self, expr: SAST, start_addr: int, end_addr: int,
                 skip_list: list[(int, int)], loc_idx: int):
        self.expr = expr
        self.start_addr = start_addr
        self.end_addr = end_addr
        self.skip_list = skip_list
        self.loc_idx = loc_idx

    def __repr__(self) -> str:
        return f"<ExprData {hex(self.start_addr)}-{hex(self.end_addr)} for {self.expr} at {self.expr.loc_range}>"


def _get_next_expr_for_processing(locs: list[DwarfLoc],
                                  expressions: list[SAST],
                                  inlines: list[DwarfInlinedFunc],
                                  ignore_expr: SAST = [],
                                  level=0) -> Optional[ExprAddressData]:
    found_expr: SAST = None
    final_loc_idx: int = 0
    for i, loc in enumerate(locs):
        # If we know last location for expr - skip to it
        if i < final_loc_idx:
            continue

        # "compiler cannot attribute instruction to any source line" per Dwarf5 specification
        if loc.lp_state.line == 0:
            continue

        # "The value 0 is reserved to indicate that a statement begins at the “left edge” of the line" per Dwarf5 specification
        # The irony is that clang injects it inside expression sometimes
        if loc.lp_state.column == 0:
            continue

        cur_expr = _find_expr_for_loc(loc, expressions, ignore_expr)

        if not cur_expr and not found_expr:
            continue
        if not found_expr:
            found_expr = cur_expr
            start_loc_idx = i
            continue
        if cur_expr != found_expr or i == (len(locs) - 1):
            if _addr_inside_inline(inlines, loc.lp_state.address):
                # We are not done yet
                continue
            final_loc_idx = _find_last_loc_for_expr(found_expr, locs, i)

            # Fixup for inlines
            if final_loc_idx < i - 1:
                final_loc_idx = i - 1

            # We have found the whole range for that expr
            start_addr = locs[start_loc_idx].lp_state.address

            # Probably a hack, but somethimes dwarf data is a bit murky...
            end_addr = locs[final_loc_idx].lp_state.address + 16

            # Return outer expr and then try....
            yield ExprAddressData(found_expr, start_addr, end_addr, [], i)

            # ... end then try to find inner ones
            # (TODO: Maybe we want to change order other way around?)
            for ead in _get_next_expr_for_processing(
                    locs[start_loc_idx:final_loc_idx], expressions, inlines,
                    found_expr):
                yield ead

            # Reset state
            found_expr = cur_expr
            start_loc_idx = i
    return


def process_cu(cu: CompileUnit, elffile: ELFFile, dis,
               expressions: list[SAST]) -> list[TracePoint]:
    cu_name: str = cu.get_top_DIE().attributes['DW_AT_name'].value.decode()
    if os.path.basename(cu_name) in ("unwind-dw2.c", "unwind-dw2-fde-dip.c",
                                     "__aarch64_have_sme.c", "unwind-c.c"):
        # Nothing good in libgcc internals
        return []
    TRACE_CU(f"Handling compile unit {cu_name}")
    dwarf_locs = parse_locs(cu)
    ret: list[TracePoint] = []
    inlines = _collect_inlines(cu)
    TRACE_CU("Inlines:")
    pprint(inlines)
    for next_expr in _get_next_expr_for_processing(dwarf_locs, expressions,
                                                   inlines):
        data = get_code_for_range(elffile, next_expr.start_addr,
                                  next_expr.end_addr)
        TRACE_CU(f"Found next expr: {next_expr}")
        if not data:
            raise Exception(f"Can't get data for expr {next_expr}")
        ret.append(
            match_bool_expr(cu, elffile, next_expr.expr,
                            list(dis.disasm(data, next_expr.start_addr)),
                            inlines))

    return ret


def process_elf(fname: str, expressions: list[SAST]):
    f = open(fname, "rb")
    elffile = ELFFile(f)
    if not elffile.has_dwarf_info():
        raise Exception("We need elf file with debugging information!")
    dwarfinfo = elffile.get_dwarf_info()
    set_global_machine_arch(elffile.get_machine_arch())
    dis = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)
    dis.detail = True
    ret: list[ExprTraceInfo] = []

    for cu in dwarfinfo.iter_CUs():
        ret.extend(process_cu(cu, elffile, dis, expressions))

    with open("plugin.conf", "wt") as out:
        out.write(f"; ELF name: {fname}\n")
        for eti in ret:
            out.write(eti.format())

    with open("mcdc-dwarf.pickle", "wb") as fp:
        pickle.dump(ret, fp)


def _get_variable_loc(die: DIE, addr: int):
    # TODO: Cache this, maybe?
    location_lists = die.dwarfinfo.location_lists()
    loc_parser = LocationParser(location_lists)
    expr_parser = DWARFExprParser(die.dwarfinfo.structs)
    parsed_loc = loc_parser.parse_from_attribute(
        die.attributes["DW_AT_location"], die.cu["version"], die)
    if isinstance(parsed_loc, LocationExpr):
        loc_expr = parsed_loc.loc_expr
    else:
        loc_expr = parsed_loc[0].loc_expr
        # TODO: Need to proces the whole list
        for entity in parsed_loc:
            print(entity, type(entity))
        raise NotImplementedError()
    return expr_parser.parse_expr(loc_expr)[0]


def _parse_frame_base(attr, func_die: DIE) -> str:
    # TODO: Cache this, maybe?
    location_lists = func_die.dwarfinfo.location_lists()
    loc_parser = LocationParser(location_lists)
    expr_parser = DWARFExprParser(func_die.dwarfinfo.structs)
    parsed_loc = loc_parser.parse_from_attribute(attr, func_die.cu["version"],
                                                 func_die)
    if isinstance(parsed_loc, LocationExpr):
        loc_expr = parsed_loc.loc_expr
    else:
        raise Exception("Didn't expected frame pointer to be complex expr")
    return expr_parser.parse_expr(loc_expr)[0]


def get_variable_at_loc(cu: CompileUnit, addr: int, name: str):
    best_match = None
    for die in cu.get_top_DIE().iter_children():
        # At top level we can have two cases
        # 1. We can have global variable
        if die.tag == "DW_TAG_variable":
            # Anonymous variable (aka const string int most cases)
            if not "DW_AT_name" in die.attributes:
                continue
            if die.attributes["DW_AT_name"].value.decode() == name:
                best_match = DWVariable(name, _get_variable_loc(die, addr), "")
        # 2. We can have function parameter or local variable inside our function
        if die.tag == "DW_TAG_subprogram":
            loc = get_variable_in_func(die, addr, name)
            if loc:
                return loc
            continue

    return best_match


# TODO: Add some caching?
def find_symbol(elf: ELFFile, name: str) -> Optional[int]:
    sym_table: SymbolTableSection = elf.get_section_by_name(".symtab")
    if not sym_table:
        raise Exception("Can't find .symtab section in provided ELF")
    assert isinstance(sym_table, SymbolTableSection)
    syms = sym_table.get_symbol_by_name(name)
    if not syms:
        return None
    if len(syms) > 1:
        raise Exception(f"Found more that one symtab entry for {name}")
    return syms[0]


def is_inlined_function(cu: CompileUnit, name: str) -> bool:
    for child in cu.iter_DIEs():
        if child.tag == "DW_TAG_subprogram":
            if child.attributes["DW_AT_name"].value.decode(
            ) == name and "DW_AT_inline" in child.attributes:
                return True
    return False


def get_variable_in_func(func_die: DIE,
                         addr: int,
                         name: str,
                         frame_base: Optional[str] = None):
    # Ugh, inlined function
    if "DW_AT_inline" in func_die.attributes:
        return None

    low_pc = func_die.attributes["DW_AT_low_pc"].value
    high_pc = func_die.attributes["DW_AT_high_pc"].value
    if func_die.attributes["DW_AT_high_pc"].form == "DW_FORM_data4":
        high_pc += low_pc - 4

    if addr < low_pc or addr > high_pc:
        return None

    best_match = None
    if not frame_base:
        frame_base = _parse_frame_base(func_die.attributes["DW_AT_frame_base"],
                                       func_die).op_name
    for child in func_die.iter_children():
        if child.tag in ("DW_TAG_formal_parameter", "DW_TAG_variable"):
            if "DW_AT_name" in child.attributes:
                if child.attributes["DW_AT_name"].value.decode() != name:
                    continue
            elif "DW_AT_abstract_origin" in child.attributes:
                var_info = func_die.dwarfinfo.get_DIE_from_refaddr(
                    child.attributes["DW_AT_abstract_origin"].value)
                if var_info.attributes["DW_AT_name"].value.decode() != name:
                    continue
            else:
                raise NotImplementedError(
                    f"Dunno what to do with this var: {child}")
            parsed_loc = _get_variable_loc(child, addr)
            best_match = DWVariable(name, parsed_loc, frame_base)
        if child.tag == "DW_TAG_inlined_subroutine":
            ret = get_variable_in_func(child, addr, name, frame_base)
            if ret:
                return ret

    return best_match


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
    if not reg_cmp(aarch64_reg_name(instr.operands[idx].reg), reg):
        raise MatchError(
            f"{idx}'th register is not one that we expect: {aarch64_reg_name(instr.operands[idx].reg)} != {reg}"
        )


def get_instr_reg_operand(instr: capstone.CsInsn, idx: int) -> str:
    if idx >= len(instr.operands):
        raise MatchError(
            f"Tried to match {idx}'th operand, but op has only {len(instr.operands)} operands"
        )
    if instr.operands[idx].type != capstone.arm64_const.ARM64_OP_REG:
        raise MatchError(
            f"{idx}'th operand is not a register: {instr.operands[idx].type}")
    return aarch64_reg_name(instr.operands[idx].reg)


def get_adrp_addr(instr: capstone.CsInsn) -> int:
    if instr.mnemonic != "adrp":
        raise MatchError(
            f"Tried to get adrp offset for '{instr.mnemonic}' instruction")
    return instr.operands[1].value.imm


def match_instr_get_operand(instr: capstone.CsInsn, idx: int, name: str):
    actual_reg = get_instr_reg_operand(instr, idx)
    if actual_reg != name:
        raise MatchError(
            f"Expected reg {name} at position {idx} but found {actual_reg} for instruction {instr.mnemonic}"
        )


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

    if aarch64_reg_name(operand.value.mem.base) != base_reg:
        raise MatchError(
            f"{idx}'th reg does not match: {aarch64_reg_name(operand.value.mem.base)} != {base_reg}"
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

    if aarch64_reg_name(operand.value.mem.base) != base_reg:
        raise MatchError(
            f"{idx}'th reg does not match: {aarch64_reg_name(operand.value.mem.base)} != {base_reg}"
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


def match_sub_instr_regs(instr: capstone.CsInsn, reg1, reg2):
    if instr.mnemonic != "subs":
        raise MatchError(f"Expected opcode 'subs' found {instr.mnemonic}")

    match_instr_reg_operand(instr, 1, reg1)
    match_instr_reg_operand(instr, 2, reg2)


class TracePoint:

    def __init__(self, addr: int, inverted: bool, bool_expr: BoolExpression):
        self.addr = addr
        self.inverted = inverted
        self.bool_expr = bool_expr

    def __repr__(self) -> str:
        return f"<TracePoint( 0x{self.addr:06x} : {self.bool_expr} (inverted: {self.inverted}) )>"


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


def reg_cmp(r1: str, r2: str):
    if r1.startswith("x") or r1.startswith("w"):
        r1 = r1[1:]
    if r2.startswith("x") or r2.startswith("w"):
        r2 = r2[1:]
    return r1 == r2


def match_bool_expr(cu: CompileUnit, elf: ELFFile, expr: BoolExpression,
                    instructions: list[capstone.CsInsn],
                    inlines: list[DwarfInlinedFunc]):

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
                    TRACE_MATCH(f"   Got exception: {e}")
                    offset += 1
            raise MatchError(f"Fuzzy matching failed for {state}")

        return result

    def match_optional_store(state: MatchState) -> MatchState:
        if state.instr_idx >= len(instructions) - 1:
            return state
        if instructions[state.instr_idx].mnemonic == "mov" and instructions[
                state.instr_idx + 1].mnemonic == "str":
            state.instr_idx += 2
        return state

    def match_optional_bool_cast(state: MatchState) -> MatchState:
        instr = instructions[state.instr_idx]
        if instr.mnemonic == "and" and reg_cmp(get_instr_reg_operand(instr, 1),
                                               state.target_reg):
            state.instr_idx += 1
            state.target_reg = get_instr_reg_operand(instr, 0)
        return state

    ret: list[TracePoint] = []

    def _handle_inlined_fcall(operand: SAST, state: MatchState):
        # Find inline function and fast forwards to its end
        fname = operand.fname.name
        for inline in inlines:
            if inline.name == fname:
                # Find idx for start address
                for idx in range(state.instr_idx, len(instructions)):
                    if instructions[idx].address == inline.low_addr:
                        break
                    else:
                        continue
                    # Find idx for end address
                for idx in range(idx, len(instructions)):
                    if instructions[idx].address == inline.high_addr:
                        target_reg = get_instr_reg_operand(
                            instructions[idx], 0)
                        return MatchState(idx + 1, target_reg, False)
                raise Exception(
                    "End of inlined function is past expression range?")
        raise Exception(
            f"Could not find inlined function {fname} new {hex(instructions[state.instr_idx].address)} in list of inlines"
        )

    def handle_fcall(operand: SAST, state: MatchState):
        if isinstance(operand.fname, NonBoolVar):
            if is_inlined_function(cu, operand.fname.name):
                return _handle_inlined_fcall(operand, state)
            # Try looking in in global symbol table
            sym = find_symbol(elf, operand.fname.name)
            func_addr = sym["st_value"]
            for idx in range(state.instr_idx, len(instructions)):
                instr = instructions[idx]
                if instr.mnemonic == "bl" and instr.operands[
                        0].value.imm == func_addr:
                    return MatchState(idx + 1, "x0")
            else:
                raise MatchError("Can't find function call")
        raise NotImplementedError()
        state = handle_operand(operand.fname, state)
        state.partial = True
        return state

    @fuzzy_matcher
    def handle_operand(operand: SAST, state: MatchState):
        TRACE_MATCH(f"handle_operand {type(operand)}")
        match operand:
            case BoolVar() | NonBoolVar():
                v = get_variable_at_loc(cu,
                                        instructions[state.instr_idx].address,
                                        operand.name)
                if not v:
                    raise Exception(
                        f"Can't find variable {operand.name} near address 0x{instructions[state.instr_idx].address:x}"
                    )
                match v.loc_expr.op_name:
                    case "DW_OP_fbreg":
                        match v.frame_base:
                            case "DW_OP_reg31":
                                target_reg = "sp"
                            case "DW_OP_reg29":
                                target_reg = "x29"
                            case _:
                                raise Exception(
                                    f"TODO: Match reg {v.frame_base}")
                        offset = v.loc_expr.args[0]
                        instr = instructions[state.instr_idx]
                        match_instr_read_mem_operand(instr, 1, target_reg,
                                                     offset)
                        TRACE_MATCH(f"  Found read at 0x{instr.address:x}")
                        return MatchState(
                            state.instr_idx + 1,
                            aarch64_reg_name(instr.operands[0].reg))
                    case "DW_OP_addrx":
                        abs_addr = cu.dwarfinfo.get_addr(
                            cu, v.loc_expr.args[0])
                        TRACE_MATCH(f"Global variable offset is {abs_addr:x}")
                        instr = instructions[state.instr_idx]
                        offset = get_adrp_addr(instr)
                        reg = get_instr_reg_operand(instr, 0)
                        rem = abs_addr - offset
                        TRACE_MATCH(f"remainder is {rem} in {reg}")
                        instr = instructions[state.instr_idx + 1]
                        match_instr_read_mem_operand(instr, 1, reg, rem)
                        return MatchState(
                            state.instr_idx + 2,
                            aarch64_reg_name(instr.operands[0].reg))
                    case "DW_OP_breg31":
                        target_reg = "sp"
                        offset = v.loc_expr.args[0]
                        instr = instructions[state.instr_idx]
                        match_instr_read_mem_operand(instr, 1, target_reg,
                                                     offset)
                        TRACE_MATCH(f"  Found read at 0x{instr.address:x}")
                        return MatchState(
                            state.instr_idx + 1,
                            aarch64_reg_name(instr.operands[0].reg))
                    case _:
                        raise Exception(f"Unknown var op {v.loc_expr.op_name}")
            case IntLiteral():
                TRACE_MATCH(
                    f"Handling int const '{operand.value}' for reg {state.target_reg}"
                )
                if operand.value == 0:
                    # Clang can generate cbnz in that case
                    if instructions[state.instr_idx].mnemonic == "cbnz":
                        # Let caller handle that case
                        return state
                    if instructions[state.instr_idx].mnemonic == "cbz":
                        # Let caller handle that case
                        return state
                match_sub_instr(instructions[state.instr_idx],
                                state.target_reg, operand.value)
                return MatchState(state.instr_idx + 1, state.target_reg)
            case BoolExpression():
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
                state = handle_operand(operand.left, state)
                state.partial = True
                return state
            case FCall():
                return handle_fcall(operand, state)
            case _:
                raise Exception(
                    f"Don't know what to do with operand {operand}")

    def handle_lt_gt_op(e: BoolExpression, state: MatchState) -> MatchState:
        # TODO: Handle differences in LT, LE, GT, GE
        op1_state = handle_operand(e.a, state)
        op1_state = match_optional_store(op1_state)
        op2_state = handle_operand(e.b, op1_state)
        new_state = op2_state

        op_is_gt_ge = (e.op == BoolExpression.OP_GT or e.op == BoolExpression.OP_GE)

        if not isinstance(e.b, IntLiteral):
            # We need subs op if it is not handled by IntLiteral() handler
            match_sub_instr_regs(instructions[new_state.instr_idx],
                                 op1_state.target_reg, op2_state.target_reg)
            new_state.instr_idx += 1

        match instructions[new_state.instr_idx].mnemonic:
            case "b.lt":
                inverted = op_is_gt_ge
                match_branch_isntr(instructions[new_state.instr_idx + 1], "b")
                ret.append(
                    TracePoint(instructions[new_state.instr_idx].address,
                               inverted, e))
            case "b.le":
                inverted = op_is_gt_ge
                match_branch_isntr(instructions[new_state.instr_idx + 1], "b")
                ret.append(
                    TracePoint(instructions[new_state.instr_idx].address,
                               inverted, e))
            case "b.gt":
                inverted = not op_is_gt_ge
                match_branch_isntr(instructions[new_state.instr_idx + 1], "b")
                ret.append(
                    TracePoint(instructions[new_state.instr_idx].address,
                               inverted, e))
            case "b.ge":
                inverted = not op_is_gt_ge
                match_branch_isntr(instructions[new_state.instr_idx + 1], "b")
                ret.append(
                    TracePoint(instructions[new_state.instr_idx].address,
                               inverted, e))
            case "tbnz":
                inverted = op_is_gt_ge
                match_branch_isntr(instructions[new_state.instr_idx + 1], "b")
                ret.append(
                    TracePoint(instructions[new_state.instr_idx].address,
                               inverted, e))
            case "tbz":
                inverted = not op_is_gt_ge
                match_branch_isntr(instructions[new_state.instr_idx + 1], "b")
                ret.append(
                    TracePoint(instructions[new_state.instr_idx].address,
                               inverted, e))
            case "cset":
                # TBD: Match cset condition flags
                instr = instructions[new_state.instr_idx]
                ret.append(
                    TracePoint(instr.address,
                               False, e))
                return MatchState(new_state.instr_idx + 1)
            case _:
                raise MatchError(
                    f"Expected b.lt or b.ge, but found {instructions[new_state.instr_idx].mnemonic}"
                )
        return MatchState(new_state.instr_idx + 2)

    @fuzzy_matcher
    def recurse(e: BoolExpression, state: MatchState) -> MatchState:
        TRACE_MATCH(f"Recurse, handling {e} at {e.loc}")
        assert isinstance(e, BoolExpression)
        match e.op:
            case BoolExpression.OP_EQ:
                new_state = handle_operand(e.a, state)
                new_state = match_optional_store(new_state)
                new_state = match_optional_bool_cast(new_state)
                new_state = handle_operand(e.b, new_state)
                idx = new_state.instr_idx
                # Optional write to variable
                if instructions[idx].mnemonic in ("str", "stur"):
                    idx += 1
                match instructions[idx].mnemonic:
                    case "b.eq":
                        match_branch_isntr(instructions[idx], "b.eq")
                        match_branch_isntr(instructions[idx + 1], "b")
                        ret.append(
                            TracePoint(instructions[idx].address,
                                       False, e))
                    case "b.ne":
                        match_branch_isntr(instructions[idx], "b.ne")
                        match_branch_isntr(instructions[idx + 1], "b")
                        ret.append(
                            TracePoint(instructions[idx].address,
                                       True, e))
                    case "cbnz":
                        match_branch_isntr(instructions[idx], "cbnz")
                        match_instr_reg_operand(instructions[idx], 0,
                                                new_state.target_reg)
                        match_branch_isntr(instructions[idx + 1], "b")
                        ret.append(
                            TracePoint(instructions[idx].address,
                                       True, e))
                    case "cbz":
                        match_branch_isntr(instructions[idx], "cbz")
                        match_instr_reg_operand(instructions[idx], 0,
                                                new_state.target_reg)
                        match_branch_isntr(instructions[idx + 1], "b")
                        ret.append(
                            TracePoint(instructions[idx].address,
                                       False, e))
                    case "cset":
                        # TBD: Match cset condition flags
                        ret.append(
                            TracePoint(
                                instructions[idx].address,
                                False,
                                e))
                        return MatchState(idx + 1)
                    case _:
                        raise MatchError(
                            f"Expected for conditional branch, found {instructions[idx].mnemonic}"
                        )

                return MatchState(idx + 2)
            case BoolExpression.OP_XOR:
                op1_state = handle_operand(e.a, state)
                op1_state = match_optional_bool_cast(op1_state)
                op2_state = handle_operand(e.b, op1_state)
                op2_state = match_optional_bool_cast(op2_state)
                instr = instructions[op2_state.instr_idx]
                match_sub_instr_regs(instr, op1_state.target_reg,
                                     op2_state.target_reg)
                new_state = MatchState(op2_state.instr_idx + 1,
                                       get_instr_reg_operand(instr, 0))
                inverted = False
                idx = new_state.instr_idx
                # Optional write to variable
                if instructions[idx].mnemonic in ("str", "stur"):
                    idx += 1
                if instructions[idx].mnemonic == "cset":
                    pass
                elif instructions[idx].mnemonic == "b.eq":
                    inverted = True
                    match_branch_isntr(instructions[idx], "b.eq")
                    match_branch_isntr(instructions[idx + 1], "b")
                elif instructions[idx].mnemonic == "b.ne":
                    match_branch_isntr(instructions[idx + 1], "b")
                elif instructions[idx].mnemonic == "cbz":
                    inverted = True
                    match_branch_isntr(instructions[idx + 1], "b")
                else:
                    match_branch_isntr(instructions[idx + 1], "cbnz")
                    match_branch_isntr(instructions[idx + 1], "b")
                ret.append(
                    TracePoint(instructions[idx].address, inverted,
                               e))
                ret.append(
                    TracePoint(instructions[idx].address, inverted,
                               e))
                return MatchState(idx + 2)
            case BoolExpression.OP_OR:
                new_state = handle_operand(e.a, state)
                new_state = match_optional_store(new_state)
                inverted = False
                if instructions[new_state.instr_idx].mnemonic == "tbnz":
                    match_branch_isntr(instructions[new_state.instr_idx + 1],
                                       "b")
                    ret.append(
                        TracePoint(instructions[new_state.instr_idx].address,
                                   False, e.a))
                    new_state.instr_idx += 2
                elif instructions[new_state.instr_idx].mnemonic == "tbz":
                    match_branch_isntr(instructions[new_state.instr_idx + 1],
                                       "b")
                    ret.append(
                        TracePoint(instructions[new_state.instr_idx].address,
                                   True, e.a))
                    new_state.instr_idx += 2
                new_state = handle_operand(e.b, new_state)
                if isinstance(e.b, BoolVar):
                    if instructions[new_state.instr_idx].mnemonic == "tbz":
                        match_branch_isntr(
                            instructions[new_state.instr_idx + 1], "b")
                        ret.append(
                            TracePoint(
                                instructions[new_state.instr_idx].address,
                                True, e.b))
                        new_state.instr_idx += 2
                    elif instructions[new_state.instr_idx].mnemonic == "tbnz":
                        match_branch_isntr(
                            instructions[new_state.instr_idx + 1], "b")
                        ret.append(
                            TracePoint(
                                instructions[new_state.instr_idx].address,
                                False, e.b))
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
                                   True, e.a))
                    new_state.instr_idx += 2
                elif instructions[new_state.instr_idx].mnemonic == "tbnz":
                    match_branch_isntr(instructions[new_state.instr_idx + 1],
                                       "b")
                    ret.append(
                        TracePoint(instructions[new_state.instr_idx].address,
                                   False, e.a))
                    new_state.instr_idx += 2
                elif instructions[new_state.instr_idx].mnemonic == "cbz":
                    match_branch_isntr(instructions[new_state.instr_idx + 1],
                                       "b")
                    ret.append(
                        TracePoint(instructions[new_state.instr_idx].address,
                                   False, e.a))
                    new_state.instr_idx += 2
                elif instructions[new_state.instr_idx].mnemonic == "cbnz":
                    match_branch_isntr(instructions[new_state.instr_idx + 1],
                                       "b")
                    ret.append(
                        TracePoint(instructions[new_state.instr_idx].address,
                                   False, e.a))
                    new_state.instr_idx += 2

                new_state = handle_operand(e.b, new_state)
                if isinstance(e.b, BoolVar):
                    if instructions[new_state.instr_idx].mnemonic == "tbz":
                        match_branch_isntr(
                            instructions[new_state.instr_idx + 1], "b")
                        ret.append(
                            TracePoint(
                                instructions[new_state.instr_idx].address,
                                True, e.b))
                        new_state.instr_idx += 2
                    elif instructions[new_state.instr_idx].mnemonic == "tbnz":
                        match_branch_isntr(
                            instructions[new_state.instr_idx + 1], "b")
                        ret.append(
                            TracePoint(
                                instructions[new_state.instr_idx].address,
                                False, e.b))
                        new_state.instr_idx += 2
                #     # Need to handle last variable
                return new_state
            case BoolExpression.OP_NOT:
                new_state = handle_operand(e.a, state)
                return new_state
            case BoolExpression.OP_LT:
                return handle_lt_gt_op(e, state)
            case BoolExpression.OP_GT:
                return handle_lt_gt_op(e, state)
            case BoolExpression.OP_IMPLICIT_CAST:
                new_state = handle_operand(e.a, state)
                match instructions[new_state.instr_idx].mnemonic:
                    case "tbz" | "cbz" | "cbnz":
                        ret.append(TracePoint(instructions[new_state.instr_idx].address, False, e))
                        new_state.instr_idx +=1
                        return new_state
                    case _:
                        raise NotImplementedError(f"Don't know how to handle implicit bool cast instrction {instructions[new_state.instr_idx].mnemonic}")
            case _:
                raise Exception(f"Don't know what to do with {e} ({e.op})")

    assert (type(expr) == BoolExpression)
    # Try to find matching expression taking into account that it can be not
    # at the beginning of a line
    # TODO: Remove min, this is only for debugging
    recurse(expr, MatchState(0, partial=True))
    pprint(ret)
    return ExprTraceInfo(expr, ret)


#    for expr in expressions:
#        loc = expr.loc
#        locations.


def load_mcdc_data() -> list[SAST]:
    with open("mcdc.pickle", "rb") as f:
        expressions: SAST = pickle.load(f)
        return expressions


def main():
    logging.basicConfig(level=logging.DEBUG)
    mcdc_data = load_mcdc_data()
    #    process_elf("~/work/xen/xen/xen-syms")
    process_elf(sys.argv[1], mcdc_data)


if __name__ == "__main__":
    main()
