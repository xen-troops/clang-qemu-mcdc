from __future__ import annotations

from elftools.elf.elffile import ELFFile
from elftools.elf.sections import SymbolTableSection
from elftools.dwarf.descriptions import set_global_machine_arch
from elftools.dwarf.locationlists import (
    LocationExpr,
    LocationParser,
)
from elftools.dwarf.lineprogram import LineProgram, LineState
from elftools.dwarf.die import DIE
from elftools.dwarf.compileunit import CompileUnit
from elftools.dwarf.dwarf_expr import DWARFExprParser, DWARFExprOp
from elftools.dwarf.ranges import RangeEntry, BaseAddressEntry
from mcdc_tool_definitions import (SAST, BoolExpression, BoolVar, NonBoolExpression, NonBoolVar,
                                   FCall, MemberExpr, SizeOf, CCast, IntLiteral, ArraySubscript,
                                   EnumConst)
import pickle
import argparse
from typing import Optional, Unpack
from pprint import pformat, pprint
from dataclasses import dataclass, fields
from copy import copy
import capstone
from mcdc_tool_capstone_helper import aarch64_reg_name
from mcdc_tool_s_loc import SFileLoc, SFileLocMap
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


TRACE_EXPR_LOCATOR = functools.partial(null_trace, "ExprLocator")
TRACE_CU = functools.partial(null_trace, "HandleCU")
TRACE_MATCH = functools.partial(null_trace, "Match")


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
        self.inlines: list[SFileLoc] = []

    def __repr__(self) -> str:
        return f"<DwarfLoc: {self.fname, self.lp_state}>"


def parse_locs(cu, sfilelocs: list[SFileLocMap]) -> list[DwarfLoc]:
    ret: list[LineState] = list()
    lp: LineProgram = cu.dwarfinfo.line_program_for_CU(cu)
    fnames = [x["DW_LNCT_path"].decode() for x in lp["file_names"]]
    lp_entries = lp.get_entries()
    for lp_entry in lp_entries:
        if lp_entry.state:
            state = lp_entry.state
            loc = DwarfLoc(fnames[state.file], state)

            # Augment with inline data
            for sl in sfilelocs:
                if sl.origin.fname == loc.fname and sl.origin.line == state.line and sl.origin.col == state.column:
                    loc.inlines = sl.inlines
                    # Heuristic (or hack, depending on how you see
                    # it):
                    # The same inlined expression can appear
                    # multiple times in the same file.  Here we rely
                    # on the fact that locations from DWARF data are
                    # in the same order as location from assembly file
                    sfilelocs.remove(sl)
                    break

            ret.append(loc)
    return ret


CODE_OUT_OF_SECTION = 0


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
            global CODE_OUT_OF_SECTION
            CODE_OUT_OF_SECTION += 1
            raise Exception(
                f"Section {sect_name} holds beginning of range ({start:x}, {end:x})  but not end")
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
        ret += f"{self.expr.uuid} " + ",".join((hex(t.addr) for t in self.trace_points)) + "\n"
        return ret

    def __str__(self):
        return f"<ExprTraceInfo for expr at {self.expr.loc_range} with {len(self.trace_points)} trace points>"


def _collect_inlines(cu: CompileUnit) -> list[DwarfInlinedFunc]:

    def _process_dies(die: DIE) -> list[DwarfInlinedFunc]:
        ret = []
        for child in die.iter_children():
            if child.tag == "DW_TAG_inlined_subroutine":
                func_info = child.get_DIE_from_attribute("DW_AT_abstract_origin")
                low_pc = child.attributes["DW_AT_low_pc"].value
                high_pc = child.attributes["DW_AT_high_pc"].value - 4
                if child.attributes["DW_AT_high_pc"].form == "DW_FORM_data4":
                    high_pc += low_pc
                if not "DW_AT_name" in func_info.attributes:
                    # Some internal compiller stuff?
                    continue
                ret.append(
                    DwarfInlinedFunc(func_info.attributes["DW_AT_name"].value.decode(), die, low_pc,
                                     high_pc))
            if child.has_children:
                ret.extend(_process_dies(child))
        return ret

    return _process_dies(cu.get_top_DIE())


def _addr_inside_inline(inline: DwarfInlinedFunc, addr) -> bool:
    return addr >= inline.low_addr and addr <= inline.high_addr


def _addr_inside_inlines(inlines: list[DwarfInlinedFunc], addr: int) -> bool:
    return any((_addr_inside_inline(inline, addr) for inline in inlines))


@functools.lru_cache
def _file_line_col_in_expr(expr: SAST, fname: str, line: int, col: int) -> bool:
    if expr.loc.file != fname:
        return False
    # Zero values are special
    if not line or not col:
        return False

    if line < expr.loc_range.begin.line or line > expr.loc_range.end.line:
        return False
    if line == expr.loc_range.begin.line and col < expr.loc_range.begin.col:
        return False
    if line == expr.loc_range.end.line and col > expr.loc_range.end.col:
        return False

    return True


@functools.lru_cache
def _loc_is_in_expr(expr: SAST, loc: DwarfLoc) -> bool:
    fname = loc.fname
    line = loc.lp_state.line
    col = loc.lp_state.column

    return _file_line_col_in_expr(expr, fname, line, col) or any(
        (_file_line_col_in_expr(expr, i.fname, i.line, i.col) for i in loc.inlines))


def _get_inlined_func_by_addr(inlines: list[DwarfInlinedFunc],
                              addr: int) -> Optional[DwarfInlinedFunc]:
    for inline in inlines:
        if _addr_inside_inline(inline, addr):
            return inline

    return None


def _get_locations_for_inline(locations: list[DwarfLoc],
                              inline: DwarfInlinedFunc) -> list[DwarfLoc]:
    start_idx = None
    end_idx = None
    for idx, loc in enumerate(locations):
        addr = loc.lp_state.address
        if _addr_inside_inline(inline, addr):
            end_idx = idx
            if not start_idx:
                start_idx = idx

    assert start_idx
    assert end_idx

    TRACE_EXPR_LOCATOR(
        f"Addr ranges for {inline}: {locations[start_idx].lp_state.address:x} - {locations[end_idx].lp_state.address:x} "
    )
    return locations[start_idx:end_idx + 1]


def _function_name_in_inlines(fname: str, inlines: list[DwarfInlinedFunc]):
    return any((fname == inline.name for inline in inlines))


def _get_fcalls_in_expr(expr: SAST) -> list[str]:
    ret = []
    if isinstance(expr, FCall):
        if isinstance(expr.fname, NonBoolVar):
            ret.append(expr.fname.name)
    for child in expr.inner:
        ret.extend(_get_fcalls_in_expr(child))
    return ret

def _get_addr_ranges_for_expr(expr: SAST, locations: list[DwarfLoc],
                              inlines: list[DwarfInlinedFunc]) -> list[(int, int)]:
    ret = []
    # Our life would be much easier if there wasn't forced inlines
    # But taking inlines into account, the same expression can appear
    # multiple times in object file

    # Also. this function will be pretty slow, as it scans whole list
    # of locations. Many optimisatation possibilities here
    start_loc: DwarfLoc = None
    end_loc: DwarfLoc = None
    TRACE_EXPR_LOCATOR(f"Looking for address ranges for expr {expr}, {expr.loc_range=}")
    if _function_name_in_inlines(expr.function_name(), inlines):
        # Hard mode
        TRACE_EXPR_LOCATOR(f"   expression belongs to inlined function {expr.function_name()}")
        for inline in inlines:
            if inline.name == expr.function_name():
                # TODO: Optimise me, please. No need to traverse
                # 'locations' for ech inline
                r = _get_addr_ranges_for_expr(expr, _get_locations_for_inline(locations, inline),
                                              [])
                # Heuristic: we need to include the whole inlined function
                # even if it is absent in DWARF location data
                if not r:
                    continue
                fcalls = _get_fcalls_in_expr(expr)
                if fcalls:
                    TRACE_EXPR_LOCATOR(f"  Function calls in expr: {fcalls}")
                for fcall in fcalls:
                    for inline2 in inlines:
                        if inline2.name == fcall and inline2.low_addr <= r[0][
                                0] and inline2.high_addr >= r[0][0]:
                            if r[0][0] > inline2.low_addr:
                                TRACE_EXPR_LOCATOR(
                                    f"  moving start of expr from {r[0][0]:#x} to {inline2.low_addr:#x}"
                                )
                                # Replace tuple with a new one
                                r[0] = (inline2.low_addr, r[0][1])
                            if r[0][1] < inline2.high_addr:
                                TRACE_EXPR_LOCATOR(
                                    f"  moving end of expr from {r[0][1]:#x} to {inline2.high_addr:#x}"
                                )
                                # Replace tuple with a new one
                                r[0] = (r[0][0], inline2.high_addr)

                ret.extend(r)
    else:
        # Easy mode
        for idx, loc in enumerate(locations):
            if _loc_is_in_expr(expr, loc):
                # Always update end_loc
                if idx + 1 < len(locations):
                    end_loc = locations[idx + 1]
                else:
                    end_loc = locations[idx]
                if not start_loc:
                    start_loc = loc

    if start_loc:
        assert end_loc
        ret.append((start_loc.lp_state.address, end_loc.lp_state.address))

    TRACE_EXPR_LOCATOR("  returning [")
    for r in ret:
        TRACE_EXPR_LOCATOR(f"    {r[0]:#x} - {r[1]:#x}")
    TRACE_EXPR_LOCATOR("  ]")
    return ret


class ExprAddressData:

    def __init__(self, expr: SAST, start_addr: int, end_addr: int):
        self.expr = expr
        self.start_addr = start_addr
        self.end_addr = end_addr

    def __repr__(self) -> str:
        return f"<ExprData {hex(self.start_addr)}-{hex(self.end_addr)} for {self.expr} at {self.expr.loc_range}>"


def _get_next_expr_for_processing(locs: list[DwarfLoc], expressions: list[SAST],
                                  inlines: list[DwarfInlinedFunc]) -> Optional[ExprAddressData]:
    for expr in expressions:
        ranges = _get_addr_ranges_for_expr(expr, locs, inlines)
        for r in ranges:
            yield ExprAddressData(expr, r[0], r[1] + 24)


FAIL_COUNTER = 0
ELF_RANGE_FAIL_CNT = 0


def _get_inlines_to_skip(expr: ExprAddressData, inlines: list[DwarfInlinedFunc],
                         used_funcs: list[str]) -> list[DwarfInlinedFunc]:

    ret = []
    for inline in inlines:
        # This function is present in expr
        if inline.name in used_funcs:
            continue
        # Inline actually covers all expr
        if inline.low_addr < expr.start_addr or inline.high_addr > expr.end_addr:
            continue

        # XXX: Make sure that we'll keep end of inlined function
        c = copy(inline)
        c.high_addr =-4
        ret.append(c)
    return ret


def process_cu(cu: CompileUnit, elffile: ELFFile, dis, expressions: list[SAST],
               s_file_locs: list[SFileLocMap]) -> list[TracePoint]:
    cu_name: str = cu.get_top_DIE().attributes['DW_AT_name'].value.decode()
    if os.path.basename(cu_name) in ("unwind-dw2.c", "unwind-dw2-fde-dip.c", "__aarch64_have_sme.c",
                                     "unwind-c.c"):
        # Nothing good in libgcc internals
        return []
    TRACE_CU(f"Handling compile unit {cu_name}")
    dwarf_locs = parse_locs(cu, s_file_locs)
    ret: list[TracePoint] = []
    inlines = _collect_inlines(cu)
    TRACE_CU("Inlines:")
    TRACE_CU(pformat(inlines))
    for next_expr in _get_next_expr_for_processing(dwarf_locs, expressions, inlines):
        try:
            data = get_code_for_range(elffile, next_expr.start_addr, next_expr.end_addr)
        except Exception:
            pass
        TRACE_CU(f"Found next expr: {next_expr}")
        if not data:
            global ELF_RANGE_FAIL_CNT
            ELF_RANGE_FAIL_CNT += 1


#            raise Exception(f"Can't get data for expr {next_expr}")
        try:
            instructions = list(dis.disasm(data, next_expr.start_addr))
            # Skip inlined functions if we are not interested in these
            fcalls = _get_fcalls_in_expr(next_expr.expr)
            skip_inlines = _get_inlines_to_skip(next_expr, inlines, fcalls)
            TRACE_CU(f"{skip_inlines=}")
            instructions = [
                insn for insn in instructions if not _addr_inside_inlines(skip_inlines, insn.address)
            ]
            ret.append(match_bool_expr(cu, elffile, next_expr.expr, instructions, inlines))
        except TypeError:
            raise
        except Exception as e:
            log.warning(f"Got exception {e}. Skipping that expr.")
            TRACE_CU(traceback.format_exc())
            if FAIL_FAST:
                raise e
            global FAIL_COUNTER
            FAIL_COUNTER += 1
    return ret


def process_elf(fname: str, expressions: list[SAST], inline_map: dict[str, list[SFileLocMap]],
                out_dwarf_pickle: str, out_plugin_conf: str, target_cu: Optional[str] = None):
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
        cu_name = cu.get_top_DIE().attributes['DW_AT_name'].value.decode()

        if target_cu and cu_name != target_cu:
            continue
        cu_inlines = inline_map.get(cu_name, [])

        ret.extend(process_cu(cu, elffile, dis, expressions, cu_inlines))

    print(f"Created {len(ret)} tracepoint objects")
    with open(out_plugin_conf, "wt") as out:
        out.write(f"; ELF name: {fname}\n")
        for eti in ret:
            out.write(eti.format())

    with open(out_dwarf_pickle, "wb") as fp:
        pickle.dump(ret, fp)


@functools.lru_cache
def _get_variable_loc(die: DIE, addr: int):
    # TODO: Cache this, maybe?
    location_lists = die.dwarfinfo.location_lists()
    loc_parser = LocationParser(location_lists)
    expr_parser = DWARFExprParser(die.dwarfinfo.structs)
    parsed_loc = loc_parser.parse_from_attribute(die.attributes["DW_AT_location"],
                                                 die.cu["version"], die)
    if isinstance(parsed_loc, LocationExpr):
        loc_expr = parsed_loc.loc_expr
    else:
        loc_expr = parsed_loc[0].loc_expr
        # TODO: Need to proces the whole list
        for entity in parsed_loc:
            print(entity, type(entity))
        raise NotImplementedError("Can't handle location expression list")
    return expr_parser.parse_expr(loc_expr)[0]


def _parse_frame_base(attr, func_die: DIE) -> str:
    # TODO: Cache this, maybe?
    location_lists = func_die.dwarfinfo.location_lists()
    loc_parser = LocationParser(location_lists)
    expr_parser = DWARFExprParser(func_die.dwarfinfo.structs)
    parsed_loc = loc_parser.parse_from_attribute(attr, func_die.cu["version"], func_die)
    if isinstance(parsed_loc, LocationExpr):
        loc_expr = parsed_loc.loc_expr
    else:
        raise Exception("Didn't expected frame pointer to be complex expr")
    return expr_parser.parse_expr(loc_expr)[0]


@dataclass
class VariableInfo:
    name: str
    op_type: str
    arg: int
    frame_base: str


def get_variable_at_loc(cu: CompileUnit, addr: int, name: str) -> VariableInfo:
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
                return VariableInfo(name, loc.loc_expr.op_name, loc.loc_expr.args[0],
                                    loc.frame_base)
            continue

    if best_match:
        return VariableInfo(name, best_match.loc_expr.op_name, best_match.loc_expr.args[0],
                            best_match.frame_base)
    return None


def get_global_variable(elf: ELFFile, name: str) -> VariableInfo:
    sym = find_symbol(elf, name)
    if not sym:
        return None
    return VariableInfo(name, "DW_OP_abs_addr", sym, None)


@functools.lru_cache
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
    return syms[0]["st_value"]


def find_function(cu: CompileUnit, name: str) -> Optional[int]:
    for child in cu.iter_DIEs():
        if child.tag == "DW_TAG_subprogram":
            if child.attributes["DW_AT_name"].value.decode() == name:
                return child.attributes["DW_AT_low_pc"].value
    return None


def is_inlined_function(cu: CompileUnit, name: str) -> bool:
    for child in cu.iter_DIEs():
        if child.tag == "DW_TAG_subprogram":
            if child.attributes["DW_AT_name"].value.decode(
            ) == name and "DW_AT_inline" in child.attributes:
                return True
    return False


def get_enum_value(cu: CompileUnit, name: str) -> Optional[int]:
    for child in cu.iter_DIEs():
        if child.tag == "DW_TAG_enumeration_type":
            for val in child.iter_children():
                if val.tag == "DW_TAG_enumerator" and val.attributes["DW_AT_name"].value.decode(
                ) == name:
                    return val.attributes["DW_AT_const_value"].value
    return None

@dataclass(repr=False)
class DWARFRange:
    low_pc: int
    high_pc: int
    def __repr__(self) -> str:
        return f"<DWARFRange {self.low_pc:x} - {self.high_pc:x}>"

def _parse_dw_at_ranges(attr, cu: CompileUnit) -> list[DWARFRange]:
    range_lists = cu.dwarfinfo.range_lists()
    rl = range_lists.get_range_list_at_offset(attr.value, cu)
    ret = []
    base_addr: int = 0
    for entry in rl:
        match(entry):
            case BaseAddressEntry():
                base_addr = entry.base_address
            case RangeEntry():
                if entry.is_absolute:
                    raise NotImplementedError("Can't handle absolute RangeEntry")
                ret.append(DWARFRange(base_addr + entry.begin_offset, base_addr + entry.end_offset))
    return ret

def _simple_range_to_ranges(die: DIE) -> list[DWARFRange]:
    low_pc = die.attributes["DW_AT_low_pc"].value
    high_pc = die.attributes["DW_AT_high_pc"].value - 4
    if die.attributes["DW_AT_high_pc"].form == "DW_FORM_data4":
        high_pc += low_pc

    return [DWARFRange(low_pc, high_pc)]

def get_variable_in_func(func_die: DIE, addr: int, name: str, frame_base: Optional[str] = None):
    # Ugh, inlined function
    if "DW_AT_inline" in func_die.attributes:
        return None

    if "DW_AT_ranges" in func_die.attributes:
        # TODO
        ranges = _parse_dw_at_ranges(func_die.attributes["DW_AT_ranges"], func_die.cu)
    else:
        ranges = _simple_range_to_ranges(func_die)

    for range in ranges:
        if addr >= range.low_pc and addr <= range.high_pc:
            break
    else:
        return None

    best_match = None
    if not frame_base:
        frame_base = _parse_frame_base(func_die.attributes["DW_AT_frame_base"], func_die).op_name
    for child in func_die.iter_children():
        if child.tag in ("DW_TAG_formal_parameter", "DW_TAG_variable"):
            if "DW_AT_name" in child.attributes:
                if child.attributes["DW_AT_name"].value.decode() != name:
                    continue
            elif "DW_AT_abstract_origin" in child.attributes:
                var_info = child.get_DIE_from_attribute("DW_AT_abstract_origin")
                if var_info.attributes["DW_AT_name"].value.decode() != name:
                    continue
            else:
                raise NotImplementedError(f"Dunno what to do with this var: {child}")
            parsed_loc = _get_variable_loc(child, addr)
            best_match = DWVariable(name, parsed_loc, frame_base)
        if child.tag in ("DW_TAG_inlined_subroutine", "DW_TAG_lexical_block"):
            ret = get_variable_in_func(child, addr, name, frame_base)
            if ret:
                return ret

    return best_match


SIZEOF_NONE_CNT = 0


def get_sizeof(cu: CompileUnit, name: str) -> Optional[int]:
    # Just pray that we don't have multidimensional arrays here
    if name == None:
        global SIZEOF_NONE_CNT
        SIZEOF_NONE_CNT += 1
        return None
    array_size = 1
    if "[" in name:
        if name[-1] != "]":
            raise Exception(f"Strange array definition: {name}")
        bracket_pos = name.index("[")
        array_size = int(name[bracket_pos + 1:-1])
        name = name[:bracket_pos]
    for child in cu.iter_DIEs():
        match child.tag:
            case "DW_TAG_base_type":
                if child.attributes["DW_AT_name"].value.decode() == name:
                    return child.attributes["DW_AT_byte_size"].value * array_size
            case "DW_TAG_typedef":
                if child.attributes["DW_AT_name"].value.decode() == name:
                    die = child
                    while die.tag == "DW_TAG_typedef":
                        die = die.get_DIE_from_attribute("DW_AT_type")
                    TRACE_MATCH(die)
                    return die.attributes["DW_AT_byte_size"].value
    return None


class MatchError(Exception):

    def __init__(self, msg):
        return super().__init__(msg)


def match_instr_reg_operand(instr: capstone.CsInsn, idx: int, reg: str):
    if idx >= len(instr.operands):
        raise MatchError(
            f"Tried to match {idx}'th operand, but op has only {len(instr.operands)} operands")
    if instr.operands[idx].type != capstone.arm64_const.ARM64_OP_REG:
        raise MatchError(f"{idx}'th operand is not a register: {instr.operands[idx].type}")

    # TODO: Enable this back
    # if not reg_cmp(aarch64_reg_name(instr.operands[idx].reg), reg):
    #     raise MatchError(
    #         f"{idx}'th register is not one that we expect: {aarch64_reg_name(instr.operands[idx].reg)} != {reg}"
    #     )


def get_instr_reg_operand(instr: capstone.CsInsn, idx: int) -> str:
    if idx >= len(instr.operands):
        raise MatchError(
            f"Tried to match {idx}'th operand, but op has only {len(instr.operands)} operands")
    if instr.operands[idx].type != capstone.arm64_const.ARM64_OP_REG:
        raise MatchError(f"{idx}'th operand is not a register: {instr.operands[idx].type}")
    return aarch64_reg_name(instr.operands[idx].reg)

def get_instr_operand_offset(instr: capstone.CsInsn, idx: int) -> int:
    if idx >= len(instr.operands):
        raise MatchError(
            f"Tried to match {idx}'th operand, but op has only {len(instr.operands)} operands")
    if instr.operands[idx].type != capstone.arm64_const.ARM64_OP_MEM:
        raise MatchError(f"{idx}'th operand is not a memory: {instr.operands[idx].type}")
    return instr.operands[idx].value.mem.disp

def get_instr_operand_base_reg(instr: capstone.CsInsn, idx: int) -> int:
    if idx >= len(instr.operands):
        raise MatchError(
            f"Tried to match {idx}'th operand, but op has only {len(instr.operands)} operands")
    if instr.operands[idx].type != capstone.arm64_const.ARM64_OP_MEM:
        raise MatchError(f"{idx}'th operand is not a memory: {instr.operands[idx].type}")
    return instr.operands[idx].value.mem.base


def get_adrp_addr(instr: capstone.CsInsn) -> int:
    if instr.mnemonic != "adrp":
        raise MatchError(f"Tried to get adrp offset for '{instr.mnemonic}' instruction")
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
            f"Tried to match {idx}'th operand, but op has only {len(instr.operands)} operands")
    if instr.operands[idx].type != capstone.arm64_const.ARM64_OP_IMM:
        raise MatchError(f"{idx}'th operand is not an immediate: {instr.operands[idx].type}")
    if instr.operands[idx].value.imm != value:
        raise MatchError(
            f"{idx}'th immediate is not one that we expect: {instr.operands[idx].value.imm} != {value}"
        )


def match_instr_mem_operand(instr: capstone.CsInsn, idx: int, base_reg: str, offset: str):
    if idx >= len(instr.operands):
        raise MatchError(
            f"Tried to match {idx}'th operand, but op has only {len(instr.operands)} operands")
    operand = instr.operands[idx]
    if operand.type != capstone.arm64_const.ARM64_OP_MEM:
        raise MatchError(f"{idx}'th operand is not an memory op: {operand.type}")

    if aarch64_reg_name(operand.value.mem.base) != base_reg:
        raise MatchError(
            f"{idx}'th reg does not match: {aarch64_reg_name(operand.value.mem.base)} != {base_reg}"
        )

    if offset and operand.value.mem.disp != offset:
        raise MatchError(
            f"Offset for memory op does not match: {operand.value.mem.disp} != {offset}")


def match_instr_read_mem_operand(instr: capstone.CsInsn, idx: int, base_reg: str, offset: str):
    if not instr.mnemonic.startswith("ld"):
        raise MatchError(f"Expected ld[us] found {instr.mnemonic}")

    if idx >= len(instr.operands):
        raise MatchError(
            f"Tried to match {idx}'th operand, but op has only {len(instr.operands)} operands")
    operand = instr.operands[idx]
    if operand.type != capstone.arm64_const.ARM64_OP_MEM:
        raise MatchError(f"{idx}'th operand is not an memory op: {operand.type}")

    # TODO: Fix this
    # And for now - just hope for the best...
    # if aarch64_reg_name(operand.value.mem.base) != base_reg:
    #     raise MatchError(
    #         f"{idx}'th reg does not match: {aarch64_reg_name(operand.value.mem.base)} != {base_reg}"
    #     )

    # TODO: Fix this
    # And for now - just hope for the best...
    # if offset and operand.value.mem.disp != offset:
    #     raise MatchError(
    #         f"Offset for memory op does not match: {operand.value.mem.disp} != {offset}")


def match_branch_isntr(instr: capstone.CsInsn, mnemonic: str):
    if instr.mnemonic != mnemonic:
        raise MatchError(f"Expected {mnemonic} found {instr.mnemonic}")


def match_sub_instr(instr: capstone.CsInsn, target_reg, const):
    if instr.mnemonic not in ("subs", "adds"):
        raise MatchError(
            f"Expected opcode 'subs'/'adds' found {instr.mnemonic} at {instr.address:x} (match_sub_instr)"
        )


#    match_instr_reg_operand(instr, 0, target_reg)
#    match_instr_reg_operand(instr, 1, target_reg)
    match_instr_const_operand(instr, 2, const)


def match_sub_instr_regs(instr: capstone.CsInsn, reg1, reg2):
    if instr.mnemonic not in ("subs", "adds"):
        raise MatchError(
            f"Expected opcode 'subs' found {instr.mnemonic} at {instr.address:x} (match_sub_instr_regs)"
        )

    match_instr_reg_operand(instr, 1, reg1)
    match_instr_reg_operand(instr, 2, reg2)


class TracePoint:

    def __init__(self, addr: int, inverted: bool, bool_expr: BoolExpression):
        self.addr = addr
        self.inverted = inverted
        self.bool_expr = bool_expr

    def __repr__(self) -> str:
        return f"<TracePoint( 0x{self.addr:06x} : {self.bool_expr} (inverted: {self.inverted}) )>"


@dataclass
class MatchState:
    instr_idx: int
    target_reg: Optional[str] = None
    partial: bool = False
    last_seen_var: Optional[str] = None
    int_const: Optional[int] = None
    saw_per_cpu: bool = False

    def derive(self, **kwargs: Unpack[MatchState]):
        ret = copy(self)
        for field in fields(self):
            if field.name in kwargs:
                ret.__dict__[field.name] = kwargs[field.name]
                del kwargs[field.name]

        if kwargs:
            raise Exception(f"Unknown values left in kwargs: {kwargs}")

        return ret

    def advance(self, cnt=1):
        return self.derive(instr_idx=self.instr_idx + cnt)


def reg_cmp(r1: str, r2: str):
    if r1.startswith("x") or r1.startswith("w"):
        r1 = r1[1:]
    if r2.startswith("x") or r2.startswith("w"):
        r2 = r2[1:]
    return r1 == r2


def match_bool_expr(cu: CompileUnit, elf: ELFFile, expr: BoolExpression,
                    instructions: list[capstone.CsInsn], inlines: list[DwarfInlinedFunc]):

    FUZZ_MATCHER_FAILURES = 0

    def fuzzy_matcher(func):

        def result(arg1, state: MatchState):
            if not state.partial:
                return func(arg1, state)
            offset = state.instr_idx
            while offset < min(offset + 10, len(instructions)):
                nonlocal FUZZ_MATCHER_FAILURES
                FUZZ_MATCHER_FAILURES += 1
                if FUZZ_MATCHER_FAILURES >= 1000:
                    raise Exception("Fuzzy matcher failed 1000 times. Bailing out")
                try:
                    return func(arg1, state.derive(instr_idx=offset, target_reg=state.target_reg))
                except MatchError as e:
                    TRACE_MATCH(f"   Got exception: {e} instruction offset = {offset} from {func}")
                    offset += 1
            raise MatchError(f"Fuzzy matching failed for {state}")

        return result

    def match_optional_store(state: MatchState) -> MatchState:
        if state.instr_idx >= len(instructions) - 1:
            return state
        if instructions[state.instr_idx].mnemonic in ("mov", "movz") \
        and instructions[state.instr_idx + 1].mnemonic in ("str", "stur"):
            state.instr_idx += 2
        return state

    def match_optional_bool_cast(state: MatchState) -> MatchState:
        instr = instructions[state.instr_idx]
        if instr.mnemonic == "and" and reg_cmp(get_instr_reg_operand(instr, 1), state.target_reg):
            state.instr_idx += 1
            state.target_reg = get_instr_reg_operand(instr, 0)
        return state

    def match_optional_nop(state: MatchState) -> MatchState:
        instr = instructions[state.instr_idx]
        if instr.mnemonic == "nop":
            state.instr_idx += 1
        return state

    def match_optional_zero_mov(state: MatchState) -> MatchState:
        #TODO: check that it is mov reg, wzr
        instr = instructions[state.instr_idx]
        if instr.mnemonic in ("mov", "movz"):
            state.instr_idx += 1
        return state

    def match_optional_mov(state: MatchState) -> MatchState:
        instr = instructions[state.instr_idx]
        if instr.mnemonic in ("mov", "movz"):
            state.instr_idx += 1
        return state

    def ff_to_instruction(state: MatchState, instr: list[str]) -> MatchState:
        skip = state.instr_idx
        while skip < len(instructions):
            if instructions[skip].mnemonic in instr:
                return state.derive(instr_idx=skip)
            skip += 1
        return state

    ret: list[TracePoint] = []

    def _handle_inlined_fcall(operand: SAST, state: MatchState):
        # Find inline function and fast forwards to its end
        fname = operand.fname.name
        TRACE_MATCH(
            f"Looking for range for inlined function {fname}, presented with range {instructions[state.instr_idx].address:x} - {instructions[-1].address:x}"
        )
        for inline in inlines:
            if inline.name == fname:
                TRACE_MATCH(f"  Found candidate {inline}")
                # Find idx for start address
                for idx in range(state.instr_idx, len(instructions)):
                    if instructions[idx].address == inline.low_addr:
                        TRACE_MATCH(
                            f"  Found start of inlined function at addr {inline.low_addr:#x}")
                        break
                    else:
                        continue
                else:
                    continue
                    # Find idx for end address
                for idx in range(idx, len(instructions)):
                    if instructions[idx].address == inline.high_addr:
                        if instructions[idx].mnemonic == "bl":
                            # Tailcall optimisatation, thanks LLVM!
                            return state.derive(instr_idx=idx + 1, target_reg="x0", partial=False)
                        target_reg = get_instr_reg_operand(instructions[idx], 0)
                        return state.derive(instr_idx=idx + 1, target_reg=target_reg, partial=False)
                raise Exception("End of inlined function is past expression range?")
        raise Exception(
            f"Could not find inlined function {fname} new {hex(instructions[state.instr_idx].address)} in list of inlines"
        )

    def handle_fcall(operand: SAST, state: MatchState):
        if isinstance(operand.fname, NonBoolVar):
            if is_inlined_function(cu, operand.fname.name):
                return _handle_inlined_fcall(operand, state)

            func_name: str = operand.fname.name
            if func_name.startswith("__builtin_"):
                TRACE_MATCH(f"Removing builtin prefix for {func_name}")
                func_name = func_name.removeprefix("__builtin_")
                if func_name == "bswap32":
                    state = ff_to_instruction(state, ["rev"])
                    return state.derive(target_reg=get_instr_reg_operand(
                        instructions[state.instr_idx], 0)).advance()
            # Try looking in the current CU, in case this is a static function
            func_addr = find_function(cu, func_name)
            if not func_addr:
                # Try looking in in global symbol table
                func_addr = find_symbol(elf, func_name)
                if not func_addr:
                    TRACE_MATCH(f"Can't find address for function {operand.fname.name}, probably pointer")
            for idx in range(state.instr_idx, len(instructions)):
                instr = instructions[idx]
                if (instr.mnemonic == "bl" and func_addr
                        and instr.operands[0].value.imm == func_addr) or (instr.mnemonic == "blr"
                                                                          and not func_addr):
                    instr = instructions[idx + 1]
                    target_reg = "x0"
                    if instr.mnemonic == "ldr":
                        # Match ldr x8, [sp, #offset] if we saw store to that pos earlier
                        base_reg = get_instr_operand_offset(instr, 1)
                        reg_offset = get_instr_operand_offset(instr, 1)
                        for idx2 in range(idx, 0, -1):
                            instr2 = instructions[idx2]
                            if instr2.mnemonic == "str" and get_instr_operand_offset(
                                    instr2, 1) == base_reg and get_instr_operand_offset(
                                        instr2, 1) == reg_offset:
                                idx += 1
                                break
                    if instr.mnemonic == "mov":
                        # Match mov w8, w0
                        idx += 1
                        target_reg = get_instr_reg_operand(instructions[idx], 0)
                    return state.derive(instr_idx=idx + 1, target_reg=target_reg, partial=False)
            else:
                raise MatchError("Can't find function call")
        else:
            # Handle function pointer calls, e.g. MemberExpr like entry->matches()
            for idx in range(state.instr_idx, len(instructions)):
                instr = instructions[idx]
                if instr.mnemonic in ("blr", "bl"):
                    next_idx = idx + 1
                    if next_idx < len(instructions) and instructions[next_idx].mnemonic == "ldr":
                        next_idx += 1
                    return state.derive(instr_idx=next_idx, target_reg="x0", partial=False)
            raise MatchError(f"Can't find function pointer call instruction for {operand.fname}")

    def handle_int_const(value: int, state: MatchState):
        if value in (0, 1, 2147483647):
            block_end = ff_to_instruction(state, ["b"])
            instr = instructions[block_end.instr_idx - 1]
            if instr.mnemonic in ("cbnz", "cbz", "tbz", "tbnz"):
                TRACE_MATCH(f"  found {instr.mnemonic}, passing control to caller")
                # Let caller handle that case
                return block_end.derive(instr_idx=block_end.instr_idx -1 , int_const=value)

        # Try to feed forward (for simple cases at least)
        if state.partial or not value:
            state = ff_to_instruction(state, ["subs", "adds"])

        instr = instructions[state.instr_idx]
        match instr.mnemonic:
            case "subs" | "adds":
                # TODO: We need to simplify expressions first.
                # Like <IntLiteral 8> * <IntLiteral 8> == <IntLiteral 64>
                # match_sub_instr(instructions[state.instr_idx],
                #                 state.target_reg, value)
                return state.derive(instr_idx=state.instr_idx + 1, partial=False, int_const=value)
            case "mov":
                # match_instr_const_operand(instr, 1, value)
                return state.derive(instr_idx=state.instr_idx + 1,
                                    target_reg=get_instr_reg_operand(instr, 0),
                                    int_const=value)
            case "asr":
                # TODO: See above
                # match_instr_const_operand(instr, 2, value)
                return state.derive(instr_idx=state.instr_idx + 1,
                                    target_reg=get_instr_reg_operand(instr, 0),
                                    int_const=value)
            case "ands":
                # TODO: See above
                # match_instr_const_operand(instr, 2, value)
                return state.derive(instr_idx=state.instr_idx + 1,
                                    target_reg=get_instr_reg_operand(instr, 0),
                                    int_const=value)
            case mnemonic:
                raise MatchError(f"Don't know how to handle {mnemonic}")

    def handle_variable(operand: SAST, state: MatchState):
        v = get_variable_at_loc(cu, instructions[state.instr_idx].address, operand.name)
        if not v:
            v = get_global_variable(elf, operand.name)
            if not v:
                raise MatchError(
                    f"Can't find variable {operand.name} near address 0x{instructions[state.instr_idx].address:x}"
                )
        match v.op_type:
            case "DW_OP_fbreg":
                match v.frame_base:
                    case "DW_OP_reg31":
                        target_reg = "sp"
                    case "DW_OP_reg29":
                        target_reg = "x29"
                    case _:
                        raise Exception(f"TODO: Match reg {v.frame_base}")
                # Special case for RELOC_HIDE()
                if operand.name == "__ptr":
                    state = ff_to_instruction(state, ["mrs"])
                    if instructions[state.instr_idx].mnemonic == "mrs":
                        state = state.derive(saw_per_cpu=True).advance()
                    return state
                offset = v.arg
                instr = instructions[state.instr_idx]
                try:
                    match_instr_read_mem_operand(instr, 1, target_reg, offset)
                except MatchError:
                    if state.last_seen_var and state.last_seen_var == operand.name:
                        # This handles clang optimisation of var->field1 == var->field2
                        TRACE_MATCH(
                            f"   last seen variable {state.last_seen_var} at {instructions[state.instr_idx].address:x}"
                        )
                        return state
                    raise
                TRACE_MATCH(f"  Found read at 0x{instr.address:x}")
                return state.derive(instr_idx=state.instr_idx + 1,
                                    target_reg=aarch64_reg_name(instr.operands[0].reg),
                                    last_seen_var=operand.name)
            case "DW_OP_addrx" | "DW_OP_abs_addr":
                if v.op_type == "DW_OP_addrx":
                    abs_addr = cu.dwarfinfo.get_addr(cu, v.arg)
                else:
                    abs_addr = v.arg
                TRACE_MATCH(f"Global variable offset is {abs_addr:x}")
                instr = instructions[state.instr_idx]
                match instr.mnemonic:
                    case "adrp":
                        offset = get_adrp_addr(instr)
                        reg = get_instr_reg_operand(instr, 0)
                        rem = abs_addr - offset
                        TRACE_MATCH(f"remainder is {rem} in {reg}")
                        instr = instructions[state.instr_idx + 1]
                        if instr.mnemonic != "add":
                            match_instr_read_mem_operand(instr, 1, reg, rem)
                            return state.derive(instr_idx=state.instr_idx + 2,
                                                target_reg=aarch64_reg_name(instr.operands[0].reg))
                        else:
                            # Pointers...
                            match_instr_const_operand(instr, 2, rem)
                            return state.derive(instr_idx=state.instr_idx + 2,
                                                target_reg=aarch64_reg_name(instr.operands[0].reg))

                    case "adr":
                        match_instr_const_operand(instr, 1, abs_addr)
                        reg = get_instr_reg_operand(instr, 0)
                        TRACE_MATCH(f"  Found read at 0x{instr.address:x}")
                        return state.derive(instr_idx=state.instr_idx + 1, target_reg=reg)
                    case "ldr":
                        # This is a hack to handle compiler optimisation
                        return state.derive(instr_idx=state.instr_idx + 1,
                                            target_reg=aarch64_reg_name(instr.operands[0].reg),
                                            last_seen_var=operand.name)

                    case mnemonic:
                        raise MatchError(f"Don't know how to handle {mnemonic} (addrx)")

            case "DW_OP_breg31":
                TRACE_MATCH("  DW_OP_breg31 aka SP")
                # Special case for RELOC_HIDE()
                if operand.name == "__ptr":
                    state = ff_to_instruction(state, ["mrs"])
                    if instructions[state.instr_idx].mnemonic == "mrs":
                        state = state.derive(saw_per_cpu=True).advance()
                    return state
                target_reg = "sp"
                offset = v.arg
                instr = instructions[state.instr_idx]
                match_instr_read_mem_operand(instr, 1, target_reg, offset)
                TRACE_MATCH(f"  Found read at 0x{instr.address:x}")
                return state.derive(instr_idx=state.instr_idx + 1,
                                    target_reg=aarch64_reg_name(instr.operands[0].reg))
            case _:
                raise Exception(f"Unknown var op {v.op_type}")

    @fuzzy_matcher
    def handle_operand(operand: SAST, state: MatchState):
        state = match_optional_nop(state)
        TRACE_MATCH(f"handle_operand {type(operand)}")
        match operand:
            case BoolVar() | NonBoolVar():
                return handle_variable(operand, state)
            case IntLiteral():
                TRACE_MATCH(
                    f"Handling int const '{operand.value}' for reg {state.target_reg} at {instructions[state.instr_idx].address:x}"
                )
                return handle_int_const(operand.value, state)
            case EnumConst():
                TRACE_MATCH(
                    f"Handling enum constant '{operand.value}' for reg {state.target_reg} at {instructions[state.instr_idx].address:x}"
                )
                val = get_enum_value(cu, operand.value)
                TRACE_MATCH(f"   enum value is {val}")
                if val == None:
                    raise Exception(f"Can't find integer value for enum {operand.value}")
                return handle_int_const(val, state)
            case SizeOf():
                TRACE_MATCH(
                    f"Handling sizeof({operand.argtype}) for reg {state.target_reg} at {instructions[state.instr_idx].address:x}"
                )
                val = get_sizeof(cu, operand.argtype)
                if val == None:
                    log.warning(f"Can't find integer value for sizeof({operand.argtype})")
                return handle_int_const(val, state)

            case BoolExpression():
                return recurse(operand, state)
            case ArraySubscript():
                new_state = handle_operand(operand.array, state)
                return new_state.derive(partial=True)
            case CCast():
                new_state = handle_operand(operand.casted, state)
                return new_state.derive(instr_idx=new_state.instr_idx + 1, partial=False)
            case MemberExpr():
                # Just do the fuzzy matching and hope for best
                state = handle_operand(operand.left, state)
                TRACE_MATCH(f"   member_expr target reg = {state.target_reg}")
                if instructions[state.instr_idx].mnemonic.startswith("ldr") and operand.arrow:
                    TRACE_MATCH("  found another ldr, advancing pointer")
                    state = state.advance()
                return state.derive(partial=True)
            case FCall():
                return handle_fcall(operand, state)
            case NonBoolExpression():
                match operand.opcode:
                    case "=":
                        new_state = handle_operand(operand.operands[1], state)
                    case "-":
                        new_state = handle_operand(operand.operands[0], state)
                    case "~":
                        new_state = state
                    case "*":
                        new_state = handle_operand(operand.operands[0], state)
                        if len(operand.operands) == 1:
                            TRACE_MATCH("  handling dereference")
                            if instructions[new_state.instr_idx].mnemonic.startswith("ldr"):
                                new_state = new_state.advance()
                    case "&":
                        new_state = handle_operand(operand.operands[0], state)
                        if len(operand.operands) == 1:
                            TRACE_MATCH("  handling reference")
                            if instructions[new_state.instr_idx].mnemonic.startswith("add"):
                                new_state = new_state.advance()
                    case _:
                        new_state = handle_operand(operand.operands[0], state)
                return new_state.derive(partial=True)
                pass
            case _:
                raise Exception(f"Don't know what to do with operand {operand}")

    def handle_and_or(e: BoolExpression, state: MatchState) -> MatchState:
        def get_cond_instr(search_state: MatchState) -> MatchState:
            branches = {"tbz", "tbnz", "cbz", "cbnz", "cset"}
            fallbacks = {"str", "stur"}
            fallback_idx = -1

            for idx in range(search_state.instr_idx, len(instructions)):
                mnem = instructions[idx].mnemonic

                if mnem in branches:
                    return search_state.derive(instr_idx=idx)

                if mnem in fallbacks:
                    fallback_idx = idx

                # stop on exit of this block
                if mnem in ("b", "ret"):
                    break

            if fallback_idx != -1:
                return search_state.derive(instr_idx=fallback_idx)

            return search_state

        new_state = handle_operand(e.a, state)
        new_state = match_optional_store(new_state)

        if not isinstance(e.a, BoolExpression):
            new_state = get_cond_instr(new_state)

            match instructions[new_state.instr_idx].mnemonic:
                case "tbz":
                    match_branch_isntr(instructions[new_state.instr_idx + 1], "b")
                    ret.append(TracePoint(instructions[new_state.instr_idx].address, True, e.a))
                    new_state.instr_idx += 2
                case "tbnz":
                    match_branch_isntr(instructions[new_state.instr_idx + 1], "b")
                    ret.append(TracePoint(instructions[new_state.instr_idx].address, False, e.a))
                    new_state.instr_idx += 2
                case "cbz":
                    match_branch_isntr(instructions[new_state.instr_idx + 1], "b")
                    ret.append(TracePoint(instructions[new_state.instr_idx].address, True, e.a))
                    new_state.instr_idx += 2
                case "cbnz":
                    match_branch_isntr(instructions[new_state.instr_idx + 1], "b")
                    ret.append(TracePoint(instructions[new_state.instr_idx].address, False, e.a))
                    new_state.instr_idx += 2
                case mnemonic:
                    TRACE_MATCH(f"Skipping {mnemonic} at {instructions[new_state.instr_idx].address:x}")

        if isinstance(e.b, IntLiteral):
            TRACE_MATCH("Ignoring const value as part of AND/OR expression")
            return new_state

        if isinstance(e.b, BoolExpression) and e.b.op == BoolExpression.OP_NOT and isinstance(
                e.b.a, IntLiteral):
            TRACE_MATCH("Ignoring NOT(const value) as part of AND/OR expression")
            return new_state

        new_state = handle_operand(e.b, new_state)
        new_state = match_optional_store(new_state)

        if not isinstance(e.b, BoolExpression):
            new_state = get_cond_instr(new_state)

            match instructions[new_state.instr_idx].mnemonic:
                case "tbz":
                    match_branch_isntr(instructions[new_state.instr_idx + 1], "b")
                    ret.append(TracePoint(instructions[new_state.instr_idx].address, True, e.b))
                    new_state.instr_idx += 2
                case "tbnz":
                    match_branch_isntr(instructions[new_state.instr_idx + 1], "b")
                    ret.append(TracePoint(instructions[new_state.instr_idx].address, False, e.b))
                    new_state.instr_idx += 2
                case "cbz":
                    match_branch_isntr(instructions[new_state.instr_idx + 1], "b")
                    ret.append(TracePoint(instructions[new_state.instr_idx].address, True, e.b))
                    new_state.instr_idx += 2
                case "cbnz":
                    match_branch_isntr(instructions[new_state.instr_idx + 1], "b")
                    ret.append(TracePoint(instructions[new_state.instr_idx].address, False, e.b))
                    new_state.instr_idx += 2
                case mnemonic:
                    TRACE_MATCH(
                        f"Didn't found conditional op, instead got  {mnemonic} at {instructions[new_state.instr_idx].address:x}"
                    )
                    ret.append(TracePoint(instructions[new_state.instr_idx].address, False, e.b))
                    new_state.instr_idx += 1

        return new_state

    def handle_lt_gt_op(e: BoolExpression, state: MatchState) -> MatchState:
        # TODO: Handle differences in LT, LE, GT, GE
        op1_state = handle_operand(e.a, state)
        op1_state = match_optional_store(op1_state)
        op2_state = handle_operand(e.b, op1_state)
        new_state = op2_state

        op_is_gt_ge = (e.op == BoolExpression.OP_GT or e.op == BoolExpression.OP_GE)

        new_state = match_optional_store(new_state)
        new_state = match_optional_zero_mov(new_state)

        new_state = ff_to_instruction(new_state, [
            "subs", "str", "b.lt", "b.le", "b.ls", "b.lo", "b.gt", "b.ge", "b.hs", "b.hi", "tbnz",
            "cbnz", "tbz", "cbz", "cset"
        ])

        while instructions[new_state.instr_idx].mnemonic == "subs":
            # We need subs op if it is not handled by IntLiteral() handler
            match_sub_instr_regs(instructions[new_state.instr_idx], op1_state.target_reg,
                                 op2_state.target_reg)
            new_state.instr_idx += 1
        if instructions[new_state.instr_idx].mnemonic == "str":
            # Sometimes compiler mixes comparison ops and load/stores, like this:
            # a000035dd1c:   b9403fe9        ldr     w9, [sp, #60]
            # a000035dd20:   b9403bea        ldr     w10, [sp, #56]
            # a000035dd24:   2a1f03e8        mov     w8, wzr
            # a000035dd28:   6b0a0129        subs    w9, w9, w10
            # a000035dd2c:   b90017e8        str     w8, [sp, #20]
            # a000035dd30:   54000122        b.cs    a000035dd54  // b.hs, b.nlast
            new_state.instr_idx += 1

        match instructions[new_state.instr_idx].mnemonic:
            case "b.lt" | "b.le" | "b.ls" | "b.lo":
                inverted = op_is_gt_ge
                match_branch_isntr(instructions[new_state.instr_idx + 1], "b")
                ret.append(TracePoint(instructions[new_state.instr_idx].address, inverted, e))
            case "b.gt" | "b.ge" | "b.hs" | "b.hi" | "b.ne":
                inverted = not op_is_gt_ge
                match_branch_isntr(instructions[new_state.instr_idx + 1], "b")
                ret.append(TracePoint(instructions[new_state.instr_idx].address, inverted, e))
            case "tbnz" | "cbnz":
                inverted = op_is_gt_ge
                match_branch_isntr(instructions[new_state.instr_idx + 1], "b")
                ret.append(TracePoint(instructions[new_state.instr_idx].address, inverted, e))
            case "tbz" | "cbz":
                inverted = not op_is_gt_ge
                match_branch_isntr(instructions[new_state.instr_idx + 1], "b")
                ret.append(TracePoint(instructions[new_state.instr_idx].address, inverted, e))
            case "cset":
                # TBD: Match cset condition flags
                instr = instructions[new_state.instr_idx]
                ret.append(TracePoint(instr.address, False, e))
                return new_state.advance()
            case _:
                raise MatchError(
                    f"Expected b.lt or b.ge, but found {instructions[new_state.instr_idx].mnemonic}"
                )
        return new_state.advance(2)

    @fuzzy_matcher
    def handle_implicit_cast_tail(e: BoolExpression, state: MatchState) -> MatchState:
        if isinstance(e.a, BoolExpression):
            return state

        match instructions[state.instr_idx].mnemonic:
            case "tbz" | "cbz" | "b.eq":
                match_branch_isntr(instructions[state.instr_idx + 1], "b")
                ret.append(TracePoint(instructions[state.instr_idx].address, True, e))
                return state.advance(2)
            case "cbnz" | "tbnz" | "b.ne":
                match_branch_isntr(instructions[state.instr_idx + 1], "b")
                ret.append(TracePoint(instructions[state.instr_idx].address, False, e))
                return state.advance(2)
            case "csel" | "csinc" | "cset" | "cinc":
                ret.append(TracePoint(instructions[state.instr_idx].address, False, e))
                return state.advance()
            case mnemonic:
                raise MatchError(
                    f"Don't know how to handle implicit bool cast instruction {mnemonic}")

    @fuzzy_matcher
    def handle_op_not_tail(e: BoolExpression, state: MatchState) -> MatchState:
        # Return early if we are not trying to handle top-level NOT expression
        if isinstance(e.a, BoolExpression):
            return state
        state = ff_to_instruction(
            state, ["cbnz", "tbnz", "b.ne", "cset", "tbz", "cbz", "b.eq", "eor", "bic"])

        match instructions[state.instr_idx].mnemonic:
            case "cbnz" | "tbnz" | "b.ne":
                match_branch_isntr(instructions[state.instr_idx + 1], "b")
                ret.append(TracePoint(instructions[state.instr_idx].address, True, e.a))
                return state.advance(2).derive(partial=True)
            case "tbz" | "cbz" | "b.eq":
                match_branch_isntr(instructions[state.instr_idx + 1], "b")
                ret.append(TracePoint(instructions[state.instr_idx].address, False, e.a))
                return state.advance(2).derive(partial=True)
            case "eor" | "bic" | "cset":
                ret.append(TracePoint(instructions[state.instr_idx].address, False, e.a))
                return state.advance().derive(partial=True)
            case mnemonic:
                raise MatchError(f"Don't know how to handle {mnemonic} (OP_NOT)")
        return state

    @fuzzy_matcher
    def recurse(e: BoolExpression, state: MatchState) -> MatchState:
        TRACE_MATCH(f"Recurse, handling {e} at {e.loc}")
        assert isinstance(e, BoolExpression)
        match e.op:
            case BoolExpression.OP_EQ | BoolExpression.OP_XOR:
                inverted: bool = e.op == BoolExpression.OP_XOR
                # TODO: Special case: a == a
                if isinstance(e.a, NonBoolVar) and isinstance(e.b, NonBoolVar) \
                   and e.a.name == e.b.name:
                    TRACE_MATCH(f"Found case {e.a.name} == {e.b.name}")
                    instr = instructions[state.instr_idx]
                    if instr.mnemonic == "cbnz":
                        ret.append(TracePoint(instructions[state.instr_idx].address, not inverted, e))
                        return state.derive(target_reg=None, partial=False)

                new_state = handle_operand(e.a, state)
                new_state = match_optional_store(new_state)
                new_state = match_optional_bool_cast(new_state)
                new_state = handle_operand(e.b, new_state)
                new_state = match_optional_bool_cast(new_state)

                new_state = match_optional_zero_mov(new_state)
                new_state = match_optional_mov(new_state)

                if new_state.saw_per_cpu:
                    new_state = ff_to_instruction(new_state, ["subs", "adds"])
                idx = new_state.instr_idx
                # Optional subs/adds:
                if instructions[idx].mnemonic in ("subs", "adds"):
                    idx += 1
                # Optional write to variable
                if instructions[idx].mnemonic in ("str", "stur"):
                    idx += 1
                match instructions[idx].mnemonic:
                    case "b.eq":
                        match_branch_isntr(instructions[idx], "b.eq")
                        match_branch_isntr(instructions[idx + 1], "b")
                        ret.append(TracePoint(instructions[idx].address, inverted, e))
                    case "b.ne":
                        match_branch_isntr(instructions[idx], "b.ne")
                        match_branch_isntr(instructions[idx + 1], "b")
                        ret.append(TracePoint(instructions[idx].address, not inverted, e))
                    case "cbnz":
                        match_branch_isntr(instructions[idx], "cbnz")
                        match_instr_reg_operand(instructions[idx], 0, new_state.target_reg)
                        match_branch_isntr(instructions[idx + 1], "b")
                        ret.append(TracePoint(instructions[idx].address, not inverted, e))
                    case "cbz":
                        match_branch_isntr(instructions[idx], "cbz")
                        match_instr_reg_operand(instructions[idx], 0, new_state.target_reg)
                        match_branch_isntr(instructions[idx + 1], "b")
                        ret.append(TracePoint(instructions[idx].address, inverted, e))
                    case "tbnz":
                        match_branch_isntr(instructions[idx], "tbnz")
                        match_instr_reg_operand(instructions[idx], 0, new_state.target_reg)
                        match_branch_isntr(instructions[idx + 1], "b")
                        ret.append(TracePoint(instructions[idx].address, not inverted, e))
                    case "tbz":
                        match_branch_isntr(instructions[idx], "tbz")
                        match_instr_reg_operand(instructions[idx], 0, new_state.target_reg)
                        match_branch_isntr(instructions[idx + 1], "b")
                        ret.append(TracePoint(instructions[idx].address, inverted, e))
                    case "cset":
                        # TBD: Match cset condition flags
                        ret.append(TracePoint(instructions[idx].address, inverted, e))
                        return new_state.derive(instr_idx=idx + 1)
                    case "csel":
                        # TBD: Match cset condition flags
                        ret.append(TracePoint(instructions[idx].address, inverted, e))
                        return new_state.derive(instr_idx=idx + 1)
                    case _:
                        raise MatchError(
                            f"Expected for conditional branch, found {instructions[idx].mnemonic}")

                return new_state.derive(instr_idx=idx + 2)
            case BoolExpression.OP_OR:
                return handle_and_or(e, state)
            case BoolExpression.OP_AND:
                return handle_and_or(e, state)
            case BoolExpression.OP_NOT:
                new_state = handle_operand(e.a, state)
                return handle_op_not_tail(e, new_state)
            case BoolExpression.OP_LT | BoolExpression.OP_GT | BoolExpression.OP_GE | BoolExpression.OP_LE:
                return handle_lt_gt_op(e, state)
            case BoolExpression.OP_IMPLICIT_CAST:
                new_state = handle_operand(e.a, state).derive(partial=True)
                return handle_implicit_cast_tail(e, new_state)
            case _:
                raise Exception(f"Don't know what to do with {e} ({e.op})")

    assert (type(expr) == BoolExpression)
    # Try to find matching expression taking into account that it can be not
    # at the beginning of a line
    # TODO: Remove min, this is only for debugging
    recurse(expr, MatchState(0, partial=True))
    pprint(ret)
    return ExprTraceInfo(expr, ret)

    # Check that we are returning sane data
    assert len(ret) == len(expr.get_leafs())


#    for expr in expressions:
#        loc = expr.loc
#        locations.


def load_mcdc_data(expr_file: str) -> tuple[list[SAST], dict[str, list[SFileLocMap]]]:
    expr: list[BoolExpression] = []
    inline_loc_map: dict[str, list[SFileLocMap]] = {}

    with open(expr_file, "rb") as f:
        expr, inline_loc_map = pickle.load(f)

    return expr, inline_loc_map

FAIL_FAST = False

def main():
    logging.basicConfig(level=logging.DEBUG)
    parser = argparse.ArgumentParser(description="MC/DC Dwarf/AST Matcher")

    parser.add_argument("executable", help="Path to the target executable file")

    parser.add_argument("input_pickle", help="Path to the generated pickle file with AST classes")
    parser.add_argument("output_pickle", help="Path to pickle file to save ExpressionInfo data")
    parser.add_argument("out_plugin_conf", help="Path to pickle file to save ExpressionInfo data")
    parser.add_argument("-c", "--compile_unit", help="Compile Unit to process")
    parser.add_argument("--fail", help="Fail at first error (do not continue)", action="store_true")

    args = parser.parse_args()

    mcdc_data, iniline_loc = load_mcdc_data(args.input_pickle)

    global FAIL_FAST
    FAIL_FAST = args.fail

    process_elf(args.executable, mcdc_data, iniline_loc, args.output_pickle, args.out_plugin_conf,
                args.compile_unit)


    log.info(f"FAIL_COUNTER = {FAIL_COUNTER}")
    log.info(f"ELF_RANGE_FAIL_CNT = {ELF_RANGE_FAIL_CNT}")
    log.info(f"SIZEOF_NONE_CNT (included in FAIL_COUNTER) = {SIZEOF_NONE_CNT}")
    log.info(f"CODE_OUT_OF_SECTION = {CODE_OUT_OF_SECTION}")


if __name__ == "__main__":
    main()
