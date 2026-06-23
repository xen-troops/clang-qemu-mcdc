from __future__ import annotations

import os
import json
import argparse
from pprint import pprint
import subprocess
import pickle

from mcdc_tool_definitions import CodeLoc, SAST, BoolExpression, BoolVar, NonBoolExpression, NonBoolVar, \
    FCall, ASTEntry, MemberExpr, SizeOf, CCast, IntLiteral, StringLiteral, ArraySubscript, FlowControlStructure, NullOp, MiscExpr
from mcdc_tool_s_loc import SFileLocMap, get_s_file_locations


def filter_same_expr(expressions: list[SAST]):
    removed = 0
    seen: list[CodeLoc] = []
    filtered = []
    for expr in expressions:
        if expr.loc in seen:
            removed += 1
        else:
            filtered.append(expr)
            seen.append(expr.loc)
    print(f"Removed {removed} similar expressions")
    return filtered


SOURCE_SKIP_LIST = [
    "arch/arm/arm64/lib/bitops.c",
    "./arch/arm/include/asm/arm64/system.h",
    "./arch/arm/include/asm/atomic.h",
    "./arch/arm/include/asm/cpuerrata.h:30",
    "./arch/arm/include/asm/flushtlb.h",  #TODO: For this one we probably can disable some optimisation...
]


def filter_and_report(predicate, expressions: list[SAST],
                      reason: str) -> list[SAST]:
    filtered = [x for x in expressions if predicate(x)]
    print(f"Removed {len(expressions) - len(filtered)} expressions {reason}")
    return filtered


def filter_by_source(expressions: list[SAST]) -> list[SAST]:
    return filter_and_report(lambda x: x.loc.file not in SOURCE_SKIP_LIST,
                             expressions, "based on source location")


def filter_by_fcall(expressions: list[SAST]):
    return filter_and_report(lambda x: not x.has_fcall(), expressions,
                             "because they had function calls")


def filter_const_expr(expressions: list[SAST]):
    return filter_and_report(lambda x: not x.is_const(), expressions,
                             "because they were const expressions")


def get_bool_expr_list(
        compile_commands: str
    ) -> tuple[list[BoolExpression], dict[str, list[SFileLocMap]]]:
    compilation_db = open(compile_commands, "rt")
    db = json.load(compilation_db)
    seen = []

    bool_expr: list[BoolExpression] = []
    inline_loc_map: dict[str, list[SFileLocMap]] = {}
    for entry in db:
        f: str = entry["file"]
        work_dir: str = entry.get("directory", os.getcwd())
        rel_f: str = os.path.relpath(f, work_dir)

        if not f.endswith(".c"):
            continue
        if f.startswith("tools/"):
            continue
        if f in SOURCE_SKIP_LIST:
            continue
        args = entry["arguments"]
        if f in seen:
            continue
        seen.append(f)
        expr, locs = handle_file(f, args)
        for e in expr:
            assert isinstance(e, BoolExpression)
        bool_expr.extend(expr)
        inline_loc_map[rel_f] = locs
    return bool_expr, inline_loc_map

def lift_up_fcalls(expressions: list[SAST]):
    subexpr = []
    for expr in expressions:
        args = expr.lift_fcall_args()
        # We are interested only in internal bool expressions (if any)
        for a in args:
            subexpr.extend(a.get_topmost_bool_expr())

    expressions.extend(subexpr)

def main():
    parser = argparse.ArgumentParser(description="MC/DC AST Parser")

    parser.add_argument(
        "output_pickle",
        help="Path to save the generated mcdc.pickle"
    )

    parser.add_argument("output_inlines_pickle",
                        help="Path to save the generated inline locations pickle")

    parser.add_argument(
        "compile_commands",
        help="Path to the compile_commands.json file"
    )

    args = parser.parse_args()

    expressions, inline_loc_map = get_bool_expr_list(args.compile_commands)

    lift_up_fcalls(expressions)
    expressions = filter_const_expr(expressions)
    expressions = filter_same_expr(expressions)
    expressions = filter_by_source(expressions)

    print(f"Saving {len(expressions)} expressions")
    for expr in expressions:
        expr.update_location_range()
        print(f"{expr} at {expr.loc_range}")

    with open(args.output_pickle, "wb") as f:
        pickle.dump(expressions, f)

    with open(args.output_inlines_pickle, "wb") as f:
        pickle.dump(inline_loc_map, f)

def get_bool_expr_per_file(fname: str, args: list[str]):
    def object_hook(data: dict):
        if "kind" in data:
            return ASTEntry(data)
        return data

    print(f"Parsing '{fname}'")

    ast_args = args.copy()

    if "-save-temps" in ast_args:
        ast_args.remove("-save-temps")
    ast_args.append("-Xclang")
    ast_args.append("-ast-dump=json")
    ast_args.append("-fsyntax-only")

    if "-c" in ast_args:
        ast_args.remove("-c")

    if "-o" in ast_args:
        pos = ast_args.index("-o")
        del ast_args[pos:pos+2]
    print(ast_args)
    result = subprocess.run(ast_args, capture_output=True, check=True)
    data = json.loads(result.stdout, object_hook=object_hook)
    data.update_locations(fname, 1)
    bool_expressions = deep_dive(data)
    return bool_expressions


def get_inline_loc(fname: str, args: list[str]):
    asm_args = args.copy()

    flags_to_remove = ["-c", "-save-temps", "-save-temps=obj"]
    for flag in flags_to_remove:
        while flag in asm_args:
            asm_args.remove(flag)

    asm_file = fname.rsplit('.', 1)[0] + ".s"

    if "-o" in asm_args:
        idx = asm_args.index("-o")
        out_path = asm_args.pop(idx + 1) if idx + 1 < len(asm_args) else ""
        asm_args.remove("-o")

        if out_path.endswith(".o"):
            asm_file = out_path[:-2] + ".s"

    asm_args.extend(["-o", asm_file])
    if "-S" not in asm_args:
        asm_args.append("-S")

    subprocess.run(asm_args, capture_output=True, check=True)

    inline_loc = get_s_file_locations(asm_file)
    return inline_loc


def handle_file(
        fname: str, args: list[str]) -> tuple[list[SAST], list[SFileLocMap]]:

    bool_expressions = get_bool_expr_per_file(fname, args)

    inline_locs = get_inline_loc(fname, args)

    return bool_expressions, inline_locs


def deep_dive(ast: ASTEntry) -> list[SAST]:
    ret = []
    if ast.kind in [
            "ImplicitCastExpr",
            "CompoundAssignOperator",
            "BinaryOperator",
            "ParenExpr",
            "ForStmt",
            "WhileStmt",
            "DoStmt",
            "IfStmt",
            "ConditionalOperator",
            "BinaryConditionalOperator",
    ]:
        r = handle_expression(ast)
        ret.extend(r)
        return ret

    for c in ast.inner:
        ret.extend(deep_dive(c))
    return ret


def qual_type_is_bool(qual_type: str) -> bool:
    return qual_type in ["bool", "_Bool"]


class Nope(Exception):

    def __init__(self):
        super().__init__()


def handle_expression(ast: ASTEntry) -> SAST:

    def handle_binary_op(ast: ASTEntry):
        opcode = ast.data["opcode"]
        op = BoolExpression.from_opcode(opcode)
        if len(ast.inner) != 2:
            raise Exception("More than two childer for binary op? Strange")
        arg1 = recurse(ast.inner[0])
        arg2 = recurse(ast.inner[1])
        if op:
            return BoolExpression(ast.get_loc(), ast, arg1, op, arg2)

        return NonBoolExpression(ast.get_loc(), opcode, [arg1, arg2], ast)

    def handle_decl_ref(ast: ASTEntry):
        ref = ast.data["referencedDecl"]
        var_name = ref.data["name"]
        qual_type = ref.data["type"]["qualType"]
        # if var_name == "ENUM_VAL_2":
        #     print(ast.data)
        #     print(ref.data)
        if qual_type_is_bool(qual_type):
            return BoolVar(ast.get_loc(), var_name, ast)
        return NonBoolVar(ast.get_loc(), var_name, qual_type, ast)

    def handle_unary_op(ast: ASTEntry):
        children = ast.inner
        opcode = ast.data["opcode"]
        if len(children) != 1:
            raise Exception("Found more than one child in unary expression")
        arg = recurse(children[0])
        if opcode == "!":
            return BoolExpression(ast.get_loc(), ast, arg,
                                  BoolExpression.OP_NOT)

        return NonBoolExpression(ast.get_loc(), opcode, [arg], ast)

    def handle_implicit_cast(ast: ASTEntry):
        if len(ast.inner) > 1:
            raise Exception(f"More than one child: {ast}")
        return recurse(ast.inner[0])

    def handle_call(ast: ASTEntry):
        fname = recurse(ast.inner[0])
        args = [recurse(x) for x in ast.inner[1:]]
        return FCall(ast.get_loc(), fname, args, ast)

    def handle_member_expr(ast: ASTEntry):
        children = ast.inner
        field_name = ast.data["name"]
        struct = recurse(children[0])
        #This can happen with anonymous fields
        if not field_name:
            field_name = "(anonymous)"
        return MemberExpr(ast.get_loc(), struct, field_name,
                          ast.data["isArrow"], ast)

    def handle_unary_expr(ast: ASTEntry):
        if ast.data["name"] == "sizeof":
            if ast.inner:
                assert len(ast.inner) == 1
                arg = recurse(ast.inner[0])
            else:
                arg = ast.data["argType"]["qualType"]
            return SizeOf(ast.get_loc(), arg, ast)
        if len(ast.inner) == 0:
            print(ast.data)
        #TODO
        if ast.data["name"] == "__alignof":
            raise Nope()
        return NonBoolExpression(ast.get_loc(), ast.data["name"],
                                 [recurse(ast.inner[0])], ast)

    def recurse(ast: ASTEntry):
        children = ast.inner
        match ast.kind:
            case "ImplicitCastExpr":
                return handle_implicit_cast(ast)
            case "BinaryOperator":
                return handle_binary_op(ast)
            case "ParenExpr":
                if len(children) != 1:
                    raise Exception(
                        "More than one expr inside PAREN_EXPR? How peculiar")
                return recurse(children[0])
            case "DeclRefExpr":
                return handle_decl_ref(ast)
            case "UnaryOperator":
                return handle_unary_op(ast)
            case "CompoundAssignOperator":
                # We are really interested only in the left part
                return recurse(children[1])
            case "IntegerLiteral":
                return IntLiteral(ast.get_loc(), int(ast.data["value"]), ast)
            case "CharacterLiteral":
                return IntLiteral(ast.get_loc(), int(ast.data["value"]), ast)
            case "StringLiteral":
                return StringLiteral(ast.get_loc(), ast.data["value"], ast)
            case "MemberExpr":
                return handle_member_expr(ast)
            case "UnaryExprOrTypeTraitExpr":
                return handle_unary_expr(ast)
            case "CallExpr":
                return handle_call(ast)
            case "CStyleCastExpr":
                # TODO: Do something with casts to bool
                t = ast.data["type"]["qualType"]
                return CCast(ast.get_loc(), t, recurse(ast.inner[0]), ast)
            case "ArraySubscriptExpr":
                return ArraySubscript(ast.get_loc(), recurse(ast.inner[0]),
                                   recurse(ast.inner[1]), ast)
            case "IfStmt" | "WhileStmt" | "ConditionalOperator" | "BinaryConditionalOperator":
                rest = [recurse(inner) for inner in ast.inner[1:]]
                return FlowControlStructure(ast.get_loc(), recurse(ast.inner[0]), rest, ast)
            case "DoStmt":
                rest = [recurse(inner) for inner in ast.inner[0:-1]]
                return FlowControlStructure(ast.get_loc(), recurse(ast.inner[-1]), rest, ast)
            case "ForStmt":
                rest = []
                for idx, item in enumerate(ast.inner):
                    if idx != 2 and item:
                        rest.append(recurse(item))
                return FlowControlStructure(ast.get_loc(), recurse(ast.inner[2]), rest, ast)


            case "CompoundStmt" | "ReturnStmt":
                return MiscExpr(ast.loc, ast, [recurse(inner) for inner in ast.inner])

            case "StmtExpr" | "VarDecl"  | "DeclStmt" | \
                "SwitchStmt" | "CaseStmt" | "DefaultStmt" | \
                "LabelStmt" | "OpaqueValueExpr" | "InitListExpr" | \
                "CompoundLiteralExpr" | "VAArgExpr" :

                children = [recurse(inner) for inner in ast.inner if inner]
                return MiscExpr(ast.loc, ast, children)

            case "NULL" | "GCCAsmStmt" | "NullStmt"  | "ContinueStmt" | \
                "BreakStmt" | "TypeOfExprType" | "GotoStmt" | "BuiltinType" | \
                "StaticAssertDecl" | "OffsetOfExpr" | "TypeTraitExpr" | \
                "ConstantExpr" | "IncompleteArrayType" | "ConstantArrayType" | \
                "RecordDecl" | "PredefinedExpr" | "ImplicitValueInitExpr" :
                return NullOp(ast.loc, ast)

            case kind if kind.endswith("Attr") :
                # UnusedAttr, AsmLabelAttr, etc
                return NullOp(ast.loc, ast)

            case _:
                pprint(ast)
                pprint(ast.data)
                raise Exception(
                    f"Didn't expected AST kind {ast.kind} at {ast.get_loc()}")

    try:
        expr = recurse(ast)
    except Nope:
        print(f"Got Nope exception for {ast.get_loc()}")
        return []

    print(expr)
    return expr.get_topmost_bool_expr()

if __name__ == "__main__":
    main()
