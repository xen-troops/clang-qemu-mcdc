import json
from pprint import pprint
import subprocess
import pickle

from mcdc_tool_definitions import CodeLoc, SAST, BoolExpression, BoolVar, NonBoolExpression, NonBoolVar, \
    FCall, ASTEntry, MemberExpr, SizeOf, CCast, IntLiteral, StringLiteral, ConditionalOp, ArraySubscript


def filter_same_expr(expressions: list[SAST]):
    print("Removing similar expressions...")
    removed = 0
    seen: list[CodeLoc] = []
    for expr in expressions:
        if expr.loc in seen:
            expressions.remove(expr)
            removed += 1
            continue
        seen.append(expr.loc)
    print(f"Removed {removed} similar expressions")


SOURCE_SKIP_LIST = [
    "arch/arm/arm64/lib/bitops.c",
    "./arch/arm/include/asm/arm64/system.h",
    "./arch/arm/include/asm/atomic.h",
    "./arch/arm/include/asm/cpuerrata.h:30",
    "./arch/arm/include/asm/flushtlb.h",  #TODO: For this one we probably can disable some optimisation...
]


def filter_by_source(expressions: list[SAST]):
    removed = 0
    for expr in expressions:
        if expr.loc.file in SOURCE_SKIP_LIST:
            expressions.remove(expr)
            removed += 1
            continue
    print(f"Removed {removed} expressions based on source location")


def filter_by_fcall(expressions: list[SAST]):
    removed = 0
    for expr in expressions:
        if expr.has_fcall():
            expressions.remove(expr)
            removed += 1

    print(f"Removed {removed} expressions because thay had function calls")


def get_bool_expr_list() -> list[BoolExpression]:
    compilation_db = open("compile_commands.json", "rt")
    db = json.load(compilation_db)
    seen = []

    bool_expr: list[BoolExpression] = []
    # handle_file("test2_helpers.c", ["clang", "-c", "-O2", "test2_expr.c"])
    # return
    for entry in db:
        f: str = entry["file"]
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
        expr = handle_file(f, args)
        for e in expr:
            assert isinstance(e, BoolExpression)
        bool_expr.extend(expr)
    return bool_expr

def lift_up_fcalls(expressions: list[SAST]):
    subexpr = []
    for expr in expressions:
        args = expr.lift_fcall_args()
        # We are interested only in internal bool expressions (if any)
        for a in args:
            subexpr.extend(a.get_topmost_bool_expr())

    expressions.extend(subexpr)

def main():
    expressions = get_bool_expr_list()
    lift_up_fcalls(expressions)
    filter_same_expr(expressions)
    filter_by_source(expressions)
    #filter_by_fcall(expressions)
    # for expr in expressions:
    #     for decision in expr.get_decisions():
    #         print(decision, decision.get_leafs())
    print(f"Saving {len(expressions)} expressions")
    for expr in expressions:
        expr.update_location_range()
        print(f"{expr} at {expr.loc_range}")
#    pprint(expressions)
    with open("mcdc.pickle", "wb") as f:
        pickle.dump(expressions, f)


def handle_file(fname: str, args: list[str]):

    def object_hook(data: dict):
        if "kind" in data:
            return ASTEntry(data)
        return data

    print(f"Parsing '{fname}'")
    if "-save-temps" in args:
        args.remove("-save-temps")
    args.append("-Xclang")
    args.append("-ast-dump=json")
    args.append("-fsyntax-only")
    if "-o" in args:
        pos = args.index("-o")
        del args[pos:pos+1]
    print(args)
    result = subprocess.run(args, capture_output=True, check=True)
    data = json.loads(result.stdout, object_hook=object_hook)
    #    pprint(data)
    data.update_locations(fname, 1)
    #    print(data)
    bool_expressions = deep_dive(data)
    # for expr in bool_expressions:
    #     print("Expression:", expr)
    #     print("    Decisions", expr.get_decisions())
    #    pprint(bool_expressions)
    return bool_expressions


def deep_dive(ast: ASTEntry) -> list[SAST]:
    ret = []
    if ast.kind in [
            "ImplicitCastExpr",
            "CompoundAssignOperator",
            "BinaryOperator",
            "ParenExpr",
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

        # replace (++x) with (x+1) and (x++) with just (x)
        # if opcode == "++" or opcode == "--":
        #     if not ast.data["isPostfix"]:
        #         opcode = opcode[0]
        #         arg2 = ExpressionOperand(ast.get_loc(), ExpressionOperand.OPR_INT_CONST, 1, ast)
        #         return ExpressionOperand(ast.get_loc(),
        #                                  ExpressionOperand.OPR_NON_BOOL_EXPR,
        #                                  Expression(ast.get_loc(), opcode, [arg, arg2]), ast)
        #     else:
        #         return arg
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
            case "ConditionalOperator":
                check = recurse(ast.inner[0])
                expr1 = recurse(ast.inner[1])
                expr2 = recurse(ast.inner[2])
                return ConditionalOp(ast.get_loc(), check, expr1, expr2, ast)
            case "CStyleCastExpr":
                # TODO: Do something with casts to bool
                t = ast.data["type"]["qualType"]
                return CCast(ast.get_loc(), t, recurse(ast.inner[0]), ast)
            case "ArraySubscriptExpr":
                return ArraySubscript(ast.get_loc(), recurse(ast.inner[0]),
                                   recurse(ast.inner[1]), ast)
#TODO
            case "StmtExpr":
                raise Nope()
#TODO
            case "ConstantExpr":
                raise Nope()
#TODO
            case "CompoundLiteralExpr":
                raise Nope()
#TODO
            case "OffsetOfExpr":
                raise Nope()
#TODO
            case "OpaqueValueExpr":
                raise Nope()
#TODO
            case "PredefinedExpr":
                raise Nope()
#TODO
            case "TypeTraitExpr":
                raise Nope()
#TODO
            case "VAArgExpr":
                raise Nope()


#TODO: Check this for correct inner[] use
            case "BinaryConditionalOperator":
                check = recurse(ast.inner[0])
                expr2 = recurse(ast.inner[2])
                return ConditionalOp(ast.get_loc(), check, check, expr2, ast)
            case _:
                pprint(ast)
                pprint(ast.data)
                raise Exception(
                    f"Didn't expected AST kind {ast.kind} at {ast.get_loc()}")

    try:
        expr = recurse(ast)
    except Nope:
        print(f"Got Nope exception for {ast.get_loc()}")
        return None

    print(expr)
    return expr.get_topmost_bool_expr()

if __name__ == "__main__":
    main()
