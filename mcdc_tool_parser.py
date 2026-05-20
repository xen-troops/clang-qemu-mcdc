import json
from pprint import pprint
import subprocess
import pickle

from mcdc_tool_definitions import Expression, ExpressionOperand, BoolExpression, FCall, ASTEntry, ConditionalOp, ArraySubscript, SizeOf, CodeLoc, CCast


def filter_same_expr(expressions: list[ExpressionOperand]):
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
    "./arch/arm/include/asm/flushtlb.h", #TODO: For this one we probably can disable some optimisation...
]


def filter_by_source(expressions: list[ExpressionOperand]):
    removed = 0
    for expr in expressions:
        if expr.loc.file in SOURCE_SKIP_LIST:
            expressions.remove(expr)
            removed += 1
            continue
    print(f"Removed {removed} expressions based on source location")


def filter_by_fcall(expressions: list[ExpressionOperand]):
    removed = 0
    for expr in expressions:
        for decision in expr.get_decisions():
            for leaf in decision.get_leafs():
                if leaf.has_fcall():
                    expressions.remove(expr)
                    removed += 1
                    break
            else:
                continue
            break
    print(f"Removed {removed} expressions because thay had function calls")


def get_bool_expr_list() -> list[ExpressionOperand]:
    compilation_db = open("compile_commands.json", "rt")
    db = json.load(compilation_db)
    seen = []

    bool_expr: list[ExpressionOperand] = []
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
        bool_expr.extend(handle_file(f, args))
    return bool_expr


def main():
    expressions = get_bool_expr_list()
    filter_same_expr(expressions)
    filter_by_source(expressions)
    filter_by_fcall(expressions)
    # for expr in expressions:
    #     for decision in expr.get_decisions():
    #         print(decision, decision.get_leafs())
    print(f"Saving {len(expressions)} expressions")
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


def deep_dive(ast: ASTEntry) -> list[ExpressionOperand]:
    ret = []
    if ast.kind in [
            "ImplicitCastExpr",
            "CompoundAssignOperator",
            "BinaryOperator",
            "ParenExpr",
    ]:
        r = handle_expression(ast)
        if r and r.has_bool_expr():
            ret.append(r)
        return ret

    for c in ast.inner:
        ret.extend(deep_dive(c))
    return ret


def qual_type_is_bool(qual_type: str) -> bool:
    return qual_type in ["bool", "_Bool"]


class Nope(Exception):

    def __init__(self):
        super().__init__()


def handle_expression(ast: ASTEntry) -> ExpressionOperand:

    def handle_binary_op(ast: ASTEntry):
        opcode = ast.data["opcode"]
        op = BoolExpression.from_opcode(opcode)
        if len(ast.inner) != 2:
            raise Exception("More than two childer for binary op? Strange")
        arg1 = recurse(ast.inner[0])
        arg2 = recurse(ast.inner[1])
        if op:
            return ExpressionOperand(
                ast.get_loc(), ExpressionOperand.OPR_EXPR,
                BoolExpression(ast.get_loc(), ast.range, arg1, op, arg2), ast)

        return ExpressionOperand(
            ast.get_loc(), ExpressionOperand.OPR_NON_BOOL_EXPR,
            Expression(ast.get_loc(), opcode, [arg1, arg2]), ast)

    def handle_decl_ref(ast: ASTEntry):
        ref = ast.data["referencedDecl"]
        var_name = ref.data["name"]
        if var_name == "ENUM_VAL_2":
            print(ast.data)
            print(ref.data)
        return ExpressionOperand(ast.get_loc(), ExpressionOperand.OPR_VAR,
                                 var_name, ast)

    def handle_unary_op(ast: ASTEntry):
        children = ast.inner
        opcode = ast.data["opcode"]
        if len(children) != 1:
            raise Exception("Found more than one child in unary expression")
        arg = recurse(children[0])
        if opcode == "!":
            return ExpressionOperand(
                ast.get_loc(), ExpressionOperand.OPR_EXPR,
                BoolExpression(ast.get_loc(), ast.range, arg, BoolExpression.OP_NOT), ast)

        # replace (++x) with (x+1) and (x++) with just (x)
        if opcode == "++" or opcode == "--":
            if not ast.data["isPostfix"]:
                opcode = opcode[0]
                arg2 = ExpressionOperand(ast.get_loc(), ExpressionOperand.OPR_INT_CONST, 1, ast)
                return ExpressionOperand(ast.get_loc(),
                                         ExpressionOperand.OPR_NON_BOOL_EXPR,
                                         Expression(ast.get_loc(), opcode, [arg, arg2]), ast)
            else:
                return arg
        return ExpressionOperand(ast.get_loc(),
                                 ExpressionOperand.OPR_NON_BOOL_EXPR,
                                 Expression(ast.get_loc(), opcode, [arg]), ast)

    def handle_implicit_cast(ast: ASTEntry):
        if len(ast.inner) > 1:
            raise Exception(f"More than one child: {ast}")
        return recurse(ast.inner[0])

    def handle_call(ast: ASTEntry):
        fname = recurse(ast.inner[0])
        args = [recurse(x) for x in ast.inner[1:]]
        return ExpressionOperand(ast.get_loc(), ExpressionOperand.OPR_FCALL,
                                 FCall(ast.loc, fname, args), ast)

    def handle_member_expr(ast: ASTEntry):
        children = ast.inner
        field_name = ast.data["name"]
        struct = recurse(children[0]).to_c()
        expr_type = ExpressionOperand.OPR_VAR
        #This can happen with anonymous fields
        if not field_name:
            return ExpressionOperand(ast.get_loc(), expr_type, f"({struct})",
                                     ast)
        if ast.data["isArrow"]:
            return ExpressionOperand(ast.get_loc(), expr_type,
                                     f"({struct})->{field_name}", ast)
        else:
            return ExpressionOperand(ast.get_loc(), expr_type,
                                     f"({struct}).{field_name}", ast)

    def handle_unary_expr(ast: ASTEntry):
        if ast.data["name"] == "sizeof":
            if ast.inner:
                assert len(ast.inner) == 1
                arg = recurse(ast.inner[0]).to_c()
            else:
                arg = ast.data["argType"]["qualType"]
            return ExpressionOperand(ast.get_loc(),
                                     ExpressionOperand.OPR_NON_BOOL_EXPR,
                                     SizeOf(ast.get_loc(), arg), ast)
        if len(ast.inner) == 0:
            print(ast.data)
        #TODO
        if ast.data["name"] == "__alignof":
            raise Nope()
        return ExpressionOperand(
            ast.get_loc(), ExpressionOperand.OPR_NON_BOOL_EXPR,
            Expression(ast.get_loc(), ast.data["name"],
                       [recurse(ast.inner[0])]), ast)

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
                return ExpressionOperand(ast.get_loc(),
                                         ExpressionOperand.OPR_INT_CONST,
                                         int(ast.data["value"]), ast)
            case "CharacterLiteral":
                return ExpressionOperand(ast.get_loc(),
                                         ExpressionOperand.OPR_INT_CONST,
                                         int(ast.data["value"]), ast)
            case "StringLiteral":
                return ExpressionOperand(ast.get_loc(),
                                         ExpressionOperand.OPR_STRING_LITERAL,
                                         ast.data["value"], ast)
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
                return ExpressionOperand(
                    ast.get_loc(), ExpressionOperand.OPR_COND_OP,
                    ConditionalOp(ast.get_loc(), check, expr1, expr2), ast)
            case "CStyleCastExpr":
                # TODO: Do something with casts to bool
                t = ast.data["type"]["qualType"]
                return ExpressionOperand(
                    ast.get_loc(), ExpressionOperand.OPR_NON_BOOL_EXPR,
                    CCast(ast.get_loc(), t, recurse(ast.inner[0])), ast)
            case "ArraySubscriptExpr":
                return ExpressionOperand(
                    ast.get_loc(), ExpressionOperand.OPR_NON_BOOL_EXPR,
                    ArraySubscript(ast.get_loc(), recurse(ast.inner[0]),
                                   recurse(ast.inner[1])), ast)
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
                return ExpressionOperand(
                    ast.get_loc(), ExpressionOperand.OPR_COND_OP,
                    ConditionalOp(ast.get_loc(), check, check, expr2), ast)
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
    return expr

if __name__ == "__main__":
    main()
