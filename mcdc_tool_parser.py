import json
from pprint import pprint
import subprocess
import pickle

from mcdc_tool_definitions import Expression, ExpressionOperand, BoolExpression, FCall, ASTEntry, ConditionalOp, ArraySubscript


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
        args = entry["arguments"]
        if f in seen:
            continue
        seen.append(f)
        bool_expr.extend(handle_file(f, args))
    return bool_expr


def main():
    expressions = get_bool_expr_list()
    for expr in expressions:
        for decision in expr.get_decisions():
            print(decision, decision.get_leafs())
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
        if r.has_bool_expr():
            ret.append(r)
        return ret

    for c in ast.inner:
        ret.extend(deep_dive(c))
    return ret

def qual_type_is_bool(qual_type: str) -> bool:
    return qual_type in ["bool", "_Bool"]

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
                BoolExpression(ast.get_loc(), arg1, op, arg2))

        return ExpressionOperand(
            ast.get_loc(), ExpressionOperand.OPR_NON_BOOL_EXPR,
            Expression(ast.get_loc(), opcode, [arg1, arg2]))

    def handle_decl_ref(ast: ASTEntry):
        ref = ast.data["referencedDecl"]
        var_name = ref.data["name"]
        qual_type = ast.data["type"]["qualType"]
        if qual_type_is_bool(qual_type):
            return ExpressionOperand(ast.get_loc(), ExpressionOperand.OPR_BOOL_VAR,
                                     var_name)
        else:
            return ExpressionOperand(ast.get_loc(), ExpressionOperand.OPR_VAR,
                                     var_name)


    def handle_unary_op(ast: ASTEntry):
        children = ast.inner
        opcode = ast.data["opcode"]
        if len(children) != 1:
            raise Exception("Found more than one child in unary expression")
        arg = recurse(children[0])
        if opcode == "!":
            return ExpressionOperand(
                ast.get_loc(), ExpressionOperand.OPR_EXPR,
                BoolExpression(ast.get_loc(), arg, BoolExpression.OP_NOT))

        return ExpressionOperand(ast.get_loc(),
                                 ExpressionOperand.OPR_NON_BOOL_EXPR,
                                 Expression(ast.get_loc(), opcode, [arg]))

    def handle_implicit_cast(ast: ASTEntry):
        if len(ast.inner) > 1:
            raise Exception(f"More than one child: {ast}")
        return recurse(ast.inner[0])

    def handle_call(ast: ASTEntry):
        fname = recurse(ast.inner[0])
        args = [recurse(x) for x in ast.inner[1:]]
        return ExpressionOperand(ast.get_loc(), ExpressionOperand.OPR_FCALL,
                                 FCall(ast.loc, fname, args))
    def handle_member_expr(ast: ASTEntry):
        children = ast.inner
        field_name = ast.data["name"]
        struct = recurse(children[0]).to_c()
        qual_type = ast.data["type"]["qualType"]
        expr_type = ExpressionOperand.OPR_BOOL_VAR if qual_type_is_bool(qual_type) else ExpressionOperand.OPR_VAR
        if ast.data["isArrow"]:
            return ExpressionOperand(ast.get_loc(),
                                    expr_type,
                                    f"({struct})->{field_name}")
        else:
            return ExpressionOperand(ast.get_loc(),
                                     expr_type,
                                     f"({struct}).{field_name}")

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
                                         ExpressionOperand.OPR_LITERAL,
                                         str(ast.data["value"]))
            case "CharacterLiteral":
                return ExpressionOperand(ast.get_loc(),
                                         ExpressionOperand.OPR_LITERAL,
                                         str(ast.data["value"]))
            case "StringLiteral":
                return ExpressionOperand(ast.get_loc(),
                                         ExpressionOperand.OPR_LITERAL,
                                         ast.data["value"])
            case "MemberExpr":
                return handle_member_expr(ast)
            case "UnaryExprOrTypeTraitExpr":
                return ExpressionOperand(
                    ast.get_loc(), ExpressionOperand.OPR_NON_BOOL_EXPR,
                    Expression(ast.get_loc(), ast.data["name"],
                               [recurse(ast.inner[0])]))
            case "CallExpr":
                return handle_call(ast)
            case "ConditionalOperator":
                check = recurse(ast.inner[0])
                expr1 = recurse(ast.inner[1])
                expr2 = recurse(ast.inner[2])
                return ExpressionOperand(
                    ast.get_loc(), ExpressionOperand.OPR_COND_OP,
                    ConditionalOp(ast.get_loc(), check, expr1, expr2))
            case "CStyleCastExpr":
                # We are interested only in what is cast
                return recurse(ast.inner[0])
            case "ArraySubscriptExpr":
                return ExpressionOperand(
                    ast.get_loc(), ExpressionOperand.OPR_NON_BOOL_EXPR,
                    ArraySubscript(ast.get_loc(), recurse(ast.inner[0]),
                                   recurse(ast.inner[1])))
            case _:
                pprint(ast)
                raise Exception(
                    f"Didn't expected AST kind {ast.kind} at {ast.get_loc()}")

    print(ast)
    expr = recurse(ast)
    return expr


if __name__ == "__main__":
    main()
