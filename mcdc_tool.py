from clang.cindex import Index, CursorKind, Cursor, TokenKind, Type, BinaryOperator
import json
from pprint import pprint
from typing import Optional, Union
from collections import OrderedDict

class Scope:

    def __init__(self, prev: Scope = None):
        self.prev = prev
        self.vars = {}

    def add_var(self, name: str, vtype: str):
        self.vars[name] = vtype

    def get_var(self, name: str):
        if name in self.vars:
            return self.vars[name]
        if self.prev:
            return self.prev.get_var(name)
        raise Exception(f"Can't find variable '{name}' in global scope")


GLOBAL_SCOPE = Scope()


def main():
    compilation_db = open("compile_commands.json", "rt")
    db = json.load(compilation_db)
    seen = []

#    handle_file("test2_helpers.c", [])
#    return
    for entry in db:
        f: str = entry["file"]
        if not f.endswith(".c"):
            continue
        args = entry["arguments"]
        if f in seen:
            continue
        seen.append(f)
        handle_file(f, args[1:])


def handle_file(fname: str, args: list[str]):
    print(f"Parsing '{fname}'")
    index = Index.create()
    if "-save-temps" in args:
        args.remove("-save-temps")
    if fname in args:
        args.remove(fname)
    print(args)
    tu = index.parse(fname, args=args)
    #    pprint(get_info(tu.cursor))
    deep_dive(tu.cursor)


def get_info(cursor: Cursor, depth=0):
    children = [get_info(c, depth + 1) for c in cursor.get_children()]
    return OrderedDict({
        "id": get_cursor_id(cursor),
        "kind": cursor.kind,
        "usr": cursor.get_usr(),
        "spelling": cursor.spelling,
        "location": cursor.location,
        "extent.start": cursor.extent.start,
        "extent.end": cursor.extent.end,
        "is_definition": cursor.is_definition(),
        "is_expression": cursor.kind.is_expression(),
        "is_statement": cursor.kind.is_statement(),
        "definition id": get_cursor_id(cursor.get_definition()),
        "type": format_type(cursor.type),
        "result_type": format_type(cursor.result_type),
        "children": children,
    })


def format_type(t: Type):
    return t.kind


def get_cursor_id(cursor, cursor_list=[]):
    if cursor is None:
        return None

    # FIXME: This is really slow. It would be nice if the index API exposed
    # something that let us hash cursors.
    for i, c in enumerate(cursor_list):
        if cursor == c:
            return i
    cursor_list.append(cursor)
    return len(cursor_list) - 1


def deep_dive(cursor: Cursor):
    if cursor.kind.is_expression():
        handle_expression(cursor)
        print(
            "   Tokens:", " ".join(
                [f"{t.spelling}" for t in cursor.get_tokens()]))
        return


#    if cursor.kind.is_declaration():
#        pprint(get_info(cursor))
    for c in cursor.get_children():
        deep_dive(c)


class BoolExprOperand:
    OPR_VAR = 1
    OPR_FCALL = 2
    OPR_EXPR = 3
    OPR_NON_BOOL_EXPR = 4

    def __init__(self, opr_type, operand: Union[str, BoolExpression]):
        self.type = opr_type
        self.operand = operand

    def __str__(self) -> str:
        match self.type:
            case self.OPR_VAR:
                return self.operand
            case self.OPR_FCALL:
                return f"{self.operand}()"
            case self.OPR_EXPR:
                return str(self.operand)
            case self.OPR_NON_BOOL_EXPR:
                return f"c-expr({self.operand})"
            case _:
                raise Exception(f"Unknown operand type: {self.type}")

    def __repr__(self) -> str:
        return str(self)


class BoolExpression:
    OP_OR = 1
    OP_AND = 2
    OP_NOT = 3
    OP_EQ = 4
    OP_XOR = 5
    OP_LT = 6
    OP_LE = 7
    OP_GT = 8
    OP_GE = 9

    OP_REPR = {
        OP_OR: "OR",
        OP_AND: "AND",
        OP_NOT: "NOT",
        OP_EQ: "EQ",
        OP_XOR: "XOR",
        OP_LT: "LT",
        OP_LE: "LE",
        OP_GT: "GT",
        OP_GE: "GE",
    }

    def __init__(self,
                 opr_a: BoolExprOperand,
                 op,
                 opr_b: Optional[BoolExprOperand] = None):
        self.a = opr_a
        self.op = op
        self.b = opr_b

    def __str__(self) -> str:
        a_str = str(self.a)
        op_str = BoolExpression.OP_REPR[self.op]
        if self.b:
            b_str = str(self.b)
        else:
            b_str = ""
        if self.op == self.OP_NOT:
            return f"({op_str} {a_str})"
        return f"({a_str} {op_str} {b_str})"

    def __repr__(self) -> str:
        return str(self)

    __bin_op_mapping = {
        BinaryOperator.LOr: OP_OR,
        BinaryOperator.LAnd: OP_AND,
        BinaryOperator.EQ: OP_EQ,
        BinaryOperator.NE: OP_XOR,
        BinaryOperator.LT: OP_LT,
        BinaryOperator.LE: OP_LE,
        BinaryOperator.GT: OP_GT,
        BinaryOperator.GE: OP_GE,
    }

    @staticmethod
    def from_BinaryOperator(op: BinaryOperator) -> Optional[int]:
        if op in BoolExpression.__bin_op_mapping:
            return BoolExpression.__bin_op_mapping[op]
        return None


def handle_expression(cursor: Cursor):

    def handle_binary_op(cursor: Cursor):
        op = BoolExpression.from_BinaryOperator(cursor.binary_operator)
        children = list(cursor.get_children())
        if len(children) != 2:
            raise Exception("More than two childer for binary op? Strange")
        if op:
            if op in [
                    BoolExpression.OP_LT, BoolExpression.OP_LE,
                    BoolExpression.OP_GT, BoolExpression.OP_GE
            ]:
                arg1 = BoolExprOperand(BoolExprOperand.OPR_NON_BOOL_EXPR, "TBD")
                arg2 = BoolExprOperand(BoolExprOperand.OPR_NON_BOOL_EXPR, "TBD")
            else:
                arg1 = recurse(children[0])
                arg2 = recurse(children[1])
            return BoolExprOperand(BoolExprOperand.OPR_EXPR,
                                   BoolExpression(arg1, op, arg2))

        return BoolExprOperand(BoolExprOperand.OPR_NON_BOOL_EXPR, "TBD")

    def handle_unexposed_expr(cursor: Cursor):
        tokens = list(cursor.get_tokens())
        if len(tokens) != 1:
            pprint(get_info(cursor))
            raise Exception(
                f"More that one token in unexposed expression: {" ".join([t.spelling for t in tokens])}")
        if tokens[0].kind != TokenKind.IDENTIFIER:
            raise Exception(f"Expected identifier token, got {tokens[0].kind}")

        return BoolExprOperand(BoolExprOperand.OPR_VAR, tokens[0].spelling)

    def handle_unary_op(cursor: Cursor):
        tokens = list(cursor.get_tokens())
        if tokens[0].kind != TokenKind.PUNCTUATION:
            raise Exception(f"Expected identifier token, got {tokens[0].kind}")
        children = list(cursor.get_children())
        if len(children) != 1:
            raise Exception("Found more than one child in unary expression")
        arg = recurse(children[0])
        if tokens[0].spelling == "!":
            return BoolExprOperand(BoolExprOperand.OPR_EXPR,
                                   BoolExpression(arg, BoolExpression.OP_NOT))

        return BoolExprOperand(BoolExprOperand.OPR_NON_BOOL_EXPR, "TBD")

    def recurse(cursor: Cursor):
        children = list(cursor.get_children())
        match cursor.kind:
            case CursorKind.BINARY_OPERATOR:
                return handle_binary_op(cursor)
            case CursorKind.PAREN_EXPR:
                if len(children) != 1:
                    raise Exception(
                        "More than one expr inside PAREN_EXPR? How peculiar")
                return recurse(children[0])
            case CursorKind.UNEXPOSED_EXPR | CursorKind.DECL_REF_EXPR:
                return handle_unexposed_expr(cursor)
            case CursorKind.UNARY_OPERATOR:
                return handle_unary_op(cursor)
            case CursorKind.COMPOUND_ASSIGNMENT_OPERATOR:
                # We are really interested only in the left part
                return recurse(children[1])
            case CursorKind.INTEGER_LITERAL:
                return BoolExprOperand(BoolExprOperand.OPR_NON_BOOL_EXPR, "TBD")
            case CursorKind.CALL_EXPR:
                return BoolExprOperand(BoolExprOperand.OPR_FCALL, cursor.spelling)
            case CursorKind.CONDITIONAL_OPERATOR:
                pass
            case _:
                pprint(get_info(cursor))
                raise Exception(f"Didn't expected cursor kind {cursor.kind} at {cursor.location}")

    expr = recurse(cursor)
    print(str(expr))
    pass


if __name__ == "__main__":
    main()
