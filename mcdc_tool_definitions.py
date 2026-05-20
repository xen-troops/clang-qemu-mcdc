from typing import Optional, Union
import uuid

LAST_CODELOC_FILE: str = None


class CodeLoc:

    def __init__(self, data: dict):
        if "expansionLoc" in data:
            data = data["expansionLoc"]
            self.kind = "Exp"
        else:
            self.kind = ""
        self.file = data.get("file")
        self.col = data.get("col")
        self.line = data.get("line")
        self.offset = data.get("offset")
        self.tokLen = data.get("tokLen")
        self.data = data

    def __eq__(self, other) -> bool:
        return self.file == other.file and self.col == other.col and self.line == other.line

    def __repr__(self) -> str:
        if self.kind:
            kind = f"({self.kind})"
        else:
            kind = ""
        return f"<{kind}{self.file}:{self.line}:{self.col}>"

    def update(self, fname: str, line: str):
        if self.file:
            global LAST_CODELOC_FILE
            LAST_CODELOC_FILE = self.file
        if not self.line:
            self.line = line
        if not self.file:
            self.file = LAST_CODELOC_FILE
            if not self.kind:
                self.kind = "Auto"


class CodeRange:

    def __init__(self, data: dict):
        self.begin = CodeLoc(data["begin"])
        self.end = CodeLoc(data["end"])

    def __repr__(self) -> str:
        return f"{self.begin} - {self.end}"

    def update(self, fname: str, line: str):
        self.begin.update(fname, line)
        self.end.update(fname, line)


class ASTEntry:

    def __init__(self, data: dict):
        self.loc: CodeLoc = None
        self.inner: list[ASTEntry] = []
        self.range: CodeRange = None
        self.kind = data["kind"]
        if "inner" in data:
            self.inner = data["inner"]
        if "loc" in data and data["loc"]:
            self.loc = CodeLoc(data["loc"])
        if "range" in data and data["range"]["begin"]:
            self.range = CodeRange(data["range"])
        self.data = data
        for i, ch in enumerate(self.inner):
            if not ch:
                self.inner[i] = ASTEntry({"kind": "NULL"})

    def __repr__(self):
        return self.__format__(0)

    def __format__(self, lvl=0):
        s = "  " * lvl + f"AST<{self.kind}>"
        if self.loc:
            s += f"({self.loc})"
        elif self.range:
            s += f"({self.range})"

        if self.inner:
            for inner in self.inner:
                s += "\n" + inner.__format__(lvl + 1)
        return s

    def update_locations(self, fname: str, line: int):
        global LAST_CODELOC_FILE
        if not LAST_CODELOC_FILE:
            LAST_CODELOC_FILE = fname
        if self.loc:
            self.loc.update(fname, line)
            fname = self.loc.file
            line = self.loc.line
        if self.range:
            self.range.update(fname, line)
            fname = self.range.end.file
            line = self.range.begin.line
        for ch in self.inner:
            ch.update_locations(fname, line)

    def get_loc(self) -> CodeLoc:
        if self.loc:
            return self.loc
        if self.range:
            return self.range.begin
        return None


class ExpressionOperand:
    OPR_VAR = 1
    OPR_FCALL = 2
    OPR_EXPR = 3
    OPR_NON_BOOL_EXPR = 4
    OPR_INT_CONST = 5
    OPR_STRING_LITERAL = 6
    OPR_COND_OP = 7

    def __init__(self, loc: CodeLoc, opr_type,
                 operand: Union[str, BoolExpression, Expression, FCall,
                                ConditionalOp], ast: ASTEntry):
        self.type = opr_type
        self.operand = operand
        self.loc = loc
        self.uuid = str(uuid.uuid4())
        self.ast = ast

    def __str__(self) -> str:
        match self.type:
            case self.OPR_VAR | self.OPR_STRING_LITERAL:
                return self.operand
            case self.OPR_INT_CONST:
                return str(self.operand)
            case self.OPR_FCALL:
                return f"{self.operand}"
            case self.OPR_EXPR:
                return str(self.operand)
            case self.OPR_NON_BOOL_EXPR:
                return f"c-expr({self.operand})"
            case self.OPR_COND_OP:
                return f"({self.operand})"
            case _:
                raise Exception(f"Unknown operand type: {self.type}")

    def to_c(self) -> str:
        match self.type:
            case self.OPR_VAR | self.OPR_STRING_LITERAL | self.OPR_EXPR | self.OPR_NON_BOOL_EXPR | self.OPR_FCALL | self.OPR_COND_OP:
                if isinstance(self.operand, str):
                    return self.operand
                return self.operand.to_c()
            case self.OPR_INT_CONST:
                return str(self.operand)
            case _:
                raise Exception(f"Unknown operand type: {self.type}")

    def __repr__(self) -> str:
        return str(self)

    def has_bool_expr(self) -> bool:
        match self.type:
            case ExpressionOperand.OPR_EXPR | ExpressionOperand.OPR_COND_OP:
                return True
            case ExpressionOperand.OPR_STRING_LITERAL | ExpressionOperand.OPR_VAR | ExpressionOperand.OPR_INT_CONST:
                return False
            case ExpressionOperand.OPR_FCALL | ExpressionOperand.OPR_NON_BOOL_EXPR:
                return self.operand.has_bool_expr()
            case _:
                raise Exception(f"Unknown operand type: {self.type}")

    def has_fcall(self) -> bool:
        match self.type:
            case ExpressionOperand.OPR_STRING_LITERAL | ExpressionOperand.OPR_INT_CONST | ExpressionOperand.OPR_VAR:
                return False
            case ExpressionOperand.OPR_FCALL:
                return True
            case ExpressionOperand.OPR_EXPR | ExpressionOperand.OPR_COND_OP | ExpressionOperand.OPR_NON_BOOL_EXPR:
                return self.operand.has_fcall()
            case _:
                raise Exception(f"Unknown operand type: {self.type}")

    def get_leafs(self) -> list[BoolExpression]:
        "Returns list of leaf boolean expressions or `conditions` in MC/DC lingo"
        match self.type:
            case ExpressionOperand.OPR_EXPR | ExpressionOperand.OPR_COND_OP | ExpressionOperand.OPR_FCALL | ExpressionOperand.OPR_NON_BOOL_EXPR:
                return self.operand.get_leafs()
            case ExpressionOperand.OPR_STRING_LITERAL | ExpressionOperand.OPR_INT_CONST | ExpressionOperand.OPR_VAR:
                return []
            case _:
                raise Exception(f"Unknown operand type: {self.type}")

    def get_decisions(self) -> list[BoolExpression]:
        "Returns list of top-most boolean expressions or `decisions` in MC/DC lingo"
        match self.type:
            case ExpressionOperand.OPR_EXPR:
                return [self.operand]
            case ExpressionOperand.OPR_COND_OP | ExpressionOperand.OPR_FCALL | ExpressionOperand.OPR_NON_BOOL_EXPR:
                return self.operand.get_decisions()
            case ExpressionOperand.OPR_STRING_LITERAL | ExpressionOperand.OPR_INT_CONST | ExpressionOperand.OPR_VAR:
                return []
            case _:
                raise Exception(f"Unknown operand type: {self.type}")


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
    OP_C_REPR = {
        OP_OR: "||",
        OP_AND: "&&",
        OP_NOT: "!",
        OP_EQ: "==",
        OP_XOR: "!=",
        OP_LT: "<",
        OP_LE: "<=",
        OP_GT: ">",
        OP_GE: ">=",
    }

    def __init__(self,
                 loc: CodeLoc,
                 loc_range: CodeRange,
                 opr_a: ExpressionOperand,
                 op,
                 opr_b: Optional[ExpressionOperand] = None):
        self.a = opr_a
        self.op = op
        self.b = opr_b
        self.loc = loc
        self.uuid = str(uuid.uuid4())
        self.parent = None
        self.children: list[BoolExpression] = []
        self.value: Optional[bool] = None
        self.loc_range = loc_range

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

    def to_c(self) -> str:
        a_str = self.a.to_c()
        op_str = BoolExpression.OP_C_REPR[self.op]
        if self.b:
            b_str = self.b.to_c()
        else:
            b_str = ""
        if self.op == self.OP_NOT:
            return f"({op_str} {a_str})"
        return f"({a_str} {op_str} {b_str})"

    def get_leafs(self) -> list[BoolExpression]:
        ret: list[BoolExpression] = []
        ret.extend(self.a.get_leafs())
        if self.op != BoolExpression.OP_NOT:
            ret.extend(self.b.get_leafs())
        if not ret:
            # We are the leaf
            return [self]
        return ret

    def has_fcall(self) -> bool:
        if self.op == BoolExpression.OP_NOT:
            return self.a.has_fcall()
        return self.a.has_fcall() or self.b.has_fcall()

    def get_decisions(self) -> list[BoolExpression]:
        return [self]

    def update_relations(self, parent: BoolExpression = None):
        self.parent = parent
        assert not self.children
        if self.a.type == ExpressionOperand.OPR_EXPR:
            self.children.append(self.a.operand)
        if self.op != BoolExpression.OP_NOT and self.b.type == ExpressionOperand.OPR_EXPR:
            self.children.append(self.b.operand)
        for child in self.children:
            child.update_relations(self)

    def reset_value(self) -> None:
        """Cleans calculated value for self and children"""
        self.value = None
        for child in self.children:
            child.reset_value()

    def set_value(self, value: bool) -> bool:
        """Set a new value an for expression, returns true if this concludes value for this expression"""
        self.value = value
        if self.parent:
            return self.parent.child_updated()
        return True

    def child_updated(self) -> bool:
        # Check if we can update own value
        assert self.children
        assert self.children[0].value != None
        v_a = self.children[0].value

        if len(self.children) > 1:
            v_b = self.children[1].value
            b_present = True
        else:
            b_present = False
        match self.op:
            case BoolExpression.OP_NOT:
                return self.set_value(not v_a)
            case BoolExpression.OP_AND:
                if not v_a:
                    return self.set_value(False)
                if b_present and v_b != None:
                    return self.set_value(v_a and v_b)
                return False
            case BoolExpression.OP_OR:
                if v_a:
                    return self.set_value(True)
                if b_present and v_b != None:
                    return self.set_value(v_a or v_b)
                return False
            case _:
                assert False
        pass

    def get_value(self) -> Optional[bool]:
        return self.value

    # This will be used mostly for self-checking
    def get_all_descendants(self) -> list[BoolExpression]:
        if not self.children:
            return [self]
        ret = []
        for child in self.children:
            ret.extend(child.get_all_descendants())

        if self.children and self.op != BoolExpression.OP_NOT and len(self.children) < 2:
            ret.append(self)
        return ret

    def get_undecided_child(self) -> BoolExpression:
        if not self.children:
            return self
        for child in self.children:
            if child.value == None:
                return child.get_undecided_child()
        return self

    __bin_op_mapping = {
        "||": OP_OR,
        "&&": OP_AND,
        "==": OP_EQ,
        "!=": OP_XOR,
        "<": OP_LT,
        "<=": OP_LE,
        ">": OP_GT,
        ">=": OP_GE,
    }

    @staticmethod
    def from_opcode(op: str) -> Optional[int]:
        if op in BoolExpression.__bin_op_mapping:
            return BoolExpression.__bin_op_mapping[op]
        return None


class Expression:

    def __init__(self, loc: CodeLoc, opcode: str,
                 operands: list[ExpressionOperand]):
        self.opcode = opcode
        self.operands = operands
        self.loc = loc
        self.uuid = str(uuid.uuid4())

    def __repr__(self) -> str:
        match len(self.operands):
            case 1:
                return f"({self.opcode} {self.operands[0]})"
            case 2:
                return f"({self.operands[0]} {self.opcode} {self.operands[1]})"
            case _:
                raise Exception(f"Too many operands: {len(self.operands)}")

    def to_c(self) -> str:
        match len(self.operands):
            case 1:
                return f"({self.opcode} {self.operands[0].to_c()})"
            case 2:
                return f"({self.operands[0].to_c()} {self.opcode} {self.operands[1].to_c()})"
            case _:
                raise Exception(f"Too many operands: {len(self.operands)}")

    def has_bool_expr(self) -> bool:
        for op in self.operands:
            if op.has_bool_expr():
                return True
        return False

    def has_fcall(self) -> bool:
        for op in self.operands:
            if op.has_fcall():
                return True
        return False

    def get_leafs(self) -> list[BoolExpression]:
        ret: list[BoolExpression] = []
        for operand in self.operands:
            ret.extend(operand.get_leafs())
        return ret

    def get_decisions(self) -> list[BoolExpression]:
        ret: list[BoolExpression] = []
        for operand in self.operands:
            ret.extend(operand.get_decisions())
        return ret


class FCall:

    def __init__(self, loc: CodeLoc, fname: ExpressionOperand,
                 args: list[ExpressionOperand]):
        self.loc = loc
        self.fname = fname
        self.args = args

    def __repr__(self) -> str:
        fname = str(self.fname)
        args = ", ".join([str(a) for a in self.args])
        return f"(<fcall> {fname})({args})"

    def to_c(self) -> str:
        fname = self.fname.to_c()
        args = ", ".join([a.to_c() for a in self.args])
        return f"({fname})({args})"

    def has_bool_expr(self) -> bool:
        for arg in self.args:
            if arg.has_bool_expr():
                return True
        return False

    def get_leafs(self) -> list[BoolExpression]:
        ret: list[BoolExpression] = []
        # If we chose function pointer based on bool operation, maybe?
        # I hope there is nothing like that in Xen
        ret.extend(self.fname.get_leafs())

        for arg in self.args:
            ret.extend(arg.get_leafs())

        return ret

    def get_decisions(self) -> list[BoolExpression]:
        ret: list[BoolExpression] = []
        ret.extend(self.fname.get_decisions())
        for arg in self.args:
            ret.extend(arg.get_decisions())
        return ret


class ConditionalOp:

    def __init__(self, loc: CodeLoc, check: ExpressionOperand,
                 expr1: ExpressionOperand, expr2: ExpressionOperand):
        self.loc = loc
        self.check = check
        self.expr1 = expr1
        self.expr2 = expr2

    def __repr__(self) -> str:
        return f"(<cond-op>{self.check})?({self.expr1}):({self.expr2})"

    def to_c(self) -> str:
        return f"({self.check.to_c()})?({self.expr1.to_c()}):({self.expr2.to_c()})"

    def get_leafs(self) -> list[BoolExpression]:
        ret: list[BoolExpression] = []
        ret.extend(self.check.get_leafs())
        ret.extend(self.expr1.get_leafs())
        ret.extend(self.expr2.get_leafs())
        #TODO: Fix this failing assert
        #        assert len(ret) > 0
        return ret

    def get_decisions(self) -> list[BoolExpression]:
        ret: list[BoolExpression] = []
        ret.extend(self.check.get_decisions())
        ret.extend(self.expr1.get_decisions())
        ret.extend(self.expr2.get_decisions())
        return ret

    def has_fcall(self) -> bool:
        return self.check.has_fcall() or self.expr1.has_fcall(
        ) or self.expr2.has_fcall()


class ArraySubscript:

    def __init__(self, loc: CodeLoc, array: ExpressionOperand,
                 subscr: ExpressionOperand):
        self.loc = loc
        self.array = array
        self.subscr = subscr

    def __repr__(self) -> str:
        return f"(<array-subscr>{self.array})[{self.subscr}]"

    def to_c(self) -> str:
        return f"({self.array.to_c()})[{self.subscr.to_c()}]"

    def get_leafs(self) -> list[BoolExpression]:
        ret: list[BoolExpression] = []
        # This is probably impossible, but who knows...
        ret.extend(self.array.get_leafs())
        # This is possible in some weird cases
        ret.extend(self.subscr.get_leafs())
        return ret

    def get_decisions(self) -> list[BoolExpression]:
        ret: list[BoolExpression] = []
        # This is probably impossible, but who knows...
        ret.extend(self.array.get_decisions())
        # This is possible in some weird cases
        ret.extend(self.subscr.get_decisions())
        return ret

    def has_fcall(self) -> bool:
        return self.array.has_fcall() or self.subscr.has_fcall()

    def has_bool_expr(self) -> bool:
        return self.array.has_bool_expr() or self.subscr.has_bool_expr()


class SizeOf:

    def __init__(self, loc: CodeLoc, argtype: str):
        self.loc = loc
        self.argtype = argtype

    def __repr__(self) -> str:
        return f"sizeof({self.argtype})"

    def to_c(self) -> str:
        return f"sizeof({self.argtype})"

    def get_leafs(self) -> list[BoolExpression]:
        return []

    def get_decisions(self) -> list[BoolExpression]:
        return []

    def has_fcall(self) -> bool:
        return False

    def has_bool_expr(self) -> bool:
        return False


class CCast:

    def __init__(self, loc: CodeLoc, cast_type: str, inner: ExpressionOperand):
        self.loc = loc
        self.cast_type = cast_type
        self.inner = inner

    def __repr__(self) -> str:
        return f"(<c-cast> {self.cast_type})({self.inner.__repr__()})"

    def to_c(self) -> str:
        return f"({self.cast_type})({self.inner.to_c()})"

    def get_leafs(self) -> list[BoolExpression]:
        return self.inner.get_leafs()

    def get_decisions(self) -> list[BoolExpression]:
        return self.inner.get_decisions()

    def has_fcall(self) -> bool:
        return self.inner.has_fcall()

    def has_bool_expr(self) -> bool:
        return self.inner.has_bool_expr()
