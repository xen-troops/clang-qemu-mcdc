from __future__ import annotations

from typing import Optional, Union
import itertools
import uuid
import sys

LAST_CODELOC_FILE: str = None


class CodeLoc:

    def __init__(self, data: dict):
        if "expansionLoc" in data:
            is_macro = "isMacroArgExpansion" in data["expansionLoc"]
            file_exp = data["expansionLoc"].get("file")
            file_spel = data["spellingLoc"].get("file")
            if is_macro and (file_exp == file_spel or file_spel == None):
                data = data["spellingLoc"]
                self.kind = "Spl"
            else:
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
        if not isinstance(other, CodeLoc):
            return False
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

    def __init__(self, data: dict, begin=None, end=None):
        if begin and end:
            self.begin = begin
            self.end = end
        elif data and "begin" in data:
            self.begin = CodeLoc(data["begin"])
            self.end = CodeLoc(data["end"])
        else:
            self.begin = None
            self.end = None

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
        self.parent = None
        for i, ch in enumerate(self.inner):
            if not ch:
                self.inner[i] = ASTEntry({"kind": "NULL"})
            else:
                ch.parent = self

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

            # For goto lables, childs begins after end of lable statement,
            # except if it is on the same line
            if self.kind == "LabelStmt":
                line = self.range.end.line or self.range.begin.line

        for ch in self.inner:
            ch.update_locations(fname, line)

    def get_loc(self) -> CodeLoc:
        if self.loc:
            return self.loc
        if self.range:
            return self.range.begin
        return None


class SAST:
    """Simple AST. Base class for other AST objects. Provides basic interface"""

    def __init__(self):
        raise NotImplementedError("This class should not be constucted directly")
        # Little help for typing hints
        self.inner: list[SAST] = []
        self.parent: Optional[SAST] = None
        self._function_name: str = None

        # Calculated location range, not to be confused with
        # ranges from ASTentry
        self.loc_range: CodeRange = None

    def _derived_init_(self,
                       loc: CodeLoc,
                       ast: ASTEntry,
                       inner: list[SAST],
                       parent: Optional[SAST] = None):
        self.inner = inner
        self.loc = loc
        self.parent = parent
        self._is_const: Optional[bool] = None
        self._is_var: Optional[bool] = None
        self._bool_const_val: Optional[bool] = None
        self.uuid = str(uuid.uuid4())

        for child in self.inner:
            if child is not None:
                child.parent = self

        self._function_name = self._resolve_function_name(ast)

        if ast and ast.range:
            self._base_range = ast.range
        else:
            self._base_range = CodeRange({}, self.loc, self.loc)

    def _resolve_function_name(self, ast: ASTEntry) -> str:
        curr = ast
        while curr:
            if curr.kind == "FunctionDecl":
                return curr.data["name"]
            curr = curr.parent
        return "(global scope)"

    @property
    def children(self) -> list[SAST]:
        """Alias for methods accessing .children"""
        return self.inner

    # If only each ASTEntry had valid code range...
    def update_location_range(self):
        if not self.inner:
            self.loc_range = self._base_range
        else:
            # TODO use max_loc and min_loc values instead
            min_line = sys.maxsize
            min_col = sys.maxsize
            max_col = 0
            max_line = 0
            fname = self.loc.file
            max_loc: CodeLoc = None
            min_loc: CodeLoc = None
            for ch in self.inner:
                if not ch.loc:
                    continue
                ch.update_location_range()

                if ch.loc.file != fname:
                    raise Exception(
                        f"Sub-expresion {ch} ({ch.loc}) of {self}({self.loc}) resides in an other file: {fname} vs {ch.loc.file}"
                    )

                if ch.loc_range.begin is None or ch.loc_range.end is None:
                    continue

                if ch.loc_range.begin.line < min_line:
                    min_line = ch.loc_range.begin.line
                    min_col = ch.loc_range.begin.col
                    min_loc = ch.loc_range.begin
                elif ch.loc_range.begin.line == min_line and ch.loc_range.begin.col < min_col:
                    min_col = min(min_col, ch.loc_range.begin.col)
                    min_loc = ch.loc_range.begin

                if ch.loc_range.end.line > max_line:
                    max_line = ch.loc_range.end.line
                    max_col = ch.loc_range.end.col
                    max_loc = ch.loc_range.end
                elif ch.loc_range.end.line == max_line and ch.loc_range.end.col > max_col:
                    max_col = max(max_col, ch.loc_range.end.col)
                    max_loc = ch.loc_range.end
            self.loc_range = CodeRange({}, min_loc, max_loc)

    def has_bool_expr(self) -> bool:
        "Return True if it is bool expr or has bool expressions as children"
        return any(ch.has_bool_expr() for ch in self.inner)

    def has_fcall(self) -> bool:
        "Return True if it is function call or has function calls as children"
        return any(ch.has_fcall() for ch in self.inner)

    def get_leafs(self) -> list[BoolExpression]:
        "Returns list of leaf boolean expressions or `conditions` in MC/DC lingo"
        return list(itertools.chain.from_iterable(ch.get_leafs() for ch in self.inner))

    def get_decisions(self) -> list[BoolExpression]:
        "Returns list of top-most boolean expressions or `decisions` in MC/DC lingo"
        return list(itertools.chain.from_iterable(ch.get_decisions() for ch in self.inner))

    def lift_fcall_args(self) -> list[SAST]:
        """
        Replace all inner function call arguments with placeholder
        and return arguments as list of expressions

        N.B. This will change structure of the inner tree
        """
        return list(itertools.chain.from_iterable(ch.lift_fcall_args() for ch in self.inner))

    def is_const(self) -> bool:
        if self._is_const == None:
            if self.inner:
                self._is_const = all((i.is_const() for i in self.inner))
            else:
                self._is_const = False
        return self._is_const

    def is_var(self) -> bool:
        if self._is_var == None:
            self._is_var = all((i._is_var == True for i in self.inner))

        return self._is_var

    def get_topmost_bool_expr(self) -> list[BoolExpression]:
        if isinstance(self, BoolExpression):
            return [self]

        ret: list[BoolExpression] = []
        for ch in self.inner:
            ret.extend(ch.get_topmost_bool_expr())
        return ret

    def simplify(self):
        # Do simplification passes.
        for idx, ch in enumerate(self.inner):
            ch.simplify()
            # For StatementExpression replace it with its return expression
            if isinstance(ch, StatementExpression):
                self.inner[idx] = ch.ret_expr

            # For c-style cast - replace with value that is casted
            if isinstance(ch, CCast):
                self.inner[idx] = ch.casted

    def function_name(self) -> str:
        return self._function_name


class NonBoolVar(SAST):

    def __init__(self, loc: CodeLoc, name: str, var_type: str, ast: ASTEntry):
        self._derived_init_(loc, ast, [])
        self.name = name
        self.var_type = var_type
        self._is_var = True

    def __repr__(self) -> str:
        return f"<NonBoolVar ({self.var_type}){self.name}>"


class BoolVar(SAST):

    def __init__(self, loc: CodeLoc, name: str, ast: ASTEntry):
        self._derived_init_(loc, ast, [])
        self.name = name
        self._is_var = True

    def __repr__(self) -> str:
        return f"<BoolVar {self.name}>"

    def get_leafs(self) -> list[SAST]:
        # Bool var is always a leaf
        return [self]

    def set_value(self, value: bool) -> bool:
        self.value = value
        if self.parent and hasattr(self.parent, 'child_updated'):
            self.parent.child_updated()


class StringLiteral(SAST):

    def __init__(self, loc: CodeLoc, value: str, ast: ASTEntry):
        self._derived_init_(loc, ast, [])
        self.value = value
        self._is_const = True
        # No one shall cast string liter to bool value,
        # but just in case...
        self._bool_const_val = True

    def __repr__(self) -> str:
        return f"<StringLiteral {self.value}>"


class IntLiteral(SAST):

    def __init__(self, loc: CodeLoc, value: int, ast: ASTEntry):
        self._derived_init_(loc, ast, [])
        self.value = value
        self._is_const = True
        self._bool_const_val = value != 0

    def __repr__(self) -> str:
        return f"<IntLiteral {self.value}>"


class EnumConst(SAST):

    def __init__(self, loc: CodeLoc, value: str, ast: ASTEntry):
        self._derived_init_(loc, ast, [])
        self.value = value
        self._is_const = True

    def __repr__(self) -> str:
        return f"<EnumConst {self.value}>"


class MemberExpr(SAST):

    def __init__(self, loc: CodeLoc, left: SAST, right: str, arrow: bool, ast: ASTEntry):
        self._derived_init_(loc, ast, [left])
        self.right = right
        self.arrow = arrow
        self.is_var = True

    @property
    def left(self):
        return self.inner[0]

    def __repr__(self) -> str:
        sep = "->" if self.arrow else "."
        return f"<MemberExpr {self.left}{sep}{self.right}>"


class BoolExpression(SAST):
    OP_OR = 1
    OP_AND = 2
    OP_NOT = 3
    OP_EQ = 4
    OP_XOR = 5
    OP_LT = 6
    OP_LE = 7
    OP_GT = 8
    OP_GE = 9
    OP_IMPLICIT_CAST = 10

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
        OP_IMPLICIT_CAST: "(IMPLICIT BOOL CAST)",
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
        OP_IMPLICIT_CAST: "(bool)",
    }

    def __init__(self, loc: CodeLoc, ast: ASTEntry, opr_a: SAST, op, opr_b: Optional[SAST] = None):
        self._derived_init_(loc, ast, [opr_a, opr_b] if opr_b else [opr_a])
        self.op = op
        self.loc = loc
        self.value: Optional[bool] = None

    @property
    def a(self) -> SAST:
        return self.inner[0]

    @property
    def b(self) -> SAST:
        return self.inner[1]

    def __str__(self) -> str:
        a_str = str(self.a)
        op_str = BoolExpression.OP_REPR[self.op]
        if len(self.inner) == 2:
            b_str = str(self.b)
        else:
            b_str = ""
        if self.op == self.OP_NOT:
            return f"({op_str} {a_str})"
        return f"({a_str} {op_str} {b_str})"

    def __repr__(self) -> str:
        return str(self)

    def has_bool_expr(self):
        return True

    def is_const(self):
        # First, run base logic
        if super().is_const():
            return True

        # Then do short circuit for constants
        match self.op:
            case self.OP_AND:
                if self.a.is_const() and self.a._bool_const_val == False:
                    self._bool_const_val = False
                    self._is_const = True
                    return True
            case self.OP_OR:
                if self.a.is_const() and self.a._bool_const_val == True:
                    self._bool_const_val = True
                    self._is_const = True
                    return True
        return False

    def get_leafs(self) -> list[BoolExpression]:
        # Arithmetic comparisons are always leafs
        if self.op in (BoolExpression.OP_EQ, BoolExpression.OP_XOR, BoolExpression.OP_GE,
                       BoolExpression.OP_GT, BoolExpression.OP_LE, BoolExpression.OP_LT):
            return [self]

        ret: list[BoolExpression] = []
        leafs_a = self.a.get_leafs()
        leafs_b = []
        b_present = self.op not in (BoolExpression.OP_NOT, BoolExpression.OP_IMPLICIT_CAST)
        a_is_const = self.a.is_const()
        b_is_const = self.b.is_const() if b_present else True

        if b_present:
            leafs_b = self.b.get_leafs()

        if (not leafs_a and not leafs_b) or (a_is_const and b_is_const):
            # We are the leaf
            return [self]
        else:
            if leafs_a:
                ret.extend(leafs_a)
            else:
                if not a_is_const:
                    ret.append(self.a)
            if b_present:
                if leafs_b:
                    ret.extend(leafs_b)
                else:
                    if not b_is_const:
                        ret.append(self.b)
        return ret

    def get_decisions(self) -> list[BoolExpression]:
        return [self]

    def reset_value(self) -> None:
        """Cleans calculated value for self and children"""
        self.value = None

        if getattr(self, 'children', None):
            for child in self.children:
                if hasattr(child, 'reset_value'):
                    child.reset_value()
                else:
                    if type(child).__name__ not in ['IntLiteral', 'StringLiteral', 'SizeOf']:
                        child.value = None

    def set_value(self, value: bool) -> bool:
        """Set a new value an for expression, returns true if this concludes value for this expression"""
        self.value = value
        if self.parent and hasattr(self.parent, 'child_updated'):
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
            case BoolExpression.OP_IMPLICIT_CAST:
                return self.set_value(v_a)
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

    def promote_double_not(self) -> BoolExpression:
        if self.op != self.OP_NOT:
            return self
        if not isinstance(self.a, BoolExpression):
            return self
        if self.a.op != self.OP_NOT:
            return self

        ret = self.a.a
        if isinstance(ret, BoolExpression):
            return ret
        return BoolExpression(self.loc, None, ret, self.OP_IMPLICIT_CAST)

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


class NonBoolExpression(SAST):

    def __init__(self, loc: CodeLoc, opcode: str, operands: list[SAST], ast: ASTEntry):
        self._derived_init_(loc, ast, operands)
        self.opcode = opcode

    @property
    def operands(self) -> list[SAST]:
        return self.inner

    def __repr__(self) -> str:
        match len(self.operands):
            case 1:
                return f"(<NonBoolExpr> {self.opcode} {self.operands[0]})"
            case 2:
                return f"(<NonBoolExpr> {self.operands[0]} {self.opcode} {self.operands[1]})"
            case _:
                raise Exception(f"Too many operands: {len(self.operands)}")


class FCall(SAST):

    def __init__(self, loc: CodeLoc, fname: SAST, args: list[SAST], ast: ASTEntry):
        self._derived_init_(loc, ast, [fname] + args)

    @property
    def fname(self):
        return self.inner[0]

    @property
    def args(self):
        return self.inner[1:]

    def __repr__(self) -> str:
        fname = str(self.fname)
        args = ", ".join([str(a) for a in self.args])
        return f"(<fcall> {fname})({args})"

    def has_fcall(self):
        "Of course I know him, because it's me"
        return True

    def lift_fcall_args(self) -> list[SAST]:
        """
        Replace all inner function call arguments with placeholder
        and return arguments as list of expressions

        N.B. This will change structure of the inner tree
        """
        ret: list[SAST] = []
        for idx, arg in enumerate(self.args):
            ret.append(arg)
            # Save location for debugging value
            self.inner[idx + 1] = FCallArg(arg.loc)
        return ret


class FCallArg(SAST):
    """Placeholder for functinal call argument, as we in fact are not interested in its value"""

    def __init__(self, loc: CodeLoc):
        self._derived_init_(loc, None, [])

    def __repr__(self) -> str:
        return f"<FCallArg at {self.loc}>"


class FlowControlStructure(SAST):
    """Control structure which has some sort of "check" which makes implicit bool cast """

    def __init__(self, loc: CodeLoc, check: SAST, rest: list[SAST], ast: ASTEntry):
        # We don't know what it is, but we need to wrap this into
        # BoolExpression just in case
        if isinstance(check, BoolExpression):
            bool_check = check
        else:
            bool_check = BoolExpression(check.loc, ast, check, BoolExpression.OP_IMPLICIT_CAST)

        self._derived_init_(loc, ast, [bool_check] + rest)

    @property
    def check(self):
        return self.inner[0]

    @property
    def rest(self):
        return self.inner[1:]

    def __repr__(self) -> str:
        return f"(<FlowControStructure>{self.check})({self.rest})"


class ArraySubscript(SAST):

    def __init__(self, loc: CodeLoc, array: SAST, subscr: SAST, ast: ASTEntry):
        self._derived_init_(loc, ast, [array, subscr])

    @property
    def array(self):
        return self.inner[0]

    @property
    def subscr(self):
        return self.inner[1]

    def __repr__(self) -> str:
        return f"(<array-subscr>{self.array})[{self.subscr}]"


class SizeOf(SAST):

    def __init__(self, loc: CodeLoc, argtype: str, ast: ASTEntry):
        self._derived_init_(loc, ast, [])
        self.argtype = argtype
        self._is_const = True
        # sizeof() is always greater than 0
        self._bool_const_val = True

    def __repr__(self) -> str:
        return f"sizeof({self.argtype})"


class CCast(SAST):

    def __init__(self, loc: CodeLoc, cast_type: str, inner: SAST, ast: ASTEntry):
        self._derived_init_(loc, ast, [inner])
        self.cast_type = cast_type

    def __repr__(self) -> str:
        return f"(<c-cast> {self.cast_type})({self.inner[0].__repr__()})"

    @property
    def casted(self):
        return self.inner[0]


class StatementExpression(SAST):

    def __init__(self, loc: CodeLoc, inner: SAST, ast: ASTEntry):
        if not isinstance(inner, CompoundStmt):
            raise Exception(f"Expected compound statement inside, got {type(inner)}")
        self._derived_init_(loc, ast, [inner])

    def __repr__(self) -> str:
        return f"<StmtExpr ({self.inner[0]})>"

    @property
    def ret_expr(self):
        return self.inner[0]

    def simplify(self):
        for idx, ch in enumerate(self.inner):
            ch.simplify()
            assert isinstance(ch, CompoundStmt)
            self.inner[idx] = ch.ret_expr


class CompoundStmt(SAST):

    def __init__(self, loc: CodeLoc, inner: [SAST], ast: ASTEntry):
        self._derived_init_(loc, ast, inner)

    def __repr__(self) -> str:
        return f"<CompoundStmt ({self.inner})>"

    @property
    def ret_expr(self):
        return self.inner[-1]


class NullOp(SAST):
    "For cases when we really not interested in expression"

    def __init__(self, loc: CodeLoc, ast: ASTEntry):
        self._derived_init_(loc, ast, [])
        self._is_const = True

    def __repr__(self) -> str:
        return f"(NullOp at {self.loc})"


class MiscExpr(SAST):
    """Some other type of expression, in which we are not interested in. Should never
    be argument for BoolExpression"""

    def __init__(self, loc: CodeLoc, ast: ASTEntry, expressions: list[SAST]):
        self._derived_init_(loc, ast, expressions)

    def __repr__(self) -> str:
        return f"(MiscExpr:{self.inner})"
