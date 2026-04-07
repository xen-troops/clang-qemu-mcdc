import json
from pprint import pprint
from typing import Optional, Union
import subprocess
import lldb

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

    def __repr__(self) -> str:
        if self.kind:
            kind = f"({self.kind})"
        else:
            kind = ""
        return f"<{kind}{self.file}:{self.line}:{self.col}>"

    def update(self, fname: str, line: str):
        if not self.line:
            self.line = line
        if not self.file:
            self.file = fname
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

    # def is_expression(self) -> bool:
    #     expr_kinds = [""]


GLOBAL_SCOPE = Scope()


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
    bool_expr = get_bool_expr_list()
#    process_mcdc_in_debugger(lldb.debugger)
#    print(bool_expr)
    for expr in bool_expr:
        print(expr, expr.get_leafs())

    target,process = connect_to_target("localhost:1234")
    print(target, process)

def get_var_by_name(var_list: lldb.SBValueList, name: str) -> lldb.SBValue:
    for v in var_list:
        if v.name == name:
            return v
    raise Exception(f"Can'd find variable '{name}'")

def process_mcdc_in_debugger(debugger: lldb.SBDebugger, bool_expr: list[ExpressionOperand]):
    debugger.SetAsync(False)
    target: lldb.SBTarget = debugger.GetTargetAtIndex(0)
    process = target.process
    set_break_points(target, bool_expr)
    process.Continue()
    thread: lldb.SBThread = process.GetThreadAtIndex(0)
    print("thread", thread)
    frame: lldb.SBFrame = thread.GetFrameAtIndex(0)
    print("frame", frame)
    function: lldb.SBFunction = frame.GetFunction()
    print("function",function)
    variables: lldb.SBValueList = frame.GetVariables(True, True, True, True)
    print("variables", variables)
#    variables.
    # print(frame.get_locals())
    # print(frame.get_all_variables())
    pass

def on_breakpoint(frame: lldb.SBFrame, bp_loc: lldb.SBBreakpointLocation, extra_args: lldb.SBStructuredData, internal_dict: dict):
    print ("on_breakpoint")
    expr_idx = extra_args.GetUnsignedIntegerValue()
    print ("bool expression id is ", expr_idx)
    expr = BOOL_EXPR[expr_idx]
    for bool_expr in expr.get_decisions():
        leafs: list[BoolExpression] = bool_expr.get_leafs()
        for leaf in leafs:
            if leaf.has_fcall():
                raise Exception("Don't know what to do with function calls (yet)")
            val: lldb.SBValue = frame.EvaluateExpression(leaf.to_c())
            print(f"[Condition]Evaluated: {leaf.to_c()} got {val}")

        if bool_expr.has_fcall():
            raise Exception("Don't know what to do with function calls on expression level (yet)")
        print(bool_expr)
        val: lldb.SBValue = frame.EvaluateExpression(bool_expr.to_c())
        print(f"[Decision]Evaluated: {bool_expr.to_c()} got {val}")

    return False

def connect_to_target(location: str):
    debugger:lldb.SBDebugger  = lldb.SBDebugger.Create()
    target:lldb.SBTarget = debugger.CreateTargetWithFileAndArch("./test", lldb.LLDB_ARCH_DEFAULT) #TODO: Set symbol file from parameter
    listener: lldb.SBListener = lldb.SBListener("remote.target.listener")
    error: lldb.SBError = lldb.SBError()
    process:lldb.SBProcess = target.ConnectRemote(listener, f"connect://{location}", None, error)
    print("error", error)
    print("target", target)
    print("process", process)
    return target, process

def set_break_points(target: lldb.SBTarget, expressions: list[ExpressionOperand]):
    for idx, expr in enumerate(expressions):
        loc = expr.loc
        bp: lldb.SBBreakpoint = target.BreakpointCreateByLocation(loc.file, loc.line)
        data: lldb.SBStructuredData = lldb.SBStructuredData()
        data.SetUnsignedIntegerValue(idx)
        bp.SetScriptCallbackFunction(f"{__name__}.on_breakpoint", data)

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


class ExpressionOperand:
    OPR_VAR = 1
    OPR_FCALL = 2
    OPR_EXPR = 3
    OPR_NON_BOOL_EXPR = 4
    OPR_LITERAL = 5
    OPR_COND_OP = 6

    def __init__(self, loc: CodeLoc, opr_type,
                 operand: Union[str, BoolExpression, Expression, FCall,
                                ConditionalOp]):
        self.type = opr_type
        self.operand = operand
        self.loc = loc

    def __str__(self) -> str:
        match self.type:
            case self.OPR_VAR | self.OPR_LITERAL:
                return self.operand
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
            case self.OPR_VAR | self.OPR_LITERAL | self.OPR_EXPR | self.OPR_NON_BOOL_EXPR | self.OPR_FCALL | self.OPR_COND_OP:
                if isinstance(self.operand, str):
                    return self.operand
                return self.operand.to_c()
            case _:
                raise Exception(f"Unknown operand type: {self.type}")

    def __repr__(self) -> str:
        return str(self)

    def has_bool_expr(self) -> bool:
        match self.type:
            case ExpressionOperand.OPR_EXPR | ExpressionOperand.OPR_COND_OP:
                return True
            case ExpressionOperand.OPR_LITERAL | ExpressionOperand.OPR_VAR:
                return False
            case ExpressionOperand.OPR_FCALL | ExpressionOperand.OPR_NON_BOOL_EXPR:
                return self.operand.has_bool_expr()
            case _:
                raise Exception(f"Unknown operand type: {self.type}")

    def has_fcall(self) -> bool:
        match self.type:
            case ExpressionOperand.OPR_LITERAL | ExpressionOperand.OPR_VAR:
                return False
            case ExpressionOperand.OPR_FCALL:
                return True
            case  ExpressionOperand.OPR_EXPR | ExpressionOperand.OPR_COND_OP | ExpressionOperand.OPR_NON_BOOL_EXPR:
                return self.operand.has_fcall()
            case _:
                raise Exception(f"Unknown operand type: {self.type}")

    def get_leafs(self) -> list[BoolExpression]:
        "Returns list of leaf boolean expressions or `conditions` in MC/DC lingo"
        match self.type:
            case ExpressionOperand.OPR_EXPR | ExpressionOperand.OPR_COND_OP | ExpressionOperand.OPR_FCALL | ExpressionOperand.OPR_NON_BOOL_EXPR:
                return self.operand.get_leafs()
            case ExpressionOperand.OPR_LITERAL | ExpressionOperand.OPR_VAR:
                return []
            case _:
                raise Exception(f"Unknown operand type: {self.type}")

    def get_decisions(self) -> list[BoolExpression]:
        "Returns list of top-most boolean expressions or `decisions` in MC/DC lingo"
        match self.type:
            case ExpressionOperand.OPR_EXPR:
                return [self]
            case ExpressionOperand.OPR_COND_OP | ExpressionOperand.OPR_FCALL | ExpressionOperand.OPR_NON_BOOL_EXPR:
                return self.operand.get_decisions()
            case ExpressionOperand.OPR_LITERAL | ExpressionOperand.OPR_VAR:
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
                 opr_a: ExpressionOperand,
                 op,
                 opr_b: Optional[ExpressionOperand] = None):
        self.a = opr_a
        self.op = op
        self.b = opr_b
        self.loc = loc

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
        return f"({fname})({args})"

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
        return f"({self.check})?({self.expr1}):({self.expr2})"

    def to_c(self) -> str:
        return f"({self.check.to_c()})?({self.expr1.to_c()}):({self.expr2.to_c()})"

    def get_leafs(self) -> list[BoolExpression]:
        ret: list[BoolExpression] = []
        ret.extend(self.check.get_leafs())
        ret.extend(self.expr1.get_leafs())
        ret.extend(self.expr2.get_leafs())
        assert len(ret) > 0
        return ret

    def get_decisions(self) -> list[BoolExpression]:
        ret: list[BoolExpression] = []
        ret.extend(self.check.get_decisions())
        ret.extend(self.expr1.get_decisions())
        ret.extend(self.expr2.get_decisions())
        return ret

    def has_fcall(self) -> bool:
        return self.check.has_fcall() or self.expr1.has_fcall() or self.expr2.has_fcall()

class ArraySubscript:

    def __init__(self, loc: CodeLoc, array: ExpressionOperand,
                 subscr: ExpressionOperand):
        self.loc = loc
        self.array = array
        self.subscr = subscr

    def __repr__(self) -> str:
        return f"({self.array})[{self.subscr}]"

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
                field_name = ast.data["name"]
                struct = recurse(children[0]).to_c()
                if ast.data["isArrow"]:
                    return ExpressionOperand(ast.get_loc(),
                                             ExpressionOperand.OPR_VAR,
                                             f"({struct})->{field_name}")
                else:
                    return ExpressionOperand(ast.get_loc(),
                                             ExpressionOperand.OPR_VAR,
                                             f"({struct}).{field_name}")

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

    expr = recurse(ast)
    return expr


if __name__ == "__main__":
    main()

def __lldb_init_module(debugger, unused):
    bool_expr = get_bool_expr_list()
    process_mcdc_in_debugger(debugger, bool_expr)

def run_within_lldb():
    bool_expr = get_bool_expr_list()
    global BOOL_EXPR
    BOOL_EXPR = bool_expr
    process_mcdc_in_debugger(lldb.debugger, bool_expr)
