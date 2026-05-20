import lldb
from mcdc_tool_parser import BoolExpression, ExpressionOperand
import pickle
import os.path
import json

COVERAGE_DATA = {}


def load_mcdc_data() -> list[ExpressionOperand]:
    with open("mcdc.pickle", "rb") as f:
        expressions: ExpressionOperand = pickle.load(f)
        return expressions


def load_coverage_data():
    if os.path.exists("mcdc_coverage.json"):
        with open("mcdc_coverage.json", "rt") as f:
            global COVERAGE_DATA
            COVERAGE_DATA = json.load(f)

def init_coverage_data(decision: BoolExpression,
                       conditions: list[ExpressionOperand]):
    COVERAGE_DATA[decision.uuid] = {}
    COVERAGE_DATA[decision.uuid]["outcomes"] = []
    COVERAGE_DATA[decision.uuid]["loc"] = str(decision.loc)
    COVERAGE_DATA[decision.uuid]["expr"] = decision.to_c()
    COVERAGE_DATA[decision.uuid]["conditions_order"] = []
    for condition in conditions:
        COVERAGE_DATA[decision.uuid]["conditions_order"].append(condition.uuid)


def update_coverage_data(decision: BoolExpression,
                         conditions: list[BoolExpression],
                         decision_result: bool):
    if not decision.uuid in COVERAGE_DATA:
        init_coverage_data(decision, conditions)
    outcomes = [decision_result, []]
    for idx, cond in enumerate(conditions):
        assert cond.uuid == COVERAGE_DATA[
            decision.uuid]["conditions_order"][idx]
        outcomes[1].append(cond.get_value())

    COVERAGE_DATA[decision.uuid]["outcomes"].append(outcomes)


def save_coverage_data():
    with open("mcdc_coverage.json", "wt") as f:
        json.dump(COVERAGE_DATA, f, indent=4)


def main():
    load_coverage_data()
    expressions = load_mcdc_data()
    for expr in expressions:
        for decision in expr.get_decisions():
            decision.update_relations()
#            print(decision, decision.get_leafs())

    target, process = connect_to_target("localhost:1234")
    print(target, process)
    process_mcdc_in_debugger(target.GetDebugger(), expressions)
    save_coverage_data()

def get_var_by_name(var_list: lldb.SBValueList, name: str) -> lldb.SBValue:
    for v in var_list:
        if v.name == name:
            return v
    raise Exception(f"Can'd find variable '{name}'")


def process_mcdc_in_debugger(debugger: lldb.SBDebugger,
                             bool_expr: list[ExpressionOperand]):
    debugger.SetAsync(False)
    target: lldb.SBTarget = debugger.GetTargetAtIndex(0)
    process = target.process
    set_break_points(target, bool_expr)
    process.Continue()
    # thread: lldb.SBThread = process.GetThreadAtIndex(0)
    # print("thread", thread)
    # frame: lldb.SBFrame = thread.GetFrameAtIndex(0)
    # print("frame", frame)
    # function: lldb.SBFunction = frame.GetFunction()
    # print("function",function)
    # variables: lldb.SBValueList = frame.GetVariables(True, True, True, True)
    # print("variables", variables)
    #    variables.
    # print(frame.get_locals())
    # print(frame.get_all_variables())
    pass

def sbval_to_bool(val: lldb.SBValue) -> bool:
    if val.GetType().GetBasicType() != lldb.eBasicTypeBool:
        print(f"!!!!!!!!!!!!!!!!!!!!!!!!!!11 basic type is {val.GetType().GetBasicType()}, which is not {lldb.eBasicTypeBool}")
    assert val.GetType().GetBasicType() == lldb.eBasicTypeBool
    return val.GetValue() == "true"

def on_breakpoint(frame: lldb.SBFrame, bp_loc: lldb.SBBreakpointLocation,
                  extra_args: lldb.SBStructuredData, internal_dict: dict):
    expr_idx = extra_args.GetUnsignedIntegerValue()
    print("bool expression id is ", expr_idx)
    expr = BOOL_EXPR[expr_idx]
    print(f"expr {expr.to_c()} at {expr.loc}")
    for bool_expr in expr.get_decisions():
        if bool_expr.has_fcall():
            print("Skipping fcall")
            return False
        bool_expr.reset_value()

        descendants = bool_expr.get_all_descendants()
        while bool_expr.get_value() == None:
            leaf = bool_expr.get_undecided_child()
            assert leaf in descendants
            if leaf.has_fcall():
                return False
                raise Exception(
                    "Don't know what to do with function calls (yet)")
            val: lldb.SBValue = frame.EvaluateExpression(leaf.to_c())
            print(f"[Condition]Evaluated: {leaf.to_c()} got {val}")
            bool_val = sbval_to_bool(val)
            leaf.set_value(bool_val)

        if bool_expr.has_fcall():
            return False
            raise Exception(
                "Don't know what to do with function calls on expression level (yet)"
            )
        print(bool_expr)
        val: lldb.SBValue = frame.EvaluateExpression(bool_expr.to_c())
        print(f"[Decision]Evaluated: {bool_expr.to_c()} got {val}")
        update_coverage_data(bool_expr, descendants, sbval_to_bool(val))
    return False


def connect_to_target(location: str):
    print("Connecting to", location)
    debugger: lldb.SBDebugger = lldb.SBDebugger.Create()
    target: lldb.SBTarget = debugger.CreateTargetWithFileAndArch(
        "./test",
        lldb.LLDB_ARCH_DEFAULT)  #TODO: Set symbol file from parameter
    error: lldb.SBError = lldb.SBError()
    process: lldb.SBProcess = target.ConnectRemote(debugger.GetListener(),
                                                   f"connect://{location}",
                                                   "gdb-remote", error)
    print("error", error)
    print("target", target)
    print("process", process)
    return target, process


def set_break_points(target: lldb.SBTarget,
                     expressions: list[ExpressionOperand]):
    for idx, expr in enumerate(expressions):
        loc = expr.loc
        bp: lldb.SBBreakpoint = target.BreakpointCreateByLocation(
            loc.file, loc.line)
        data: lldb.SBStructuredData = lldb.SBStructuredData()
        data.SetUnsignedIntegerValue(idx)
        bp.SetScriptCallbackFunction(f"{__name__}.on_breakpoint", data)


if __name__ == "__main__":
    main()


def run_within_lldb():
    load_coverage_data()
    bool_expr = load_mcdc_data()
    for expr in bool_expr:
        for decision in expr.get_decisions():
            decision.update_relations()
    global BOOL_EXPR
    BOOL_EXPR = bool_expr
    process_mcdc_in_debugger(lldb.debugger, bool_expr)
    save_coverage_data()
