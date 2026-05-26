from mcdc_tool_parser import SAST, ASTEntry
from pprint import pprint
import pickle
import json

def load_mcdc_data() -> list[SAST]:
    with open("mcdc.pickle", "rb") as f:
        expressions: SAST = pickle.load(f)
        return expressions

def main():
    data = load_mcdc_data()
    # for idx, expr in enumerate(data):
    #     print(idx)
    #     pprint(expr)
    #     pprint(expr.ast.data)
    print(f"Total number of entries: {len(data)}")
    for expr in data:
        print(expr.uuid, expr, expr.has_fcall())
    #recurse_dump(0, data[3260].ast)

def recurse_dump(shift: int, ast: ASTEntry):
    tmp = ast.data.copy()
    if "inner" in tmp.keys():
        del tmp["inner"]
    pprint(tmp)
    for child in ast.inner:
        recurse_dump(shift + 1, child)

def dump_compile_command():
    compilation_db = open("compile_commands.json", "rt")
    db = json.load(compilation_db)
    for entry in db:
        f: str = entry["file"]
        if f == "arch/arm/vcpreg.c":
            print(" ".join(entry["arguments"]))

if __name__ == "__main__":
    main()
    #dump_compile_command()
