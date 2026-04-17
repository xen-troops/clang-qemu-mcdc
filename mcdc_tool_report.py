import json

class Result:
    def __init__(self, result: bool, message:str):
        self.result = result
        self.message = message
    def __bool__(self):
        return self.result

def main():
    with open("mcdc_coverage.json", "rt") as f:
        data:dict = json.load(f)

    for key, value in data.items():
        outcomes:list[list] = value["outcomes"]
        for test in TESTS:
            result: Result = test(outcomes)
            if not result:
                print(f"Fail for cond {value['expr']} at {value['loc']}: {result.message}")

def check_for_all_decisions(outcomes: list) -> Result:
    """Checks if all possible decisions were taken"""
    seen_true = False
    seen_false = False
    for outcome in outcomes:
        if outcome[0]:
            seen_true = True
        if not outcome[0]:
            seen_false = True
        if seen_true and seen_false:
            return Result(True, "")
    if not seen_false:
        return Result(False, "No False outcome")
    if not seen_true:
        return Result(False, "No True outcome")
    return Result(False, "No True outcome, no False outcome")

def check_for_all_conditions(outcomes: list) -> Result:
    num_conditions = len(outcomes[0][1])
    seen_false = [False] * num_conditions
    seen_true = [False] * num_conditions
    for outcome in outcomes:
        condition_outcomes = outcome[1]
        assert len(condition_outcomes) == num_conditions
        for idx, val in enumerate(condition_outcomes):
            if val:
                seen_true[idx] = True
            if not val:
                seen_false[idx] = True
    for idx in range(num_conditions):
        match (seen_false[idx], seen_true[idx]):
            case False, False:
                return Result(False, "No true and no false in conditions. (WTF?)")
            case False, True:
                return Result(False, f"No False outcome for condition {idx}")
            case True, False:
                return Result(False, f"No True outcome for condition {idx}")
            case True, True:
                pass
    return Result(True, "")

def check_for_independence(outcomes: list) -> Result:
    num_conditions = len(outcomes[0][1])

    for idx in range(num_conditions):
        result = check_for_indepence_for_cond(outcomes, idx)
        if not result:
            return result
    return Result(True, "")

def check_for_indepence_for_cond(outcomes: list, idx: int) -> Result:
    num_conditions = len(outcomes[0][1])
    # Okay, so for each condition we need to find a pair of outcomes that differ only for that condition
    # Sadly, it will be O(N^2)
    for i in range(len(outcomes)):
        for j in range(len(outcomes)):
            outcomes_i = outcomes[i][1]
            outcomes_j = outcomes[j][1]
            # Check if there is a difference only at `idx` position
            for k in range(num_conditions):
                if k == idx:
                    continue
                if outcomes_i[k] != outcomes_j[k]:
                    break
            else:
                # Okay, now need to check `idx` position
                if outcomes_i[idx] != outcomes_j[idx]:
                    # we have a winner
                    if outcomes[i][0] != outcomes[j][0]:
                        return Result(True, "")
                    else:
                        pass
                        #return Result(False, f"Condition on position {idx} failed to show independence. Both outcomes are the same")

    return Result(False, f"Failed to find two indepened set for condition on position {idx}")

TESTS = [check_for_all_decisions, check_for_all_conditions, check_for_independence]

if __name__ == "__main__":
    main()
