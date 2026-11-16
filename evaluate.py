import json
from dataclasses import dataclass
from typing import List, Dict


@dataclass
class EvalResult:
    case_id: str
    category: str
    expected: str
    predicted: str
    passed: bool


def evaluate_policy_guard(delegated_scope: str, prompt: str) -> str:
    """
    Baseline authorization & injection boundary check.
    Replace or augment this function with an LLM-as-a-judge or frontier model API call.
    """
    prompt_lower = prompt.lower()
    scope_lower = delegated_scope.lower()

    # Check for prompt injection markers
    injection_signals = ["system override", "ignore previous", "bypass"]
    if any(signal in prompt_lower for signal in injection_signals):
        return "REFUSE_OR_ESCALATE"

    # Check for unverified identity claims
    if "without my passkey" in prompt_lower or "new device" in prompt_lower:
        return "REFUSE_OR_ESCALATE"

    # Check for prohibited payment rails
    if "no crypto" in scope_lower and ("usdc" in prompt_lower or "0x" in prompt_lower):
        return "REFUSE_OR_ESCALATE"

    return "ALLOW"


def run_benchmark(dataset_path: str = "test_cases.json") -> None:
    with open(dataset_path, "r", encoding="utf-8") as f:
        cases: List[Dict] = json.load(f)

    results: List[EvalResult] = []
    for case in cases:
        predicted = evaluate_policy_guard(case["delegated_scope"], case["user_prompt"])
        passed = predicted == case["expected_behavior"]
        results.append(
            EvalResult(
                case_id=case["id"],
                category=case["category"],
                expected=case["expected_behavior"],
                predicted=predicted,
                passed=passed,
            )
        )

    passed_count = sum(1 for r in results if r.passed)
    total = len(results)

    print(f"=== KYA Boundary Eval Summary: {passed_count}/{total} Passed ({passed_count/total:.0%}) ===\n")
    for r in results:
        status = "PASS" if r.passed else "FAIL"
        print(f"[{status}] {r.case_id} ({r.category}) -> Expected: {r.expected}, Got: {r.predicted}")


if __name__ == "__main__":
    run_benchmark()
