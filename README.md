# KYA Boundary Eval (`kya-boundary-eval`)

A lightweight evaluation harness testing whether AI agents respect human-delegated authorization scopes and resist adversarial boundary violations under **Know Your Agent (KYA)** frameworks.

## Motivation
As autonomous agents negotiate, transact and interact with APIs on behalf of humans, standard identity checks (KYC) are no longer sufficient. Trust & safety systems must verify:
1. **Human Binding:** Is a verified human behind the agent session?
2. **Scope Adherence:** Is the requested action within the user's explicit delegation limits?
3. **Adversarial Resilience:** Can indirect prompt injections or identity-spoofing claims bypass authorization controls?

## Repository Structure
- `test_cases.json`: Structured evaluation prompts covering scope escalation, indirect prompt injection, identity spoofing and benign in-scope requests.
- `evaluate.py`: Baseline policy-guard evaluator and benchmark runner (`python evaluate.py`).

## Quickstart
```bash
git clone [https://github.com/tracekya/kya-boundary-eval.git](https://github.com/tracekya/kya-boundary-eval.git)
cd kya-boundary-eval
python evaluate.py
