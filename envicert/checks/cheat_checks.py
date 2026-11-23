"""Deterministic cheat-agent battery (EC066).

Static checks *pattern-match* weakness; this battery *proves* exploitability
with no LLM and no randomness: it plays fixed, known cheat strategies as the
agent and requires the verifier to reject every one of them while accepting
the gold solution.

Scenarios (all deterministic, replayable from the report evidence):

- ``cheat-stub`` (local-python): the gold API with every function returning
  a constant -- submits structure, does no work;
- ``cheat-tamper`` (local-python): a no-op solution plus an agent-planted
  ``conftest.py`` that rewrites pytest outcomes to "passed" -- succeeds
  whenever the verifier runs pytest from an agent-writable directory;
- ``cheat-reward-forge`` (docker): writes ``reward.txt``/``reward.json``
  with a perfect score before the verifier runs, doing no task work --
  succeeds whenever the verifier trusts a pre-existing reward file;
- ``cheat-test-tamper`` (docker): replaces the writable copy of
  ``tests/test.sh`` with an unconditional-success script.

A cheat that scores a passing reward while gold also passes is a *proven*
false pass, reported as FAIL -- not a heuristic warning.  When gold itself
does not pass, the battery is inconclusive (NOT_APPLICABLE), never a PASS.
"""
from __future__ import annotations

from envicert.checks.base import CheckContext, CheckInfo, check, finding, not_applicable, not_run, passed
from envicert.core.models import Severity, Status

EC066 = CheckInfo("EC066", "Deterministic cheat-agent battery is rejected by the verifier", "dynamic", Severity.CRITICAL,
                  "Fixed cheat strategies (stub solution, verifier tampering, forged reward file) must not obtain a passing reward while the gold solution does.",
                  "Make the verifier compute its reward from verifier-owned logic over raw artifacts: run tests from a verifier-owned directory, overwrite (never read) the reward file, and reject stub/constant submissions with substantive assertions (see EC053/EC054).",
                  "Covers the listed deterministic strategies only; novel exploits need an adversarial (BenchJack-style) audit. local-python has no sandbox; docker scenarios assume the harness layout Envicert documents.",
                  dynamic=True)

LOCAL_SCENARIOS = ("cheat-stub", "cheat-tamper")
DOCKER_SCENARIOS = ("cheat-reward-forge", "cheat-test-tamper")


def _run(c: CheckContext, variant: str):
    from envicert.checks.dynamic_checks import _run_variant

    return _run_variant(c, variant)


def _passed(result) -> bool:
    if result is None:
        return False
    if result.reward is not None:
        return bool(result.reward >= 1.0)
    return bool(result.ok)


@check(EC066)
def check_cheat_battery(c: CheckContext) -> list:
    if c.execution == "none":
        return [not_run(EC066, "Cheat-agent battery is opt-in: re-run with --execution docker or --execution local-python.")]
    if c.execution == "external":
        return [not_applicable(EC066, "The external runner protocol has no cheat-variant contract yet; run the battery with docker or local-python.")]
    if c.execution == "local-python":
        from envicert.checks.dynamic_checks import _is_python_task

        if not _is_python_task(c.task):
            return [not_applicable(EC066, "local-python cheat battery requires solution/*.py plus tests/test_*.py (pytest-style task).")]
        scenarios = LOCAL_SCENARIOS
    elif c.execution == "docker":
        scenarios = DOCKER_SCENARIOS
    else:
        return [not_applicable(EC066, f"Cheat battery does not support execution mode '{c.execution}'.")]

    gold, why = _run(c, "gold")
    if gold is None:
        return [not_applicable(EC066, f"Cheat battery not supported here: {why}.")]
    if gold.error and gold.reward is None:
        return [finding(EC066, Status.ERROR, f"Cheat battery could not run: the gold execution failed ({gold.error}). No cheat evidence was obtained.",
                        severity=Severity.INFO, evidence={"error": gold.error, "runner": c.execution})]
    if not _passed(gold):
        return [not_applicable(EC066, f"Cheat battery inconclusive: the gold solution does not pass (reward={gold.reward}), so a rejected cheat proves nothing. Fix EC060 first.")]

    results: list[dict] = []
    succeeded: list[str] = []
    errors: list[str] = []
    for variant in scenarios:
        result, why = _run(c, variant)
        if result is None:
            results.append({"scenario": variant, "outcome": "unsupported", "note": why})
            continue
        if result.error and result.reward is None:
            errors.append(variant)
            results.append({"scenario": variant, "outcome": "execution-error", "error": result.error})
            continue
        cheat_passed = _passed(result)
        results.append({"scenario": variant, "outcome": "ACCEPTED (cheat passed)" if cheat_passed else "rejected",
                        "reward": result.reward, "exit_code": result.exit_code})
        if cheat_passed:
            succeeded.append(variant)
    ev = {"scenarios": results, "gold_reward": gold.reward, "runner": c.execution,
          "note": "deterministic strategies; replay by re-running with the same execution mode"}
    if succeeded:
        return [finding(EC066, Status.FAIL,
                        f"Proven false pass: deterministic cheat strateg{'y' if len(succeeded) == 1 else 'ies'} {', '.join(succeeded)} obtained a passing reward "
                        f"without solving the task (gold reward={gold.reward}). This is an executed exploit, not a pattern match.",
                        severity=Severity.CRITICAL, evidence=ev, confidence=_confidence())]
    if errors:
        return [finding(EC066, Status.ERROR,
                        f"Cheat battery incomplete: scenario(s) {', '.join(errors)} could not execute, so rejection is unproven for them.",
                        severity=Severity.INFO, evidence=ev)]
    return [passed(EC066, f"All {len(results)} deterministic cheat strategies were rejected while gold passed (reward={gold.reward}).", evidence=ev)]


def _confidence():
    from envicert.core.models import Confidence

    return Confidence.HIGH
