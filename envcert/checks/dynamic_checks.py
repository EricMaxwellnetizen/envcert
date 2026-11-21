"""Dynamic checks. Explicitly opt-in via execution mode.

- docker: build + run a Harbor task in the restricted DockerRunner.
- local-python: run pytest-style tests/ against solution/*.py in a temp copy
  (no sandbox — trusted tasks only, recorded in the report).
- none (default): every dynamic check returns NOT_RUN, never PASS.
"""
from __future__ import annotations

from envcert.checks.base import CheckContext, CheckInfo, check, finding, not_applicable, not_run, passed
from envcert.core.models import Severity, Status
from envcert.runners.docker_runner import DockerRunner
from envcert.runners.local_runner import LocalPythonRunner

EC060 = CheckInfo("EC060", "Reference (gold) solution passes the verifier", "dynamic", Severity.HIGH,
                  "Executing the reference solution should produce the expected (passing) reward.",
                  "Fix the reference solution or the verifier so a correct solution passes.",
                  "Only supported for docker (Harbor shell tasks) and local-python (pytest tasks) execution.", dynamic=True)
EC061 = CheckInfo("EC061", "Negative control (no-op/empty) is rejected by the verifier", "dynamic", Severity.HIGH,
                  "A no-op or empty submission should not pass, unless the task semantics say otherwise.",
                  "Strengthen the verifier so trivial submissions fail.",
                  "Some tasks legitimately pass with no action; then this returns NOT_APPLICABLE/WARN for human review, not a hard failure.", dynamic=True)
EC062 = CheckInfo("EC062", "Verifier outcome is repeatable across repetitions", "dynamic", Severity.MEDIUM,
                  "Re-running gold verification should give a consistent reward/exit outcome.",
                  "Remove nondeterminism (time, randomness, network, ordering) from the task or verifier.",
                  "Compares reward/exit outcome, not bitwise-identical stdout.", dynamic=True)
EC064 = CheckInfo("EC064", "Shell-solution mutation: verifier rejects mutated reference solutions (docker)", "mutation", Severity.MEDIUM,
                  "Mutating literal outputs in solution/solve.sh should make the verifier reject the run; surviving mutants signal a weak verifier.",
                  "Strengthen verifier assertions on the mutated outputs.",
                  "Docker execution only; only literal-bearing shell solutions can be mutated. Mutant validity is heuristic.", dynamic=True)
EC063 = CheckInfo("EC063", "Mutation testing: verifier rejects mutated (incorrect) solutions", "mutation", Severity.MEDIUM,
                  "Mutated variants of a correct Python solution should be rejected; the rejection rate is a verifier-strength signal.",
                  "Add assertions covering the mutated behaviour; do not treat the rate as proof of correctness.",
                  "Equivalent/invalid mutants and the small mutant set limit this signal. Python/pytest tasks only.", dynamic=True)


def _is_python_task(ctx) -> bool:
    has_py_solution = any(f.startswith("solution/") and f.endswith(".py") for f in ctx.files)
    has_py_tests = any(f.startswith("tests/") and f.endswith(".py") and "test" in f.rsplit("/", 1)[-1] for f in ctx.files)
    return has_py_solution and has_py_tests


def _run_variant(c: CheckContext, variant: str):
    ctx = c.task
    if c.execution == "docker":
        result = DockerRunner().run_harbor_task(ctx.root, variant=variant)
        if result.image_digest:
            c.shared["image_digest"] = result.image_digest
        return result, None
    if c.execution == "external":
        from envcert.runners.external_runner import ExternalRunner

        result = ExternalRunner(c.runner_command).run_harbor_task(ctx.root, variant=variant)
        if result.image_digest:
            c.shared["image_digest"] = result.image_digest
        return result, None
    if c.execution == "local-python":
        if not _is_python_task(ctx):
            return None, "local-python execution requires solution/*.py plus tests/test_*.py (pytest-style task)"
        return LocalPythonRunner().run_task(ctx.root, solution_variant=variant), None
    return None, f"execution mode is '{c.execution}'"


@check(EC060)
def check_gold(c: CheckContext) -> list:
    if c.execution == "none":
        return [not_run(EC060, "Dynamic checks are opt-in: re-run with --execution docker or --execution local-python.")]
    result, why = _run_variant(c, "gold")
    if result is None:
        return [not_applicable(EC060, f"Gold run not supported here: {why}.")]
    if result.error and result.reward is None:
        return [finding(EC060, Status.ERROR, f"Gold execution failed to run: {result.error}",
                        severity=Severity.INFO, evidence={"error": result.error, "runner": c.execution})]
    if result.reward is not None:
        if result.reward >= 1.0 or (c.execution == "local-python" and result.ok):
            return [passed(EC060, f"Reference solution passed verification (reward={result.reward}).",
                           evidence={"reward": result.reward, "exit_code": result.exit_code, "runner": c.execution, "duration_sec": result.duration_sec})]
        return [finding(EC060, Status.FAIL, f"Reference solution did NOT pass verification (reward={result.reward}, exit={result.exit_code}). Either the solution or the verifier is broken.",
                        evidence={"reward": result.reward, "exit_code": result.exit_code, "stderr_tail": result.stderr[-1000:]})]
    if result.ok:
        return [passed(EC060, "Reference solution run exited successfully.", evidence={"exit_code": result.exit_code, "runner": c.execution})]
    return [finding(EC060, Status.FAIL, f"Reference solution run failed (exit={result.exit_code}): {result.error or result.stderr[-500:]}",
                    evidence={"exit_code": result.exit_code, "stderr_tail": result.stderr[-1000:]})]


@check(EC061)
def check_negative_control(c: CheckContext) -> list:
    if c.execution == "none":
        return [not_run(EC061, "Dynamic checks are opt-in: re-run with --execution docker or --execution local-python.")]
    result, why = _run_variant(c, "noop")
    if result is None:
        return [not_applicable(EC061, f"Negative control not supported here: {why}.")]
    if result.error and result.reward is None:
        return [finding(EC061, Status.ERROR, f"Negative-control execution failed to run: {result.error}", severity=Severity.INFO, evidence={"error": result.error})]
    # Reward, when present, is authoritative (a docker harness exits 0 even
    # when the reward is 0); only fall back to exit status without a reward.
    noop_passed = (result.reward >= 1.0) if result.reward is not None else result.ok
    if noop_passed:
        return [finding(EC061, Status.WARN,
                        "No-op (skipped/emptied) solution PASSED the verifier. If a no-op should not solve this task, the verifier is too weak; if no action is a legitimate solution, record that and ignore this warning.",
                        severity=Severity.HIGH, evidence={"reward": result.reward, "exit_code": result.exit_code, "variant": "noop"})]
    return [passed(EC061, "No-op negative control was rejected by the verifier (non-passing outcome).",
                   evidence={"reward": result.reward, "exit_code": result.exit_code, "variant": "noop"})]


@check(EC062)
def check_repeatability(c: CheckContext) -> list:
    if c.execution == "none":
        return [not_run(EC062, "Dynamic checks are opt-in: re-run with --execution docker or --execution local-python.")]
    if c.execution in ("docker", "external"):
        outcomes = []
        for _ in range(max(2, min(c.repetitions, 3))):
            r, _why = _run_variant(c, "gold")
            if r is None:
                return [not_applicable(EC062, f"Repeatability not supported here: {_why}.")]
            outcomes.append({"reward": r.reward, "exit_code": r.exit_code, "error": r.error})
        rewards = {o["reward"] for o in outcomes}
        if len(rewards) == 1 and None not in rewards:
            return [passed(EC062, f"Gold reward was consistent across {len(outcomes)} {c.execution} runs (reward={outcomes[0]['reward']}).", evidence={"runs": outcomes})]
        return [finding(EC062, Status.WARN, f"Gold outcome varied across {len(outcomes)} {c.execution} runs: {outcomes}. Investigate nondeterminism.", evidence={"runs": outcomes})]
    if c.execution != "local-python":
        return [not_applicable(EC062, "Repeatability requires an execution mode.")]
    if not _is_python_task(c.task):
        return [not_applicable(EC062, "Repeatability requires a pytest-style Python task under local-python execution.")]
    runner = LocalPythonRunner()
    outcomes = []
    for _ in range(max(2, c.repetitions)):
        r = runner.run_task(c.task.root, solution_variant="gold")
        outcomes.append({"reward": r.reward, "exit_code": r.exit_code, "error": r.error})
    rewards = {o["reward"] for o in outcomes}
    if len(rewards) == 1 and None not in rewards:
        return [passed(EC062, f"Gold outcome was consistent across {len(outcomes)} runs (reward={outcomes[0]['reward']}).",
                       evidence={"runs": outcomes})]
    return [finding(EC062, Status.WARN, f"Gold outcome varied across {len(outcomes)} runs: {outcomes}. Investigate nondeterminism.",
                    evidence={"runs": outcomes})]


@check(EC063)
def check_mutation(c: CheckContext) -> list:
    if not c.enable_mutation:
        return [not_run(EC063, "Mutation testing is opt-in: re-run with --mutation (and --execution local-python).")]
    if c.execution != "local-python" or not _is_python_task(c.task):
        return [not_applicable(EC063, "Mutation testing in this version supports pytest-style Python tasks under --execution local-python only.")]
    from envcert.checks.mutation import run_mutation

    report = run_mutation(c.task.root, max_mutants=c.max_mutants)
    if report["eligible"] == 0:
        return [not_applicable(EC063, f"No eligible mutants could be generated/applied: {report['notes']}")]
    rate = report["rejection_rate"]
    ev = {"tested": report["eligible"], "rejected": report["rejected"], "survived": report["survived"],
          "invalid": report["invalid"], "rejection_rate": rate, "mutants": report["mutants"][:20]}
    if rate is not None and rate < 0.5:
        return [finding(EC063, Status.WARN, f"Mutation rejection rate is {rate:.0%} ({report['rejected']}/{report['eligible']}); most incorrect variants survive, so the verifier is weak for the mutated behaviour.",
                        evidence=ev)]
    return [passed(EC063, f"Mutation rejection rate {rate:.0%} ({report['rejected']}/{report['eligible']} incorrect variants rejected). This is a strength signal, not proof of verifier correctness.",
                   evidence=ev)]


@check(EC064)
def check_shell_mutation(c: CheckContext) -> list:
    if not c.enable_mutation:
        return [not_run(EC064, "Shell-solution mutation is opt-in: re-run with --mutation and --execution docker.")]
    if c.execution != "docker":
        return [not_applicable(EC064, "Shell-solution mutation in this version runs under --execution docker only.")]
    if c.task.adapter != "harbor":
        return [not_applicable(EC064, "Shell-solution mutation supports Harbor tasks with solution/solve.sh.")]
    import re
    import shutil
    import tempfile
    from pathlib import Path

    solve_rel = "solution/solve.sh"
    if not c.task.has(solve_rel):
        return [not_applicable(EC064, "No solution/solve.sh to mutate.")]
    original = c.task.text(solve_rel) or ""
    mutants: list[tuple[str, str]] = []
    for m in re.finditer(r"'([^']{3,})'|\"([^\"]{3,})\"", original):
        val = m.group(1) or m.group(2)
        mutants.append((f"string literal {val[:30]!r} mutated", original.replace(val, val + "-MUTATED", 1)))
        if len(mutants) >= 3:
            break
    if not mutants:
        for m in re.finditer(r"\b(\d+)\b", original):
            mutants.append((f"number {m.group(1)} incremented", original[:m.start(1)] + str(int(m.group(1)) + 1) + original[m.end(1):]))
            if len(mutants) >= 2:
                break
    if not mutants:
        return [not_applicable(EC064, "solution/solve.sh contains no string/number literals to mutate.")]
    runner = DockerRunner()
    if not runner.info().available:
        return [finding(EC064, Status.ERROR, f"Docker unavailable for shell mutation: {runner.info().reason}", severity=Severity.INFO, evidence={"runner": "docker"})]
    gold = runner.run_harbor_task(c.task.root, variant="gold")
    if gold.reward is not None and gold.reward < 1.0:
        return [not_applicable(EC064, f"Gold run does not pass (reward={gold.reward}); mutation would be meaningless.")]
    results = []
    rejected = 0
    for desc, mutated in mutants[: c.max_mutants]:
        with tempfile.TemporaryDirectory(prefix="envcert-shellmut-") as td:
            dest = Path(td) / "task"
            shutil.copytree(c.task.root, dest, ignore=shutil.ignore_patterns(".git"))
            (dest / solve_rel).write_text(mutated, encoding="utf-8")
            r = runner.run_harbor_task(dest, variant="gold")
        survived = r.reward is not None and r.reward >= 1.0
        results.append({"change": desc, "reward": r.reward, "outcome": "survived" if survived else "rejected"})
        rejected += 0 if survived else 1
    rate = rejected / len(results) if results else None
    if rate is not None and rate < 0.5:
        return [finding(EC064, Status.WARN, f"Shell-solution mutation rejection rate is {rate:.0%} ({rejected}/{len(results)}); mutated (wrong) solutions still pass.", evidence={"mutants": results, "rejection_rate": rate})]
    return [passed(EC064, f"Shell-solution mutation rejection rate {rate:.0%} ({rejected}/{len(results)}). A strength signal, not proof of verifier correctness.", evidence={"mutants": results, "rejection_rate": rate})]
