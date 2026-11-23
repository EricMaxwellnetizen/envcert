"""Dynamic checks. Explicitly opt-in via execution mode.

- docker: build + run a Harbor task in the restricted DockerRunner.
- local-python: run pytest-style tests/ against solution/*.py in a temp copy
  (no sandbox — trusted tasks only, recorded in the report).
- none (default): every dynamic check returns NOT_RUN, never PASS.
"""
from __future__ import annotations

from envicert.checks.base import CheckContext, CheckInfo, check, finding, not_applicable, not_run, passed
from envicert.core.models import Severity, Status
from envicert.runners.docker_runner import DockerRunner
from envicert.runners.local_runner import LocalPythonRunner

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
EC065 = CheckInfo("EC065", "NeMo verifier probing with mutated inputs (gold/wrong/swapped answers)", "dynamic", Severity.HIGH,
                  "Feeding a NeMo Gym verifier its rows' expected answers should score 1; mutated and row-swapped answers should score < 1.",
                  "Fix the verifier so correct answers pass and incorrect/swapped answers fail for every probed row.",
                  "Probes up to 10 rows. Local mode imports verify() in a subprocess (trusted code, no sandbox); HTTP mode POSTs to an operator-supplied Resources-Server endpoint (--nemo-endpoint) and reads reward/score.", dynamic=True)
EC064 = CheckInfo("EC064", "Shell-solution mutation: verifier rejects mutated reference solutions (docker)", "mutation", Severity.MEDIUM,
                  "Mutating literal outputs in solution/solve.sh should make the verifier reject the run; surviving mutants signal a weak verifier.",
                  "Strengthen verifier assertions on the mutated outputs.",
                  "Docker execution only; only literal-bearing shell solutions can be mutated. Mutant validity is heuristic.", dynamic=True)
EC063 = CheckInfo("EC063", "Mutation testing: verifier rejects mutated (incorrect) solutions", "mutation", Severity.MEDIUM,
                  "Mutated variants of a correct solution should be rejected; the rejection rate is a verifier-strength signal.",
                  "Add assertions covering the mutated behaviour; do not treat the rate as proof of correctness.",
                  "Equivalent/invalid mutants and the small mutant set limit this signal. Python/pytest and JS/TS (node) tasks under --execution local-python.", dynamic=True)


def _is_python_task(ctx) -> bool:
    has_py_solution = any(f.startswith("solution/") and f.endswith(".py") for f in ctx.files)
    has_py_tests = any(f.startswith("tests/") and f.endswith(".py") and "test" in f.rsplit("/", 1)[-1] for f in ctx.files)
    return has_py_solution and has_py_tests


def _is_js_task(ctx) -> bool:
    js = (".js", ".mjs", ".cjs", ".ts", ".mts", ".cts")
    has_solution = any(f.startswith("solution/") and f.endswith(js) for f in ctx.files)
    has_tests = any(f.startswith("tests/") and f.endswith(js) for f in ctx.files)
    return has_solution and has_tests


def _run_variant(c: CheckContext, variant: str):
    ctx = c.task
    if c.execution == "docker":
        env_cfg = ctx.config.get("environment") or {}
        declared_image = env_cfg.get("docker_image") if isinstance(env_cfg, dict) else None
        compose = ctx.compose_path if ctx.compose_path is not None else None
        result = DockerRunner().run_harbor_task(
            ctx.root, variant=variant,
            image=str(declared_image) if declared_image and not ctx.dockerfile_path and compose is None else None,
            compose=str(compose) if compose is not None else None)
        if result.image_digest:
            c.shared["image_digest"] = result.image_digest
        if result.image_digest_note:
            c.shared["image_digest_note"] = result.image_digest_note
        return result, None
    if c.execution == "external":
        from envicert.runners.external_runner import ExternalRunner

        result = ExternalRunner(c.runner_command).run_harbor_task(ctx.root, variant=variant)
        if result.image_digest:
            c.shared["image_digest"] = result.image_digest
        if result.image_digest_note:
            c.shared["image_digest_note"] = result.image_digest_note
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
    c.shared["gold_ran"] = True
    c.shared["gold_reward"] = result.reward
    c.shared["gold_ok"] = bool(result.ok)
    if result.error and result.reward is None:
        c.shared["gold_execution_error"] = result.error
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
    gold_error = c.shared.get("gold_execution_error")
    if gold_error:
        # The gold run never executed: a rejected no-op proves nothing about
        # verifier strength, so this must not be reported as a PASS.
        return [finding(EC061, Status.ERROR,
                        f"Negative control could not be evaluated: the gold run failed to execute ({gold_error}). "
                        "A rejected no-op is not evidence when the verifier never ran.",
                        severity=Severity.INFO, evidence={"gold_error": gold_error})]
    if not c.shared.get("gold_ran"):
        # Selected without EC060: a rejected no-op is only meaningful when a
        # correct solution passes, so establish the gold baseline here
        # instead of trusting that another check ran first.
        gold, gold_why = _run_variant(c, "gold")
        if gold is None:
            return [not_applicable(EC061, f"Negative control not supported here: {gold_why}.")]
        if gold.error and gold.reward is None:
            return [finding(EC061, Status.ERROR,
                            f"Negative control could not be evaluated: the gold run failed to execute ({gold.error}).",
                            severity=Severity.INFO, evidence={"gold_error": gold.error})]
        gold_passed = (gold.reward >= 1.0) if gold.reward is not None else bool(gold.ok)
        if not gold_passed:
            return [not_applicable(EC061, f"Negative control inconclusive: the gold solution does not pass (reward={gold.reward}), so a rejected no-op proves nothing. Fix EC060 first.")]
        c.shared["gold_ran"] = True
        c.shared["gold_reward"] = gold.reward
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
        if any(o["error"] and o["reward"] is None for o in outcomes):
            errors = sorted({o["error"] for o in outcomes if o["error"]})
            return [finding(EC062, Status.ERROR,
                            f"Repeatability could not be measured: the gold run failed to execute ({'; '.join(errors)}). "
                            "Consistent failures are not evidence of repeatability.",
                            severity=Severity.INFO, evidence={"runs": outcomes})]
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
    if any(o["error"] and o["reward"] is None for o in outcomes):
        errors = sorted({o["error"] for o in outcomes if o["error"]})
        return [finding(EC062, Status.ERROR,
                        f"Repeatability could not be measured: the gold run failed to execute ({'; '.join(errors)}). "
                        "Consistent failures are not evidence of repeatability.",
                        severity=Severity.INFO, evidence={"runs": outcomes})]
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
    if c.execution != "local-python":
        return [not_applicable(EC063, "Mutation testing runs under --execution local-python (trusted tasks, no sandbox) for Python/pytest or JS/TS node tasks.")]
    if _is_python_task(c.task):
        from envicert.checks.mutation import run_mutation

        report = run_mutation(c.task.root, max_mutants=c.max_mutants)
    elif _is_js_task(c.task):
        from envicert.checks.mutation_js import run_js_mutation

        report = run_js_mutation(c.task.root, max_mutants=c.max_mutants)
    else:
        return [not_applicable(EC063, "Mutation testing needs solution/*.py + tests/test_*.py (pytest) or solution/*.js|.ts + tests/*.js|.ts (node).")]
    if report.get("error"):
        return [finding(EC063, Status.ERROR, f"Mutation testing could not run: {report['error']}",
                        severity=Severity.INFO, evidence={"error": report["error"], "runner": c.execution})]
    if report["eligible"] == 0:
        return [not_applicable(EC063, f"No eligible mutants could be generated/applied: {report['notes']}")]
    rate = report["rejection_rate"]
    ev = {"tested": report["eligible"], "rejected": report["rejected"], "survived": report["survived"],
          "invalid": report["invalid"], "uncovered_inconclusive": report.get("uncovered", 0),
          "execution_errors": report.get("errors", 0),
          "coverage_used": report.get("coverage_used", False),
          "language": report.get("language", "python"),
          "rejection_rate": rate, "mutants": report["mutants"][:20]}
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
    if gold.error and gold.reward is None:
        return [finding(EC064, Status.ERROR, f"Shell mutation could not run: the gold execution failed ({gold.error})",
                        severity=Severity.INFO, evidence={"error": gold.error, "runner": "docker"})]
    if gold.reward is not None and gold.reward < 1.0:
        return [not_applicable(EC064, f"Gold run does not pass (reward={gold.reward}); mutation would be meaningless.")]
    results: list[dict] = []
    rejected = 0
    errors = 0
    for desc, mutated in mutants[: c.max_mutants]:
        with tempfile.TemporaryDirectory(prefix="envicert-shellmut-") as td:
            dest = Path(td) / "task"
            shutil.copytree(c.task.root, dest, ignore=shutil.ignore_patterns(".git"))
            (dest / solve_rel).write_text(mutated, encoding="utf-8")
            r = runner.run_harbor_task(dest, variant="gold")
        if r.error and r.reward is None:
            # The mutant could not be executed: that is not evidence that the
            # verifier rejected it.
            errors += 1
            results.append({"change": desc, "reward": None, "outcome": "execution-error", "error": r.error})
            continue
        survived = r.reward is not None and r.reward >= 1.0
        results.append({"change": desc, "reward": r.reward, "outcome": "survived" if survived else "rejected"})
        rejected += 0 if survived else 1
    executed = [r for r in results if r["outcome"] != "execution-error"]
    if not executed:
        return [finding(EC064, Status.ERROR,
                        f"Shell mutation mutants could not be executed ({errors} execution error(s)); no rejection evidence was obtained.",
                        severity=Severity.INFO, evidence={"mutants": results, "execution_errors": errors, "runner": "docker"})]
    rate = rejected / len(executed)
    ev = {"mutants": results, "rejection_rate": rate, "execution_errors": errors}
    if rate < 0.5:
        return [finding(EC064, Status.WARN, f"Shell-solution mutation rejection rate is {rate:.0%} ({rejected}/{len(executed)}); mutated (wrong) solutions still pass.", evidence=ev)]
    return [passed(EC064, f"Shell-solution mutation rejection rate {rate:.0%} ({rejected}/{len(executed)}). A strength signal, not proof of verifier correctness.", evidence=ev)]


@check(EC065)
def check_nemo_probe(c: CheckContext) -> list:
    ctx = c.task
    if c.execution == "none" and not c.nemo_endpoint:
        return [not_run(EC065, "Dynamic probing is opt-in: re-run with --execution local-python (trusted verifier code only) or supply --nemo-endpoint for an HTTP Resources Server.")]
    if ctx.adapter != "nemo-gym":
        return [not_applicable(EC065, "Verifier probing applies to NeMo Gym datasets with a shared verify() or an HTTP Resources Server.")]
    if not ctx.dataset_files:
        return [not_applicable(EC065, "Probing needs JSONL rows with expected answers.")]
    if c.nemo_endpoint:
        from envicert.runners.nemo_probe import probe_http_verifier

        result = probe_http_verifier(c.nemo_endpoint, ctx.root, ctx.dataset_files[0],
                                     headers=dict(c.nemo_headers or {}))
        runner = "http resources server"
        endpoint = c.nemo_endpoint.split("?", 1)[0]
    else:
        if c.execution != "local-python":
            return [not_applicable(EC065, "NeMo probing needs --execution local-python for a local verify() or --nemo-endpoint for an HTTP Resources Server.")]
        if not ctx.verifier_paths:
            return [not_applicable(EC065, "No verifier.py found; use --nemo-endpoint to probe an HTTP Resources Server.")]
        from envicert.runners.nemo_probe import probe_verifier

        result = probe_verifier(ctx.root, ctx.verifier_paths[0], ctx.dataset_files[0])
        runner = "local-python (no sandbox)"
        endpoint = ""
    if result.error and result.reward is None:
        # probe errors that still scored rows surface via stdout payload; treat hard errors as ERROR
        return [finding(EC065, Status.ERROR, f"Verifier probing could not run: {result.error}",
                        severity=Severity.INFO, evidence={"error": result.error, "runner": runner})]
    import json as _json

    try:
        payload = _json.loads(result.stdout) if result.stdout else {}
    except ValueError:
        payload = {}
    rows = payload.get("results", [])
    scored = [r for r in rows if r.get("gold") is not None]
    ev = {"rows_probed": len(scored), "results": rows[:10], "runner": runner}
    if endpoint:
        ev["endpoint"] = endpoint
    if not scored:
        return [finding(EC065, Status.ERROR, "Verifier probing scored no rows (missing expected answers or the verifier raised).",
                        severity=Severity.INFO, evidence=ev)]
    gold_bad = [r for r in scored if r["gold"] < 1.0]
    mutant_survived = [r for r in scored if r.get("mutant") is not None and r["mutant"] >= 1.0]
    swap_survived = [r for r in scored if r.get("swap") is not None and r["swap"] >= 1.0]
    inconclusive = [r for r in scored if r.get("mutant") is None
                    or (r.get("swap") is None and not r.get("swap_na"))]
    if gold_bad:
        hint = (" Confirm the endpoint accepts {\"response\", \"task_data\"} and returns reward/score."
                if runner == "http resources server" else "")
        return [finding(EC065, Status.FAIL, f"The verifier rejects its own expected answer on {len(gold_bad)}/{len(scored)} probed rows; the verifier or dataset is broken.{hint}", evidence=ev)]
    if mutant_survived or swap_survived:
        return [finding(EC065, Status.WARN, f"The verifier accepts mutated answers on {len(mutant_survived)} row(s) and swapped answers on {len(swap_survived)} row(s); it is too weak.", severity=Severity.HIGH, evidence=ev)]
    if inconclusive:
        return [finding(EC065, Status.WARN,
                        f"The verifier accepted expected answers but {len(inconclusive)}/{len(scored)} mutant or swapped probes were inconclusive (transport error or no score); re-run to complete the weak-verifier check.",
                        severity=Severity.MEDIUM, evidence=ev)]
    return [passed(EC065, f"The verifier accepts expected answers and rejects mutated/swapped answers on all {len(scored)} probed rows ({runner}).", evidence=ev)]
