"""Regression tests for the 0.3.2 review fixes.

- local-python must never report a PASS when the verifier could not run
- baseline suppression must be verifiable, not self-asserted
- `verify --recheck` must detect findings that were dropped from a report
"""
import json

import pytest

from envicert.cli.main import main
from envicert.core.config import load_settings
from envicert.core.engine import run_checks
from envicert.core.report import validate_baseline_suppression

ROOT = "examples"


def _by_id(report):
    out = {}
    for f in report["findings"]:
        out.setdefault(f["check_id"], []).append(f)
    return out


def test_missing_pytest_never_produces_a_false_pass(monkeypatch):
    import envicert.runners.local_runner as local_runner

    monkeypatch.setattr(local_runner, "pytest_available", lambda: False)
    settings = load_settings(None, None, {"execution": "local-python", "mutation": True})
    report = run_checks(f"{ROOT}/python-task", settings)
    findings = _by_id(report)
    assert findings["EC060"][0]["status"] == "ERROR", findings["EC060"][0]["description"]
    assert "pytest" in findings["EC060"][0]["description"].lower()
    # the negative control and repeatability must not claim a PASS when the
    # verifier never ran
    assert findings["EC061"][0]["status"] == "ERROR"
    assert findings["EC062"][0]["status"] == "ERROR"
    assert findings["EC063"][0]["status"] == "ERROR"
    assert report["policy"]["passed"] is False


def test_runner_info_reports_missing_pytest(monkeypatch):
    import envicert.runners.local_runner as local_runner

    monkeypatch.setattr(local_runner, "pytest_available", lambda: False)
    info = local_runner.LocalPythonRunner().info()
    assert info.available is False
    assert "pytest" in info.reason.lower()


def test_mutation_execution_errors_are_not_counted_as_rejections(monkeypatch, tmp_path):
    import envicert.checks.mutation as mutation

    calls = {"n": 0}
    real = mutation.LocalPythonRunner.run_python_verifier

    def flaky(self, workdir, timeout=120):
        calls["n"] += 1
        if calls["n"] == 1:  # gold run
            return real(self, workdir, timeout=timeout)
        from envicert.runners.base import RunResult

        return RunResult(ok=False, error="runner exploded", reward=None)

    monkeypatch.setattr(mutation.LocalPythonRunner, "run_python_verifier", flaky)
    result = mutation.run_mutation(f"{ROOT}/python-task", max_mutants=3)
    assert result["errors"] >= 1
    assert result["rejected"] == 0
    assert result["rejection_rate"] is None


def test_verify_requires_the_baseline_it_relies_on(tmp_path, capsys):
    baseline = tmp_path / "baseline.json"
    baseline.write_text(json.dumps(run_checks(f"{ROOT}/intentionally-vulnerable-environment",
                                              load_settings(None, None, None))), encoding="utf-8")
    out = tmp_path / "suppressed.json"
    rc = main(["check", f"{ROOT}/intentionally-vulnerable-environment", "--baseline", str(baseline),
               "--format", "json", "--output", str(out), "--quiet"])
    assert rc == 0
    data = json.loads(out.read_text(encoding="utf-8"))
    assert data["summary"]["baseline_suppressed"] > 0

    # without the baseline the suppression cannot be checked
    assert main(["verify", str(out)]) == 2
    assert "baseline" in capsys.readouterr().err
    # with the matching baseline it verifies
    assert main(["verify", str(out), "--baseline", str(baseline)]) == 0
    capsys.readouterr()
    # a baseline that does not contain the findings is rejected
    empty = tmp_path / "empty-baseline.json"
    empty.write_text(json.dumps({"findings": []}), encoding="utf-8")
    assert main(["verify", str(out), "--baseline", str(empty)]) == 2
    assert "baseline" in capsys.readouterr().out


def test_attest_requires_the_baseline_it_relies_on(tmp_path, capsys):
    baseline = tmp_path / "baseline.json"
    baseline.write_text(json.dumps(run_checks(f"{ROOT}/intentionally-vulnerable-environment",
                                              load_settings(None, None, None))), encoding="utf-8")
    report = tmp_path / "report.json"
    rc = main(["check", f"{ROOT}/intentionally-vulnerable-environment", "--baseline", str(baseline),
               "--format", "json", "--output", str(report), "--quiet"])
    assert rc == 0
    att = tmp_path / "att.json"
    assert main(["attest", str(report), "--output", str(att)]) == 2
    assert not att.exists()
    assert "baseline" in capsys.readouterr().err
    assert main(["attest", str(report), "--output", str(att), "--baseline", str(baseline)]) == 0
    assert att.exists()
    capsys.readouterr()


def test_validate_baseline_suppression_detects_forged_flags():
    report = {"findings": [
        {"check_id": "EC011", "status": "FAIL", "severity": "CRITICAL", "path": "environment/Dockerfile",
         "line": 3, "title": "t", "description": "d", "evidence": {"x": 1}},
    ]}
    assert validate_baseline_suppression(report, {"findings": []}) == []
    forged = json.loads(json.dumps(report))
    forged["findings"][0]["baseline_suppressed"] = True
    problems = validate_baseline_suppression(forged, {"findings": []})
    assert problems and "not present in the baseline report" in problems[0]
    matching = {"findings": [report["findings"][0]]}
    assert validate_baseline_suppression(report, matching) == []


def test_verify_recheck_detects_dropped_findings(tmp_path, capsys):
    report = tmp_path / "report.json"
    assert main(["check", f"{ROOT}/intentionally-vulnerable-environment", "--format", "json",
                 "--output", str(report), "--quiet"]) == 1
    # an honest report reproduces (verify checks integrity, not the policy outcome)
    assert main(["verify", str(report), "--task", f"{ROOT}/intentionally-vulnerable-environment",
                 "--recheck"]) == 0
    out = capsys.readouterr().out
    assert "re-check OK" in out

    # a report that drops its findings does not reproduce
    data = json.loads(report.read_text(encoding="utf-8"))
    data["findings"] = []
    data["summary"]["total_findings"] = 0
    data["summary"]["by_status"] = {}
    data["summary"]["by_severity_failing"] = {}
    data["policy"]["passed"] = True
    dropped = tmp_path / "dropped.json"
    dropped.write_text(json.dumps(data), encoding="utf-8")
    assert main(["verify", str(dropped), "--task", f"{ROOT}/intentionally-vulnerable-environment",
                 "--recheck"]) == 1
    out = capsys.readouterr().out
    assert "reproduced on re-check but missing from the report" in out


def test_verify_recheck_requires_task(capsys):
    assert main(["verify", "does-not-exist.json", "--recheck"]) == 2
    capsys.readouterr()


def test_verify_fail_on_override_gates_policy(tmp_path, capsys):
    report = tmp_path / "report.json"
    assert main(["check", f"{ROOT}/safe-environment", "--format", "json", "--output", str(report),
                 "--quiet"]) == 0
    # the safe example passes under its own policy
    assert main(["verify", str(report)]) == 0
    capsys.readouterr()
    # and under a stricter consumer threshold it still passes
    assert main(["verify", str(report), "--fail-on", "critical,high,medium"]) == 0
    capsys.readouterr()

    vuln = tmp_path / "vuln.json"
    assert main(["check", f"{ROOT}/intentionally-vulnerable-environment", "--format", "json",
                 "--output", str(vuln), "--quiet"]) == 1
    assert main(["verify", str(vuln), "--fail-on", "critical,high"]) == 1
    assert "policy fails under --fail-on" in capsys.readouterr().out


@pytest.mark.parametrize("severity", ["bogus", ""])
def test_verify_fail_on_rejects_bad_input(tmp_path, severity, capsys):
    report = tmp_path / "report.json"
    assert main(["check", f"{ROOT}/safe-environment", "--format", "json", "--output", str(report),
                 "--quiet"]) == 0
    assert main(["verify", str(report), "--fail-on", severity]) == 2
    capsys.readouterr()


def _minimal_report(version, summary):
    return {
        "envicert_version": version,
        "environment": {"bundle_digest_sha256": "a" * 64, "file_count": 3},
        "execution": {"fail_on": ["CRITICAL", "HIGH"]},
        "policy": {"passed": True, "fail_on": ["CRITICAL", "HIGH"]},
        "summary": summary,
        "findings": [{"check_id": "EC001", "status": "PASS", "severity": "INFO"}],
        "checks_executed": ["EC001"],
        "checks_not_executed": [],
    }


def test_pre_030_reports_may_omit_summary_counters():
    from envicert.core.report import validate_report_consistency

    old = _minimal_report("0.2.0", {"total_findings": 1, "by_status": {"PASS": 1}})
    assert validate_report_consistency(old) == []
    modern = _minimal_report("0.3.1", {"total_findings": 1, "by_status": {"PASS": 1}})
    problems = validate_report_consistency(modern)
    assert any("summary.by_severity_failing is missing" in p for p in problems)
    assert any("summary.baseline_suppressed is missing" in p for p in problems)


def test_shell_mutation_execution_errors_are_not_rejections(monkeypatch):
    import envicert.checks.dynamic_checks as dyn
    from envicert.checks.base import CheckContext
    from envicert.core.engine import load_task
    from envicert.runners.base import RunnerInfo, RunResult

    class FakeDockerRunner:
        calls = 0

        def info(self):
            return RunnerInfo("docker", True, "fake", "fake")

        def run_harbor_task(self, task_root, timeout=600, network="none", variant="gold"):
            type(self).calls += 1
            if type(self).calls == 1:
                return RunResult(ok=True, exit_code=0, reward=1.0)
            return RunResult(ok=False, error="container exploded", reward=None)

    monkeypatch.setattr(dyn, "DockerRunner", FakeDockerRunner)
    ctx = CheckContext(task=load_task(f"{ROOT}/safe-environment"), execution="docker", enable_mutation=True)
    findings = dyn.check_shell_mutation(ctx)
    assert findings[0].status.value == "ERROR"
    assert findings[0].evidence["execution_errors"] >= 1
