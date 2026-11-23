import json
import pathlib

from envicert.cli.main import main
from envicert.core.config import load_settings
from envicert.core.engine import run_checks
from envicert.core.rollup import find_task_folders, run_dataset_rollup
from envicert.reports.sarif import to_sarif

ROOT = pathlib.Path(__file__).resolve().parents[2]
EXAMPLES = ROOT / "examples"


def by_id(report):
    out = {}
    for f in report["findings"]:
        out.setdefault(f["check_id"], []).append(f)
    return out


def test_nemo_probe_check():
    s = load_settings(None, None, {"execution": "local-python"})
    report = run_checks(EXAMPLES / "nemo-gym-dataset", s)
    assert by_id(report)["EC065"][0]["status"] == "PASS"


def test_nemo_probe_detects_weak_verifier(task_factory):
    task = task_factory({
        "verifier.py": "def verify(response=None, task_data=None):\n    return 1.0\n",
        "rows.jsonl": '{"responses_create_params": {"input": "q1"}, "expected_answer": "111"}\n'
                      '{"responses_create_params": {"input": "q2"}, "expected_answer": "222"}\n',
    })
    s = load_settings(None, None, {"execution": "local-python"})
    report = run_checks(task, s, adapter_name="nemo-gym")
    assert by_id(report)["EC065"][0]["status"] == "WARN"


def test_inspect_scorer_strength():
    report = run_checks(EXAMPLES / "inspect-eval", load_settings(None, None, None))
    assert by_id(report)["EC055"][0]["status"] == "PASS"  # match() is not in the weakest class


def test_inspect_includes_scorer_warns(task_factory):
    task = task_factory({
        "eval.py": "from inspect_ai import Task, task\nfrom inspect_ai.scorer import includes\nfrom inspect_ai.solver import generate\n\n@task\ndef e():\n    return Task(dataset=[], solver=generate(), scorer=includes())\n",
    })
    report = run_checks(task, load_settings(None, None, None))
    assert report["environment"]["adapter"] == "inspect"
    assert by_id(report)["EC055"][0]["status"] == "WARN"


def test_dataset_rollup():
    folders = find_task_folders(EXAMPLES / "dataset-rollup")
    assert len(folders) == 2
    rollup = run_dataset_rollup(EXAMPLES / "dataset-rollup", load_settings(None, None, None))
    assert rollup["kind"] == "envicert-dataset-rollup"
    assert rollup["summary"]["tasks"] == 2
    assert rollup["summary"]["policy_passed_tasks"] == 1
    assert rollup["summary"]["overall_policy_passed"] is False
    assert len(rollup["reports"]) == 2


def test_dataset_rollup_cli(tmp_path, capsys):
    out = tmp_path / "rollup.json"
    rc = main(["check", str(EXAMPLES / "dataset-rollup"), "--dataset", "--format", "json", "--output", str(out), "--quiet"])
    assert rc == 1
    data = json.loads(out.read_text(encoding="utf-8"))
    assert data["summary"]["tasks"] == 2
    capsys.readouterr()


def test_baseline_suppresses_policy_and_sarif(tmp_path, basic_task):
    from envicert.core.engine import run_checks as rc2

    vuln = rc2(EXAMPLES / "intentionally-vulnerable-environment", load_settings(None, None, None))
    baseline = tmp_path / "baseline.json"
    baseline.write_text(json.dumps(vuln), encoding="utf-8")
    s = load_settings(None, None, {"baseline": str(baseline)})
    report2 = rc2(EXAMPLES / "intentionally-vulnerable-environment", s)
    assert report2["policy"]["passed"] is True
    assert report2["summary"]["baseline_suppressed"] >= 5
    sarif = to_sarif(report2)
    suppressed = [r for r in sarif["runs"][0]["results"] if r.get("suppressions")]
    assert suppressed


def test_diff_command(tmp_path, capsys):
    old = tmp_path / "old.json"
    new = tmp_path / "new.json"
    for path, passed in ((old, True), (new, False)):
        path.write_text(json.dumps({
            "environment": {"task_name": "t", "bundle_digest_sha256": "x" * 64},
            "policy": {"passed": passed},
            "summary": {},
            "findings": [] if passed else [{"check_id": "EC011", "path": "Dockerfile", "line": 1,
                                             "status": "FAIL", "severity": "CRITICAL", "title": "leak"}],
        }), encoding="utf-8")
    assert main(["diff", str(old), str(new)]) == 0
    out = capsys.readouterr().out
    assert "new findings: 1" in out
    assert main(["diff", str(old), str(new), "--strict"]) == 1
    capsys.readouterr()
    assert main(["diff", str(old), str(new), "--format", "json"]) == 0
    assert json.loads(capsys.readouterr().out)["new_critical_or_high"] == 1
