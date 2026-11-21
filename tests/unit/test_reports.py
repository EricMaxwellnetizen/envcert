import json

from envcert.cli.main import validate_report
from envcert.core.config import load_settings
from envcert.core.engine import run_checks
from envcert.reports.sarif import to_sarif
from envcert.reports.text import to_text


def test_report_validates_against_schema(basic_task):
    report = run_checks(basic_task, load_settings(None, None, None))
    assert validate_report(report) == []


def test_report_distinguishes_not_run(basic_task):
    report = run_checks(basic_task, load_settings(None, None, None))
    dyn = [f for f in report["findings"] if f["check_id"] == "EC060"][0]
    assert dyn["status"] == "NOT_RUN"
    assert report["checks_executed"]


def test_sarif_structure(basic_task):
    report = run_checks(basic_task, load_settings(None, None, None))
    sarif = to_sarif(report)
    assert sarif["version"] == "2.1.0"
    run = sarif["runs"][0]
    assert run["tool"]["driver"]["name"] == "EnvCert"
    assert len(run["tool"]["driver"]["rules"]) >= 20
    json.dumps(sarif)  # serialisable


def test_sarif_contains_failures(task_factory):
    files = {
        "task.toml": '[task]\nname = "x/y"\n',
        "instruction.md": "# T\n\nDo something meaningful and verifiable here.\n",
        "environment/Dockerfile": "FROM python:latest\n",
    }
    report = run_checks(task_factory(files), load_settings(None, None, None))
    sarif = to_sarif(report)
    ids = {r["ruleId"] for r in sarif["runs"][0]["results"]}
    assert "EC050" in ids


def test_text_report(basic_task):
    report = run_checks(basic_task, load_settings(None, None, None))
    text = to_text(report)
    assert "EC001" in text and "Policy:" in text


def test_validate_report_rejects_garbage():
    assert validate_report({"foo": 1}) != []


def test_bundle_digest_changes_with_content(basic_task):
    r1 = run_checks(basic_task, load_settings(None, None, None))
    (basic_task / "instruction.md").write_text("# Changed\n\nDifferent instruction content here.\n", encoding="utf-8")
    r2 = run_checks(basic_task, load_settings(None, None, None))
    assert r1["environment"]["bundle_digest_sha256"] != r2["environment"]["bundle_digest_sha256"]
