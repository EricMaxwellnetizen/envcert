"""Regression tests for the 0.3.1 integrity/UX hardening fixes."""
import json
import os
import shutil
import subprocess
import sys

import pytest

from envicert.cli.main import main
from envicert.core.config import Settings, load_settings
from envicert.core.digests import bundle_digest
from envicert.core.engine import resolve_image_digest, run_checks
from envicert.core.errors import ConfigError
from envicert.core.report import validate_report_consistency
from envicert.runners.external_runner import split_runner_command
from tests.conftest import BASIC, make_task

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
VULN = os.path.join(ROOT, "examples", "intentionally-vulnerable-environment")


def _write_report(tmp_path, report):
    path = tmp_path / "report.json"
    path.write_text(json.dumps(report), encoding="utf-8")
    return path


def test_consistency_recomputes_policy_and_summary(basic_task):
    report = run_checks(basic_task, load_settings(None, None, None))
    assert validate_report_consistency(report) == []

    forged_policy = json.loads(json.dumps(report))
    forged_policy["policy"]["passed"] = not forged_policy["policy"]["passed"]
    problems = validate_report_consistency(forged_policy)
    assert any("policy.passed" in p for p in problems)

    forged_summary = json.loads(json.dumps(report))
    forged_summary["summary"]["total_findings"] += 1
    problems = validate_report_consistency(forged_summary)
    assert any("summary.total_findings" in p for p in problems)


def test_verify_rejects_forged_policy_with_exit_2(tmp_path, basic_task, capsys):
    report = run_checks(basic_task, load_settings(None, None, None))
    report["findings"][0]["status"] = "FAIL"
    report["findings"][0]["severity"] = "CRITICAL"
    path = _write_report(tmp_path, report)
    assert main(["verify", str(path)]) == 2
    out = capsys.readouterr().out
    assert "contradicts the findings" in out


def test_verify_rejects_forged_summary_with_exit_2(tmp_path, basic_task, capsys):
    report = run_checks(basic_task, load_settings(None, None, None))
    report["summary"]["by_status"] = {}
    path = _write_report(tmp_path, report)
    assert main(["verify", str(path)]) == 2
    assert "summary.by_status" in capsys.readouterr().out


def test_attest_refuses_inconsistent_report(tmp_path, basic_task, capsys):
    report = run_checks(basic_task, load_settings(None, None, None))
    report["policy"]["passed"] = not report["policy"]["passed"]
    path = _write_report(tmp_path, report)
    out = tmp_path / "att.json"
    assert main(["attest", str(path), "--output", str(out)]) == 2
    assert not out.exists()
    assert "refusing to attest" in capsys.readouterr().err


def test_attest_refuses_image_digest_mismatch(tmp_path, basic_task, capsys):
    report = run_checks(basic_task, load_settings(None, None, None))
    report["environment"]["image_digest"] = "sha256:" + "a" * 64
    path = _write_report(tmp_path, report)
    out = tmp_path / "att.json"
    assert main(["attest", str(path), "--output", str(out),
                 "--image", "img@sha256:" + "b" * 64]) == 2
    assert not out.exists()
    assert "does not match the report" in capsys.readouterr().err


def test_unknown_check_ids_are_rejected(tmp_path, basic_task, capsys):
    with pytest.raises(ConfigError, match="unknown check ID"):
        run_checks(basic_task, load_settings(None, None, {"enable": ["EC999"]}))
    with pytest.raises(ConfigError, match="unknown check ID"):
        run_checks(basic_task, load_settings(None, None, {"disable": ["EC999"]}))
    assert main(["check", str(basic_task), "--enable", "EC999"]) == 2
    assert "unknown check ID" in capsys.readouterr().err


def test_empty_check_selection_is_rejected(tmp_path, basic_task):
    config = tmp_path / "envicert.toml"
    config.write_text("[checks]\nenabled = []\n", encoding="utf-8")
    with pytest.raises(ConfigError, match="must not be empty"):
        load_settings(config, None, None)
    with pytest.raises(ConfigError, match="no checks selected"):
        run_checks(basic_task, Settings(enabled=[]))


def test_dynamic_enabled_requires_explicit_execution(tmp_path):
    config = tmp_path / "envicert.toml"
    config.write_text("[checks.dynamic]\nenabled = true\n", encoding="utf-8")
    with pytest.raises(ConfigError, match="explicit execution mode"):
        load_settings(config, None, None)
    config.write_text(
        "[checks.dynamic]\nenabled = true\n\n[execution]\nmode = \"local-python\"\n",
        encoding="utf-8",
    )
    settings = load_settings(config, None, None)
    assert settings.execution == "local-python"


def test_windows_runner_command_splitting():
    parts = split_runner_command(r'"C:\Program Files\Python\python.exe" "C:\tasks\provider.py"', windows=True)
    assert parts == [r"C:\Program Files\Python\python.exe", r"C:\tasks\provider.py"]
    assert split_runner_command(r"C:\tools\provider.exe --flag", windows=True) == [
        r"C:\tools\provider.exe", "--flag",
    ]
    assert split_runner_command("python -m provider", windows=False) == ["python", "-m", "provider"]


@pytest.mark.skipif(os.name != "nt", reason="Windows path regression")
def test_external_runner_accepts_unquoted_windows_paths(tmp_path, basic_task):
    if " " in sys.executable or " " in str(tmp_path):
        pytest.skip("unquoted command lines cannot represent paths containing spaces")
    fake = tmp_path / "fake_runner.py"
    fake.write_text(
        "import argparse, json\n"
        "p = argparse.ArgumentParser(); p.add_argument('--task'); p.add_argument('--variant'); p.add_argument('--timeout')\n"
        "a = p.parse_args()\n"
        "print(json.dumps({'reward': 1.0 if a.variant == 'gold' else 0.0, 'exit_code': 0}))\n",
        encoding="utf-8",
    )
    settings = load_settings(None, None, {
        "execution": "external", "runner_command": f"{sys.executable} {fake}",
    })
    report = run_checks(basic_task, settings)
    assert report["findings"]
    ec060 = next(f for f in report["findings"] if f["check_id"] == "EC060")
    assert ec060["status"] == "PASS"


class _Proc:
    def __init__(self, returncode=0, stdout="", stderr=""):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


def test_image_digest_prefers_repo_digests(monkeypatch):
    monkeypatch.setattr(shutil, "which", lambda _name: "docker")
    digest = "sha256:" + "d" * 64
    calls = []

    def fake_run(cmd, **_kwargs):
        calls.append(cmd)
        if "{{json .RepoDigests}}" in cmd:
            return _Proc(stdout=json.dumps([f"registry.example/app@{digest}"]))
        return _Proc(stdout="sha256:" + "e" * 64)

    monkeypatch.setattr(subprocess, "run", fake_run)
    resolved, note = resolve_image_digest(load_settings(None, None, {"image": "registry.example/app:1.0"}))
    assert resolved == digest
    assert "RepoDigests" in note
    assert len(calls) == 1


def test_image_digest_local_id_fallback_is_labelled(monkeypatch):
    monkeypatch.setattr(shutil, "which", lambda _name: "docker")
    local_id = "sha256:" + "f" * 64

    def fake_run(cmd, **_kwargs):
        if "{{json .RepoDigests}}" in cmd:
            return _Proc(stdout="[]")
        return _Proc(stdout=local_id)

    monkeypatch.setattr(subprocess, "run", fake_run)
    resolved, note = resolve_image_digest(load_settings(None, None, {"image": "local/build:dev"}))
    assert resolved == local_id
    assert "not a registry manifest digest" in note


def test_unresolvable_image_is_an_error(monkeypatch):
    monkeypatch.setattr(shutil, "which", lambda _name: "docker")
    monkeypatch.setattr(subprocess, "run", lambda *_a, **_k: _Proc(returncode=1, stderr="no such image"))
    with pytest.raises(ConfigError, match="cannot resolve a digest"):
        resolve_image_digest(load_settings(None, None, {"image": "does-not-exist:latest"}))


def test_bundle_digest_reports_truncation(tmp_path):
    task = make_task(tmp_path, {"a.txt": "a", "b.txt": "b", "c.txt": "c"})
    warnings = []
    _digest, count = bundle_digest(task, warnings=warnings, max_files=2)
    assert count == 2
    assert any("more than 2 files" in w for w in warnings)


def test_bundle_digest_reports_unreadable_files(monkeypatch, tmp_path):
    import envicert.core.digests as digests

    task = make_task(tmp_path, {"a.txt": "a"})

    def boom(_path):
        raise OSError("permission denied")

    monkeypatch.setattr(digests, "sha256_file", boom)
    warnings = []
    digests.bundle_digest(task, warnings=warnings)
    assert any("could not read" in w for w in warnings)


def test_baseline_does_not_hide_a_new_issue_at_the_same_location(tmp_path):
    base_files = dict(BASIC)
    base_files["environment/gold.txt"] = "the answer is 42\n"
    (tmp_path / "base").mkdir()
    baseline_task = make_task(tmp_path / "base", base_files)
    baseline = run_checks(baseline_task, load_settings(None, None, None))
    baseline_path = tmp_path / "baseline.json"
    baseline_path.write_text(json.dumps(baseline), encoding="utf-8")

    new_files = dict(BASIC)
    new_files["environment/answers.txt"] = "a different answer is 43\n"
    (tmp_path / "new").mkdir()
    new_task = make_task(tmp_path / "new", new_files)
    report = run_checks(new_task, load_settings(None, None, {"baseline": str(baseline_path)}))
    ec011 = [f for f in report["findings"] if f["check_id"] == "EC011"]
    assert ec011
    assert not any(f["baseline_suppressed"] for f in ec011)
    assert report["policy"]["passed"] is False
