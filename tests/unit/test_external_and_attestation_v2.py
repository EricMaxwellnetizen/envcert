import json

import envcert.checks.external_checks as ext
from envcert.attestations.intoto import build_statement, cosign_attest_image
from envcert.checks.base import CheckContext
from envcert.cli.main import main
from envcert.core.config import load_settings
from envcert.core.engine import load_task, run_checks


def _ctx(task_path, external=True):
    task = load_task(task_path)
    return CheckContext(task=task, external_tools=external)


def test_hadolint_mapping(monkeypatch, basic_task):
    monkeypatch.setattr(ext.shutil, "which", lambda name: f"/fake/{name}")
    monkeypatch.setattr(ext, "_run", lambda argv, cwd: (1, json.dumps(
        [{"code": "DL3008", "message": "Pin versions", "line": 3, "level": "warning"}]), ""))
    findings = ext.check_hadolint(_ctx(basic_task))
    assert findings[0].status.value == "WARN"
    assert "DL3008" in findings[0].description

    monkeypatch.setattr(ext, "_run", lambda argv, cwd: (0, "[]", ""))
    findings = ext.check_hadolint(_ctx(basic_task))
    assert findings[0].status.value == "PASS"


def test_trivy_mapping(monkeypatch, basic_task):
    monkeypatch.setattr(ext.shutil, "which", lambda name: f"/fake/{name}")
    payload = {"Results": [{"Vulnerabilities": [
        {"VulnerabilityID": "CVE-0000-1", "Severity": "CRITICAL", "PkgName": "openssl"}]}]}
    monkeypatch.setattr(ext, "_run", lambda argv, cwd: (0, json.dumps(payload), ""))
    findings = ext.check_trivy(_ctx(basic_task))
    assert findings[0].status.value == "WARN"
    assert findings[0].severity.value == "HIGH"


def test_semgrep_requires_task_config(monkeypatch, basic_task):
    monkeypatch.setattr(ext.shutil, "which", lambda name: f"/fake/{name}")
    findings = ext.check_semgrep(_ctx(basic_task))
    assert findings[0].status.value == "NOT_APPLICABLE"


def test_external_tools_gate_off(basic_task):
    findings = ext.check_hadolint(_ctx(basic_task, external=False))
    assert findings[0].status.value == "NOT_RUN"


def test_cosign_attest_refuses_mutable_ref(tmp_path):
    pred = tmp_path / "pred.json"
    pred.write_text("{}", encoding="utf-8")
    ok, msg = cosign_attest_image(pred, "myimage:latest")
    assert not ok and "mutable" in msg


def test_verify_attestation_cli(tmp_path, basic_task, capsys):
    report = run_checks(basic_task, load_settings(None, None, None))
    att = tmp_path / "att.json"
    att.write_text(json.dumps(build_statement(report, b"{}")), encoding="utf-8")
    assert main(["verify-attestation", str(att)]) == 0
    out = capsys.readouterr().out
    assert "structure OK" in out and "no cryptographic verification" in out

    bad = tmp_path / "bad.json"
    bad.write_text(json.dumps({"_type": "x", "subject": [], "predicate": {}}), encoding="utf-8")
    assert main(["verify-attestation", str(bad)]) == 1
    capsys.readouterr()


def test_attest_with_image_requires_cosign(monkeypatch, tmp_path, basic_task, capsys):
    import envcert.cli.main as cli

    report_path = tmp_path / "r.json"
    report_path.write_text(json.dumps(run_checks(basic_task, load_settings(None, None, None))), encoding="utf-8")
    # cosign absent on most dev machines: statement still written, clear message, no crash
    if cli.cosign_available() is None:
        out = tmp_path / "a.json"
        main(["attest", str(report_path), "--output", str(out), "--image", "img@sha256:" + "a" * 64])
        assert out.is_file()
        assert "cosign not found" in capsys.readouterr().out
