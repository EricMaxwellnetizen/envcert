"""Targeted coverage for runner/attestation internals that need no daemon,
no cosign binary and no network."""
import json
import subprocess
import sys

from envcert.attestations.intoto import build_statement, verify_statement_local
from envcert.core.config import load_settings
from envcert.runners import docker_runner
from envcert.runners.external_runner import ExternalRunner, split_runner_command
from envcert.runners.nemo_probe import probe_verifier


def _report():
    return {
        "envcert_version": "0.4.0", "schema_version": "1.0.0",
        "generated_at": "2026-01-01T00:00:00Z", "assurance_context": "test",
        "environment": {"task_name": "t/t", "bundle_digest_sha256": "a" * 64,
                        "verifier_digest_sha256": "b" * 64, "solution_digest_sha256": None,
                        "image_digest": None},
        "execution": {"profile": "harbor", "mode": "none"},
        "policy": {"passed": True, "fail_on": ["CRITICAL", "HIGH"]},
        "summary": {"total_findings": 1},
        "findings": [{"check_id": "EC001", "status": "PASS", "severity": "INFO"}],
        "limitations": [],
    }


def test_statement_local_verification_roundtrip_and_tamper():
    report = _report()
    statement = build_statement(report, json.dumps(report).encode())
    assert verify_statement_local(statement) == []
    tampered = json.loads(json.dumps(statement))
    tampered["predicate"]["result"] = "MAYBE"
    assert verify_statement_local(tampered)
    tampered2 = json.loads(json.dumps(statement))
    tampered2["subject"] = []
    assert verify_statement_local(tampered2)
    tampered3 = json.loads(json.dumps(statement))
    tampered3["subject"][0]["digest"]["sha256"] = "not-a-digest"
    assert verify_statement_local(tampered3)
    assert verify_statement_local({"predicateType": "wrong"})


def test_cosign_paths_with_fake_cosign(tmp_path, monkeypatch):
    import envcert.attestations.intoto as intoto

    monkeypatch.setattr(intoto, "cosign_available", lambda: "cosign")
    calls = []

    def fake_run(cmd, capture_output=True, text=True, timeout=120):
        calls.append(cmd)
        if "sign-blob" in cmd:
            return subprocess.CompletedProcess(cmd, 0, stdout="signed", stderr="")
        return subprocess.CompletedProcess(cmd, 0, stdout="verified", stderr="")

    monkeypatch.setattr(intoto.subprocess, "run", fake_run)
    blob = tmp_path / "att.json"
    blob.write_text("{}", encoding="utf-8")
    ok, msg = intoto.sign_with_cosign(blob)
    assert ok and "signed" in msg
    ok, msg = intoto.cosign_verify_blob(blob, tmp_path / "att.json.sig", "key.pub")
    assert ok
    report = _report()
    statement = build_statement(report, b"{}")
    envelope = intoto.dsse_envelope_unsigned(statement)
    ok, msg = intoto.sign_dsse_with_cosign(envelope)
    assert isinstance(ok, bool)

    def failing_run(cmd, capture_output=True, text=True, timeout=120):
        return subprocess.CompletedProcess(cmd, 1, stdout="", stderr="boom")

    monkeypatch.setattr(intoto.subprocess, "run", failing_run)
    ok, msg = intoto.sign_with_cosign(blob)
    assert not ok and "failed" in msg
    monkeypatch.setattr(intoto, "cosign_available", lambda: None)
    ok, msg = intoto.sign_with_cosign(blob)
    assert not ok and "not found" in msg


def test_watch_mode_runs_bounded_iterations(tmp_path, capsys):
    from envcert.cli.main import main

    rc = main(["check", "examples/safe-environment", "--watch", "--watch-interval", "1", "--watch-iterations", "2"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "watching" in out and "no change" in out


def test_parquet_without_pyarrow_is_reported(tmp_path):
    data = tmp_path / "rows.parquet"
    data.write_bytes(b"PAR1 fake parquet bytes PAR1")
    from envcert.core.engine import run_checks

    report = run_checks(data, load_settings(None, None, None), adapter_name="dataset")
    statuses = {f["check_id"]: f["status"] for f in report["findings"]}
    try:
        import pyarrow  # noqa: F401

        assert statuses["EC084"] in ("PASS", "WARN")
    except ImportError:
        # Uninspectable must be loud (WARN), never a silent PASS.
        assert statuses["EC084"] == "WARN"


def test_docker_runner_rejects_windows_containers_engine(monkeypatch):
    def fake_run(cmd, timeout):
        return subprocess.CompletedProcess(cmd, 0, stdout="windows 29.0.0\n", stderr="")

    monkeypatch.setattr(docker_runner, "_run", fake_run)
    monkeypatch.setattr(docker_runner.shutil, "which", lambda _: "docker")
    info = docker_runner.DockerRunner().info()
    assert info.available is False
    assert "Linux containers" in info.reason


def test_external_runner_with_fake_provider(tmp_path):
    provider = tmp_path / "provider.py"
    provider.write_text(
        "import json, sys\n"
        "print(json.dumps({'reward': 1.0, 'exit_code': 0}))\n",
        encoding="utf-8")
    runner = ExternalRunner(f'"{sys.executable}" "{provider}"')
    assert runner.info().available
    result = runner.run_harbor_task(tmp_path, variant="gold")
    assert result.reward == 1.0

    bad = tmp_path / "bad.py"
    bad.write_text("print('not json')\n", encoding="utf-8")
    result = ExternalRunner(f'"{sys.executable}" "{bad}"').run_harbor_task(tmp_path, variant="gold")
    assert result.error


def test_split_runner_command_platforms():
    assert split_runner_command("run.sh --x 1", windows=False) == ["run.sh", "--x", "1"]
    parts = split_runner_command(r'"C:\Program Files\tool.exe" --x', windows=True)
    assert parts[0].endswith("tool.exe")


def test_nemo_probe_scores_rows(tmp_path):
    verifier = tmp_path / "verifier.py"
    verifier.write_text(
        "def verify(response=None, task_data=None):\n"
        "    return 1.0 if response == task_data.get('expected_answer') else 0.0\n",
        encoding="utf-8")
    rows = tmp_path / "rows.jsonl"
    rows.write_text('{"prompt": "q1", "expected_answer": "a"}\n{"prompt": "q2", "expected_answer": "b"}\n', encoding="utf-8")
    result = probe_verifier(tmp_path, "verifier.py", "rows.jsonl")
    payload = json.loads(result.stdout)
    scored = [r for r in payload["results"] if r.get("gold") is not None]
    assert scored and all(r["gold"] == 1.0 for r in scored)
    assert all(r["mutant"] < 1.0 for r in scored if r.get("mutant") is not None)


def test_docker_runner_with_fake_docker(monkeypatch, tmp_path):
    (tmp_path / "environment").mkdir()
    (tmp_path / "environment" / "Dockerfile").write_text("FROM python:3.12\n", encoding="utf-8")
    calls = []

    def fake_run(cmd, timeout):
        calls.append(cmd)
        if "version" in cmd:
            return subprocess.CompletedProcess(cmd, 0, stdout="linux 29.0.0\n", stderr="")
        if "build" in cmd:
            return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")
        if "inspect" in cmd:
            return subprocess.CompletedProcess(cmd, 0, stdout="sha256:" + "c" * 64 + "\n", stderr="")
        if "run" in cmd:
            return subprocess.CompletedProcess(cmd, 0, stdout="done\n1\n", stderr="")
        return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

    monkeypatch.setattr(docker_runner, "_run", fake_run)
    monkeypatch.setattr(docker_runner.shutil, "which", lambda _: "docker")
    runner = docker_runner.DockerRunner()
    assert runner.info().available
    result = runner.run_harbor_task(tmp_path, variant="gold")
    assert result.reward == 1.0
    assert result.image_digest and result.image_digest.startswith("sha256:")
    result = runner.run_harbor_task(tmp_path, variant="cheat-reward-forge")
    assert result.reward == 1.0  # fake docker echoes 1; variant plumbing exercised
    assert len(calls) >= 8
