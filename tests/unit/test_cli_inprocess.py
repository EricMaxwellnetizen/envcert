import json
import pathlib

from envcert.cli.main import main

ROOT = pathlib.Path(__file__).resolve().parents[2]


def test_main_check_text(capsys):
    assert main(["check", str(ROOT / "examples" / "safe-environment")]) == 0
    assert "Policy: PASSED" in capsys.readouterr().out


def test_main_check_json_output(tmp_path, capsys):
    out = tmp_path / "r.json"
    rc = main(["check", str(ROOT / "examples" / "intentionally-vulnerable-environment"),
               "--format", "json", "--output", str(out)])
    assert rc == 1
    data = json.loads(out.read_text(encoding="utf-8"))
    assert data["policy"]["passed"] is False
    capsys.readouterr()


def test_main_verify_and_attest(tmp_path, capsys):
    out = tmp_path / "r.json"
    assert main(["check", str(ROOT / "examples" / "safe-environment"), "--format", "json",
                 "--output", str(out), "--quiet"]) == 0
    assert main(["verify", str(out)]) == 0
    att = tmp_path / "a.json"
    assert main(["attest", str(out), "--output", str(att), "--dsse"]) == 0
    env = json.loads(att.read_text(encoding="utf-8"))
    assert env["signatures"] == []
    text = capsys.readouterr().out
    assert "UNSIGNED" in text or "unsigned" in text


def test_main_list_explain_schema(capsys):
    assert main(["list-checks", "-v"]) == 0
    out = capsys.readouterr().out
    assert "EC001" in out and "remediation" in out
    assert main(["explain", "EC060"]) == 0
    assert "EC060" in capsys.readouterr().out
    assert main(["schema"]) == 0
    assert "EnvCert Report" in capsys.readouterr().out
    assert main(["version"]) == 0
    assert "0.3.0" in capsys.readouterr().out


def test_main_no_args_is_invalid(capsys):
    assert main([]) == 2
    capsys.readouterr()


def test_main_init(tmp_path, capsys):
    assert main(["init", str(tmp_path)]) == 0
    assert (tmp_path / "envcert.toml").is_file()
    capsys.readouterr()


def test_main_attest_sign_without_cosign_reports_gracefully(tmp_path, capsys, monkeypatch):
    import envcert.cli.main as cli

    monkeypatch.setattr(cli, "cosign_available", lambda: None)
    out = tmp_path / "r.json"
    assert main(["check", str(ROOT / "examples" / "safe-environment"), "--format", "json",
                 "--output", str(out), "--quiet"]) == 0
    att = tmp_path / "a.json"
    # sign requested but cosign missing: statement still written, no crash, message explains
    rc = main(["attest", str(out), "--output", str(att), "--sign"])
    assert att.is_file()
    assert rc in (0, 3)
    capsys.readouterr()


def test_docker_runner_unavailable_is_graceful(monkeypatch):
    from envcert.runners.docker_runner import DockerRunner

    info = DockerRunner().info()
    # On hosts without a daemon this must report unavailable, never raise.
    assert isinstance(info.available, bool)
    if not info.available:
        # also with a relative path (volume mounts need a resolved absolute path)
        result = DockerRunner().run_harbor_task(pathlib.Path("examples/safe-environment"))
        assert not result.ok and result.error
