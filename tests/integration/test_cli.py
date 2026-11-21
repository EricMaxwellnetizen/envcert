import json
import pathlib
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parents[2]
EXAMPLES = ROOT / "examples"


def run_cli(*args, cwd=ROOT):
    return subprocess.run([sys.executable, "-m", "envcert", *args], cwd=str(cwd),
                          capture_output=True, text=True, timeout=300)


def test_version_and_list_checks():
    r = run_cli("version")
    assert r.returncode == 0 and "0.1.0" in r.stdout
    r = run_cli("list-checks")
    assert r.returncode == 0 and "EC011" in r.stdout and "EC063" in r.stdout
    r = run_cli("explain", "EC011")
    assert r.returncode == 0 and "remediation" in r.stdout
    r = run_cli("explain", "EC999")
    assert r.returncode == 2


def test_check_safe_example_exit_0():
    r = run_cli("check", "examples/safe-environment")
    assert r.returncode == 0, r.stdout + r.stderr
    assert "Policy: PASSED" in r.stdout


def test_check_vulnerable_example_exit_1():
    r = run_cli("check", "examples/intentionally-vulnerable-environment")
    assert r.returncode == 1
    for cid in ("EC010", "EC011", "EC052"):
        assert cid in r.stdout


def test_check_missing_path_exit_2():
    r = run_cli("check", "does-not-exist")
    assert r.returncode == 2


def test_json_verify_attest_roundtrip(tmp_path):
    report = tmp_path / "report.json"
    r = run_cli("check", "examples/safe-environment", "--format", "json", "--output", str(report))
    assert r.returncode == 0
    data = json.loads(report.read_text(encoding="utf-8"))
    assert data["schema_version"] == "1.0.0"
    r = run_cli("verify", str(report), "--task", "examples/safe-environment")
    assert r.returncode == 0 and "report OK" in r.stdout
    att = tmp_path / "attestation.json"
    r = run_cli("attest", str(report), "--output", str(att))
    assert r.returncode == 0
    stmt = json.loads(att.read_text(encoding="utf-8"))
    assert stmt["predicateType"] == "https://in-toto.io/attestation/test-result/v0.1"


def test_verify_detects_tampered_task(tmp_path):
    import shutil

    task = tmp_path / "task"
    shutil.copytree(EXAMPLES / "safe-environment", task)
    report = tmp_path / "report.json"
    r = run_cli("check", str(task), "--format", "json", "--output", str(report), "--quiet")
    assert r.returncode == 0
    (task / "instruction.md").write_text("# Tampered\n\nChanged after the report was made.\n", encoding="utf-8")
    r = run_cli("verify", str(report), "--task", str(task))
    assert r.returncode == 1 and "digest mismatch" in r.stdout


def test_sarif_output(tmp_path):
    out = tmp_path / "r.sarif"
    r = run_cli("check", "examples/intentionally-vulnerable-environment", "--format", "sarif", "--output", str(out))
    assert r.returncode == 1
    sarif = json.loads(out.read_text(encoding="utf-8"))
    assert sarif["version"] == "2.1.0"
    assert sarif["runs"][0]["results"]


def test_schema_command():
    r = run_cli("schema")
    assert r.returncode == 0
    assert json.loads(r.stdout)["title"] == "EnvCert Report"


def test_init_and_config(tmp_path):
    r = run_cli("init", str(tmp_path))
    assert r.returncode == 0 and (tmp_path / "envcert.toml").is_file()
    r = run_cli("init", str(tmp_path))
    assert r.returncode == 2  # refuses to overwrite


def test_dynamic_cli_on_python_task():
    r = run_cli("check", "examples/python-task", "--execution", "local-python", "--mutation")
    assert r.returncode == 0, r.stdout[-2000:]
    assert "EC060" in r.stdout
