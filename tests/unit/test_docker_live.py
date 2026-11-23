"""Live Docker coverage (skipped when no daemon is available).

The restricted runner, gold/no-op/repeatability checks and the EC066
cheat battery are exercised against a real build of the safe example.
A second task whose verifier trusts a pre-existing reward file must be
proven exploitable by the forge scenario.
"""
import pathlib
import shutil

import pytest

from envcert.core.config import load_settings
from envcert.core.engine import run_checks
from envcert.runners.docker_runner import DockerRunner

EXAMPLES = pathlib.Path(__file__).resolve().parents[2] / "examples"

pytestmark = pytest.mark.skipif(
    not DockerRunner().info().available, reason="docker daemon not available")


def _statuses(report):
    return {f["check_id"]: f["status"] for f in report["findings"]}


def test_docker_gold_noop_and_cheat_battery_on_safe_example():
    settings = load_settings(None, None, {"execution": "docker"})
    report = run_checks(EXAMPLES / "safe-environment", settings)
    statuses = _statuses(report)
    assert statuses["EC060"] == "PASS"
    assert statuses["EC061"] == "PASS"
    assert statuses["EC066"] == "PASS"


def test_docker_prebuilt_image_task(tmp_path):
    # A Harbor task declaring [environment] docker_image (no Dockerfile)
    # executes gold/no-op/cheat-battery against the pulled image.
    task = tmp_path / "prebuilt-task"
    (task / "tests").mkdir(parents=True)
    (task / "solution").mkdir()
    (task / "task.toml").write_text(
        'schema_version = "1.4"\n[task]\nname = "t/prebuilt"\n'
        '[verifier]\nenvironment_mode = "separate"\n'
        '[environment]\ndocker_image = "python:3.12-slim@sha256:5e2bdb1b0d542d5039cffb8181c65930093949194a65c365dfb1b0fe13a4fa5b"\nnetwork_mode = "no-network"\n',
        encoding="utf-8")
    (task / "instruction.md").write_text("# Write the greeting\n\nCreate /app/hello.txt containing exactly `hello envcert`.\n", encoding="utf-8")
    (task / "solution" / "solve.sh").write_text("#!/bin/bash\nmkdir -p /app\nprintf 'hello envcert\\n' > /app/hello.txt\n", encoding="utf-8")
    (task / "tests" / "test.sh").write_text(
        "#!/bin/bash\nmkdir -p /logs/verifier\n"
        "if grep -qx 'hello envcert' /app/hello.txt; then echo 1 > /logs/verifier/reward.txt; else echo 0 > /logs/verifier/reward.txt; fi\n",
        encoding="utf-8")
    settings = load_settings(None, None, {"execution": "docker"})
    report = run_checks(task, settings)
    statuses = _statuses(report)
    assert statuses["EC060"] == "PASS"
    assert statuses["EC061"] == "PASS"
    assert statuses["EC066"] == "PASS"


def test_docker_cheat_battery_proves_forgeable_verifier(tmp_path):
    task = tmp_path / "forge-task"
    shutil.copytree(EXAMPLES / "safe-environment", task)
    (task / "tests" / "test.sh").write_text(
        "#!/bin/bash\n"
        "mkdir -p /logs/verifier\n"
        "if [ ! -f /logs/verifier/reward.txt ]; then\n"
        "  if python3 -m pytest -q /tests/test_outputs.py; then echo 1 > /logs/verifier/reward.txt; else echo 0 > /logs/verifier/reward.txt; fi\n"
        "fi\n",
        encoding="utf-8")
    settings = load_settings(None, None, {"execution": "docker", "enable": ["EC060", "EC066"]})
    report = run_checks(task, settings)
    statuses = _statuses(report)
    assert statuses["EC060"] == "PASS"
    assert statuses["EC066"] == "FAIL"
    evidence = next(f for f in report["findings"] if f["check_id"] == "EC066")["evidence"]
    outcomes = {s["scenario"]: s["outcome"] for s in evidence["scenarios"]}
    assert outcomes["cheat-reward-forge"].startswith("ACCEPTED")
    assert outcomes["cheat-test-tamper"] == "rejected"
