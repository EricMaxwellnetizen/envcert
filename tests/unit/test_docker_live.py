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
