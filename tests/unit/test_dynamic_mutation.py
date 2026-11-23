import pathlib

from envicert.checks.mutation import run_mutation
from envicert.core.config import load_settings
from envicert.core.engine import run_checks

EXAMPLES = pathlib.Path(__file__).resolve().parents[2] / "examples"


def test_dynamic_not_run_by_default():
    from envicert.checks.base import REGISTRY

    report = run_checks(EXAMPLES / "python-task", load_settings(None, None, None))
    dyn = {f["check_id"]: f["status"] for f in report["findings"] if REGISTRY[f["check_id"]][0].dynamic}
    assert set(dyn.values()) == {"NOT_RUN"}


def test_local_python_gold_negative_repeat():
    s = load_settings(None, None, {"execution": "local-python", "repetitions": 2})
    report = run_checks(EXAMPLES / "python-task", s)
    by = {f["check_id"]: f for f in report["findings"]}
    assert by["EC060"]["status"] == "PASS"
    assert by["EC061"]["status"] == "PASS"
    assert by["EC062"]["status"] == "PASS"
    assert report["execution"]["runner"]["isolation"].startswith("none")


def test_mutation_rejects_mutants():
    result = run_mutation(EXAMPLES / "python-task", max_mutants=8)
    assert result["eligible"] >= 3
    assert result["rejection_rate"] is not None and result["rejection_rate"] >= 0.5


def test_mutation_requires_gold_pass(tmp_path, task_factory):
    files = {
        "task.toml": '[task]\nname = "x/y"\n',
        "instruction.md": "# T\n\nDo a meaningful verifiable thing here please.\n",
        "environment/Dockerfile": "FROM python:3.12\n",
        "solution/calc.py": "def add(a, b):\n    return a - b\n",
        "tests/test_calc.py": "from calc import add\ndef test_add():\n    assert add(2, 3) == 5\n",
        "tests/test.sh": "#!/bin/bash\necho 0 > /logs/verifier/reward.txt\n",
    }
    result = run_mutation(task_factory(files))
    assert result["eligible"] == 0
    assert "gold" in result["notes"]


def test_local_python_not_applicable_for_shell_task(basic_task):
    s = load_settings(None, None, {"execution": "local-python"})
    report = run_checks(basic_task, s)
    by = {f["check_id"]: f for f in report["findings"]}
    assert by["EC060"]["status"] == "NOT_APPLICABLE"
