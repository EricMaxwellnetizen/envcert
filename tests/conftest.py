import pathlib
import sys

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
EXAMPLES = ROOT / "examples"


def make_task(tmp_path, files: dict[str, str]):
    root = tmp_path / "task"
    root.mkdir()
    for rel, content in files.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content, encoding="utf-8")
    return root


@pytest.fixture
def task_factory(tmp_path):
    def _make(files: dict[str, str]):
        return make_task(tmp_path, files)

    return _make


BASIC = {
    "task.toml": 'schema_version = "1.4"\n[task]\nname = "t/t"\n[verifier]\nenvironment_mode = "separate"\n[environment]\nnetwork_mode = "no-network"\n',
    "instruction.md": "# Do a thing\n\nCreate the required output file with the correct content.\n",
    "environment/Dockerfile": "FROM python:3.12-slim@sha256:" + "a" * 64 + "\nWORKDIR /app\nUSER nobody\n",
    "tests/test.sh": "#!/bin/bash\nmkdir -p /logs/verifier\nif python3 -m pytest -q /tests/test_x.py; then echo 1 > /logs/verifier/reward.txt; else echo 0 > /logs/verifier/reward.txt; fi\n",
    "tests/test_x.py": "def test_out():\n    assert 1 + 1 == 2\n    assert 'abc'.upper() == 'ABC'\n",
    "solution/solve.sh": "#!/bin/bash\necho done > /app/out.txt\n",
}


@pytest.fixture
def basic_task(task_factory):
    return task_factory(dict(BASIC))
