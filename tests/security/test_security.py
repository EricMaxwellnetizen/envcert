import json
import pathlib

import pytest

from envicert.cli.main import main
from envicert.core.config import load_settings
from envicert.core.engine import run_checks

ROOT = pathlib.Path(__file__).resolve().parents[2]


def test_malformed_toml_is_invalid_input(task_factory, tmp_path):
    task = task_factory({"task.toml": "this is [not valid toml\n", "instruction.md": "# x\n"})
    with pytest.raises(Exception) as ei:
        run_checks(task, load_settings(None, None, None))
    assert getattr(ei.value, "exit_code", None) == 2


def test_malformed_report_verify_exit_2(tmp_path, capsys):
    bad = tmp_path / "bad.json"
    bad.write_text("{not json", encoding="utf-8")
    assert main(["verify", str(bad)]) == 2


def test_attest_refuses_invalid_report(tmp_path):
    bad = tmp_path / "bad.json"
    bad.write_text(json.dumps({"foo": 1}), encoding="utf-8")
    assert main(["attest", str(bad), "--output", str(tmp_path / "a.json")]) == 2


def test_symlink_inside_task_does_not_escape(tmp_path, task_factory):
    outside = tmp_path / "outside.txt"
    outside.write_text("SECRET-OUTSIDE", encoding="utf-8")
    task = task_factory({
        "task.toml": '[task]\nname = "x/y"\n',
        "instruction.md": "# T\n\nDo a meaningful verifiable thing here please.\n",
        "environment/Dockerfile": "FROM python:3.12\n",
        "tests/test.sh": "#!/bin/bash\necho 1 > /logs/verifier/reward.txt\n",
    })
    try:
        (task / "environment" / "link.txt").symlink_to(outside)
    except OSError:
        pytest.skip("symlink creation not permitted on this host")
    report = run_checks(task, load_settings(None, None, None))
    blob = json.dumps(report)
    assert "SECRET-OUTSIDE" not in blob  # symlink target content is never read into the report
    env_files = report["environment"]
    assert env_files["bundle_digest_sha256"]  # digest still computed (over link target string)


def test_large_file_does_not_crash(task_factory):
    big = "x" * 3_000_000
    task = task_factory({
        "task.toml": '[task]\nname = "x/y"\n',
        "instruction.md": "# T\n\nDo a meaningful verifiable thing here please.\n",
        "environment/Dockerfile": "FROM python:3.12\n",
        "environment/big.txt": big,
        "tests/test.sh": "#!/bin/bash\nif [ -f /app/x ]; then echo 1 > /logs/verifier/reward.txt; else echo 0 > /logs/verifier/reward.txt; fi\n",
        "solution/solve.sh": "#!/bin/bash\ntrue\n",
    })
    report = run_checks(task, load_settings(None, None, None))
    assert report["environment"]["file_count"] >= 5


def test_shell_metachars_in_path_are_not_executed(task_factory, tmp_path):
    # A task directory whose name contains shell metacharacters must be treated
    # as a plain path (Envicert never builds shell strings from task paths).
    task = task_factory({
        "task.toml": '[task]\nname = "x/y"\n',
        "instruction.md": "# T\n\nDo a meaningful verifiable thing here please.\n",
        "environment/Dockerfile": "FROM python:3.12\n",
        "tests/test.sh": "#!/bin/bash\necho 1 > /logs/verifier/reward.txt\n",
    })
    evil = tmp_path / "task; echo pwned"
    task.rename(evil)
    report = run_checks(evil, load_settings(None, None, None))
    assert report["environment"]["task_name"] == "x/y"
    assert not (tmp_path / "pwned").exists()
