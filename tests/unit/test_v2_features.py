import json
import pathlib
import sys

import pytest

from envicert.attestations.intoto import build_statement, verify_statement_local
from envicert.core.config import load_settings
from envicert.core.engine import resolve_image_digest, run_checks
from envicert.core.errors import ConfigError

ROOT = pathlib.Path(__file__).resolve().parents[2]
EXAMPLES = ROOT / "examples"


def by_id(report):
    out = {}
    for f in report["findings"]:
        out.setdefault(f["check_id"], []).append(f)
    return out


def test_nemo_adapter_and_checks():
    report = run_checks(EXAMPLES / "nemo-gym-dataset", load_settings(None, None, None))
    assert report["environment"]["adapter"] == "nemo-gym"
    b = by_id(report)
    assert b["EC001"][0]["status"] == "PASS"
    assert b["EC051"][0]["status"] == "PASS"
    assert b["EC014"][0]["status"] == "PASS"
    assert report["policy"]["passed"]


def test_nemo_expected_answer_leaked_into_prompt(task_factory):
    task = task_factory({
        "verifier.py": "def verify(response=None, task_data=None):\n    return 1.0 if response == task_data['expected_answer'] else 0.0\n",
        "data.jsonl": '{"responses_create_params": {"input": [{"role": "user", "content": "What is 15*7? The answer is 105"}]}, "expected_answer": "105"}\n',
    })
    (task / "verifier.py").exists()

    # task_factory created a harbor-ish root; rename data file stays, adapter auto-detects verifier.py
    report = run_checks(task, load_settings(None, None, {"profile": "harbor"}), adapter_name="nemo-gym")
    assert by_id(report)["EC014"][0]["status"] == "WARN"


def test_inspect_adapter_and_checks():
    report = run_checks(EXAMPLES / "inspect-eval", load_settings(None, None, None))
    assert report["environment"]["adapter"] == "inspect"
    b = by_id(report)
    assert b["EC001"][0]["status"] == "PASS"
    assert b["EC050"][0]["status"] == "PASS"
    assert b["EC051"][0]["status"] == "PASS"


def test_multistep_auditing():
    report = run_checks(EXAMPLES / "multistep-task", load_settings(None, None, None))
    b = by_id(report)
    assert b["EC001"][0]["status"] == "PASS"
    assert b["EC004"][0]["status"] == "PASS"
    assert b["EC002"][0]["status"] == "PASS"
    assert report["policy"]["passed"]


def test_multistep_incomplete_step(task_factory):
    from tests.conftest import BASIC

    files = dict(BASIC)
    files["steps/step-1/instruction.md"] = "# Step one\n\nDo the first meaningful part of the task now.\n"
    # no per-step tests, but top-level tests/ exists in BASIC -> EC004 warns on instruction only exists; tests missing
    files.pop("instruction.md", None)
    report = run_checks(task_factory(files), load_settings(None, None, None))
    ec004 = by_id(report)["EC004"][0]
    assert ec004["status"] in ("PASS", "WARN")  # fallback note included either way
    assert "step-1" in json.dumps(ec004["evidence"])


def test_image_digest_binding_and_attestation_subject():
    s = load_settings(None, None, {"image_digest": "sha256:" + "b" * 64})
    report = run_checks(EXAMPLES / "safe-environment", s)
    assert report["environment"]["image_digest"] == "sha256:" + "b" * 64
    stmt = build_statement(report, json.dumps(report).encode())
    names = [x["name"] for x in stmt["subject"]]
    assert "oci-image" in names
    assert verify_statement_local(stmt) == []


def test_image_digest_resolution_from_ref():
    digest, note = resolve_image_digest(load_settings(None, None, {"image": "myimg@sha256:" + "c" * 64}))
    assert digest == "sha256:" + "c" * 64
    with pytest.raises(ConfigError, match="invalid --image-digest"):
        resolve_image_digest(load_settings(None, None, {"image_digest": "not-a-digest"}))
    with pytest.raises(ConfigError, match="invalid digest"):
        resolve_image_digest(load_settings(None, None, {"image": "myimg@sha256:short"}))


def test_external_tools_not_run_by_default(basic_task):
    report = run_checks(basic_task, load_settings(None, None, None))
    b = by_id(report)
    for cid in ("EC070", "EC071", "EC072"):
        assert b[cid][0]["status"] == "NOT_RUN"


def test_external_runner_protocol(tmp_path, basic_task):
    fake = tmp_path / "fake_runner.py"
    fake.write_text(
        "import argparse, json\n"
        "p = argparse.ArgumentParser(); p.add_argument('--task'); p.add_argument('--variant'); p.add_argument('--timeout')\n"
        "a = p.parse_args()\n"
        "print(json.dumps({'reward': 1.0 if a.variant == 'gold' else 0.0, 'exit_code': 0, 'image_digest': 'sha256:' + 'd' * 64}))\n",
        encoding="utf-8")
    cmd = f'"{sys.executable}" "{fake}"'
    s = load_settings(None, None, {"execution": "external", "runner_command": cmd})
    report = run_checks(basic_task, s)
    b = by_id(report)
    assert b["EC060"][0]["status"] == "PASS"
    assert b["EC061"][0]["status"] == "PASS"
    assert report["environment"]["image_digest"] == "sha256:" + "d" * 64
    assert report["execution"]["runner"]["name"] == "external"


def test_external_runner_missing_command(basic_task):
    s = load_settings(None, None, {"execution": "external"})
    report = run_checks(basic_task, s)
    assert by_id(report)["EC060"][0]["status"] in ("ERROR", "FAIL", "NOT_APPLICABLE", "NOT_RUN")


def test_richer_mutation_operators():
    from envicert.checks.mutation import run_mutation

    result = run_mutation(EXAMPLES / "python-task", max_mutants=20)
    changes = " ".join(m["change"] for m in result["mutants"])
    # at least one of the new operator families appears across the mutant set
    assert any(k in changes for k in ("boolop", "string", "compare", "->", "return", "constant"))
    assert result["rejection_rate"] is not None


def test_mutation_print_only_tagging(tmp_path, task_factory):
    files = {
        "task.toml": '[task]\nname = "x/y"\n',
        "instruction.md": "# T\n\nDo a meaningful verifiable thing here please.\n",
        "environment/Dockerfile": "FROM python:3.12\n",
        "solution/calc.py": "def describe(a, b):\n    print('sum is', a + b)\n    return a + b\n",
        "tests/test_calc.py": "from calc import describe\ndef test_d():\n    assert describe(2, 3) == 5\n    assert describe(1, 1) == 2\n",
        "tests/test.sh": "#!/bin/bash\necho 0 > /logs/verifier/reward.txt\n",
    }
    from envicert.checks.mutation import run_mutation

    result = run_mutation(task_factory(files), max_mutants=20)
    tagged = [m for m in result["mutants"] if m.get("possible_equivalent")]
    assert tagged, result["mutants"]
