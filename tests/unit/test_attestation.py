import base64
import json

from envicert.attestations.intoto import TEST_RESULT_PREDICATE, build_statement, dsse_envelope_unsigned
from envicert.core.config import load_settings
from envicert.core.engine import run_checks


def test_statement_binds_digests(basic_task):
    report = run_checks(basic_task, load_settings(None, None, None))
    raw = json.dumps(report).encode()
    stmt = build_statement(report, raw)
    assert stmt["_type"] == "https://in-toto.io/Statement/v1"
    assert stmt["predicateType"] == TEST_RESULT_PREDICATE
    subjects = {s["name"]: s["digest"]["sha256"] for s in stmt["subject"]}
    assert subjects[report["environment"]["task_name"]] == report["environment"]["bundle_digest_sha256"]
    assert "verifier" in subjects
    assert stmt["predicate"]["result"] in ("PASSED", "FAILED")
    assert stmt["predicate"]["x-envicert"]["signed"] is False


def test_dsse_envelope_unsigned_is_labelled(basic_task):
    report = run_checks(basic_task, load_settings(None, None, None))
    stmt = build_statement(report, b"{}")
    env = dsse_envelope_unsigned(stmt)
    assert env["signatures"] == []
    assert "UNSIGNED" in env["_envicert_note"]
    decoded = json.loads(base64.b64decode(env["payload"]))
    assert decoded["predicateType"] == TEST_RESULT_PREDICATE
