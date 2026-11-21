"""in-toto attestation generation (unsigned statement + optional cosign).

Uses the established in-toto Statement v1 and the vetted Test Result
predicate (https://in-toto.io/attestation/test-result/v0.1) instead of
inventing a new predicate.  EnvCert-specific detail (per-check results,
bundle/verifier digests, profile, limitations) is carried in the Test Result
`configurationSource.digest` + an `externalParameters`-style extension key is
avoided; instead the full report digest binds the statement to the exact
report file, and consumers fetch the report by digest.  Signing is optional
via Cosign sign-blob when the binary is present; an unsigned statement is
explicitly labelled unsigned and is never described as verified.
"""
from __future__ import annotations

import base64
import hashlib
import json
import shutil
import subprocess
from pathlib import Path
from typing import Any

STATEMENT_TYPE = "https://in-toto.io/Statement/v1"
TEST_RESULT_PREDICATE = "https://in-toto.io/attestation/test-result/v0.1"


def build_statement(report: dict[str, Any], report_bytes: bytes) -> dict[str, Any]:
    env = report.get("environment") or {}
    policy = report.get("policy") or {}
    report_digest = hashlib.sha256(report_bytes).hexdigest()
    subjects = [{
        "name": env.get("task_name") or "envcert-task",
        "digest": {"sha256": env.get("bundle_digest_sha256") or report_digest},
    }]
    if env.get("verifier_digest_sha256"):
        subjects.append({"name": "verifier", "digest": {"sha256": env["verifier_digest_sha256"]}})
    if env.get("solution_digest_sha256"):
        subjects.append({"name": "reference-solution", "digest": {"sha256": env["solution_digest_sha256"]}})
    failing = [f for f in report.get("findings", []) if f.get("status") in ("FAIL", "WARN")]
    predicate: dict[str, Any] = {
        "result": "PASSED" if policy.get("passed") else "FAILED",
        "configurationSource": {
            "uri": f"envcert://profile/{(report.get('execution') or {}).get('profile', 'harbor')}",
            "digest": {"sha256": report_digest},
        },
        "metadata": {
            "buildStartedOn": report.get("generated_at"),
            "completeness": {"parameters": True, "environment": False, "materials": False},
        },
        # Extension documented in docs/architecture/REPORT_SCHEMA.md: the Test
        # Result predicate allows additional fields for tool-specific detail.
        "x-envcert": {
            "envcert_version": report.get("envcert_version"),
            "report_schema_version": report.get("schema_version"),
            "report_digest_sha256": report_digest,
            "adapter": env.get("adapter"),
            "assurance_context": report.get("assurance_context"),
            "checks_executed": report.get("checks_executed"),
            "failing_check_ids": sorted({f["check_id"] for f in failing}),
            "limitations": report.get("limitations"),
            "signed": False,
        },
    }
    return {"_type": STATEMENT_TYPE, "subject": subjects, "predicateType": TEST_RESULT_PREDICATE, "predicate": predicate}


def dsse_envelope_unsigned(statement: dict[str, Any]) -> dict[str, Any]:
    payload = base64.b64encode(json.dumps(statement, sort_keys=True).encode()).decode()
    return {"payloadType": "application/vnd.in-toto+json", "payload": payload, "signatures": [],
            "_envcert_note": "UNSIGNED envelope: signatures is empty. Sign with cosign sign-blob or a DSSE signer before treating this as cryptographic evidence."}


def cosign_available() -> str | None:
    return shutil.which("cosign")


def sign_with_cosign(envelope_path: Path, key_path: str | None = None) -> tuple[bool, str]:
    exe = cosign_available()
    if not exe:
        return False, "cosign not found on PATH; attestation left unsigned (this is not an error — install cosign to sign)"
    cmd = [exe, "sign-blob", "--output-signature", str(envelope_path) + ".sig", str(envelope_path)]
    if key_path:
        cmd[2:2] = ["--key", key_path]
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
    if proc.returncode != 0:
        return False, f"cosign sign-blob failed: {(proc.stderr or proc.stdout)[:400]}"
    return True, f"signed with cosign; signature at {envelope_path}.sig"
