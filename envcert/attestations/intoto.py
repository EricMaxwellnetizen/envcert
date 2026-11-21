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
    if env.get("image_digest"):
        digest = str(env["image_digest"]).removeprefix("sha256:")
        subjects.append({"name": env.get("image_reference") or "oci-image", "digest": {"sha256": digest}})
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


def cosign_attest_image(predicate_path: Path, image: str, key_path: str | None = None) -> tuple[bool, str]:
    """Attach the statement as an OCI attestation on `image` via cosign attest.

    The predicate file must contain the in-toto *predicate* (this module's
    caller extracts it).  `image` should be referenced by digest
    (name@sha256:...) so the attestation binds to immutable content.
    """
    if "@sha256:" not in image:
        return False, f"refusing to attest a mutable image reference {image!r}: use name@sha256:<digest> so the attestation binds to immutable content"
    exe = cosign_available()
    if not exe:
        return False, "cosign not found on PATH; OCI attestation not performed (statement file was still written)"
    cmd = [exe, "attest", "--yes", "--predicate", str(predicate_path),
           "--type", TEST_RESULT_PREDICATE, image]
    if key_path:
        cmd[2:2] = ["--key", key_path]
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
    if proc.returncode != 0:
        return False, f"cosign attest failed: {(proc.stderr or proc.stdout)[:500]}"
    return True, f"cosign attestation attached to {image} (predicate type {TEST_RESULT_PREDICATE})"


def cosign_verify_attestation(image: str, key_path: str | None = None, policy: str | None = None) -> tuple[bool, str]:
    exe = cosign_available()
    if not exe:
        return False, "cosign not found on PATH; cryptographic verification not performed"
    cmd = [exe, "verify-attestation", "--type", TEST_RESULT_PREDICATE]
    if key_path:
        cmd += ["--key", key_path]
    else:
        cmd += ["--certificate-identity-regexp", ".*", "--certificate-oidc-issuer-regexp", ".*"]
    if policy:
        cmd += ["--policy", policy]
    cmd.append(image)
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
    if proc.returncode != 0:
        return False, f"cosign verify-attestation failed: {(proc.stderr or proc.stdout)[:500]}"
    return True, f"cosign verify-attestation passed for {image}"


def verify_statement_local(statement: dict[str, Any]) -> list[str]:
    """Structural verification only (no cryptography): type, subjects, result."""
    problems = []
    if statement.get("_type") != STATEMENT_TYPE:
        problems.append(f"unexpected _type: {statement.get('_type')!r}")
    if statement.get("predicateType") != TEST_RESULT_PREDICATE:
        problems.append(f"unexpected predicateType: {statement.get('predicateType')!r}")
    subjects = statement.get("subject") or []
    if not subjects or not all((s.get("digest") or {}).get("sha256") for s in subjects):
        problems.append("statement has no sha256-bound subjects")
    predicate = statement.get("predicate") or {}
    if predicate.get("result") not in ("PASSED", "FAILED"):
        problems.append("predicate.result is not PASSED/FAILED")
    return problems


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
