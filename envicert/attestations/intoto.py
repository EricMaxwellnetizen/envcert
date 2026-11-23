"""in-toto attestation generation (unsigned statement + optional cosign).

Uses the established in-toto Statement v1 and the vetted Test Result
predicate (https://in-toto.io/attestation/test-result/v0.1) instead of
inventing a new predicate.  Envicert-specific detail (per-check results,
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
import re
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any

from envicert.core.errors import ConfigError
from envicert.core.images import parse_image_digest

STATEMENT_TYPE = "https://in-toto.io/Statement/v1"
TEST_RESULT_PREDICATE = "https://in-toto.io/attestation/test-result/v0.1"

_SHA256_RE = re.compile(r"[0-9a-f]{64}")


def _sha256(value: Any) -> str | None:
    if isinstance(value, str) and _SHA256_RE.fullmatch(value):
        return value
    return None


def build_statement(report: dict[str, Any], report_bytes: bytes, *, signed: bool = False) -> dict[str, Any]:
    if not isinstance(report, dict):
        raise ValueError("report must be a JSON object")
    env = report.get("environment")
    if not isinstance(env, dict):
        env = {}
    policy = report.get("policy")
    if not isinstance(policy, dict):
        policy = {}
    findings = report.get("findings")
    if not isinstance(findings, list):
        findings = []
    report_digest = hashlib.sha256(report_bytes).hexdigest()
    bundle_digest = _sha256(env.get("bundle_digest_sha256")) or report_digest
    task_name = env.get("task_name")
    if not isinstance(task_name, str) or not task_name:
        task_name = "envicert-task"
    subjects = [{
        "name": task_name,
        "digest": {"sha256": bundle_digest},
    }]
    verifier_digest = _sha256(env.get("verifier_digest_sha256"))
    if verifier_digest:
        subjects.append({"name": "verifier", "digest": {"sha256": verifier_digest}})
    solution_digest = _sha256(env.get("solution_digest_sha256"))
    if solution_digest:
        subjects.append({"name": "reference-solution", "digest": {"sha256": solution_digest}})
    image_digest = env.get("image_digest")
    if isinstance(image_digest, str) and image_digest.startswith("sha256:"):
        image_sha = _sha256(image_digest.removeprefix("sha256:"))
        if image_sha:
            subjects.append({"name": env.get("image_reference") or "oci-image",
                             "digest": {"sha256": image_sha}})
    # Baseline-suppressed findings are still recorded in the report, but they
    # do not fail policy and must not appear as failing checks in an
    # attestation whose predicate.result is PASSED.
    failing = [f for f in findings
               if isinstance(f, dict)
               and f.get("status") in ("FAIL", "WARN")
               and not f.get("baseline_suppressed")]
    predicate: dict[str, Any] = {
        "result": "PASSED" if policy.get("passed") else "FAILED",
        "configurationSource": {
            "uri": f"envicert://profile/{(report.get('execution') or {}).get('profile', 'harbor')}",
            "digest": {"sha256": report_digest},
        },
        "metadata": {
            "buildStartedOn": report.get("generated_at"),
            "completeness": {"parameters": True, "environment": False, "materials": False},
        },
        # Extension documented in docs/architecture/REPORT_SCHEMA.md: the Test
        # Result predicate allows additional fields for tool-specific detail.
        "x-envicert": {
            "envicert_version": report.get("envicert_version"),
            "report_schema_version": report.get("schema_version"),
            "report_digest_sha256": report_digest,
            "adapter": env.get("adapter"),
            "assurance_context": report.get("assurance_context"),
            "checks_executed": report.get("checks_executed"),
            "failing_check_ids": sorted({f["check_id"] for f in failing}),
            "limitations": report.get("limitations"),
            # True only when this invocation embedded a DSSE signature over
            # this exact payload; the envelope signatures are the evidence.
            "signed": bool(signed),
        },
    }
    return {"_type": STATEMENT_TYPE, "subject": subjects, "predicateType": TEST_RESULT_PREDICATE, "predicate": predicate}


def dsse_envelope_unsigned(statement: dict[str, Any]) -> dict[str, Any]:
    payload = base64.b64encode(json.dumps(statement, sort_keys=True).encode()).decode()
    return {"payloadType": "application/vnd.in-toto+json", "payload": payload, "signatures": [],
            "_envicert_note": "UNSIGNED envelope: signatures is empty. Sign with cosign sign-blob or a DSSE signer before treating this as cryptographic evidence."}


def dsse_pae(payload_type: str, payload: bytes) -> bytes:
    """DSSE Pre-Authentication Encoding (the bytes a DSSE signature covers)."""
    return (b"DSSEv1 " + str(len(payload_type)).encode("ascii") + b" "
            + payload_type.encode("utf-8") + b" " + str(len(payload)).encode("ascii")
            + b" " + payload)


def _dsse_payload(envelope: dict[str, Any]) -> tuple[str, bytes] | tuple[None, None]:
    payload_type = envelope.get("payloadType")
    payload_b64 = envelope.get("payload")
    if not isinstance(payload_type, str) or not isinstance(payload_b64, str):
        return None, None
    try:
        payload = base64.b64decode(payload_b64, validate=True)
    except Exception:  # noqa: BLE001
        return None, None
    return payload_type, payload


def sign_dsse_with_cosign(envelope: dict[str, Any], key_path: str | None = None) -> tuple[bool, str]:
    """Sign the DSSE PAE with cosign and embed the signature in the envelope.

    A detached signature over the envelope JSON is *not* a DSSE signature: a
    DSSE verifier reconstructs the PAE from payloadType+payload.  This writes
    the signature where DSSE consumers expect it.
    """
    exe = cosign_available()
    if not exe:
        return False, "cosign not found on PATH; DSSE signing was requested but could not be performed"
    payload_type, payload = _dsse_payload(envelope)
    if payload_type is None or payload is None:
        return False, "not a valid DSSE envelope: payloadType/payload are missing or payload is not base64"
    with tempfile.TemporaryDirectory() as tmp:
        pae_path = Path(tmp) / "dsse.pae"
        sig_path = Path(tmp) / "dsse.sig"
        pae_path.write_bytes(dsse_pae(payload_type, payload))
        cmd = [exe, "sign-blob", "--yes", "--output-signature", str(sig_path), str(pae_path)]
        if key_path:
            cmd[2:2] = ["--key", key_path]
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        if proc.returncode != 0:
            return False, f"cosign sign-blob failed: {(proc.stderr or proc.stdout)[:400]}"
        try:
            signature = sig_path.read_text(encoding="utf-8").strip()
        except OSError as exc:
            return False, f"cosign did not write a signature: {exc}"
    if not signature:
        return False, "cosign produced an empty DSSE signature"
    signatures = envelope.get("signatures")
    if not isinstance(signatures, list):
        signatures = []
    signatures.append({"sig": signature, "keyid": ""})
    envelope["signatures"] = signatures
    envelope.pop("_envicert_note", None)
    return True, "DSSE envelope signed with cosign (embedded signature over the DSSE PAE)"


def cosign_verify_dsse(envelope: dict[str, Any], key_path: str | None = None) -> tuple[bool, str]:
    """Verify at least one embedded DSSE signature over the reconstructed PAE."""
    exe = cosign_available()
    if not exe:
        return False, "cosign not found on PATH; cannot verify the embedded DSSE signature"
    payload_type, payload = _dsse_payload(envelope)
    if payload_type is None or payload is None:
        return False, "not a valid DSSE envelope: payloadType/payload are missing or payload is not base64"
    signatures = envelope.get("signatures")
    if not isinstance(signatures, list) or not signatures:
        return False, "DSSE envelope carries no embedded signatures"
    pae = dsse_pae(payload_type, payload)
    failures: list[str] = []
    with tempfile.TemporaryDirectory() as tmp:
        pae_path = Path(tmp) / "dsse.pae"
        pae_path.write_bytes(pae)
        for index, signature in enumerate(signatures):
            raw = signature.get("sig") if isinstance(signature, dict) else None
            if not isinstance(raw, str) or not raw:
                failures.append(f"signature {index} has no sig")
                continue
            sig_path = Path(tmp) / f"dsse-{index}.sig"
            sig_path.write_text(raw, encoding="utf-8")
            cmd = [exe, "verify-blob", "--signature", str(sig_path)]
            if key_path:
                cmd += ["--key", key_path]
            else:
                cmd += ["--certificate-identity-regexp", ".*", "--certificate-oidc-issuer-regexp", ".*"]
            cmd.append(str(pae_path))
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
            if proc.returncode == 0:
                return True, f"cosign verified embedded DSSE signature {index} over the PAE"
            failures.append(f"signature {index}: {(proc.stderr or proc.stdout)[:200]}")
    return False, "no embedded DSSE signature verified: " + "; ".join(failures[:3])


def cosign_available() -> str | None:
    return shutil.which("cosign")


def cosign_attest_image(predicate_path: Path, image: str, key_path: str | None = None) -> tuple[bool, str]:
    """Attach the statement as an OCI attestation on `image` via cosign attest.

    The predicate file must contain the in-toto *predicate* (this module's
    caller extracts it).  `image` should be referenced by digest
    (name@sha256:...) so the attestation binds to immutable content.
    """
    try:
        parse_image_digest(image)
    except ConfigError as exc:
        return False, str(exc)
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
    try:
        parse_image_digest(image)
    except ConfigError as exc:
        return False, str(exc)
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


def cosign_verify_blob(blob_path: Path, signature_path: Path, key_path: str | None = None) -> tuple[bool, str]:
    """Verify a detached cosign signature (the `.sig` written by --sign)."""
    exe = cosign_available()
    if not exe:
        return False, "cosign not found on PATH; cannot verify the detached signature"
    cmd = [exe, "verify-blob", "--signature", str(signature_path)]
    if key_path:
        cmd += ["--key", key_path]
    else:
        cmd += ["--certificate-identity-regexp", ".*", "--certificate-oidc-issuer-regexp", ".*"]
    cmd.append(str(blob_path))
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
    if proc.returncode != 0:
        return False, f"cosign verify-blob failed: {(proc.stderr or proc.stdout)[:500]}"
    return True, f"cosign verified the detached signature {signature_path.name} for {blob_path.name}"


def verify_statement_local(statement: dict[str, Any]) -> list[str]:
    """Structural verification only (no cryptography): type, subjects, result."""
    if not isinstance(statement, dict):
        return ["statement is not a JSON object"]
    problems = []
    if statement.get("_type") != STATEMENT_TYPE:
        problems.append(f"unexpected _type: {statement.get('_type')!r}")
    if statement.get("predicateType") != TEST_RESULT_PREDICATE:
        problems.append(f"unexpected predicateType: {statement.get('predicateType')!r}")
    subjects = statement.get("subject")
    if not isinstance(subjects, list) or not subjects:
        problems.append("statement has no subject list")
    else:
        for index, subject in enumerate(subjects):
            if not isinstance(subject, dict):
                problems.append(f"subject[{index}] is not an object")
                continue
            digest = subject.get("digest")
            if not isinstance(digest, dict):
                problems.append(f"subject[{index}].digest is not an object")
                continue
            sha = digest.get("sha256")
            if not isinstance(sha, str) or not _SHA256_RE.fullmatch(sha):
                problems.append(f"subject[{index}] has no valid sha256 digest")
    predicate = statement.get("predicate")
    if not isinstance(predicate, dict):
        problems.append("predicate is not an object")
    else:
        if predicate.get("result") not in ("PASSED", "FAILED"):
            problems.append("predicate.result is not PASSED/FAILED")
        extension = predicate.get("x-envicert")
        if isinstance(extension, dict) and "report_digest_sha256" in extension:
            if _sha256(extension.get("report_digest_sha256")) is None:
                problems.append("predicate.x-envicert.report_digest_sha256 is not a sha256 digest")
    return problems


def sign_with_cosign(envelope_path: Path, key_path: str | None = None) -> tuple[bool, str]:
    exe = cosign_available()
    if not exe:
        return False, "cosign not found on PATH; signing was requested but could not be performed"
    cmd = [exe, "sign-blob", "--yes", "--output-signature", str(envelope_path) + ".sig", str(envelope_path)]
    if key_path:
        cmd[2:2] = ["--key", key_path]
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
    if proc.returncode != 0:
        return False, f"cosign sign-blob failed: {(proc.stderr or proc.stdout)[:400]}"
    return True, f"signed with cosign; signature at {envelope_path}.sig"
