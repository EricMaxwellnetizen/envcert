"""Report consistency validation.

A report is a self-asserted JSON document.  Consumers (`envcert verify`,
`envcert attest`) must not trust its `policy.passed` flag or its summary
counters: both are recomputed from the findings and the recorded policy
inputs.  Any disagreement is reported as a validation failure.

This is deliberately about *internal consistency*, not authenticity.  A
forged report that is internally consistent is still only supplier-asserted
evidence; cryptographic assurance requires signing/attestation.
"""
from __future__ import annotations

import hashlib
import json
import re
from collections import Counter
from typing import Any

from envcert.core.models import Severity, Status

SEVERITY_NAMES = [s.value for s in Severity]
STATUS_NAMES = [s.value for s in Status]

# Evidence fields that legitimately change between otherwise identical runs.
# They are ignored when fingerprinting a finding for baseline suppression so a
# stable static finding can be suppressed without hiding a new issue.
_VOLATILE_EVIDENCE_KEYS = frozenset({
    "duration_sec", "reward", "exit_code", "runs", "stdout_tail", "stderr_tail",
    "generated_at", "image_digest", "task_path",
})


def _stable(value: Any) -> Any:
    if isinstance(value, dict):
        return {str(k): _stable(v) for k, v in sorted(value.items()) if k not in _VOLATILE_EVIDENCE_KEYS}
    if isinstance(value, list):
        return [_stable(v) for v in value]
    return value


def finding_fingerprint(finding: dict[str, Any]) -> str:
    """Stable identity for a finding, used by baseline suppression.

    Includes the check, location, status/severity and the finding's message
    and (scrubbed) evidence.  A different issue at the same path/line no
    longer matches an old baseline entry just because the coordinates agree.
    """
    payload = {key: finding.get(key) for key in (
        "check_id", "title", "description", "category", "severity", "status",
        "artifact", "path", "line", "confidence",
    )}
    payload["evidence"] = _stable(finding.get("evidence") or {})
    canonical = json.dumps(payload, sort_keys=True, default=str, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _severity_set(value: Any) -> set[str] | None:
    if not isinstance(value, list) or not value:
        return None
    names: set[str] = set()
    for item in value:
        name = str(item).upper()
        if name not in SEVERITY_NAMES:
            return None
        names.add(name)
    return names


def validate_report_consistency(report: dict[str, Any]) -> list[str]:
    """Return consistency problems; an empty list means the report agrees with itself."""
    problems: list[str] = []
    if not isinstance(report, dict):
        return ["report root is not a JSON object"]

    environment = report.get("environment")
    execution = report.get("execution")
    policy = report.get("policy")
    summary = report.get("summary")
    findings = report.get("findings")
    if not isinstance(environment, dict):
        problems.append("environment is not an object")
    else:
        bundle = environment.get("bundle_digest_sha256")
        if not isinstance(bundle, str) or not re.fullmatch(r"[0-9a-f]{64}", bundle):
            problems.append("environment.bundle_digest_sha256 is not a 64-character lowercase hex digest")
        for key in ("verifier_digest_sha256", "solution_digest_sha256"):
            value = environment.get(key)
            if value is not None and (not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{64}", value)):
                problems.append(f"environment.{key} is neither null nor a 64-character lowercase hex digest")
        image = environment.get("image_digest")
        if image is not None and (not isinstance(image, str) or not re.fullmatch(r"sha256:[0-9a-f]{64}", image)):
            problems.append("environment.image_digest is neither null nor sha256:<64 lowercase hex>")
        file_count = environment.get("file_count")
        if not isinstance(file_count, int) or isinstance(file_count, bool) or file_count < 0:
            problems.append("environment.file_count is not a non-negative integer")
    if not isinstance(execution, dict):
        problems.append("execution is not an object")
    if not isinstance(policy, dict):
        problems.append("policy is not an object")
        policy = {}
    if not isinstance(summary, dict):
        problems.append("summary is not an object")
        summary = {}
    if not isinstance(findings, list):
        problems.append("findings is not a list")
        findings = []

    valid_findings: list[dict[str, Any]] = []
    for index, finding in enumerate(findings):
        if not isinstance(finding, dict):
            problems.append(f"findings[{index}] is not an object")
            continue
        status = finding.get("status")
        severity = finding.get("severity")
        if not isinstance(finding.get("check_id"), str):
            problems.append(f"findings[{index}] has no string check_id")
            continue
        if status not in STATUS_NAMES:
            problems.append(f"findings[{index}] has invalid status {status!r}")
            continue
        if severity not in SEVERITY_NAMES:
            problems.append(f"findings[{index}] has invalid severity {severity!r}")
            continue
        suppressed = finding.get("baseline_suppressed", False)
        if not isinstance(suppressed, bool):
            problems.append(f"findings[{index}].baseline_suppressed is not a boolean")
        if suppressed and status not in (Status.FAIL.value, Status.WARN.value):
            problems.append(f"findings[{index}] is baseline_suppressed but status is {status}")
        valid_findings.append(finding)

    policy_names = _severity_set(policy.get("fail_on"))
    execution_names = _severity_set(execution.get("fail_on")) if isinstance(execution, dict) else None
    if policy_names is None:
        problems.append("policy.fail_on is not a non-empty list of severities")
    if execution_names is not None and policy_names is not None and execution_names != policy_names:
        problems.append(
            "policy.fail_on and execution.fail_on disagree: "
            f"{sorted(policy_names)} != {sorted(execution_names)}"
        )
    fail_on = policy_names or execution_names or set()

    failing = [
        f for f in valid_findings
        if f["status"] in (Status.FAIL.value, Status.WARN.value)
        and f["severity"] in fail_on
        and not f.get("baseline_suppressed", False)
    ]
    errored = [f for f in valid_findings if f["status"] == Status.ERROR.value]
    recomputed_passed = not failing and not errored
    claimed_passed = policy.get("passed")
    if not isinstance(claimed_passed, bool):
        problems.append("policy.passed is not a boolean")
    elif claimed_passed != recomputed_passed:
        problems.append(
            f"policy.passed={claimed_passed} contradicts the findings "
            f"(recomputed={recomputed_passed}; {len(failing)} failing, {len(errored)} errored)"
        )

    expected_status = Counter(f["status"] for f in valid_findings)
    expected_severity = Counter(
        f["severity"] for f in valid_findings if f["status"] in (Status.FAIL.value, Status.WARN.value)
    )
    expected_suppressed = sum(1 for f in valid_findings if f.get("baseline_suppressed") is True)
    if summary.get("total_findings") != len(valid_findings):
        problems.append(
            f"summary.total_findings={summary.get('total_findings')!r} does not match {len(valid_findings)} findings"
        )
    if summary.get("by_status") != dict(expected_status):
        problems.append(
            f"summary.by_status={summary.get('by_status')!r} does not match findings {dict(expected_status)!r}"
        )
    if summary.get("by_severity_failing") != dict(expected_severity):
        problems.append(
            "summary.by_severity_failing="
            f"{summary.get('by_severity_failing')!r} does not match findings {dict(expected_severity)!r}"
        )
    if summary.get("baseline_suppressed") != expected_suppressed:
        problems.append(
            f"summary.baseline_suppressed={summary.get('baseline_suppressed')!r} does not match {expected_suppressed} suppressed findings"
        )
    if expected_suppressed and not summary.get("baseline"):
        problems.append("findings claim baseline suppression but summary.baseline is empty")

    executed = report.get("checks_executed")
    if not isinstance(executed, list) or not all(isinstance(x, str) for x in executed):
        problems.append("checks_executed is not a list of check IDs")
    else:
        if not executed:
            problems.append("checks_executed is empty; a report with no executed checks cannot support a passing policy")
        duplicates = sorted({x for x in executed if executed.count(x) > 1})
        if duplicates:
            problems.append(f"checks_executed contains duplicates: {duplicates}")
        finding_ids = {f["check_id"] for f in valid_findings}
        unexecuted = sorted(finding_ids - set(executed))
        if unexecuted:
            problems.append(f"findings reference checks not listed in checks_executed: {unexecuted}")
    not_executed = report.get("checks_not_executed")
    if isinstance(not_executed, list) and isinstance(executed, list):
        overlap = sorted(set(executed) & set(not_executed))
        if overlap:
            problems.append(f"checks are listed as both executed and not executed: {overlap}")

    return problems
