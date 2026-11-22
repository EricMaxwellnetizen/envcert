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

# Check IDs that existed in each released registry.  Reports must account for
# every check that was available when they were produced: a check that did not
# run belongs in checks_not_executed, never in an implicit gap.  New reports
# carry checks_available so future versions do not need this table.
KNOWN_REGISTRY_SNAPSHOTS: dict[tuple[int, int], frozenset[str]] = {
    (0, 1): frozenset(
        "EC001 EC002 EC003 EC010 EC011 EC012 EC013 EC014 "
        "EC020 EC021 EC022 EC023 EC024 EC030 EC031 EC032 EC033 "
        "EC040 EC041 EC050 EC051 EC052 EC053 EC054 "
        "EC060 EC061 EC062 EC063".split()
    ),
    (0, 2): frozenset(
        "EC001 EC002 EC003 EC004 EC010 EC011 EC012 EC013 EC014 "
        "EC020 EC021 EC022 EC023 EC024 EC030 EC031 EC032 EC033 "
        "EC040 EC041 EC050 EC051 EC052 EC053 EC054 "
        "EC060 EC061 EC062 EC063 EC064 EC070 EC071 EC072".split()
    ),
    (0, 3): frozenset(
        "EC001 EC002 EC003 EC004 EC010 EC011 EC012 EC013 EC014 "
        "EC020 EC021 EC022 EC023 EC024 EC030 EC031 EC032 EC033 "
        "EC040 EC041 EC050 EC051 EC052 EC053 EC054 EC055 "
        "EC060 EC061 EC062 EC063 EC064 EC065 EC070 EC071 EC072".split()
    ),
    (0, 4): frozenset(
        "EC001 EC002 EC003 EC004 EC010 EC011 EC012 EC013 EC014 "
        "EC020 EC021 EC022 EC023 EC024 EC030 EC031 EC032 EC033 "
        "EC040 EC041 EC050 EC051 EC052 EC053 EC054 EC055 EC056 "
        "EC060 EC061 EC062 EC063 EC064 EC065 EC066 EC070 EC071 EC072 "
        "EC080 EC081 EC082 EC083 EC084 EC085".split()
    ),
}

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


def version_tuple(version: Any) -> tuple[int, ...]:
    """Parse a dotted version into integers; empty tuple when unparseable."""
    try:
        parts = tuple(int(part) for part in str(version).split("."))
    except (AttributeError, TypeError, ValueError):
        return ()
    return parts


def version_at_least(version: Any, minimum: tuple[int, ...]) -> bool:
    """True when the report's envcert_version is >= minimum (e.g. (0, 3, 2))."""
    parts = version_tuple(version)
    if not parts:
        return False
    width = max(len(parts), len(minimum))
    left = parts + (0,) * (width - len(parts))
    right = tuple(minimum) + (0,) * (width - len(minimum))
    return left >= right


_version_at_least = version_at_least  # backwards-compatible internal alias


def registry_snapshot(report: dict[str, Any]) -> frozenset[str] | None:
    """The check registry the report claims to have run against.

    Newer reports record `checks_available` explicitly; older reports are
    mapped to the registry snapshot of their EnvCert minor version.
    """
    available = report.get("checks_available")
    if isinstance(available, list) and all(isinstance(item, str) for item in available):
        return frozenset(available)
    parts = version_tuple(report.get("envcert_version"))
    if len(parts) < 2:
        return None
    return KNOWN_REGISTRY_SNAPSHOTS.get((parts[0], parts[1]))


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
    # Reports from EnvCert < 0.3.0 did not carry every summary counter (the
    # report schema is still 1.0.0), so absent counters are only an error for
    # versions that always wrote them.
    modern = _version_at_least(report.get("envcert_version"), (0, 3))
    summary_checks = (
        ("total_findings", len(valid_findings)),
        ("by_status", dict(expected_status)),
        ("by_severity_failing", dict(expected_severity)),
        ("baseline_suppressed", expected_suppressed),
    )
    for key, expected in summary_checks:
        if key in summary:
            if summary[key] != expected:
                problems.append(f"summary.{key}={summary[key]!r} does not match {expected!r} from the findings")
        elif modern:
            problems.append(f"summary.{key} is missing")
    if expected_suppressed and not summary.get("baseline"):
        problems.append("findings claim baseline suppression but summary.baseline is empty")

    executed = report.get("checks_executed")
    if not isinstance(executed, list) or not all(isinstance(x, str) for x in executed):
        problems.append("checks_executed is not a list of check IDs")
        executed = None
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
    if "checks_not_executed" not in report:
        if modern:
            problems.append("checks_not_executed is missing")
        not_executed = None
    elif not isinstance(not_executed, list) or not all(isinstance(x, str) for x in not_executed):
        problems.append("checks_not_executed is not a list of check IDs")
        not_executed = None
    else:
        duplicates = sorted({x for x in not_executed if not_executed.count(x) > 1})
        if duplicates:
            problems.append(f"checks_not_executed contains duplicates: {duplicates}")
    if isinstance(executed, list) and isinstance(not_executed, list):
        overlap = sorted(set(executed) & set(not_executed))
        if overlap:
            problems.append(f"checks are listed as both executed and not executed: {overlap}")

    # A passing report must account for every check that existed when it was
    # produced.  Without this, a report can silently omit checks from both
    # lists and still look internally consistent.  New reports record
    # checks_available; older ones map to the registry snapshot of their
    # EnvCert minor version.
    available = report.get("checks_available")
    expected_registry: frozenset[str] | None = None
    parts = version_tuple(report.get("envcert_version"))
    known_registry = KNOWN_REGISTRY_SNAPSHOTS.get((parts[0], parts[1])) if len(parts) >= 2 else None
    if available is not None:
        if not isinstance(available, list) or not all(isinstance(x, str) for x in available):
            problems.append("checks_available is not a list of check IDs")
        else:
            expected_registry = frozenset(available)
            if len(expected_registry) != len(available):
                problems.append("checks_available contains duplicates")
            if known_registry is not None:
                missing_available = sorted(known_registry - expected_registry)
                extra_available = sorted(expected_registry - known_registry)
                if missing_available:
                    problems.append(
                        "checks_available omits checks known to exist in this EnvCert version: "
                        f"{missing_available}"
                    )
                if extra_available:
                    problems.append(
                        "checks_available lists checks unknown to this EnvCert version: "
                        f"{extra_available}"
                    )
    elif modern:
        expected_registry = known_registry
    if isinstance(executed, list) and isinstance(not_executed, list) and expected_registry is not None:
        union = set(executed) | set(not_executed)
        missing = sorted(expected_registry - union)
        extra = sorted(union - expected_registry)
        if missing:
            problems.append(
                "checks_not_executed does not account for checks available in this EnvCert version: "
                f"{missing}"
            )
        if extra:
            problems.append(
                "report lists checks that were not available in its EnvCert version: "
                f"{extra}"
            )

    return problems


def suppressed_findings(report: dict[str, Any]) -> list[dict[str, Any]]:
    """Findings the report claims are covered by a baseline."""
    findings = report.get("findings")
    if not isinstance(findings, list):
        return []
    return [f for f in findings
            if isinstance(f, dict) and f.get("baseline_suppressed") is True
            and f.get("status") in (Status.FAIL.value, Status.WARN.value)]


def validate_baseline_suppression(report: dict[str, Any], baseline_report: dict[str, Any]) -> list[str]:
    """Recompute baseline suppression from the baseline report and compare it
    with the flags in the report under verification.

    Without this, a report could mark every failing finding as
    "baseline_suppressed" and assert a passing policy without ever showing
    the baseline it claims to rely on.
    """
    problems: list[str] = []
    if not isinstance(baseline_report, dict):
        return ["baseline report is not a JSON object"]
    base_findings = baseline_report.get("findings")
    if not isinstance(base_findings, list):
        return ["baseline report has no findings list"]
    baseline_fingerprints = {finding_fingerprint(f) for f in base_findings if isinstance(f, dict)}
    for finding in report.get("findings") or []:
        if not isinstance(finding, dict):
            continue
        if finding.get("status") not in (Status.FAIL.value, Status.WARN.value):
            continue
        if finding.get("baseline_suppressed") is not True:
            # Not suppressed: the operator simply chose not to suppress it.
            continue
        if finding_fingerprint(finding) not in baseline_fingerprints:
            label = f"{finding.get('check_id')} at {finding.get('path') or '-'}:{finding.get('line') or '-'}"
            problems.append(
                f"finding is marked baseline_suppressed but is not present in the baseline report: {label}")
    return problems
