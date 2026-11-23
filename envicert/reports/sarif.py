from __future__ import annotations

from typing import Any

from envicert import __version__
from envicert.checks.base import REGISTRY

LEVEL = {"CRITICAL": "error", "HIGH": "error", "MEDIUM": "warning", "LOW": "note", "INFO": "none"}


def to_sarif(report: dict[str, Any]) -> dict[str, Any]:
    rules = []
    for cid, (info, _fn) in sorted(REGISTRY.items()):
        rules.append({
            "id": cid, "name": info.title.replace(" ", ""),
            "shortDescription": {"text": info.title},
            "fullDescription": {"text": info.description},
            "help": {"text": info.remediation or info.description},
            "defaultConfiguration": {"level": LEVEL[info.severity.value]},
            "properties": {"severity": info.severity.value, "category": info.category, "tags": ["envicert", info.category]},
        })
    results = []
    import hashlib

    for f in report.get("findings", []):
        # FAIL/WARN are code-scanning results; ERROR means a check could not
        # run, which code scanning must surface rather than silently drop.
        if f["status"] not in ("FAIL", "WARN", "ERROR"):
            continue
        loc: dict[str, Any] = {}
        if f.get("path"):
            artifact_loc: dict[str, Any] = {"uri": f["path"]}
            region: dict[str, Any] = {}
            if f.get("line"):
                region = {"startLine": f["line"]}
            loc = {"physicalLocation": {"artifactLocation": artifact_loc, **({"region": region} if region else {})}}
        fingerprint = hashlib.sha256(
            f"{f['check_id']}|{f.get('path')}|{f.get('line')}|{f['status']}|{f['severity']}".encode()
        ).hexdigest()
        result: dict[str, Any] = {
            "ruleId": f["check_id"],
            "level": LEVEL.get(f["severity"], "warning"),
            "message": {"text": f["description"]},
            "locations": [loc] if loc else [],
            "partialFingerprints": {"envicert/v1": fingerprint},
            "properties": {"status": f["status"], "confidence": f.get("confidence"), "evidence": f.get("evidence")},
        }
        if f.get("remediation"):
            result["fixes"] = [{"description": {"text": f["remediation"]}}]
        if f.get("baseline_suppressed"):
            result["suppressions"] = [{"kind": "external", "justification": "identical finding present in the Envicert baseline report"}]
            result["properties"]["baseline_suppressed"] = True
        results.append(result)
    return {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "Envicert", "version": __version__,
                                "informationUri": "https://github.com/EricMaxwellnetizen/envicert", "rules": rules}},
            "results": results,
            "properties": {"envicert_report_schema": report.get("schema_version"),
                           "bundle_digest_sha256": (report.get("environment") or {}).get("bundle_digest_sha256"),
                           "policy_passed": (report.get("policy") or {}).get("passed")},
        }],
    }
