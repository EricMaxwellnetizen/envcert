from __future__ import annotations

from typing import Any

from envcert import __version__
from envcert.checks.base import REGISTRY

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
            "properties": {"severity": info.severity.value, "category": info.category, "tags": ["envcert", info.category]},
        })
    results = []
    for f in report.get("findings", []):
        if f["status"] not in ("FAIL", "WARN"):
            continue
        loc: dict[str, Any] = {}
        if f.get("path"):
            artifact_loc: dict[str, Any] = {"uri": f["path"]}
            region: dict[str, Any] = {}
            if f.get("line"):
                region = {"startLine": f["line"]}
            loc = {"physicalLocation": {"artifactLocation": artifact_loc, **({"region": region} if region else {})}}
        result: dict[str, Any] = {
            "ruleId": f["check_id"],
            "level": LEVEL.get(f["severity"], "warning"),
            "message": {"text": f["description"]},
            "locations": [loc] if loc else [],
            "properties": {"status": f["status"], "confidence": f.get("confidence"), "evidence": f.get("evidence")},
        }
        if f.get("baseline_suppressed"):
            result["suppressions"] = [{"kind": "external", "justification": "identical finding present in the EnvCert baseline report"}]
            result["properties"]["baseline_suppressed"] = True
        results.append(result)
    return {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "EnvCert", "version": __version__,
                                "informationUri": "https://github.com/EricMaxwellnetizen/envcert", "rules": rules}},
            "results": results,
            "properties": {"envcert_report_schema": report.get("schema_version"),
                           "bundle_digest_sha256": (report.get("environment") or {}).get("bundle_digest_sha256"),
                           "policy_passed": (report.get("policy") or {}).get("passed")},
        }],
    }
