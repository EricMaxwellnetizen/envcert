from __future__ import annotations

from typing import Any

ICON = {"PASS": "PASS", "FAIL": "FAIL", "WARN": "WARN", "NOT_RUN": "SKIP", "NOT_APPLICABLE": "N/A ", "ERROR": "ERR "}


def to_text(report: dict[str, Any]) -> str:
    env = report["environment"]
    lines = []
    lines.append(f"Envicert {report['envicert_version']}  report schema {report['schema_version']}")
    lines.append(f"Task: {env['task_name']}  adapter={env['adapter']}  files={env['file_count']}")
    lines.append(f"Bundle digest (sha256): {env['bundle_digest_sha256']}")
    ex = report["execution"]
    lines.append(f"Profile: {ex['profile']}  execution: {ex['mode']}  fail_on: {', '.join(ex['fail_on'])}")
    if ex.get("runner"):
        lines.append(f"Runner: {ex['runner']['name']} available={ex['runner']['available']} -- {ex['runner']['isolation']}")
    lines.append("")
    order = {"FAIL": 0, "WARN": 1, "ERROR": 2, "PASS": 3, "NOT_RUN": 4, "NOT_APPLICABLE": 5}
    for f in sorted(report["findings"], key=lambda x: (order.get(x["status"], 9), x["check_id"])):
        loc = f.get("path") or f.get("artifact") or ""
        if f.get("line"):
            loc += f":{f['line']}"
        lines.append(f"[{ICON.get(f['status'], f['status'])}] {f['check_id']} ({f['severity']}/{f['status']}) {f['title']}")
        lines.append(f"       {f['description']}")
        if loc:
            lines.append(f"       at: {loc}")
        if f["status"] in ("FAIL", "WARN") and f.get("remediation"):
            lines.append(f"       fix: {f['remediation']}")
    lines.append("")
    s = report["summary"]
    lines.append(f"Summary: {s['total_findings']} findings {s['by_status']}")
    lines.append(f"Policy: {'PASSED' if report['policy']['passed'] else 'FAILED'} (fail_on={', '.join(report['policy']['fail_on'])})")
    lines.append("Limitations: static/dynamic evidence only -- not a certification of unhackability. See report JSON for full limitations.")
    return "\n".join(lines) + "\n"
