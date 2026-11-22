"""Markdown report: the format pull requests and issues actually render.

Used by ``envcert check --format markdown`` and by the GitHub Action's
step-summary / PR-comment support.  Deterministic ordering, no timestamps
in the body beyond the report header, FAIL/WARN first.
"""
from __future__ import annotations

from typing import Any

ICON = {"PASS": "✅", "FAIL": "❌", "WARN": "⚠️", "NOT_RUN": "⏭️", "NOT_APPLICABLE": "➖", "ERROR": "💥"}
ORDER = {"FAIL": 0, "WARN": 1, "ERROR": 2, "PASS": 3, "NOT_RUN": 4, "NOT_APPLICABLE": 5}


def _cell(text: Any) -> str:
    return str(text or "").replace("|", "\\|").replace("\n", " ")


def to_markdown(report: dict[str, Any]) -> str:
    env = report["environment"]
    policy = report["policy"]
    summary = report["summary"]
    verdict = "PASSED ✅" if policy["passed"] else "FAILED ❌"
    lines = [
        f"## EnvCert {report['envcert_version']} — {verdict}",
        "",
        f"**Task:** `{_cell(env['task_name'])}` · adapter `{_cell(env['adapter'])}` · "
        f"profile `{_cell(report['execution']['profile'])}` · execution `{_cell(report['execution']['mode'])}`",
        f"**Bundle:** `sha256:{env['bundle_digest_sha256'][:16]}…` · fail-on: {', '.join(policy['fail_on'])}",
        "",
        "| Status | Check | Severity | Finding |",
        "|---|---|---|---|",
    ]
    for f in sorted(report["findings"], key=lambda x: (ORDER.get(x["status"], 9), x["check_id"])):
        if f["status"] in ("PASS", "NOT_APPLICABLE") and summary.get("total_findings", 0) > 60:
            continue
        loc = _cell(f.get("path") or "")
        if f.get("line"):
            loc += f":{f['line']}"
        title = _cell(f["title"])
        if loc:
            title += f" (`{loc}`)"
        lines.append(f"| {ICON.get(f['status'], '')} {f['status']} | {f['check_id']} | {f['severity']} | {title} |")
    lines += ["", f"**Summary:** {summary['total_findings']} findings {summary['by_status']} · policy **{verdict}**"]
    bad = [f for f in report["findings"] if f["status"] in ("FAIL", "WARN")]
    if bad:
        lines += ["", "### What to fix", ""]
        for f in sorted(bad, key=lambda x: (ORDER.get(x["status"], 9), x["check_id"]))[:15]:
            lines.append(f"- **{f['check_id']}** {_cell(f['title'])} — {_cell(f.get('remediation'))}")
    lines += ["", "_EnvCert reports evidence about checked properties; it is not a certification that an environment is unhackable._", ""]
    return "\n".join(lines)
