"""Self-contained HTML report: one file, no external assets, shareable.

Benchmark maintainers need to *show* an audit to people who will never
install the tool.  ``envcert check --format html`` emits a single escaped,
dependency-free page (inline CSS only) that renders anywhere.
"""
from __future__ import annotations

import html
from typing import Any

ORDER = {"FAIL": 0, "WARN": 1, "ERROR": 2, "PASS": 3, "NOT_RUN": 4, "NOT_APPLICABLE": 5}
COLOR = {"PASS": "#137333", "FAIL": "#b3261e", "WARN": "#b06000", "NOT_RUN": "#5f6368",
         "NOT_APPLICABLE": "#5f6368", "ERROR": "#b3261e"}

CSS = """
body{font-family:system-ui,-apple-system,Segoe UI,Roboto,sans-serif;margin:2rem auto;max-width:62rem;padding:0 1rem;color:#1f2328}
h1{font-size:1.4rem} table{border-collapse:collapse;width:100%;font-size:.9rem}
th,td{border:1px solid #d0d7de;padding:.4rem .5rem;text-align:left;vertical-align:top}
th{background:#f6f8fa} code{background:#f6f8fa;padding:.1rem .3rem;border-radius:4px}
.meta{color:#57606a} .verdict{font-weight:700}
"""


def to_html(report: dict[str, Any]) -> str:
    env = report["environment"]
    policy = report["policy"]
    summary = report["summary"]
    verdict = "PASSED" if policy["passed"] else "FAILED"
    rows = []
    for f in sorted(report["findings"], key=lambda x: (ORDER.get(x["status"], 9), x["check_id"])):
        loc = html.escape(str(f.get("path") or ""))
        if f.get("line"):
            loc += f":{f['line']}"
        detail = html.escape(str(f.get("description") or ""))
        fix = html.escape(str(f.get("remediation") or "")) if f["status"] in ("FAIL", "WARN") else ""
        rows.append(
            f"<tr><td style='color:{COLOR.get(f['status'], '#000')};font-weight:600'>{html.escape(f['status'])}</td>"
            f"<td>{html.escape(f['check_id'])}</td><td>{html.escape(f['severity'])}</td>"
            f"<td><strong>{html.escape(f['title'])}</strong><br>{detail}"
            + (f"<br><em>Fix:</em> {fix}" if fix else "")
            + (f"<br><code>{loc}</code>" if loc else "") + "</td></tr>"
        )
    by_status = html.escape(str(summary["by_status"]))
    return f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>EnvCert report — {html.escape(str(env['task_name']))}</title>
<style>{CSS}</style></head><body>
<h1>EnvCert {html.escape(str(report['envcert_version']))} — <span class="verdict">{verdict}</span></h1>
<p class="meta">Task <code>{html.escape(str(env['task_name']))}</code> · adapter {html.escape(str(env['adapter']))} ·
profile {html.escape(str(report['execution']['profile']))} · execution {html.escape(str(report['execution']['mode']))}<br>
Bundle sha256 <code>{html.escape(str(env['bundle_digest_sha256']))}</code> · schema {html.escape(str(report['schema_version']))}</p>
<p>{summary['total_findings']} findings · {by_status} · fail-on: {html.escape(', '.join(policy['fail_on']))}</p>
<table><thead><tr><th>Status</th><th>Check</th><th>Severity</th><th>Finding</th></tr></thead>
<tbody>
{chr(10).join(rows)}
</tbody></table>
<p class="meta">EnvCert reports evidence about checked properties; it is not a certification that an environment is unhackable. Verify this report with <code>envcert verify</code>.</p>
</body></html>
"""
