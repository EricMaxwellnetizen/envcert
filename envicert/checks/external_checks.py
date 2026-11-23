"""Companion-tool orchestration (opt-in, --external-tools).

Envicert does not reimplement CVE scanning, Dockerfile linting or generic
SAST.  When the operator opts in and the tools are installed, this module
runs Hadolint (Dockerfile), Trivy (filesystem vulnerabilities) and Semgrep
(generic rules, only if a config is present in the task) and maps their
output into Envicert findings with clear provenance.  Absent tools produce
NOT_RUN — never a silent pass — and Envicert's own checks are unaffected.
"""
from __future__ import annotations

import json
import shutil
import subprocess

from envicert.checks.base import CheckContext, CheckInfo, check, finding, not_run, passed
from envicert.core.models import Severity, Status

TIMEOUT = 180


def _tool_info(cid, title, category, desc, remediation):
    return CheckInfo(cid, title, category, Severity.MEDIUM, desc, remediation,
                     "External tool output is mapped, not re-derived; the tool's own version and ruleset determine coverage.")


EC070 = _tool_info("EC070", "Hadolint Dockerfile lint (external companion)", "external",
                   "Runs hadolint on the task Dockerfile when installed and --external-tools is given.",
                   "Fix the hadolint findings or document suppressions in a .hadolint.yaml.")
EC071 = _tool_info("EC071", "Trivy filesystem vulnerability scan (external companion)", "external",
                   "Runs `trivy fs` (vuln+secret scanners) on the task directory when installed and --external-tools is given. May need network for its DB on first run.",
                   "Update or replace flagged dependencies/images; do not treat a clean Envicert static run as a CVE verdict.")
EC072 = _tool_info("EC072", "Semgrep scan (external companion, task-provided rules only)", "external",
                   "Runs semgrep only when the task ships a .semgrep.yml/.semgrep.yaml config, so rule choice stays with the task owner.",
                   "Address semgrep findings or curate the task's semgrep config.")


def _run(argv: list[str], cwd) -> tuple[int | None, str, str]:
    try:
        proc = subprocess.run(argv, cwd=str(cwd), capture_output=True, text=True, timeout=TIMEOUT)
        return proc.returncode, proc.stdout or "", proc.stderr or ""
    except Exception as exc:  # noqa: BLE001
        return None, "", str(exc)


def _gate(c: CheckContext, info: CheckInfo, tool: str):
    if not c.external_tools:
        return not_run(info, f"External companion tools are opt-in: re-run with --external-tools (and install {tool}).")
    exe = shutil.which(tool)
    if not exe:
        return not_run(info, f"{tool} is not installed on PATH; Envicert did not run it. Install {tool} or treat this check as not performed.")
    return None


@check(EC070)
def check_hadolint(c: CheckContext) -> list:
    ctx = c.task
    gate = _gate(c, EC070, "hadolint")
    if gate:
        return [gate]
    if ctx.dockerfile_path is None:
        return [finding(EC070, Status.NOT_APPLICABLE, "No Dockerfile in this task for hadolint to lint.", severity=Severity.INFO)]
    rel = ctx.dockerfile_path.relative_to(ctx.root).as_posix()
    res = _run(["hadolint", "--format", "json", rel], ctx.root)
    if res is None or res[0] is None:
        return [finding(EC070, Status.ERROR, f"hadolint failed to run: {res[2] if res else 'unknown'}", severity=Severity.INFO)]
    _rc, out, _err = res
    try:
        issues = json.loads(out) if out.strip() else []
    except ValueError:
        issues = []
    actionable = [i for i in issues if i.get("level") in ("error", "warning")]
    if actionable:
        first = actionable[0]
        sev = Severity.HIGH if first.get("level") == "error" else Severity.MEDIUM
        return [finding(EC070, Status.WARN, f"hadolint reports {len(actionable)} error/warning Dockerfile issue(s) (plus {len(issues) - len(actionable)} info/style), e.g. {first.get('code')}: {first.get('message')} ({rel}:{first.get('line')}).",
                        severity=sev, path=rel, line=first.get("line"), evidence={"issues": issues[:20], "tool": "hadolint"})]
    if issues:
        return [passed(EC070, f"hadolint reports only {len(issues)} info/style note(s), e.g. {issues[0].get('code')}; no error/warning issues.",
                       evidence={"issues": issues[:20], "tool": "hadolint", "dockerfile": rel})]
    return [passed(EC070, "hadolint reports no Dockerfile issues.", evidence={"tool": "hadolint", "dockerfile": rel})]


@check(EC071)
def check_trivy(c: CheckContext) -> list:
    ctx = c.task
    gate = _gate(c, EC071, "trivy")
    if gate:
        return [gate]
    res = _run(["trivy", "fs", "--scanners", "vuln,secret", "--format", "json", "--quiet", "."], ctx.root)
    if res is None or res[0] is None:
        return [finding(EC071, Status.ERROR, f"trivy failed to run: {res[2] if res else 'unknown'}", severity=Severity.INFO)]
    _rc, out, _err = res
    vulns = []
    try:
        data = json.loads(out) if out.strip() else {}
        for result in data.get("Results", []):
            for v in result.get("Vulnerabilities", []) or []:
                vulns.append({"id": v.get("VulnerabilityID"), "severity": v.get("Severity"), "pkg": v.get("PkgName")})
            for s in result.get("Secrets", []) or []:
                vulns.append({"id": s.get("RuleID"), "severity": s.get("Severity"), "pkg": result.get("Target")})
    except ValueError:
        return [finding(EC071, Status.ERROR, "trivy output could not be parsed as JSON.", severity=Severity.INFO)]
    high = [v for v in vulns if v["severity"] in ("CRITICAL", "HIGH")]
    if high:
        return [finding(EC071, Status.WARN, f"trivy reports {len(high)} CRITICAL/HIGH finding(s) (of {len(vulns)} total), e.g. {high[0]['id']} in {high[0]['pkg']}.",
                        severity=Severity.HIGH, evidence={"findings": vulns[:30], "tool": "trivy"})]
    if vulns:
        return [finding(EC071, Status.WARN, f"trivy reports {len(vulns)} lower-severity finding(s); review them in the trivy output.",
                        evidence={"findings": vulns[:30], "tool": "trivy"})]
    return [passed(EC071, "trivy reports no vulnerabilities/secrets in the task filesystem.", evidence={"tool": "trivy"})]


@check(EC072)
def check_semgrep(c: CheckContext) -> list:
    ctx = c.task
    gate = _gate(c, EC072, "semgrep")
    if gate:
        return [gate]
    config = next((f for f in ctx.files if f.rsplit("/", 1)[-1] in (".semgrep.yml", ".semgrep.yaml", "semgrep.yml", "semgrep.yaml")), None)
    if not config:
        return [finding(EC072, Status.NOT_APPLICABLE, "No semgrep config in the task (.semgrep.yml); Envicert does not impose generic rulesets.", severity=Severity.INFO)]
    res = _run(["semgrep", "--config", config, "--json", "--quiet", "."], ctx.root)
    if res is None or res[0] is None:
        return [finding(EC072, Status.ERROR, f"semgrep failed to run: {res[2] if res else 'unknown'}", severity=Severity.INFO)]
    _rc, out, _err = res
    try:
        results = (json.loads(out) if out.strip() else {}).get("results", [])
    except ValueError:
        results = []
    if results:
        first = results[0]
        return [finding(EC072, Status.WARN, f"semgrep (task config {config}) reports {len(results)} result(s), e.g. {first.get('check_id')} at {first.get('path')}:{first.get('start', {}).get('line')}.",
                        evidence={"results": [{"check_id": r.get("check_id"), "path": r.get("path")} for r in results[:20]], "tool": "semgrep", "config": config})]
    return [passed(EC072, f"semgrep (task config {config}) reports no results.", evidence={"tool": "semgrep", "config": config})]
