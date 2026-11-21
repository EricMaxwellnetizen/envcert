from __future__ import annotations

import datetime as _dt
from pathlib import Path
from typing import Any

# import for registry side effects
import envcert.checks.dynamic_checks  # noqa: F401,E402
import envcert.checks.external_checks  # noqa: F401,E402
import envcert.checks.static_checks  # noqa: F401,E402
from envcert import REPORT_SCHEMA_VERSION, __version__
from envcert.adapters import generic as generic_adapter
from envcert.adapters import harbor as harbor_adapter
from envcert.adapters import inspect_adapter
from envcert.adapters import nemo_gym as nemo_adapter
from envcert.adapters.base import TaskContext
from envcert.checks.base import REGISTRY, CheckContext
from envcert.core.config import Settings
from envcert.core.digests import bundle_digest, sha256_file
from envcert.core.models import Finding, Severity, Status
from envcert.runners.docker_runner import DockerRunner
from envcert.runners.local_runner import LocalPythonRunner

LIMITATIONS = [
    "Static analysis cannot prove runtime agent visibility; potential exposures are labelled with confidence and limitations.",
    "A passing reference solution does not prove incorrect solutions fail; use negative controls and mutation testing where supported.",
    "Docker is a shared-kernel boundary, not a VM; dynamic docker runs are restricted but not a guarantee of host safety.",
    "Local-python execution provides no sandbox and must only be used on trusted tasks.",
    "EnvCert reports evidence about checked properties; it is not a certification that an environment is unhackable.",
]


def load_task(path: Path, adapter_name: str = "auto") -> TaskContext:
    path = Path(path)
    if adapter_name == "harbor" or (adapter_name == "auto" and harbor_adapter.is_harbor_task(path)):
        return harbor_adapter.load(path)
    if adapter_name == "nemo-gym":
        return nemo_adapter.load(path)
    if adapter_name == "inspect":
        return inspect_adapter.load(path)
    if adapter_name == "generic":
        return generic_adapter.load(path)
    if adapter_name == "auto":
        if nemo_adapter.is_nemo_gym(path):
            return nemo_adapter.load(path)
        if inspect_adapter.is_inspect(path):
            return inspect_adapter.load(path)
        return generic_adapter.load(path)
    raise ValueError(f"unknown adapter {adapter_name!r}")


def resolve_image_digest(settings: Settings) -> tuple[str | None, str]:
    """Return (digest, note). Explicit digest wins; then a docker-inspect of
    --image; a bare tag is never treated as a digest."""
    import re
    import shutil
    import subprocess

    if settings.image_digest:
        d = settings.image_digest.strip()
        return (d if re.fullmatch(r"sha256:[0-9a-f]{64}", d) else None,
                "explicit --image-digest" if re.fullmatch(r"sha256:[0-9a-f]{64}", d) else "invalid --image-digest ignored (expected sha256:<64 hex>)")
    if settings.image:
        ref = settings.image
        if "@sha256:" in ref:
            return "sha256:" + ref.rsplit("@sha256:", 1)[1], "digest taken from --image reference"
        exe = shutil.which("docker")
        if not exe:
            return None, f"could not resolve digest for {ref!r}: docker not installed (pass --image-digest explicitly)"
        try:
            proc = subprocess.run([exe, "image", "inspect", "--format", "{{.Id}}", ref],
                                  capture_output=True, text=True, timeout=30)
            if proc.returncode == 0 and proc.stdout.strip().startswith("sha256:"):
                return proc.stdout.strip(), f"resolved --image {ref!r} via docker image inspect (.Id)"
            return None, f"could not resolve digest for {ref!r}: image not present locally or inspect failed"
        except Exception as exc:  # noqa: BLE001
            return None, f"could not resolve digest for {ref!r}: {exc}"
    return None, ""


def selected_checks(settings: Settings) -> list[str]:
    ids = []
    for cid, (info, _fn) in sorted(REGISTRY.items()):
        if settings.enabled is not None and cid not in settings.enabled:
            continue
        if cid in settings.disabled:
            continue
        if settings.categories is not None and info.category not in settings.categories and not info.dynamic:
            continue
        ids.append(cid)
    return ids


def run_checks(task_path: Path, settings: Settings, adapter_name: str = "auto") -> dict[str, Any]:
    ctx = load_task(task_path, adapter_name)
    digest, file_count = bundle_digest(ctx.root)
    check_ctx = CheckContext(task=ctx, execution=settings.execution, repetitions=settings.repetitions,
                             enable_mutation=settings.enable_mutation, external_tools=settings.external_tools,
                             runner_command=settings.runner_command)
    image_digest, image_note = resolve_image_digest(settings)
    if image_note and (settings.image or settings.image_digest):
        ctx.warnings.append(f"image digest: {image_note}")
    findings: list[Finding] = []
    errors: list[dict[str, str]] = []
    executed: list[str] = []
    for cid in selected_checks(settings):
        info, fn = REGISTRY[cid]
        executed.append(cid)
        try:
            findings.extend(fn(check_ctx))
        except Exception as exc:  # a crashing check must never become a silent PASS
            errors.append({"check_id": cid, "error": f"{type(exc).__name__}: {exc}"})
            findings.append(Finding(check_id=cid, title=info.title,
                                    description=f"Check raised an error and did not complete: {exc}",
                                    category=info.category, severity=Severity.INFO, status=Status.ERROR,
                                    evidence={"error": str(exc)}))
    fail_on = settings.fail_on
    policy_passed = not any(f.status in (Status.FAIL, Status.WARN) and f.severity in fail_on for f in findings) \
        and not any(f.status == Status.ERROR for f in findings)
    counts: dict[str, int] = {}
    for f in findings:
        counts[f.status.value] = counts.get(f.status.value, 0) + 1
    severity_counts: dict[str, int] = {}
    for f in findings:
        if f.status in (Status.FAIL, Status.WARN):
            severity_counts[f.severity.value] = severity_counts.get(f.severity.value, 0) + 1
    runner_info = None
    if settings.execution == "docker":
        ri = DockerRunner().info()
        runner_info = {"name": ri.name, "available": ri.available, "reason": ri.reason, "isolation": ri.isolation}
    elif settings.execution == "local-python":
        ri = LocalPythonRunner().info()
        runner_info = {"name": ri.name, "available": ri.available, "reason": ri.reason, "isolation": ri.isolation}
    elif settings.execution == "external":
        from envcert.runners.external_runner import ExternalRunner

        ri = ExternalRunner(settings.runner_command).info()
        runner_info = {"name": ri.name, "available": ri.available, "reason": ri.reason, "isolation": ri.isolation}
    if image_digest is None and check_ctx.shared.get("image_digest"):
        image_digest = check_ctx.shared["image_digest"]
    verifier_digest = _dir_digest(ctx, ctx.tests_dir)
    solution_digest = _dir_digest(ctx, ctx.solution_dir)
    report: dict[str, Any] = {
        "schema_version": REPORT_SCHEMA_VERSION,
        "envcert_version": __version__,
        "generated_at": _dt.datetime.now(_dt.UTC).isoformat().replace("+00:00", "Z"),
        "assurance_context": "supplier-self-testing (run by whoever invoked EnvCert; not independent third-party auditing unless run by one)",
        "environment": {
            "task_name": ctx.task_name,
            "task_path": str(ctx.root),
            "adapter": ctx.adapter,
            "bundle_digest_sha256": digest,
            "file_count": file_count,
            "verifier_digest_sha256": verifier_digest,
            "solution_digest_sha256": solution_digest,
            "image_digest": image_digest,
            "image_reference": settings.image,
            "warnings": ctx.warnings,
        },
        "execution": {
            "mode": settings.execution,
            "profile": settings.profile,
            "config_source": settings.source,
            "fail_on": settings.fail_on_names(),
            "repetitions": settings.repetitions,
            "mutation_enabled": settings.enable_mutation,
            "external_tools": settings.external_tools,
            "runner": runner_info,
        },
        "checks_executed": executed,
        "checks_not_executed": sorted(set(REGISTRY) - set(executed)),
        "findings": [f.to_dict() for f in findings],
        "summary": {"total_findings": len(findings), "by_status": counts, "by_severity_failing": severity_counts},
        "errors": errors,
        "policy": {"passed": policy_passed,
                   "fail_on": settings.fail_on_names(),
                   "rule": "policy fails when any FAIL/WARN finding has a severity in fail_on, or any check ERRORs"},
        "limitations": LIMITATIONS + ctx.warnings,
    }
    return report


def _dir_digest(ctx: TaskContext, directory: Path | None) -> str | None:
    if directory is None or not directory.is_dir():
        return None
    import hashlib

    h = hashlib.sha256()
    prefix = directory.relative_to(ctx.root).as_posix() + "/"
    for rel in ctx.files:
        if rel.startswith(prefix):
            h.update(rel.encode())
            h.update(sha256_file(ctx.root / rel).encode())
    return h.hexdigest()
