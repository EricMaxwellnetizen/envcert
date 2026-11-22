from __future__ import annotations

import datetime as _dt
from pathlib import Path
from typing import Any

# import for registry side effects
import envcert.checks.cheat_checks  # noqa: F401,E402
import envcert.checks.dataset_checks  # noqa: F401,E402
import envcert.checks.dynamic_checks  # noqa: F401,E402
import envcert.checks.external_checks  # noqa: F401,E402
import envcert.checks.static_checks  # noqa: F401,E402
from envcert import REPORT_SCHEMA_VERSION, __version__
from envcert.adapters import dataset as dataset_adapter
from envcert.adapters import generic as generic_adapter
from envcert.adapters import harbor as harbor_adapter
from envcert.adapters import inspect_adapter
from envcert.adapters import nemo_gym as nemo_adapter
from envcert.adapters.base import TaskContext
from envcert.checks.base import REGISTRY, CheckContext
from envcert.core.config import Settings
from envcert.core.digests import bundle_digest, sha256_file
from envcert.core.errors import ConfigError
from envcert.core.images import image_digest_from_reference, normalize_digest
from envcert.core.models import Finding, Severity, Status
from envcert.core.report import (
    finding_fingerprint,
    registry_snapshot,
    version_at_least,
)
from envcert.runners.docker_runner import DockerRunner
from envcert.runners.local_runner import LocalPythonRunner

LIMITATIONS = [
    "Static analysis cannot prove runtime agent visibility; potential exposures are labelled with confidence and limitations.",
    "A passing reference solution does not prove incorrect solutions fail; use negative controls and mutation testing where supported.",
    "Docker is a shared-kernel boundary, not a VM; dynamic docker runs are restricted but not a guarantee of host safety.",
    "Local-python execution provides no sandbox and must only be used on trusted tasks.",
    "EnvCert reports evidence about checked properties; it is not a certification that an environment is unhackable.",
]

_PLUGINS_LOADED = False
PLUGIN_LOAD_ERRORS: list[str] = []


def load_plugin_checks() -> list[str]:
    """Import third-party checks registered under the ``envcert.checks``
    entry-point group.  A broken plugin is reported, never silently loaded
    or silently dropped."""
    global _PLUGINS_LOADED
    if _PLUGINS_LOADED:
        return PLUGIN_LOAD_ERRORS
    _PLUGINS_LOADED = True
    try:
        from importlib.metadata import entry_points

        eps = entry_points(group="envcert.checks")
    except Exception as exc:  # noqa: BLE001
        PLUGIN_LOAD_ERRORS.append(f"plugin discovery failed: {type(exc).__name__}: {exc}")
        return PLUGIN_LOAD_ERRORS
    for ep in eps:
        try:
            ep.load()
        except Exception as exc:  # noqa: BLE001
            PLUGIN_LOAD_ERRORS.append(f"plugin check {ep.name!r} failed to load: {type(exc).__name__}: {exc}")
    return PLUGIN_LOAD_ERRORS


def load_task(path: Path, adapter_name: str = "auto") -> TaskContext:
    path = Path(path)
    if adapter_name == "dataset" or (adapter_name == "auto" and dataset_adapter.is_dataset_path(path)):
        return dataset_adapter.load(path)
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
    """Return (digest, note), or raise ConfigError when an explicit image
    reference cannot be bound honestly.

    Explicit `--image-digest` wins.  For `--image`, a name@sha256 reference is
    used directly; otherwise Docker's RepoDigests are preferred (the registry
    manifest digest).  A locally built image with no RepoDigests falls back to
    the local image ID *with an explicit warning*, because that is not a
    registry manifest digest.  A bare tag is never silently treated as a
    digest.
    """
    import json
    import re
    import shutil
    import subprocess

    digest_re = re.compile(r"sha256:[0-9a-f]{64}")
    explicit = normalize_digest(settings.image_digest, "--image-digest") if settings.image_digest else None
    reference_digest = image_digest_from_reference(settings.image) if settings.image else None
    if explicit and reference_digest and explicit != reference_digest:
        raise ConfigError(
            f"--image-digest {explicit} conflicts with the digest in --image "
            f"{settings.image!r} ({reference_digest}); refusing to bind contradictory image evidence"
        )
    if explicit:
        return explicit, "explicit --image-digest"
    if settings.image:
        ref = settings.image.strip()
        if reference_digest:
            return reference_digest, "digest taken from --image reference"
        exe = shutil.which("docker")
        if not exe:
            raise ConfigError(
                f"cannot resolve a digest for --image {ref!r}: docker is not installed. "
                "Pass --image-digest sha256:<64 hex> or use name@sha256:<digest>."
            )
        try:
            proc = subprocess.run([exe, "image", "inspect", "--format", "{{json .RepoDigests}}", ref],
                                  capture_output=True, text=True, timeout=30)
        except Exception as exc:  # noqa: BLE001
            raise ConfigError(f"cannot resolve a digest for --image {ref!r}: {exc}") from exc
        if proc.returncode != 0:
            raise ConfigError(
                f"cannot resolve a digest for --image {ref!r}: image is not present locally or inspect failed. "
                "Pull the image, pass --image-digest explicitly, or use name@sha256:<digest>."
            )
        try:
            repo_digests = json.loads(proc.stdout.strip() or "[]")
        except ValueError:
            repo_digests = []
        last = ref.rsplit("/", 1)[-1]
        repo_name = ref.rsplit(":", 1)[0] if ":" in last else ref

        def _normalize_repo(name: str) -> str:
            name = name.lower()
            for prefix in ("docker.io/", "index.docker.io/"):
                if name.startswith(prefix):
                    name = name[len(prefix):]
            return name[len("library/"):] if name.startswith("library/") else name

        candidates = [
            entry for entry in (repo_digests if isinstance(repo_digests, list) else [])
            if isinstance(entry, str) and "@sha256:" in entry
        ]
        chosen = next(
            (e for e in candidates if _normalize_repo(e.rsplit("@", 1)[0]) == _normalize_repo(repo_name)),
            None,
        )
        if chosen is not None:
            d = "sha256:" + chosen.rsplit("@sha256:", 1)[1].lower()
            if digest_re.fullmatch(d):
                return d, f"resolved --image {ref!r} via docker image inspect (RepoDigests manifest digest)"
        try:
            proc = subprocess.run([exe, "image", "inspect", "--format", "{{.Id}}", ref],
                                  capture_output=True, text=True, timeout=30)
        except Exception as exc:  # noqa: BLE001
            raise ConfigError(f"cannot resolve a digest for --image {ref!r}: {exc}") from exc
        if proc.returncode == 0 and digest_re.fullmatch(proc.stdout.strip().lower()):
            return proc.stdout.strip().lower(), (
                f"resolved --image {ref!r} via docker image inspect: only a local image ID is available "
                "(no matching registry RepoDigests); this is not a registry manifest digest"
            )
        raise ConfigError(f"cannot resolve a digest for --image {ref!r}: inspect returned no usable digest")
    return None, ""


def validate_check_selection(settings: Settings) -> None:
    """Reject unknown --enable/--disable IDs before any task is inspected."""
    known = set(REGISTRY)
    requested = set(settings.enabled or []) | set(settings.disabled)
    unknown = sorted(requested - known)
    if unknown:
        raise ConfigError(
            f"unknown check ID(s): {', '.join(unknown)}; run 'envcert list-checks' to see valid IDs"
        )


def selected_checks(settings: Settings) -> list[str]:
    ids = []
    for cid, (info, _fn) in sorted(REGISTRY.items()):
        if settings.enabled is not None:
            # An explicit list is the operator's selection; it overrides the
            # profile's category filter instead of being intersected with it.
            if cid not in settings.enabled:
                continue
        elif settings.categories is not None and info.category not in settings.categories and not info.dynamic:
            continue
        if cid in settings.disabled:
            continue
        ids.append(cid)
    return ids


def run_checks(task_path: Path, settings: Settings, adapter_name: str = "auto") -> dict[str, Any]:
    validate_check_selection(settings)
    ctx = load_task(task_path, adapter_name)
    for plugin_error in load_plugin_checks():
        ctx.warnings.append(plugin_error)
    digest, file_count = bundle_digest(ctx.root, warnings=ctx.warnings, only=ctx.bundle_files)
    if ctx.adapter == "dataset" and settings.enabled is None:
        # A data file has no Dockerfile/verifier bundle to lint: run the
        # dataset suite plus the generic content checks that apply to rows.
        from dataclasses import replace

        settings = replace(settings, enabled=["EC001", "EC013", "EC080", "EC081", "EC082", "EC083", "EC084", "EC085"])
    # Naming an external-companion check explicitly is itself a request to run
    # it; otherwise `--enable EC070` would select a check that always returns
    # NOT_RUN because --external-tools was not also passed.
    external_tools = settings.external_tools or any(
        cid in REGISTRY and REGISTRY[cid][0].category == "external"
        for cid in (settings.enabled or [])
    )
    check_ctx = CheckContext(task=ctx, execution=settings.execution, repetitions=settings.repetitions,
                             enable_mutation=settings.enable_mutation, max_mutants=settings.max_mutants,
                             external_tools=external_tools,
                             runner_command=settings.runner_command)
    image_digest, image_note = resolve_image_digest(settings)
    if image_note and settings.image and "not a registry manifest digest" in image_note:
        ctx.warnings.append(f"image digest: {image_note}")
    findings: list[Finding] = []
    errors: list[dict[str, str]] = []
    executed: list[str] = []
    checks_to_run = selected_checks(settings)
    if not checks_to_run:
        raise ConfigError(
            "no checks selected; refusing to produce a vacuous PASS report "
            "(review --enable/--disable and [checks] enabled/disabled)"
        )
    for cid in checks_to_run:
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
    suppressed_count = 0
    if settings.baseline:
        import json as _json

        baseline_path = Path(settings.baseline)
        if not baseline_path.is_file():
            raise ConfigError(f"baseline report not found: {baseline_path}")
        try:
            baseline_report = _json.loads(baseline_path.read_text(encoding="utf-8"))
        except Exception as exc:
            raise ConfigError(f"baseline report is not valid JSON: {exc}") from exc
        if not isinstance(baseline_report, dict):
            raise ConfigError("baseline report root is not a JSON object")
        baseline_findings = baseline_report.get("findings")
        if not isinstance(baseline_findings, list):
            raise ConfigError("baseline report has no findings list")
        for index, finding in enumerate(baseline_findings):
            if not isinstance(finding, dict):
                raise ConfigError(f"baseline report findings[{index}] is not an object")
        baseline_keys = {finding_fingerprint(f) for f in baseline_findings}
        for f in findings:
            if f.status in (Status.FAIL, Status.WARN) and finding_fingerprint(f.to_dict()) in baseline_keys:
                f.baseline_suppressed = True
                suppressed_count += 1
    fail_on = settings.fail_on
    policy_passed = not any(f.status in (Status.FAIL, Status.WARN) and f.severity in fail_on and not f.baseline_suppressed for f in findings) \
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
        import re

        candidate = str(check_ctx.shared["image_digest"]).lower()
        if re.fullmatch(r"sha256:[0-9a-f]{64}", candidate):
            image_digest = candidate
        else:
            ctx.warnings.append(
                f"runner returned invalid image_digest {check_ctx.shared['image_digest']!r}; ignored "
                "(expected sha256:<64 hex>)"
            )
    if check_ctx.shared.get("image_digest_note"):
        ctx.warnings.append(str(check_ctx.shared["image_digest_note"]))
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
            "external_tools": external_tools,
            # Recorded so --recheck can distinguish a deliberate subset from a
            # report that silently omitted checks.
            "selection": {
                "enabled": settings.enabled,
                "disabled": settings.disabled,
                "categories": settings.categories,
                "external_tools": external_tools,
            },
            "runner": runner_info,
        },
        "checks_available": sorted(REGISTRY),
        "checks_executed": executed,
        "checks_not_executed": sorted(set(REGISTRY) - set(executed)),
        "findings": [f.to_dict() for f in findings],
        "summary": {"total_findings": len(findings), "by_status": counts, "by_severity_failing": severity_counts,
                    "baseline_suppressed": suppressed_count, "baseline": settings.baseline},
        "errors": errors,
        "policy": {"passed": policy_passed,
                   "fail_on": settings.fail_on_names(),
                   "rule": "policy fails when any FAIL/WARN finding has a severity in fail_on, or any check ERRORs"},
        "limitations": LIMITATIONS + ctx.warnings,
    }
    return report


def recheck_report(report: dict[str, Any], task_path: Path) -> list[str]:
    """Re-run the report's recorded static check selection and compare findings.

    This answers a question report schema validation cannot: *are the findings
    in this report the findings EnvCert actually produces for this task?*  It
    also checks that the report did not quietly shrink its selection: a report
    that omits checks from both `checks_executed` and `checks_not_executed`, or
    that claims a full run while listing only a subset, fails.

    Dynamic checks are not re-run (they execute task code); external-tool
    checks are skipped because their availability changes between machines.
    """
    from collections import Counter

    from envcert.core.config import PROFILES, Settings
    from envcert.core.errors import ConfigError

    if not isinstance(report, dict):
        return ["report root is not a JSON object"]
    problems: list[str] = []
    execution = report.get("execution")
    environment = report.get("environment")
    if not isinstance(execution, dict):
        return ["report.execution is not an object"]
    if not isinstance(environment, dict):
        environment = {}
    profile = execution.get("profile") or "harbor"
    if not isinstance(profile, str) or profile not in PROFILES:
        return [f"report names an unknown profile {profile!r}; cannot re-check"]
    executed = report.get("checks_executed")
    if not isinstance(executed, list) or not all(isinstance(item, str) for item in executed):
        return ["report.checks_executed is not a list of check IDs"]
    findings = report.get("findings")
    if not isinstance(findings, list) or not all(isinstance(item, dict) for item in findings):
        return ["report.findings is not a list of objects"]
    unknown = [cid for cid in executed if cid not in REGISTRY]
    if unknown:
        problems.append(f"report references unknown check IDs: {sorted(unknown)}")
    not_executed = report.get("checks_not_executed")
    if not_executed is not None and (
            not isinstance(not_executed, list) or not all(isinstance(item, str) for item in not_executed)):
        return problems + ["report.checks_not_executed is not a list of check IDs"]

    selection = execution.get("selection")
    if selection is not None:
        if not isinstance(selection, dict):
            return problems + ["report.execution.selection is not an object"]
        enabled = selection.get("enabled")
        disabled = selection.get("disabled") or []
        categories = selection.get("categories")
        if enabled is not None and (
                not isinstance(enabled, list) or not all(isinstance(item, str) for item in enabled)):
            return problems + ["report.execution.selection.enabled is not a list of check IDs"]
        if not isinstance(disabled, list) or not all(isinstance(item, str) for item in disabled):
            return problems + ["report.execution.selection.disabled is not a list of check IDs"]
        if categories is not None and (
                not isinstance(categories, list) or not all(isinstance(item, str) for item in categories)):
            return problems + ["report.execution.selection.categories is not a list of category names"]
        settings = Settings(
            profile=profile,
            enabled=enabled,
            disabled=list(disabled),
            categories=categories if categories is not None else PROFILES[profile]["categories"],
            execution="none",
            external_tools=bool(selection.get("external_tools", False)),
        )
        expected = selected_checks(settings)
        missing = sorted(set(expected) - set(executed))
        extra = sorted(set(executed) - set(expected))
        if missing:
            problems.append(
                "report omits checks selected by its recorded configuration: "
                f"{missing}"
            )
        if extra:
            problems.append(
                "report lists checks not selected by its recorded configuration: "
                f"{extra}"
            )
        static_ids = [
            cid for cid in expected
            if cid in REGISTRY
            and not REGISTRY[cid][0].dynamic
            and REGISTRY[cid][0].category != "external"
        ]
    else:
        # Older reports did not record the selection.  A full run (empty
        # checks_not_executed and every then-available check in
        # checks_executed) is still re-checkable; a subset is not, because it
        # cannot be distinguished from a report that silently omitted checks.
        if not_executed:
            return problems + [
                "report does not record its check selection; cannot re-check a report that "
                "skipped checks (regenerate it with EnvCert >= 0.3.3)"
            ]
        snapshot = registry_snapshot(report)
        if snapshot is None:
            return problems + [
                "report does not record checks_available and its registry version is unknown; "
                "cannot determine whether checks were omitted"
            ]
        missing = sorted(set(snapshot) - set(executed))
        if missing:
            return problems + [
                "report claims a full check run but omits checks available in its version: "
                f"{missing}"
            ]
        static_ids = [
            cid for cid in executed
            if cid in REGISTRY
            and not REGISTRY[cid][0].dynamic
            and REGISTRY[cid][0].category != "external"
        ]

    if not static_ids:
        return problems or ["report records no static checks to re-check"]
    settings = Settings(profile=profile, enabled=list(static_ids), execution="none", external_tools=False)
    try:
        rerun = run_checks(task_path, settings, adapter_name=str(environment.get("adapter") or "auto"))
    except ConfigError as exc:
        return problems + [f"could not re-run the checks: {exc}"]
    except Exception as exc:  # noqa: BLE001
        return problems + [f"could not re-run the checks: {type(exc).__name__}: {exc}"]

    def key(finding: dict[str, Any]) -> tuple:
        return (finding.get("check_id"), finding.get("status"), finding.get("severity"),
                finding.get("path"), finding.get("line"))

    def label(finding: dict[str, Any]) -> str:
        return (f"{finding.get('check_id')} {finding.get('status')}/{finding.get('severity')} "
                f"at {finding.get('path') or '-'}:{finding.get('line') or '-'}")

    reported_findings = [f for f in findings if f.get("check_id") in static_ids]
    reproduced_findings = [f for f in rerun.get("findings") or [] if f.get("check_id") in static_ids]

    # Newer reports are compared on full content (message/evidence too), so
    # editing a finding in place is detected.  Pre-0.3.2 reports are compared
    # on identity only because check wording may legitimately have changed.
    reported: Counter[Any]
    reproduced: Counter[Any]
    if version_at_least(report.get("envcert_version"), (0, 3, 2)):
        reported = Counter(finding_fingerprint(f) for f in reported_findings)
        reproduced = Counter(finding_fingerprint(f) for f in reproduced_findings)
        reported_examples = {finding_fingerprint(f): f for f in reported_findings}
        reproduced_examples = {finding_fingerprint(f): f for f in reproduced_findings}
        for item, count in (reported - reproduced).items():
            problems.append(
                f"finding reported but not reproduced on re-check: {label(reported_examples[item])} (x{count})"
            )
        for item, count in (reproduced - reported).items():
            problems.append(
                f"finding reproduced on re-check but missing from the report: "
                f"{label(reproduced_examples[item])} (x{count})"
            )
    else:
        reported = Counter(key(f) for f in reported_findings)
        reproduced = Counter(key(f) for f in reproduced_findings)
        for item, count in (reported - reproduced).items():
            problems.append(
                f"finding reported but not reproduced on re-check: {item[0]} {item[1]}/{item[2]} "
                f"at {item[3] or '-'}:{item[4] or '-'} (x{count})"
            )
        for item, count in (reproduced - reported).items():
            problems.append(
                f"finding reproduced on re-check but missing from the report: {item[0]} {item[1]}/{item[2]} "
                f"at {item[3] or '-'}:{item[4] or '-'} (x{count})"
            )
    return problems


def _dir_digest(ctx: TaskContext, directory: Path | None) -> str | None:
    if directory is None or not directory.is_dir():
        return None
    import hashlib

    h = hashlib.sha256()
    prefix = directory.relative_to(ctx.root).as_posix() + "/"
    for rel in ctx.files:
        if rel.startswith(prefix):
            h.update(rel.encode())
            try:
                file_digest = sha256_file(ctx.root / rel)
            except OSError as exc:
                ctx.warnings.append(f"could not read {rel} for directory digest: {exc}")
                file_digest = "unreadable"
            h.update(file_digest.encode())
    return h.hexdigest()
