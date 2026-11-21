from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from envcert.core.errors import ConfigError
from envcert.core.models import Severity

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover
    import tomli as tomllib  # type: ignore[no-redef]

PROFILES: dict[str, dict[str, Any]] = {
    "minimal": {
        "description": "Structure, leakage, boundary and verifier checks only; fails on CRITICAL/HIGH.",
        "categories": ["structure", "leakage", "boundary", "verifier"],
        "fail_on": ["CRITICAL", "HIGH"],
    },
    "harbor": {
        "description": "Full static suite for Harbor tasks; fails on CRITICAL/HIGH.",
        "categories": None,
        "fail_on": ["CRITICAL", "HIGH"],
    },
    "strict": {
        "description": "Full static suite; fails on CRITICAL/HIGH/MEDIUM.",
        "categories": None,
        "fail_on": ["CRITICAL", "HIGH", "MEDIUM"],
    },
    "ci": {
        "description": "Full static suite tuned for CI; fails on CRITICAL/HIGH, reports everything else.",
        "categories": None,
        "fail_on": ["CRITICAL", "HIGH"],
    },
}


@dataclass
class Settings:
    profile: str = "harbor"
    fail_on: set[Severity] = field(default_factory=lambda: {Severity.CRITICAL, Severity.HIGH})
    enabled: list[str] | None = None  # None = all in profile
    disabled: list[str] = field(default_factory=list)
    categories: list[str] | None = None
    execution: str = "none"
    repetitions: int = 3
    enable_mutation: bool = False
    source: str = "defaults"
    image: str | None = None          # OCI image reference to resolve a digest for
    image_digest: str | None = None   # explicit sha256:... digest to bind into the report
    runner_command: str = ""          # external runner executable (execution=external)
    external_tools: bool = False      # run hadolint/trivy/semgrep companions when installed
    baseline: str | None = None       # previous report: identical findings are suppressed from policy

    def fail_on_names(self) -> list[str]:
        return sorted((s.value for s in self.fail_on), key=lambda v: ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"].index(v))


def _parse_fail_on(values: Any, where: str) -> set[Severity]:
    if not isinstance(values, list) or not values:
        raise ConfigError(f"{where}: fail_on must be a non-empty list of severities")
    out = set()
    for v in values:
        try:
            out.add(Severity(str(v).upper()))
        except ValueError:
            raise ConfigError(f"{where}: unknown severity {v!r} (expected CRITICAL/HIGH/MEDIUM/LOW/INFO)") from None
    return out


def load_settings(config_path: Path | None, profile: str | None, overrides: dict[str, Any] | None = None) -> Settings:
    s = Settings()
    data: dict[str, Any] = {}
    source = "defaults"
    if config_path is not None:
        if not config_path.is_file():
            raise ConfigError(f"config file not found: {config_path}")
        try:
            with config_path.open("rb") as fh:
                data = tomllib.load(fh)
        except Exception as exc:
            raise ConfigError(f"invalid TOML in {config_path}: {exc}") from exc
        source = str(config_path)
    envcert = data.get("envcert") or {}
    if not isinstance(envcert, dict):
        raise ConfigError("[envcert] must be a table")
    chosen_profile = profile or envcert.get("profile") or "harbor"
    if chosen_profile not in PROFILES:
        raise ConfigError(f"unknown profile {chosen_profile!r}; available: {', '.join(sorted(PROFILES))}")
    s.profile = chosen_profile
    prof = PROFILES[chosen_profile]
    s.categories = prof["categories"]
    s.fail_on = _parse_fail_on(prof["fail_on"], f"profile {chosen_profile}")
    checks = data.get("checks") or {}
    if checks:
        enabled = checks.get("enabled")
        if enabled is not None:
            if enabled == ["all"] or enabled == "all":
                s.enabled = None
            elif isinstance(enabled, list):
                s.enabled = [str(x) for x in enabled]
            else:
                raise ConfigError("[checks] enabled must be a list of check IDs or [\"all\"]")
        disabled = checks.get("disabled") or []
        if not isinstance(disabled, list):
            raise ConfigError("[checks] disabled must be a list of check IDs")
        s.disabled = [str(x) for x in disabled]
        dyn = checks.get("dynamic") or {}
        if dyn.get("enabled"):
            s.execution = "local-python"
        if "repetitions" in dyn:
            s.repetitions = int(dyn["repetitions"])
    policy = data.get("policy") or {}
    if policy.get("fail_on") is not None:
        s.fail_on = _parse_fail_on(policy["fail_on"], "[policy]")
    execution_tbl = data.get("execution") or {}
    if execution_tbl.get("mode"):
        s.execution = str(execution_tbl["mode"])
    if execution_tbl.get("runner_command"):
        s.runner_command = str(execution_tbl["runner_command"])
    if execution_tbl.get("image"):
        s.image = str(execution_tbl["image"])
    s.source = source
    if overrides:
        if overrides.get("profile"):
            if overrides["profile"] not in PROFILES:
                raise ConfigError(f"unknown profile {overrides['profile']!r}")
            s.profile = overrides["profile"]
            s.categories = PROFILES[s.profile]["categories"]
            s.fail_on = _parse_fail_on(PROFILES[s.profile]["fail_on"], "profile")
        if overrides.get("fail_on"):
            s.fail_on = _parse_fail_on(overrides["fail_on"], "--fail-on")
        if overrides.get("execution"):
            s.execution = overrides["execution"]
        if overrides.get("enable"):
            s.enabled = list(overrides["enable"])
        if overrides.get("disable"):
            s.disabled = list(overrides["disable"])
        if overrides.get("repetitions"):
            s.repetitions = int(overrides["repetitions"])
        if overrides.get("mutation"):
            s.enable_mutation = True
        if overrides.get("image"):
            s.image = str(overrides["image"])
        if overrides.get("image_digest"):
            s.image_digest = str(overrides["image_digest"])
        if overrides.get("runner_command"):
            s.runner_command = str(overrides["runner_command"])
        if overrides.get("external_tools"):
            s.external_tools = True
        if overrides.get("baseline"):
            s.baseline = str(overrides["baseline"])
    if s.execution not in ("none", "docker", "local-python", "external"):
        raise ConfigError(f"unknown execution mode {s.execution!r}; expected none, docker, local-python or external")
    if s.repetitions < 1 or s.repetitions > 20:
        raise ConfigError("repetitions must be between 1 and 20")
    return s
