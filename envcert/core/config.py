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
    max_mutants: int = 10             # mutant budget for EC063/EC064
    nemo_endpoint: str | None = None  # NeMo Gym Resources-Server URL for HTTP verifier probing
    nemo_headers: dict[str, str] = field(default_factory=dict)

    def fail_on_names(self) -> list[str]:
        return sorted((s.value for s in self.fail_on), key=lambda v: ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"].index(v))


def parse_fail_on(values: Any, where: str) -> set[Severity]:
    if not isinstance(values, list) or not values:
        raise ConfigError(f"{where}: fail_on must be a non-empty list of severities")
    out = set()
    for v in values:
        try:
            out.add(Severity(str(v).upper()))
        except ValueError:
            raise ConfigError(f"{where}: unknown severity {v!r} (expected CRITICAL/HIGH/MEDIUM/LOW/INFO)") from None
    return out


_parse_fail_on = parse_fail_on  # backwards-compatible alias


def _table(data: dict[str, Any], key: str, where: str) -> dict[str, Any]:
    value = data.get(key)
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise ConfigError(f"{where} must be a table")
    return value


def _parse_repetitions(value: Any, where: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ConfigError(f"{where}: repetitions must be an integer between 1 and 20")
    if not 1 <= value <= 20:
        raise ConfigError(f"{where}: repetitions must be between 1 and 20")
    return value


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
    envcert = _table(data, "envcert", "[envcert]")
    chosen_profile = profile if profile is not None else envcert.get("profile")
    if chosen_profile is None:
        chosen_profile = "harbor"
    if not isinstance(chosen_profile, str):
        raise ConfigError(f"profile must be a string, got {chosen_profile!r}")
    if chosen_profile not in PROFILES:
        raise ConfigError(f"unknown profile {chosen_profile!r}; available: {', '.join(sorted(PROFILES))}")
    s.profile = chosen_profile
    prof = PROFILES[chosen_profile]
    s.categories = prof["categories"]
    s.fail_on = _parse_fail_on(prof["fail_on"], f"profile {chosen_profile}")
    dynamic_requested = False
    checks = _table(data, "checks", "[checks]")
    if checks:
        enabled = checks.get("enabled")
        if enabled is not None:
            if (isinstance(enabled, list) and len(enabled) == 1
                    and isinstance(enabled[0], str) and enabled[0].lower() == "all") \
                    or (isinstance(enabled, str) and enabled.lower() == "all"):
                s.enabled = None
            elif isinstance(enabled, list):
                if not enabled:
                    raise ConfigError("[checks] enabled must not be empty; use [\"all\"] or list at least one check ID")
                if not all(isinstance(item, str) for item in enabled):
                    raise ConfigError("[checks] enabled must be a list of check IDs")
                s.enabled = [item.upper() for item in enabled]
            else:
                raise ConfigError("[checks] enabled must be a list of check IDs or [\"all\"]")
        disabled = checks.get("disabled")
        if disabled is None:
            disabled = []
        if not isinstance(disabled, list) or not all(isinstance(item, str) for item in disabled):
            raise ConfigError("[checks] disabled must be a list of check IDs")
        s.disabled = [item.upper() for item in disabled]
        dyn = _table(checks, "dynamic", "[checks.dynamic]")
        if "enabled" in dyn:
            if not isinstance(dyn["enabled"], bool):
                raise ConfigError("[checks.dynamic] enabled must be a boolean")
            if dyn["enabled"]:
                # Dynamic checks run code from the task.  Never infer that
                # from a boolean alone: the execution mode (and therefore the
                # isolation boundary) must be chosen explicitly.
                dynamic_requested = True
        if "repetitions" in dyn:
            s.repetitions = _parse_repetitions(dyn["repetitions"], "[checks.dynamic]")
        nemo = _table(checks, "nemo", "[checks.nemo]")
        endpoint = nemo.get("endpoint")
        if endpoint is not None:
            if not isinstance(endpoint, str) or not endpoint.startswith(("http://", "https://")):
                raise ConfigError("[checks.nemo] endpoint must be an http:// or https:// URL")
            s.nemo_endpoint = endpoint
        headers = nemo.get("headers")
        if headers is not None:
            if not isinstance(headers, dict) or not all(
                    isinstance(k, str) and isinstance(v, str) for k, v in headers.items()):
                raise ConfigError("[checks.nemo] headers must be a table of string values")
            s.nemo_headers = dict(headers)
    policy = _table(data, "policy", "[policy]")
    if policy.get("fail_on") is not None:
        s.fail_on = _parse_fail_on(policy["fail_on"], "[policy]")
    execution_tbl = _table(data, "execution", "[execution]")
    mode = execution_tbl.get("mode")
    if mode is not None:
        if not isinstance(mode, str):
            raise ConfigError("[execution] mode must be a string")
        s.execution = mode
    runner_command = execution_tbl.get("runner_command")
    if runner_command is not None:
        if not isinstance(runner_command, str):
            raise ConfigError("[execution] runner_command must be a string")
        s.runner_command = runner_command
    image = execution_tbl.get("image")
    if image is not None:
        if not isinstance(image, str):
            raise ConfigError("[execution] image must be a string")
        s.image = image
    s.source = source
    if overrides:
        if overrides.get("profile"):
            override_profile = overrides["profile"]
            if not isinstance(override_profile, str) or override_profile not in PROFILES:
                raise ConfigError(f"unknown profile {override_profile!r}")
            s.profile = override_profile
            s.categories = PROFILES[s.profile]["categories"]
            s.fail_on = _parse_fail_on(PROFILES[s.profile]["fail_on"], "profile")
        if overrides.get("fail_on"):
            s.fail_on = _parse_fail_on(overrides["fail_on"], "--fail-on")
        if overrides.get("execution"):
            if not isinstance(overrides["execution"], str):
                raise ConfigError("--execution must be a string")
            s.execution = overrides["execution"]
        if overrides.get("enable"):
            requested = [str(item) for item in overrides["enable"]]
            if len(requested) == 1 and requested[0].lower() == "all":
                s.enabled = None
            else:
                s.enabled = [item.upper() for item in requested]
        if overrides.get("disable"):
            s.disabled = [str(item).upper() for item in overrides["disable"]]
        if overrides.get("repetitions") is not None:
            s.repetitions = _parse_repetitions(overrides["repetitions"], "--repetitions")
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
        if overrides.get("max_mutants") is not None:
            value = overrides["max_mutants"]
            if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= 200:
                raise ConfigError("--max-mutants must be an integer between 1 and 200")
            s.max_mutants = value
        if overrides.get("nemo_endpoint"):
            value = str(overrides["nemo_endpoint"])
            if not value.startswith(("http://", "https://")):
                raise ConfigError("--nemo-endpoint must be an http:// or https:// URL")
            s.nemo_endpoint = value
    if s.execution not in ("none", "docker", "local-python", "external"):
        raise ConfigError(f"unknown execution mode {s.execution!r}; expected none, docker, local-python or external")
    if dynamic_requested and s.execution == "none":
        raise ConfigError(
            "[checks.dynamic] enabled = true requires an explicit execution mode; "
            "set [execution] mode = \"local-python\" (trusted tasks only, no sandbox) or \"docker\", "
            "or pass --execution. EnvCert will not silently run task code unsandboxed."
        )
    if not 1 <= s.repetitions <= 20:
        raise ConfigError("repetitions must be between 1 and 20")
    return s
