"""Example custom check (not registered by default).

Copy this pattern into your own module, import the module so `@check`
registers it, and run Envicert from your own entry point — or contribute it
upstream with tests (see docs/guides/WRITING_A_CHECK.md).
Stable IDs above EC900 are reserved for local/experimental checks.
"""
from envicert.checks.base import CheckInfo, check, finding, not_applicable, passed
from envicert.core.models import Severity, Status

EC900 = CheckInfo(
    "EC900", "Example: verifier timeout is declared", "verifier", Severity.LOW,
    "Tasks should declare a verifier timeout so a hung verifier fails visibly instead of hanging a run.",
    "Add timeout_sec under [verifier] in task.toml.",
    "Harbor tasks only.",
)


@check(EC900)
def check_verifier_timeout(c):
    if c.task.adapter != "harbor":
        return [not_applicable(EC900, "Harbor-only example check.")]
    verifier = c.task.config.get("verifier") or {}
    if isinstance(verifier, dict) and verifier.get("timeout_sec"):
        return [passed(EC900, f"Verifier timeout declared ({verifier['timeout_sec']}s).")]
    return [finding(EC900, Status.WARN, "No [verifier] timeout_sec declared in task.toml.",
                    evidence={"verifier_table": verifier if isinstance(verifier, dict) else str(verifier)})]
