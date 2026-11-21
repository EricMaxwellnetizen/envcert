# Writing a check

Checks are pure functions from a `CheckContext` to findings. They never print
and never execute task code (dynamic checks go through a Runner).

```python
# envcert/checks/my_checks.py
from envcert.checks.base import CheckInfo, check, finding, passed
from envcert.core.models import Severity, Status

EC900 = CheckInfo(
    "EC900", "Example: verifier timeout is declared", "verifier", Severity.LOW,
    "Tasks should declare a verifier timeout so hung verifiers fail visibly.",
    "Add timeout_sec under [verifier] in task.toml.",
    "Only applies to Harbor tasks.",
)

@check(EC900)
def check_verifier_timeout(c):
    if c.task.adapter != "harbor":
        from envcert.checks.base import not_applicable
        return [not_applicable(EC900, "Harbor-only check.")]
    verifier = c.task.config.get("verifier") or {}
    if verifier.get("timeout_sec"):
        return [passed(EC900, "Verifier timeout declared.")]
    return [finding(EC900, Status.WARN, "No [verifier] timeout_sec declared.",
                    evidence={"verifier_table": verifier})]
```

Rules for contributors:

1. Pick the next free stable ID in your range; IDs are public API and are
   never reused (see CHECK_CATALOG.md).
2. Default severity = severity *when the property fails*. PASS findings use
   INFO automatically.
3. Decide, don't just detect filenames: assess build-context/import-path/
   runtime relevance, and when you cannot prove it statically, return WARN
   with `confidence=Confidence.LOW` and state the limitation (copy an existing
   check's phrasing).
4. Always include `evidence` (paths, lines, matched patterns) and a concrete
   `remediation`.
5. Add unit tests: one triggering fixture, one near-miss fixture that must
   NOT trigger (false-positive control), and register the check so
   `list-checks` shows it (import your module from `core/engine.py` and
   `cli/main.py` — follow how `static_checks` is imported).
6. Document the check: it appears automatically in the generated catalog;
   regenerate `docs/architecture/CHECK_CATALOG.md` (command in CONTRIBUTING).
