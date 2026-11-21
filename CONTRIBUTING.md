# Contributing to EnvCert

Thanks for helping make evaluation environments more trustworthy.

## Setup

```bash
git clone https://github.com/EricMaxwellnetizen/envcert
cd envcert
python -m venv .venv && source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
pytest
```

Python ≥ 3.11. The runtime core is **standard-library only** — new runtime
dependencies need a strong justification in the PR; put optional tooling in
the `dev`/`validate` extras.

## Workflow

1. Open an issue first for new checks/adapters (use the templates).
2. Branch, implement, add tests, update docs.
3. Run: `pytest`, `ruff check envcert tests`, `mypy envcert`.
4. Regenerate the check catalog if you touched checks:

```bash
python -c "import pathlib; from envcert.checks.base import REGISTRY; import envcert.checks.static_checks, envcert.checks.dynamic_checks; lines=['# Check catalog','','Stable check IDs are a public interface.','']; [lines.extend([f'## {cid} - {i.title}','','- Category: '+i.category+'  |  Default severity: '+i.severity.value+'  |  Dynamic: '+str(i.dynamic),'- Description: '+i.description,'- Remediation: '+i.remediation,'- Limitations: '+(i.limitations or '(none)'),'']) for cid,(i,_) in sorted(REGISTRY.items())]; pathlib.Path('docs/architecture/CHECK_CATALOG.md').write_text(chr(10).join(lines), encoding='utf-8')"
```

## Guides

- Adding a check: `docs/guides/WRITING_A_CHECK.md` (stable IDs, severity and
  confidence rules, false-positive controls are mandatory).
- Adding an adapter/runner: `docs/guides/WRITING_AN_ADAPTER_OR_RUNNER.md`.
- Writing fixtures: mirror `tests/fixtures/expected-*.json` — every example
  task declares the findings it must (and must not) produce.

## Ground rules

- Never make a check claim more than its evidence supports: use WARN +
  confidence + limitations for heuristics.
- A failing check must never silently become PASS (engine turns exceptions
  into ERROR findings; keep it that way).
- No telemetry, no network calls in static mode, no AI-API requirements.
- All user-facing text is plain, specific and honest about limitations.

## Licence

Contributions are licensed under Apache-2.0. Do not copy code from other
projects without licence compatibility and attribution.
