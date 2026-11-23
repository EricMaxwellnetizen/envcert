# Quality report and release readiness

Maintained per release (prompt.md Parts 10/12/15). Numbers are from the
runs named; anything not executed is stated as such.

## Quality report (0.4.3 candidate)

- Tests: full suite executed locally (unit + integration + security,
  including live Docker tests when a Linux daemon is present) and in
  GitHub CI across Ubuntu/macOS/Windows × Python 3.11–3.13.
- Coverage: branch coverage gate `fail_under = 80` in pyproject; the
  suite is run with `--cov` in CI.
- Lint/type: `ruff check envcert tests`, `mypy envcert` clean.
- Security self-review (Part 10.5): symlink escape (link content never
  read into reports, digest over target string), malicious/malformed
  TOML/JSON/report/attestation inputs (exit 2, never internal errors),
  hostile volume/path handling in runners (argument arrays, no shell),
  resource caps (2MB text reads for bundle files, 20k rows/file for
  datasets with caps recorded in evidence, 5k file digest cap with
  truncation warnings). Dataset rows are data and are never executed.
- Known bugs/limitations: see README "What it cannot do",
  `docs/architecture/CHECK_CATALOG.md` per-check limitations, and
  `docs/research/PILOT_SCALE.md` method limits.

## Release readiness (0.4.3)

- Version: package `envcert` (pyproject + `envcert/__init__.py` kept in
  lockstep; the test suite asserts the CLI reports it).
- Installation: `pip install envcert` / `pipx install envcert`
  (Python 3.11+, zero runtime dependencies); clean-venv install of the
  built wheel is verified before tagging.
- Artifacts: wheel + sdist via `python -m build`, `twine check` in the
  Release workflow; PyPI Trusted Publishing (OIDC, `pypi` environment)
  on `v*` tags; GitHub Release created from `docs/releases/vX.Y.Z.md`;
  moving `v0` tag for the Marketplace action.
- Supported formats: Harbor, generic Docker, NeMo Gym, Inspect AI,
  dataset files (JSONL/JSON/CSV/Parquet-with-pyarrow).
- Outstanding before publish: full-suite + coverage + lint/type green,
  clean-install smoke test, pilot re-run recorded.
- Publication steps (owner-run, in order): commit → `git tag -a vX.Y.Z`
  → push `main` and the tag → confirm Release workflow (build+publish)
  and CI are green → create the GitHub Release from the release notes
  → move `v0` → verify `pip install envcert==X.Y.Z` in a clean venv.
