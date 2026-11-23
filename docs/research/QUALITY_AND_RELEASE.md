# Quality report and release readiness

Maintained per release (prompt.md Parts 10/12/15). Numbers are from the
runs named; anything not executed is stated as such.

## Quality report (0.4.5 candidate)

- Tests: full suite executed locally (unit + integration + security,
  including live Docker tests when a Linux daemon is present) and in
  GitHub CI across Ubuntu/macOS/Windows × Python 3.11–3.13.  Local
  0.4.5 run: 269 passed, 1 skipped, coverage 82.03% (gate 80%).
- Coverage: branch coverage gate `fail_under = 80` in pyproject; the
  suite is run with `--cov` in CI.  The 0.4.5 modules (compose runner,
  HTTP verifier probe, JS/TS mutation, semantic dedup) are covered by
  new unit tests plus a live compose test.
- Lint/type: `ruff check envicert tests`, `mypy envicert` clean.
- Security self-review (Part 10.5): symlink escape (link content never
  read into reports, digest over target string), malicious/malformed
  TOML/JSON/report/attestation inputs (exit 2, never internal errors),
  hostile volume/path handling in runners (argument arrays, no shell),
  resource caps (2MB text reads for bundle files, 20k rows/file for
  datasets with caps recorded in evidence, 5k file digest cap with
  truncation warnings). Dataset rows are data and are never executed.
  The new HTTP verifier probe is opt-in, sends only the row and the
  expected/mutated answer, bounds rows (10), response size (1 MB) and
  wall clock, and never echoes endpoint headers into evidence.
- Performance regressions found and fixed in this cycle: the AST is
  walked once per node per analysis (cad-bench 113s → 72s) and the
  semantic pass normalises each row once (full SWE-bench audit 19s →
  ~5s).  Both were caught by re-running the 723-task campaign.
- Known bugs/limitations: see README "What it cannot do",
  `docs/architecture/CHECK_CATALOG.md` per-check limitations, and
  `docs/research/PILOT_SCALE.md` method limits.

## Release readiness (0.4.5)

- Version: package `envicert` (pyproject + `envicert/__init__.py` kept in
  lockstep; the test suite asserts the CLI reports it).
- Installation: `pip install envicert` / `pipx install envicert`
  (Python 3.11+, zero runtime dependencies); clean-venv install of the
  built wheel is verified before tagging.
- Artifacts: wheel + sdist via `python -m build`, `twine check` in the
  Release workflow; PyPI Trusted Publishing (OIDC, `pypi` environment)
  on `v*` tags; GitHub Release created from `docs/releases/vX.Y.Z.md`;
  moving `v0` tag for the Marketplace action.
- Supported formats: Harbor (Dockerfile, compose, prebuilt image),
  generic Docker, NeMo Gym (local verify() and HTTP Resources Server),
  Inspect AI, dataset files (JSONL/JSON/CSV/Parquet-with-pyarrow).
- Outstanding before publish: full-suite + coverage + lint/type green,
  clean-install smoke test, pilot re-run recorded.
- Publication steps (owner-run, in order): commit → `git tag -a vX.Y.Z`
  → push `main` and the tag → confirm Release workflow (build+publish)
  and CI are green → create the GitHub Release from the release notes
  → move `v0` → verify `pip install envicert==X.Y.Z` in a clean venv.
