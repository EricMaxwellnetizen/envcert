# Changelog

All notable changes are documented here (Keep a Changelog format).

## [Unreleased]

## [0.3.2] - 2026-11-22

### Fixed
- **No false PASS when the verifier cannot run**: the local-python runner now
  detects that `pytest` is missing and reports an execution error instead of
  a test failure. EC060/EC061/EC062/EC063 return ERROR (never PASS) when the
  verifier never ran — previously EC061 and EC062 could report "no-op
  rejected" and "outcome repeatable" for a runner that did not execute a
  single test. Docker shell mutation (EC064) and mutation mutants that fail
  to execute are likewise no longer counted as verifier rejections.
- **Baseline suppression is verifiable, not self-asserted**: `verify` and
  `attest` recompute suppression from the baseline report. A report that
  marks findings as `baseline_suppressed` now requires `--baseline <file>`;
  without it, or when the flagged findings are absent from the baseline, the
  report is rejected (exit 2) instead of being accepted with a passing
  policy.
- **Reports from EnvCert 0.1.0/0.2.0 verify again**: the consistency
  validator no longer requires summary counters that those versions did not
  write (0.3.0+ reports remain strictly checked).
- `verify` no longer implies that a report's findings are complete: the
  output states that checks are not re-run unless asked.

### Added
- `envcert verify --recheck --task <dir>`: re-runs the report's static checks
  against the task and compares the findings, so findings dropped from (or
  added to) a report are detected.
- `envcert verify --fail-on critical,high`: evaluates the policy under the
  consumer's own severity threshold instead of the report's self-asserted
  `fail_on`; a failing policy exits 1.
- `envcert attest --baseline <file>`: verifies baseline suppression before
  building an attestation.

## [0.3.1] - 2026-11-22

### Fixed
- `verify` and `attest` now recompute `policy.passed` and all summary counters
  from the findings instead of trusting self-asserted fields. Forged or
  inconsistent reports are rejected (exit 2); `verify` exits 2 for
  schema/consistency failures and keeps exit 1 for a bundle-digest mismatch.
- `verify-attestation` fails on unsigned statements and DSSE envelopes unless
  `--allow-unsigned` is passed. Detached `.sig` files produced by `--sign` are
  verified with `cosign verify-blob`; a present but invalid signature always
  fails, even with `--allow-unsigned`.
- `attest --sign` and `attest --image` now exit 3 when signing or OCI
  attestation was requested but did not happen (cosign missing, tlog/network
  failure, mutable ref), instead of exiting 0 with an unsigned statement.
- `--image`/`--image-digest` resolution failures and malformed digests are
  configuration errors (exit 2). Docker `RepoDigests` (registry manifest
  digest) is preferred over the local image ID; the ID fallback is labelled
  explicitly in report warnings.
- Windows `--runner-command` splitting preserves backslash paths without
  requiring quotes; quoted paths with spaces still work.
- Unknown `--enable`/`--disable` check IDs, empty `[checks] enabled` lists and
  configurations selecting no checks are rejected instead of producing a
  vacuous PASS report.
- `[checks.dynamic] enabled = true` no longer silently implies unsandboxed
  `local-python` execution; an explicit execution mode is required.
- Docker check images use a unique per-run tag, avoiding collisions between
  concurrent runs.
- Baseline suppression now fingerprints finding content (message, severity,
  status, evidence) rather than only `(check_id, path, line)`, so a new issue
  at the same location is not hidden by an old baseline entry.
- Bundle digests report file-listing truncation and unreadable files instead
  of silently hashing incomplete/empty content.
- `attest --image` refuses an image digest that differs from the report's
  recorded `image_digest`, and temporary predicate files are cleaned up.

## [0.3.0] - 2026-11-22

### Added
- EC065 NeMo Gym verifier probing with gold/mutated/swapped inputs
  (`--execution local-python`); EC055 Inspect scorer-strength checks.
- Dataset rollups: `envcert check --dataset` over all task folders in a
  dataset tree, with per-task reports embedded in the JSON rollup.
- Coverage-aware mutation: mutants on verifier-unexecuted lines are
  inconclusive and excluded from the EC063 rejection rate.
- Report baselines (`--baseline`, SARIF suppressions) and `envcert diff`
  trend comparison with `--strict`.
- Inspect dynamic-runner example and keyless GHCR Cosign attestation
  workflow example; local-registry Cosign round-trip verified.

## [0.2.0] - 2026-11-22

### Added
- NeMo Gym and Inspect AI adapters (auto-detected; fixture examples included).
- EC004 multi-step step-completeness auditing; per-step instruction checks.
- Docker negative controls (EC061 no-op), Docker repeatability (EC062),
  shell-solution mutation (EC064).
- OCI image-digest binding (`--image`/`--image-digest`, automatic capture
  from Docker builds) and OCI subjects in attestations.
- Cosign OCI attestation (`attest --image`, mutable refs refused),
  `verify-attestation` command, CUE/Rego policy examples.
- External (disposable VM/remote) runner protocol
  (`--execution external --runner-command`).
- Companion-tool orchestration (`--external-tools`: Hadolint/Trivy/Semgrep
  as EC070–EC072; absent tools report NOT_RUN).
- Richer mutation operators and print/logging possible-equivalent tagging.

## [0.1.0] - 2026-11-22

Initial public-release candidate.

### Added
- CLI: `check`, `list-checks`, `explain`, `verify`, `attest`, `init`,
  `schema`, `version` with documented exit codes (0/1/2/3).
- Harbor adapter (task.toml schema 1.4-era layouts, incl. docker_image-only
  environments, verifier.py, multi-step detection) and a generic Docker
  adapter.
- 24 static checks (EC001–EC054): task structure, answer/git/secret leakage,
  agent–verifier boundary (separation, import/PATH shadowing, writable
  paths, mounts), Dockerfile integrity, dependency pinning, verifier
  structure/strength/self-reported-reward heuristics.
- Opt-in dynamic checks (EC060–EC062) via a restricted Docker runner or a
  labelled no-sandbox local-python runner; AST mutation testing (EC063)
  with rejection-rate reporting.
- Reports: text, JSON (published schema 1.0.0, `envcert schema`), SARIF 2.1.0.
- Policy profiles (harbor/strict/minimal/ci) and `envcert.toml` config.
- in-toto Test Result attestation generation with optional DSSE envelope
  and Cosign sign-blob; report verification with bundle-digest recomputation.
- Composite GitHub Action, example workflows, full docs (research,
  architecture, threat model, check catalog, guides), examples (safe,
  intentionally vulnerable, unsupported, python-task) with expected-results
  fixtures, and a pytest suite covering unit/integration/security cases.
