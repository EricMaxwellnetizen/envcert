# Changelog

All notable changes are documented here (Keep a Changelog format).

## [Unreleased]

## [0.4.4] - 2026-11-23

### Added
- **Prebuilt-image Docker execution**: Harbor tasks declaring
  `[environment] docker_image` (no Dockerfile) now run EC060/EC061/
  EC062/EC066 against the pulled image (roadmap #4, compose remains).
- **Transitive call-graph validation (EC054)**: helper chains that
  delegate to comparing helpers validate (A → B → compare), completing
  the inter-procedural step started in 0.4.1/0.4.2 (roadmap #1 core).

## [0.4.3] - 2026-11-23

### Fixed (scale campaign: 723 tasks, 2,294-row dataset, 131 evals)
- **Dataset loader silently truncated files at 2MB** (the bundle text
  cap): a 2,294-row SWE-bench file audited only its first 57 rows. The
  loader now streams from disk (20k rows/file cap, recorded in
  evidence); the full split audits in ~2s.
- **Performance**: EC052/EC053/EC054/EC056 share one cached AST
  analysis per run (cad-bench rollup 208s → 51s, identical findings).
- **Inspect adapter** includes sibling scorer modules in verifier
  analysis; assertion-free false alarms on inspect_evals dropped.
- **EC023** matches chmod targets component-exactly (`/testbed` agent
  workspace no longer reads as verifier `/tests`).
- **EC032**: pipe-to-shell from a version-pinned URL is MEDIUM;
  unversioned installers remain HIGH.

### Added
- Scale pilot (723 Hub/TB/Harbor tasks + full SWE-bench + 131 Inspect
  evals) in docs/research/PILOT_SCALE.md, incl. the hand-verified
  SWE-bench duplicate-instance finding (19 identical-issue pairs).
- docs/architecture/ROADMAP.md; docs/research/QUALITY_AND_RELEASE.md;
  SWE-ABS (ICML 2026) verified and positioned in the research docs.

## [0.4.2] - 2026-11-23

### Fixed
- EC054: validation assigned to a variable (`reward = grade(state)`)
  now propagates to its return/sink instead of producing a second,
  unvalidated hit (CI caught this on all platforms).
- Docker runner availability now requires a Linux containers engine:
  Windows-containers daemons (GitHub windows-latest) report themselves
  unavailable, so live Docker tests skip instead of failing with ERROR.
- Docs workflow action references corrected (Pages now deploys).

## [0.4.1] - 2026-11-23

### Added
- Inter-procedural validation in EC054's data-flow analysis: reward
  flows passing through a local helper that itself compares/asserts are
  recognised as validated (grade.py-style graders no longer WARN).
- EC056 covers JavaScript/TypeScript verifiers (`eval(`, `new Function`,
  `vm.runIn*`, template-literal `exec(`).
- Documentation site (MkDocs Material, GitHub Pages workflow), PyPI/CI
  badges, real generated demo reports under `docs/demo/`, and six
  roadmap issues filed on GitHub (#1–#6).

## [0.4.0] - 2026-11-22

### Added
- **Deterministic cheat-agent battery (EC066)**: fixed cheat strategies —
  stub solution and agent-planted conftest outcome-faking (local-python),
  forged reward file and verifier-entrypoint tampering (docker) — are
  executed against the verifier. A cheat that passes while gold passes is
  a proven false pass (FAIL, high confidence) with no LLM involved.
- **Dataset-file auditing (EC080–EC085 + `dataset` adapter)**: `envcert
  check data.jsonl` (also `.json`/`.csv`, or a directory of them) checks
  answers embedded in prompts (including `hints_text`-style auxiliary
  fields), exact/near duplicates and label conflicts, train/test split
  overlap, degenerate labels, broken rows and inconsistent
  FAIL_TO_PASS/PASS_TO_PASS grading specs. Field names are detected
  across SWE-bench/NeMo/OpenAI-style conventions. NeMo Gym directories
  keep their adapter. EC054 reports LLM-judge-mediated reward flows as
  WARN rather than direct-self-grading FAIL.
- **`envcert fix`**: deterministic, idempotent, dry-run-first remediation
  (.dockerignore entries for .git/solution/answer material; declared
  network/verifier-separation policies labelled *needs review*).
- **`envcert new`**: scaffolds a Harbor task (separate verifier,
  no-network, digest-pinned image, real assertions) that passes
  `envcert check`.
- **AST data-flow verifier analysis**: EC054 now tracks reward provenance
  (file/env/argv/stdin/subprocess sources → return/reward sinks) and
  fails on rewards parsed from agent-controlled content without
  comparison against an expected value — including
  `return float(open(...).read())`. EC056 inventories eval/exec, unsafe
  deserialisation and `shell=True` in verifiers.
- **Reports**: `--format markdown` (PR-ready) and `--format html`
  (single self-contained file); SARIF gains partial fingerprints,
  suggested fixes and ERROR results.
- **Adoption surface**: GitHub Action step-summary and opt-in PR
  comments; `.pre-commit-hooks.yaml`; third-party checks via the
  `envcert.checks` entry-point group.
- Registry snapshot for 0.4.x (42 checks); report schema admits the
  `dataset` adapter.

### Added (pre-release)
- `.parquet` dataset files (via optional pyarrow; without it the file is
  reported uninspectable as a WARN, never silently passed).
- `envcert check --watch` re-runs a task check when its bundle digest
  changes.
- Hand-review round over every Terminal-Bench policy driver (see
  docs/research/PILOT_040.md): EC054 trusts verifier-owned paths
  (`/logs/verifier`, `/tests`), EC011 excludes instruction-declared
  public inputs, EC010 matches `.git` component-exactly, EC053 counts
  `require()`/`assert*` helpers, EC023 targets verifier/reward/system
  paths only. Terminal-Bench: 47/51 pass after review.

### Fixed
- Real-world pilot false positives (Terminal-Bench, 51 rendered tasks):
  EC056 no longer flags `source .venv/bin/activate` (only `eval`/`sh -c`
  over interpolated content); EC054 no longer treats data-loading helper
  returns as reward sinks; the Dockerfile parser ignores heredoc bodies
  (`from pathlib import Path` is not a `FROM`) and EC030 ignores
  build-stage aliases. Terminal-Bench policy pass rate on the pilot:
  8/51 before these fixes, 32/51 after, with the remaining failures
  driven by review-level findings (see docs/research/PILOT_040.md).
- EC061 selected without EC060 now establishes its own gold baseline
  (and is inconclusive when gold fails) instead of trusting check order.
- Docker harness snapshots verifier tests to a pristine location before
  the agent step and restores them after, modelling verifier-owned test
  uploads; EC066's tamper scenario proves the property per run.
- `--max-mutants` CLI control for the mutation budget; dataset rollups
  support `--format markdown`; coverage gate set to 80%.
- EC052: an `if` anywhere in a verifier no longer excuses an
  unconditional `echo 1 > reward.txt`; conditionality is judged per line.
- EC012: files the instruction itself hands to the agent as inputs are
  no longer flagged on filename alone.
- EC053: merely mentioning a test runner no longer counts as a check
  signal, and `__name__ == "__main__"` guards are not assertions.

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
