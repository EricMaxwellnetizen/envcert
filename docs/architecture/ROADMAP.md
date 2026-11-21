# Roadmap

## Implemented in 0.1.0
- Harbor + generic adapters; 24 static checks (EC001–EC054), dynamic
  gold/negative/repeatability (EC060–EC062), Python mutation testing (EC063).
- JSON (schema 1.0.0) / text / SARIF reports, policy exit codes, profiles,
  `envcert.toml`, GitHub Action, in-toto Test Result attestations.

## Implemented in 0.2.0
- **NeMo Gym adapter** (`nemo-gym`): dataset.toml / root verifier.py / JSONL
  rows; expected-answer-in-prompt leakage check (EC014).
- **Inspect AI adapter** (`inspect`): `@task` files, scorer detection,
  model-graded-scorer reproducibility warnings.
- **Docker negative controls & repeatability**: EC061 runs a no-op (solution
  skipped) in the restricted Docker runner; EC062 repeats gold runs and
  compares rewards.
- **OCI image-digest subjects**: `--image` / `--image-digest`, automatic
  digest capture from Docker builds (`environment.image_digest`), image
  subject in in-toto attestations.
- **Per-step multi-step auditing**: EC004 plus per-step EC002 instruction
  auditing for Harbor `steps/` tasks.
- **Cosign OCI attestations**: `envcert attest --image name@sha256:...`
  (mutable refs refused), `envcert verify-attestation`, CUE/Rego policy
  examples in `examples/cosign/`.
- **Richer mutation**: BoolOp/AugAssign/UnaryOp/string operators and
  print/logging-only `possible_equivalent` tagging (EC063); shell-solution
  mutation under Docker (EC064).
- **External (VM/remote) runner**: `--execution external --runner-command`
  implementing the documented JSON protocol in
  `envcert/runners/external_runner.py`, for operator-run disposable
  VM/remote sandboxes.
- **Companion-tool orchestration**: `--external-tools` runs Hadolint /
  Trivy / Semgrep (task-config only) as EC070–EC072 when installed.

## Implemented in 0.3.0
- NeMo `verify()` live probing with gold/mutated/swapped inputs (EC065)
  and per-task-folder dataset rollups (`check --dataset`).
- Inspect dynamic runs behind the external-runner protocol
  (`examples/external-runners/inspect_runner.py`); scorer-strength
  checks EC055 (includes/model-graded patterns).
- Coverage-based equivalent-mutant reduction: mutants on lines the gold
  run never executes are inconclusive (EC063); verifier-input mutation
  is EC065.
- Registry attestation flow: Cosign attest/verify against an OCI
  registry (verified end-to-end against a local registry), plus a
  keyless GHCR GitHub Actions example.
- SARIF baseline suppressions (`--baseline`) and report trend diffing
  (`envcert diff [--strict]`).

## Next (0.4 candidates, not promised dates)
1. NeMo Resources-Server HTTP probing against a *running* server
   (`/verify` endpoint) as an external-runner example with a live server
   fixture.
2. Coverage-guided mutant prioritisation and larger operator sets;
   mutation for Inspect custom scorers.
3. Dataset rollups with SARIF merging and per-dataset attestations whose
   subjects are every task-folder digest.
4. Scheduled-revalidation examples (cron workflows that re-run checks and
   open issues on `envcert diff --strict` regressions).

## Explicit non-goals
Hosted dashboard/SaaS, LLM exploit generation, a numerical quality score,
guaranteeing environments are unhackable, replacing Harbor/NeMo Gym/BenchJack.
