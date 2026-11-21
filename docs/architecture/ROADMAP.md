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

## Next (0.3 candidates, not promised dates)
1. NeMo Gym Resources-Server (`verify()` over HTTP) live probing and
   per-task-folder dataset rollups in one report.
2. Inspect dynamic runs (`inspect eval`) behind the external-runner
   protocol examples; scorer-specific strength checks (exact/includes
   weakness patterns).
3. Equivalent-mutant reduction via coverage data; mutation of verifier
   *inputs* for data-driven verifiers.
4. Registry push/pull of attestations in CI examples (cosign attest to a
   real registry with keyless signing in GitHub Actions).
5. SARIF suppressions/baseline files and trend diffing between reports.

## Explicit non-goals
Hosted dashboard/SaaS, LLM exploit generation, a numerical quality score,
guaranteeing environments are unhackable, replacing Harbor/NeMo Gym/BenchJack.
