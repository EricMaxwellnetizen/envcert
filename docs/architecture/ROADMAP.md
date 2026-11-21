# Roadmap

## Implemented in 0.1.0
- Harbor + generic adapters; 24 static checks (EC001–EC054), dynamic
  gold/negative/repeatability (EC060–EC062), Python mutation testing (EC063).
- JSON (schema 1.0.0) / text / SARIF reports, policy exit codes, profiles,
  `envcert.toml`, GitHub Action, in-toto Test Result attestations.

## Next (0.2 candidates, not promised dates)
1. Docker negative controls via Harbor artifact semantics (needs per-task
   artifact handling; deliberately not faked in 0.1.0).
2. NeMo Gym adapter (JSONL/resources-server layouts) and Inspect adapter —
   only after fixture-verified format research.
3. OCI image-digest subject: build/inspect an image and bind its digest into
   reports/attestations (currently `image_digest: null`).
4. Cosign `attest` against OCI subjects (in addition to sign-blob) and
   `verify-attestation` policy examples (CUE/Rego).
5. Multi-step Harbor tasks: per-step instruction/verifier auditing.
6. Richer mutation operators and equivalent-mutant heuristics; shell-verifier
   mutation via test-input mutation.
7. Remote/VM runner implementation behind the existing Runner interface for
   high-risk untrusted bundles.
8. Optional companion-tool orchestration (hadolint/trivy/semgrep) as
   explicitly-labelled external checks.

## Explicit non-goals
Hosted dashboard/SaaS, LLM exploit generation, a numerical quality score,
guaranteeing environments are unhackable, replacing Harbor/NeMo Gym/BenchJack.
