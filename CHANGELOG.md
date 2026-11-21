# Changelog

All notable changes are documented here (Keep a Changelog format).

## [Unreleased]

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
