# Product decisions

## Position

Envicert is an **independent, extensible verification and evidence layer** for
the integrity of AI training/evaluation environments. It is not a Docker CVE
scanner, not a Harbor/NeMo Gym replacement, not a BenchJack replacement, not a
certification authority, and it never claims an environment is unhackable.

## Build / integrate / deliberately-not-build

### Build (implemented in 0.1.0)
- Deterministic, offline, stdlib-only static check engine with stable check
  IDs (EC001–EC063), explicit PASS/FAIL/WARN/NOT_RUN/NOT_APPLICABLE/ERROR.
- Harbor adapter first (verified against schema 1.4 docs), generic Docker
  adapter second; adapter interface leaves room for NeMo Gym/Inspect layouts.
- JSON report (schema 1.0.0, published JSON Schema), text and SARIF output,
  policy-based exit codes (0/1/2/3), TOML config + profiles.
- Opt-in dynamic checks: gold, no-op negative control, repeatability —
  restricted Docker runner, plus a clearly-labelled no-sandbox local-python
  runner for pytest tasks.
- Small AST mutation framework for Python solutions (rejection rate as a
  signal, never as proof).
- in-toto Test Result attestation generation (unsigned by default, optional
  Cosign sign-blob), report `verify` with digest re-computation.
- Composite GitHub Action + example workflows; static-only by default.

### Integrate (documented, not bundled)
- Hadolint/Trivy/Semgrep as companion scanners in CI examples/docs — Envicert
  does not reimplement CVE or generic SAST coverage.
- Cosign for signing; Harbor/NeMo Gym for full task execution — Envicert's
  docker runner is a restricted checker, not a trial runner.

### Deliberately not build (0.1.0)
- No LLM/agent-based exploit generation (BenchJack/trustworthy-env territory;
  non-deterministic, needs API keys, breaks offline/CI-evidence positioning).
- No Z3/formal proof engine (research-grade; would dwarf the core).
- No hosted service, dashboard, database, accounts or telemetry.
- No new attestation predicate (in-toto Test Result suffices; extension field
  documented in REPORT_SCHEMA.md).
- No numerical "quality score" (conceals critical failures; policy on explicit
  findings instead — per brief §4.3).
- (0.1.0 scope) No NeMo Gym / Inspect adapters yet. Both were added in
  0.2.0; see CHANGELOG.md. Future work is tracked in GitHub Issues.

## Validated / rejected product hypotheses (brief §1.3)

| Hypothesis | Verdict |
|---|---|
| Deterministic explainable checks | Validated — core design; every finding carries evidence, confidence, limitations |
| CI-native execution | Validated — exit codes, SARIF, composite Action, static default |
| Cross-framework compatibility | Validated in 0.2.0 — Harbor, generic, NeMo Gym and Inspect adapters implemented |
| Reusable validation profiles | Validated — harbor/strict/minimal/ci profiles in TOML-selectable form |
| Structured evidence | Validated — JSON Schema + per-finding evidence objects |
| Portable digest-bound attestations | Validated — in-toto Test Result, subject = bundle/verifier/solution digests |
| Clear limitations & reproducible findings | Validated — limitations are in every report; bundle digest reproduces the exact input |
| Offline-first open source | Validated — core has zero third-party dependencies |

## Assumptions recorded

- Python ≥3.11 (for `tomllib`); tested on 3.12.
- Harbor tasks are the MVP format; `tests/verifier.py` (NeMo Gym convention)
  is recognised as a verifier entrypoint.
- Example Dockerfiles carry a placeholder base-image digest that must be
  replaced before a real build (documented inline); static checks do not
  need to build images.
