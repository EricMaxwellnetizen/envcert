# Competitive analysis

Date: 2026-11-22. Legend: **Y** = verified in a primary source, **N** = verified
absent (looked for, not found in docs/repo), **?** = unknown / not verified.
Do not read `?` as "missing".

| Capability | EnvCert (this repo) | BenchJack | trustworthy-env | Harbor | NeMo Gym | Inspect AI | Hadolint | Semgrep | Trivy |
|---|---|---|---|---|---|---|---|---|---|
| Static analysis of task bundles | Y | Y | Y | ? (task load validation) | ? | N (different layer) | Dockerfile only | generic code | image/CVE |
| Dynamic validation (gold run) | Y (opt-in docker/local) | Y (exploit runs) | Y (runtime stage) | Y | Y (`gym dataset validate`) | Y (eval runs) | N | N | N |
| Reward/verifier correctness focus | Y | Y | Y | partial | partial (gold only, per its docs) | scorer-level | N | N | N |
| Answer/solution leakage checks | Y | Y | Y | ? | ? | N | N | generic rules possible | N |
| Filesystem/verifier isolation checks | Y | Y | Y | runtime feature | runtime feature | sandbox feature | N | N | N |
| Mutation testing of verifier | Y (Python/pytest) | ? | Y (runtime stage) | N | N (docs advise manual break-test) | N | N | N | N |
| Negative controls (no-op must fail) | Y | Y (exploits) | Y | ? | manual per docs | N | N | N | N |
| Reproducibility signals (pinning/lockfiles) | Y | ? | ? | ? | ? | log-level | partial | N | Y (image) |
| Docker support | Y | Y | Y | Y | Y | Y | Y | N | Y |
| CI integration (exit codes, Action) | Y | ? | ? | Y | Y | Y | Y | Y | Y |
| JSON report with published schema | Y | findings.json (? schema) | Y (? schema) | trial logs | result rows | Y (eval logs) | Y | Y | Y |
| SARIF output | Y | ? | ? | ? | ? | ? | ? | Y | Y |
| Signed attestations (in-toto/DSSE) | Y (optional cosign) | N (not found) | N (not found) | ? | ? | N | N | N | Y (cosign ecosystem) |
| Policy enforcement (fail_on severities) | Y | ? | risk scoring | ? | exit codes | ? | exit codes | Y | Y |
| Framework compatibility | Harbor + generic Docker | many benchmarks (agent-driven) | many benchmarks | Harbor | Harbor + JSONL | own task format | Dockerfile | many languages | OCI/filesystem |
| Offline operation (static) | Y | N (AI phases need API) | partial (formal engine only) | Y | Y | Y | Y | Y | partial (DB) |
| Extensibility (add a check) | Y (documented, stable IDs) | adapters proposed | ? | providers | servers | extensions | rules | rules | plugins |
| Licence | Apache-2.0 | Apache-2.0 | ? (check repo) | ? (check repo) | ? (check repo) | MIT (?) | Haskell, GPL-3 (?) | LGPL-2.1 (?) | Apache-2.0 |
| Maintenance activity (at research time) | new | active (2026) | active (2026) | active | active | active | maintained | active | active |

Licence cells marked `(?)` were not re-verified for every project in this
session and must be checked before any code reuse. EnvCert reuses **no code**
from any of these projects; it interoperates with Harbor's documented task
format and in-toto's published predicate types only.

## Reading of the matrix

- The "integrity evidence" column-combination — deterministic checks +
  schema'd report + SARIF + policy exit codes + digest-bound attestation,
  offline, no LLM — is not occupied by a verified competitor.
- BenchJack/trustworthy-env are stronger at *discovering novel exploits*
  (agent + PoC). EnvCert is deliberately weaker there and stronger at
  *repeatable CI evidence*. These are complementary; docs recommend running
  an adversarial audit (BenchJack-style) in addition to EnvCert for
  high-stakes benchmarks.

## 0.4.0 update (2026-11-22, see PRODUCT_REVIEW.md)

EnvCert 0.4.0 adds capabilities with no verified equivalent above:
deterministic cheat-agent battery (EC066 — executed false-pass proof
without an LLM), AST data-flow reward-provenance analysis (EC054/EC056),
bare dataset-file auditing (EC080–EC084: answer leakage, duplicates,
split overlap, degenerate labels), deterministic auto-remediation
(`envcert fix`), task scaffolding (`envcert new`), Markdown/HTML
reports, Action PR comments/step summaries, pre-commit hooks and
entry-point plugin checks. The rows above predate 0.4.0 where they
describe EnvCert as task-bundle-only or heuristic-only.
