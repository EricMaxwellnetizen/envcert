# Architecture

## Overview

```
task dir ──► Adapter (harbor | generic) ──► TaskContext
                                                │
CLI ──► Settings (profile + envicert.toml) ──► Engine ──► Checks (static | dynamic | mutation)
                                                │              │  via Runners (none | docker | local-python)
                                                ▼              ▼
                                     Report dict ──► text | JSON (schema 1.0.0) | SARIF
                                                │
                                                └──► in-toto Test Result attestation (optional Cosign signing)
                                     verify: schema validation + bundle-digest recomputation
```

## Modules

| Path | Responsibility |
|---|---|
| `envicert/cli/main.py` | argparse CLI: `check`, `list-checks`, `explain`, `verify`, `attest`, `init`, `schema`, `version`. Exit codes 0/1/2/3. |
| `envicert/core/models.py` | `Finding`, `Severity`, `Status`, `Confidence` — the public finding model. |
| `envicert/core/config.py` | Profiles (harbor/strict/minimal/ci) + `envicert.toml` parsing/validation. |
| `envicert/core/engine.py` | Loads a task, runs selected checks, builds the report, evaluates policy. A crashing check becomes an ERROR finding — never a silent PASS. |
| `envicert/core/digests.py` | Deterministic sha256 bundle/verifier/solution digests. |
| `envicert/adapters/` | `TaskContext` construction. `harbor.py` implements the verified Harbor layout; `generic.py` handles plain Docker bundles with reduced confidence. New frameworks = new adapter, core untouched. |
| `envicert/checks/base.py` | Check registry (`@check`), `CheckInfo` (stable ID, severity, remediation, limitations). |
| `envicert/checks/static_checks.py` | EC001–EC054 static checks (structure, leakage, boundary, docker, dependencies, verifier). |
| `envicert/checks/dynamic_checks.py` | EC060–EC063, opt-in only. |
| `envicert/checks/mutation.py` | AST mutation operators + rejection-rate computation. |
| `envicert/runners/` | Execution abstraction. `docker_runner.py`: restricted container run. `local_runner.py`: temp-copy pytest run, no sandbox (trusted tasks only). |
| `envicert/reports/` | Text and SARIF serializers (JSON is the report dict itself). |
| `envicert/attestations/intoto.py` | in-toto Statement v1 + Test Result predicate, DSSE envelope, optional Cosign sign-blob. |
| `envicert/schemas/report.schema.json` | Published JSON Schema for report 1.0.0 (shipped in the package; `envicert schema` prints it). |
| `envicert/utils/` | Dockerfile parser, `.dockerignore` matching, safe file walking/reading. |

## Interfaces

- **EnvironmentAdapter**: `load(root) -> TaskContext` (see `adapters/harbor.py`).
- **Check**: function `(CheckContext) -> list[Finding]`, registered with
  `@check(CheckInfo(...))`. Checks never print; they return findings.
- **ExecutionRunner**: `info() -> RunnerInfo`, plus task-run methods returning
  `RunResult` (reward, exit code, bounded output, error).
- **PolicyEvaluator**: `engine.run_checks` — policy fails iff any FAIL/WARN
  finding's severity ∈ `fail_on`, or any check ERRORs. No numeric score.
- **ReportSerializer**: `reports/text.py`, `reports/sarif.py`.
- **AttestationProvider**: `attestations/intoto.py:build_statement`.

## Principles honoured

Local-first, offline static analysis (zero third-party core dependencies),
deterministic (same bundle digest ⇒ same static findings), vendor-neutral,
safe-by-default (dynamic execution is opt-in and capability-aware), no
microservices/databases/hosted APIs, no AI-API requirement.

## Data flow for `envicert check`

1. Parse CLI + `envicert.toml` → `Settings` (validated; bad config exits 2).
2. Detect adapter (task.toml ⇒ harbor, else generic) → `TaskContext`
   (file inventory without following directory symlinks, Dockerfile AST,
   `.dockerignore` patterns, task.toml tables).
3. Compute bundle digest over relative paths + file hashes (symlinks hashed
   by target string, never followed).
4. Run selected checks; each returns findings with evidence.
5. Build report dict, evaluate policy, serialize (text/JSON/SARIF), exit
   0 (policy passed), 1 (policy failed), 2 (invalid input), 3 (internal error).
