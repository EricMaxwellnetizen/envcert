# EnvCert

**Integrity verification and evidence for AI training and evaluation environments.**

EnvCert checks whether an AI evaluation environment — a task bundle with an
instruction, a Docker environment, a reference solution and a verifier — is
actually trustworthy: Is the answer leaked to the agent? Can agent-controlled
files influence the verifier? Would an incorrect solution pass? Is the build
reproducible, the network policy declared, the evidence reproducible?

It answers with explicit, deterministic findings (never a single score),
a schema-versioned JSON report, SARIF for code scanning, and an optional
digest-bound [in-toto](https://in-toto.io) attestation.

EnvCert is **not** a certification authority and never claims an environment
is unhackable. It is an independent, extensible verification and evidence
layer — complementary to Harbor / NeMo Gym (which run tasks), BenchJack /
trustworthy-env (which hunt exploits with AI agents), and Trivy/Hadolint/
Semgrep (CVE/lint/SAST). See `docs/research/COMPETITIVE_ANALYSIS.md`.

## Who is it for?

Environment developers, benchmark maintainers, AI researchers and model
developers who publish or consume evaluation tasks and need to know *what
was checked, what failed, what could not be checked, and whether someone
else can reproduce that*.

## Install

Requires Python 3.11+.

```bash
pip install envcert          # from PyPI
pipx install envcert         # or isolated
# From a checkout of this repository:
pip install .
```

The core has **zero runtime dependencies**: static analysis works offline,
with no Docker, account, network or API key.

## Quick start

```bash
envcert check ./examples/safe-environment
envcert check ./examples/intentionally-vulnerable-environment   # exit 1: try it
envcert check ./my-task --format json --output report.json
envcert check ./my-task --format sarif --output envcert.sarif
envcert verify report.json --task ./my-task
envcert list-checks
envcert explain EC011
```

Real output (safe example, abridged):

```text
EnvCert 0.1.0  report schema 1.0.0
Task: envcert/hello-file  adapter=harbor  files=8
Profile: harbor  execution: none  fail_on: CRITICAL, HIGH

[PASS] EC001 (INFO/PASS) Task structure is recognisable and complete
[PASS] EC011 (INFO/PASS) Reference solution is not copied into the agent environment
[PASS] EC020 (INFO/PASS) Verifier runs separated from the agent where the framework supports it
[PASS] EC051 (INFO/PASS) Verifier produces a reward in the framework's expected location
[SKIP] EC060 (INFO/NOT_RUN) Reference (gold) solution passes the verifier
       Dynamic checks are opt-in: re-run with --execution docker or --execution local-python.
Summary: 28 findings {'PASS': 24, 'NOT_RUN': 4}
Policy: PASSED (fail_on=CRITICAL, HIGH)
```

The intentionally vulnerable example produces (among others):

```text
[FAIL] EC010 (HIGH/FAIL)  .git metadata is inside the Docker build context and not excluded by .dockerignore
[FAIL] EC011 (CRITICAL/FAIL) Reference/answer material inside the build context is plausibly copied into the image by 'COPY .'
[FAIL] EC052 (CRITICAL/FAIL) Possible unconditional-success path in verifier: unconditional 'echo 1 > reward.txt'
[WARN] EC021 (HIGH/WARN) 'environment/conftest.py' is in an agent-visible area and pytest auto-loads conftest.py ...
```

## What it checks

28 checks with stable public IDs (full catalog:
`docs/architecture/CHECK_CATALOG.md`, or `envcert list-checks -v`):

| Area | Checks | Examples |
|---|---|---|
| Structure | EC001–EC003 | missing verifier/instruction, absent reference solution |
| Leakage | EC010–EC014 | .git in build context, solution copied into image, gold files, hard-coded secrets, instruction disclosing the solution |
| Agent/verifier boundary | EC020–EC024 | shared verifier mode, sitecustomize/conftest shadowing, PATH tool shadowing, world-writable paths, docker.sock/privileged |
| Docker | EC030–EC033 | unpinned base images, root user, remote ADD / curl\|sh, undeclared network policy |
| Dependencies | EC040–EC041 | unpinned pip deps, unverified downloads |
| Verifier quality | EC050–EC054 | missing/empty verifier, no reward production, unconditional success, assertion-free tests, self-reported rewards |
| Dynamic (opt-in) | EC060–EC062 | gold run, no-op negative control, repeatability |
| Mutation (opt-in) | EC063 | AST mutants of a Python solution; rejection rate as a strength signal |

Every finding carries evidence, a severity, a confidence, a remediation and
stated limitations. Heuristics report WARN — EnvCert does not present a
potential exposure as a confirmed vulnerability.

## What it cannot do

- Prove a verifier semantically correct, or an environment unhackable.
- See runtime mounts/configuration outside the task bundle (static mode).
- Scan base images for CVEs (use Trivy/Grype) or replace an adversarial
  audit (BenchJack-style) for high-stakes benchmarks.
- Dynamic Docker checks need a Docker daemon; `local-python` execution has
  **no sandbox** and must only be used on trusted tasks. See
  `docs/guides/DYNAMIC_EXECUTION.md`.

## Dynamic & mutation checks (opt-in)

```bash
envcert check ./my-harbor-task --execution docker                 # restricted container run
envcert check ./examples/python-task --execution local-python --mutation
# EC060 PASS gold, EC061 PASS no-op rejected, EC062 PASS repeatable, EC063 mutation rejection rate
```

## Reports, verification, attestations

```bash
envcert check ./my-task --format json --output report.json
envcert verify report.json --task ./my-task        # schema + bundle-digest recomputation
envcert schema                                     # published JSON Schema (report 1.0.0)
envcert attest report.json --output attestation.json          # in-toto Test Result statement
envcert attest report.json --dsse --sign --key cosign.key     # DSSE + Cosign, when installed
```

Unsigned attestations are labelled unsigned everywhere — they are portable
evidence records, not cryptographic proof. Report fields and the attestation
extension are specified in `docs/architecture/REPORT_SCHEMA.md`.

## GitHub Actions

See `action.yml` (composite action), `examples/github-actions/` and
`docs/guides/CI.md`. Static checks by default; dynamic execution only when
you explicitly select it.

Exit codes: `0` policy passed · `1` policy failed · `2` invalid
input/config · `3` internal/execution error.

## Supported formats

| Format | Status |
|---|---|
| Harbor task directories (task.toml schema 1.x) | Implemented and fixture-tested |
| Generic Docker task bundles (Dockerfile + tests/solution) | Implemented, reduced-confidence heuristics |
| NeMo Gym JSONL/resources layouts, Inspect AI tasks | Not yet — roadmap, not promised (`docs/architecture/ROADMAP.md`) |

## Configuration

`envcert init` writes `envcert.toml` (profiles: harbor/strict/minimal/ci,
per-check enable/disable, `fail_on` policy). See `docs/guides/CONFIGURATION.md`.

## Contributing

See `CONTRIBUTING.md` and `docs/guides/WRITING_A_CHECK.md` — adding a check
needs a triggering fixture *and* a near-miss false-positive control.

## Development

```bash
pip install -e ".[dev]"
pytest --cov=envcert
ruff check envcert tests
mypy envcert
python -m build
```

## Licence

Apache-2.0. Research and design rationale: `docs/research/`,
`docs/architecture/`. Release status: `RELEASE_READINESS.md`.
