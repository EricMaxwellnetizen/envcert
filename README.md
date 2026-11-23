# Envicert

[![PyPI](https://img.shields.io/pypi/v/envicert.svg)](https://pypi.org/project/envicert/)
[![CI](https://github.com/EricMaxwellnetizen/envicert/actions/workflows/ci.yml/badge.svg)](https://github.com/EricMaxwellnetizen/envicert/actions/workflows/ci.yml)
[![Docs](https://img.shields.io/badge/docs-mkdocs-blue.svg)](https://ericmaxwellnetizen.github.io/envicert/)

**Integrity verification and evidence for AI training and evaluation environments.**

Envicert checks whether the thing you measure models with is trustworthy:
a task bundle (instruction, Docker environment, reference solution,
verifier) or the dataset file itself (JSONL/JSON/CSV). Is the answer
leaked to the agent? Can agent-controlled files influence the verifier?
Would a *cheating* solution pass? Are train and test rows the same rows?
Is the build reproducible, the evidence verifiable?

It answers with explicit, deterministic findings (never a single score),
schema-versioned reports (text/JSON/SARIF/Markdown/HTML), a cheat-agent
battery that *proves* false passes by execution, deterministic fixes,
and an optional digest-bound [in-toto](https://in-toto.io) attestation.

Envicert is **not** a certification authority and never claims an environment
is unhackable. It is an independent, extensible verification and evidence
layer — complementary to Harbor / NeMo Gym (which run tasks), BenchJack /
trustworthy-env (which hunt novel exploits with AI agents), and Trivy/
Hadolint/Semgrep (CVE/lint/SAST). No LLM, no API key, no account:
everything above runs offline. See `docs/research/PRODUCT_REVIEW.md`
for the evidence that this gap is real, and
`docs/research/COMPETITIVE_ANALYSIS.md` for the feature matrix.

## Who is it for?

Environment developers, benchmark maintainers, AI researchers and model
developers who publish or consume evaluation tasks and need to know *what
was checked, what failed, what could not be checked, and whether someone
else can reproduce that*.

## Install

Requires Python 3.11+.

```bash
pip install envicert          # from PyPI
pipx install envicert         # or isolated
# From a checkout of this repository:
pip install .
```

The core has **zero runtime dependencies**: static analysis works offline,
with no Docker, account, network or API key.

## Quick start

```bash
envicert check ./examples/safe-environment
envicert check ./examples/intentionally-vulnerable-environment   # exit 1: try it
envicert check ./my-task --format json --output report.json
envicert check ./my-task --format sarif --output envicert.sarif
envicert check ./my-task --format markdown --output summary.md    # PR-ready
envicert check ./my-task --format html --output report.html       # shareable
envicert check ./data/train.jsonl                                 # dataset files, no bundle needed
envicert check ./my-task --execution docker                       # gold + no-op + cheat battery
envicert fix ./my-task                                            # dry-run deterministic fixes
envicert fix ./my-task --apply
envicert new ./my-new-task                                        # scaffold that passes check
envicert verify report.json --task ./my-task
envicert list-checks
envicert explain EC066
```

Real output (safe example, abridged):

```text
Envicert 0.4.5  report schema 1.0.0
Task: envicert/hello-file  adapter=harbor  files=8
Profile: harbor  execution: none  fail_on: CRITICAL, HIGH

[PASS] EC001 (INFO/PASS) Task structure is recognisable and complete
[PASS] EC011 (INFO/PASS) Reference solution is not copied into the agent environment
[PASS] EC020 (INFO/PASS) Verifier runs separated from the agent where the framework supports it
[PASS] EC051 (INFO/PASS) Verifier produces a reward in the framework's expected location
[SKIP] EC060 (INFO/NOT_RUN) Reference (gold) solution passes the verifier
       Dynamic checks are opt-in: re-run with --execution docker or --execution local-python.
Summary: 43 findings {'PASS': 25, 'NOT_APPLICABLE': 8, 'NOT_RUN': 10}
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

43 checks with stable public IDs (full catalog:
`docs/architecture/CHECK_CATALOG.md`, or `envicert list-checks -v`):

| Area | Checks | Examples |
|---|---|---|
| Structure | EC001–EC003 | missing verifier/instruction, absent reference solution |
| Leakage | EC010–EC014 | .git in build context, solution copied into image, gold files, hard-coded secrets, instruction disclosing the solution |
| Agent/verifier boundary | EC020–EC024 | shared verifier mode, sitecustomize/conftest shadowing, PATH tool shadowing, world-writable paths, docker.sock/privileged |
| Docker | EC030–EC033 | unpinned base images, root user, remote ADD / curl\|sh, undeclared network policy |
| Dependencies | EC040–EC041 | unpinned pip deps, unverified downloads |
| Verifier quality | EC050–EC056 | missing/empty verifier, no reward production, unconditional success, assertion-free tests, self-reported rewards (AST data-flow), eval/unsafe-deserialisation in the verifier |
| Dataset integrity | EC080–EC085 | answer embedded in the prompt, exact/near/semantic duplicate rows, train/test overlap, degenerate labels, broken rows, inconsistent grading specs |
| Multi-step | EC004 | per-step instruction/verifier completeness (plus per-step EC002) |
| Dynamic (opt-in) | EC060–EC062, EC065 | gold run, no-op negative control, repeatability, NeMo verify()/HTTP Resources-Server probing |
| Cheat battery (opt-in) | EC066 | deterministic cheat agents — stub solution, conftest outcome-faking, forged reward file, verifier tampering — must all be rejected |
| Mutation (opt-in) | EC063–EC064 | AST mutants of Python solutions, lexer mutants of JS/TS solutions, literal mutants of shell solutions under Docker |
| External companions (opt-in) | EC070–EC072 | Hadolint, Trivy, Semgrep — run only when installed and `--external-tools` is passed |

Every finding carries evidence, a severity, a confidence, a remediation and
stated limitations. Heuristics report WARN — Envicert does not present a
potential exposure as a confirmed vulnerability.

## What it cannot do

- Prove a verifier semantically correct, or an environment unhackable.
- See runtime mounts/configuration outside the task bundle (static mode).
- Scan base images for CVEs (use Trivy/Grype) or replace an adversarial
  audit (BenchJack-style) for high-stakes benchmarks.
- Dynamic Docker checks need a Docker daemon; `local-python` execution has
  **no sandbox** and must only be used on trusted tasks. See
  `docs/guides/DYNAMIC_EXECUTION.md`.

## Dynamic, cheat-battery & mutation checks (opt-in)

```bash
envicert check ./my-harbor-task --execution docker                 # Dockerfile, compose or prebuilt image
envicert check ./examples/python-task --execution local-python --mutation
envicert check ./js-task --execution local-python --mutation       # JS/TS mutants too
envicert check ./nemo-dataset --execution local-python              # local verify() probing
envicert check ./nemo-dataset --nemo-endpoint https://gym.example/verify  # HTTP Resources Server
# EC060 PASS gold, EC061 PASS no-op rejected, EC062 PASS repeatable, EC063 mutation rejection rate
# EC066: deterministic cheat agents (stub solution, conftest outcome-faking,
#        forged reward file, verifier tampering) are played against your
#        verifier -- a cheat that passes is a proven false pass, not a heuristic.
```

## Datasets, fixes and scaffolding

```bash
envicert check ./train.jsonl            # answers-in-prompts, duplicates, split overlap, degenerate labels
envicert check ./data/                  # every .jsonl/.json/.csv beneath a directory (train/test aware)
envicert fix ./my-task                  # dry-run: deterministic, idempotent remediation plan
envicert fix ./my-task --apply          # write it (.dockerignore, declared policies), then re-check
envicert new ./my-task --name org/my-task   # a Harbor task scaffolded to pass `envicert check`
```

Pre-commit: `repo: https://github.com/EricMaxwellnetizen/envicert` with hook
id `envicert` (tasks) or `envicert-dataset` (data files). Third-party checks
can register under the `envicert.checks` entry-point group — no fork needed.

## Reports, verification, attestations

```bash
envicert check ./my-task --format json --output report.json
envicert verify report.json --task ./my-task        # schema + consistency + bundle digest
envicert verify report.json --task ./my-task --recheck   # + re-run the static checks and compare
envicert verify report.json --baseline old.json     # verify the baseline suppression
envicert schema                                     # published JSON Schema (report 1.0.0)
envicert attest report.json --output attestation.json          # in-toto Test Result statement
envicert attest report.json --dsse --sign --key cosign.key     # DSSE + Cosign, when installed
envicert verify-attestation attestation.json --key cosign.pub  # verify a detached .sig
```

`verify` recomputes policy and summary counts from the findings, so editing
`policy.passed` or the counters is detected; `--recheck` additionally proves
that the report's findings are the findings Envicert produces for the task.
Reports that rely on baseline suppression must be verified with `--baseline`.
Unsigned attestations are labelled unsigned everywhere and require
`--allow-unsigned` for structural verification only — they are portable
evidence records, not cryptographic proof. Report fields and the attestation
extension are specified in `docs/architecture/REPORT_SCHEMA.md`.

## GitHub Actions

```yaml
- uses: EricMaxwellnetizen/envicert@v0.4.5   # or @v0 for the latest 0.x
  with:
    path: ./my-task
    fail-on: critical,high
    sarif: envicert.sarif   # optional, for GitHub code scanning
```

See `action.yml` (composite action), `examples/github-actions/` and
`docs/guides/CI.md`. Static checks by default; dynamic execution only when
you explicitly select it.

Exit codes: `0` policy passed · `1` policy failed · `2` invalid
input/config · `3` internal/execution error.

## Supported formats

| Format | Status |
|---|---|
| Harbor task directories (task.toml schema 1.x, incl. multi-step `steps/`, Dockerfile / docker-compose / prebuilt `docker_image`) | Implemented and fixture-tested |
| Generic Docker task bundles (Dockerfile + tests/solution) | Implemented, reduced-confidence heuristics |
| NeMo Gym datasets (dataset.toml / verifier.py / JSONL rows) | Implemented (static + local verify() probing + HTTP Resources-Server probing) — `examples/nemo-gym-dataset` |
| Inspect AI evaluations (@task Python files) | Implemented (static) — `examples/inspect-eval` |
| Dataset files (`.jsonl` / `.json` / `.csv`, SWE-bench/NeMo/OpenAI-style fields) | Implemented (EC080–EC085) — `envicert check data.jsonl` |

Dynamic execution modes: `docker` (restricted), `local-python` (trusted
pytest tasks, no sandbox), `external` (your disposable-VM/remote runner via
a documented JSON protocol). OCI image digests can be bound with
`--image`/`--image-digest`; Cosign OCI attestation is available via
`envicert attest --image name@sha256:...` and `envicert verify-attestation`.

## Configuration

`envicert init` writes `envicert.toml` (profiles: harbor/strict/minimal/ci,
per-check enable/disable, `fail_on` policy). See `docs/guides/CONFIGURATION.md`.

## Adopting it

`docs/research/INDUSTRY_READINESS.md` is the operator's entry point: the
deployment envelope, what was proven on 723 real task bundles and the full
2,294-row SWE-bench split, the guarantees and the honest limits, an
adoption checklist and the release-integrity checklist.

## Contributing

See `CONTRIBUTING.md` and `docs/guides/WRITING_A_CHECK.md` — adding a check
needs a triggering fixture *and* a near-miss false-positive control.

## Development

```bash
pip install -e ".[dev]"
pytest --cov=envicert
ruff check envicert tests
mypy envicert
python -m build
```

## Licence

Apache-2.0. Research and design rationale: `docs/research/`,
`docs/architecture/`. Release history: `CHANGELOG.md` and GitHub Releases.
Future work is tracked in GitHub Issues.
