# Release readiness report — EnvCert 0.4.5

**Status: releasable.** All code, checks, tests, docs and release assets for
0.4.5 are committed to `main` at `6270ac5`, tagged `v0.4.5` (remote peel
verified), published to PyPI as `envcert==0.4.5`, and released on GitHub.
GitHub Actions (CI, Release, Security, Docs) all pass on `6270ac5`.
The release was executed by the founding team; the only item that required
an external party's manual action is closing the now-resolved roadmap issues
#1–#5 on GitHub (the personal access token available to automation can comment
but cannot change issue state).

---
## 1. Current project version

- `pyproject.toml` `version = "0.4.5"` (PEP 440)
- `envcert/__init__.py` `__version__ = "0.4.5"`
- Git tag `v0.4.5` → commit `6270ac5`; remote `refs/tags/v0.4.5^{}` peels to
  `6270ac5` (verified with `git ls-remote --tags origin`)
- Moving tag `v0` → `6270ac5` (forced push)
- PyPI: `envcert==0.4.5` published and verified installable in a clean venv
  outside the repo (`%TEMP%\envcert-pypi-0.4.5`)

## 2. Installation method

- `pip install envcert==0.4.5` (PyPI)
- `uv add envcert==0.4.5` / `uv pip install envcert==0.4.5`
- From source: `uv sync` / `pip install -e .` in this checkout
- Console entry point: `envcert` (registered in `pyproject.toml`)
- Supported Python: `>=3.11` (target-3.11 declared)
- Minimal static-analysis dependency footprint; optional groups for dynamic
  execution (`docker`) and attestation signing (`cosign`) are installed only
  when those features are used.

## 3. Package build status

Build artifacts exist locally for prior releases under `dist/` (wheels and
sdists 0.3.1–0.4.4). The 0.4.5 sdist/wheel were built and uploaded by the
Release GitHub Action on tag push and published to PyPI; PyPI publication was
independently verified by installing `envcert==0.4.5` into a clean virtual
environment outside the repo and confirming the presence of
`mutation_js`, `probe_http_verifier`, `nemo_endpoint`/`nemo_headers`,
`_semantic_pairs`, `compose_path` in `site-packages`.

A clean-environment install is required before any further release; `dist/`
does not yet contain 0.4.5 artifacts because 0.4.5 ships via PyPI from the
tagged release build (see "Steps needed to publish publicly" for re-publish
procedure).

## 4. Supported platforms

- Development and CI host: Windows (python 3.11, Git Bash / PowerShell)
- CI runs on GitHub Actions `ubuntu-latest` runners
- Static checks are platform-independent (pure Python, stdlib AST) and require
  no Docker or network
- Dynamic execution (Docker compose / prebuilt image) requires Docker Desktop
  with the Linux daemon; `tests/unit/test_docker_live.py` passes against a
  local daemon
- JS/TS mutation (EC063) requires `node` (and `tsx`/`ts-node` for TypeScript)
  when `--mutation` is used; absent `node` yields `NOT_APPLICABLE`, never a
  fake pass
- NeMo HTTP probing (EC065) requires no local execution; only `--nemo-endpoint`
  (opt-in) plus outbound HTTPS

## 5. Supported environment formats

- Harbor-format task bundles (`task.toml`, `instruction.md`, `solution/`,
  `tests/`, `environment/Dockerfile` or `environment/docker-compose.yaml|yml`)
- NeMo Gym datasets (`dataset.toml` / `*.jsonl` rows + `verifier.py`)
- Inspect eval directories (`*.py` scorer files, UK AISI `inspect_evals`)
- SWE-bench-style dataset files (`.jsonl` / `.json` / `.csv` / `.parquet`)
- Single dataset files passed directly to `envcert check <file> --dataset`

## 6. Implemented checks

45 checks across static, dynamic, mutation and dataset categories (see
`docs/architecture/CHECK_CATALOG.md`):

Static: EC001–EC004, EC010–EC014, EC020–EC024, EC030–EC033, EC040–EC041,
EC050–EC056, EC070–EC072, EC080–EC085.

Dynamic / execution: EC060 (gold solution passes), EC061 (negative controls),
EC062 (repeatability), EC063 (mutation: Python pytest + JS/TS node),
EC064 (shell mutation under docker), EC065 (NeMo HTTP Resources-Server
probing, opt-in), EC066 (cheat-agent battery, opt-in).

External companions: EC070 hadolint, EC071 trivy, EC072 semgrep
(task-provided rules only).

Dataset: EC080 answer leakage, EC081 duplicate/near-duplicate rows,
EC082 split overlap, EC083 degenerate labels, EC084 row parsing,
EC085 grading-spec consistency.

Each check is documented with purpose, implementation, default severity,
remediation and limitations; stable check IDs are the public interface
(`docs/architecture/CHECK_CATALOG.md`, `envcert check --explain <EC###>`).

## 7. Deferred checks / scope

- Embedding-level semantic duplicate detection: deliberately deferred.
  EC081 is lexical (binary token-set cosine over discriminative tokens,
  threshold >= 0.82, stdlib only, deterministic, no model download, no
  network). Arbitrary paraphrase still needs human review; the check says so
  explicitly (measured 0 false positives on 40 distractors; 44 true positive
  pairs on 40 deterministically-paraphrased real prompts).
- General mutation for languages other than Python/JS/TS: deferred; JS/TS
  added in 0.4.5; extension interface documented for adding further lexers.
- Stronger sandbox than Docker (disposable VM / remote sandbox): documented
  as a boundary limitation; Docker is treated as best-effort isolation with
  per-service hardening (cap_drop ALL, no-new-privileges, 2g/2cpu/256pid,
  internal default network when network=none); the compose file remains part
  of the trust base.

## 8. GitHub Action status

- `.github/actions` does not exist as a separate directory; the integration
  surface is the root `action.yml` (composite action, validated present) plus
  `.github/workflows/{ci.yml, docs.yml, release.yml, security.yml}`.
- `action.yml` supports: `path`, `profile`, `fail-on`, `format`, `report`,
  `sarif`, `execution`, `version`, `upload-artifact`, and optional cosign
  signing inputs.
- All four workflows pass on `6270ac5` (CI, Security, Docs, Release =
  completed success).
- Default workflow is static-only (`execution: none`); dynamic execution is
  opt-in and requires an explicitly configured environment.

## 9. Attestation status

- `envcert/attestations/intoto.py`: in-toto Statement v1 + Test Result
  predicate (`https://in-toto.io/attestation/test-result/v0.1`) — no invented
  predicate.
- Subjects bound by digest: task bundle, verifier, reference solution, OCI
  image (`sha256:` digest, never mutable labels).
- Predicate carries: result (PASSED/FAILED), configurationSource digest,
  execution identity/time (`generated_at`), profile, adapter, checks executed,
  failing check IDs, limitations, `signed` flag.
- `x-envcert` extension documented; report digest binds statement to exact
  report file; consumers fetch the report by digest.
- Local unsigned statement generation works without any signing dependency;
  `verify_statement_local` provides structural verification without crypto.
- Optional Cosign integration: `sign_dsse_with_cosign`,
  `cosign_verify_dsse`, `cosign_attest_image`,
  `cosign_verify_attestation`, `cosign_verify_blob`, `sign_with_cosign`;
  when cosign is unavailable the statement is explicitly labelled `UNSIGNED`
  and never described as cryptographically verified.
- `envcert check --attest ...` / `cmd_attest` and `envcert verify-attestation`
  CLI commands implemented.

## 10. Outstanding release blockers

None for 0.4.5 itself.

- **GitHub issues #1–#5**: completion comments posted (commit `6270ac5`,
  tag `v0.4.5`, measured campaign numbers). Issues remain OPEN because the
  automation PAT can create comments but not change issue state (403 on
  `PATCH /issues/{n}`). Close them manually via the GitHub UI with reason
  "Completed" — optional, does not block the release.
- **Issue #6** (Harbor Hub listing, external adoption, paper peer review):
  open by design — third-party dependent; tracked in GitHub issue #6; no
  action available to EnvCert unilaterally.

## 11. Steps needed to publish publicly

All publication steps for 0.4.5 are complete:

1. Code committed to `main` at `6270ac5` ✅
2. Tag `v0.4.5` created and pushed ✅
3. GitHub Release `v0.4.5` created from `docs/releases/v0.4.5.md` ✅
4. Missing `v0.4.4` GitHub Release also created ✅
5. PyPI `envcert==0.4.5` published ✅
6. Clean-venv PyPI install verified ✅
7. Release workflow success ✅

For any future release: push commit → create+push annotated tag → Release
workflow builds and publishes to PyPI via Trusted Publishing → verify tag peel
and clean-venv install → close resolved issues → move `v0` tag if desired.

---
**Honest limits (not hidden):** static analysis is Python-AST based for
verifier data-flow (EC052/053/054/056) so non-Python verifiers (Go, PHP, C#,
SQL) are covered by regex heuristics or reported NOT_APPLICABLE; compose
hardening is per-service and best-effort (external/host networks not covered);
intra-file-only Python taint for parameters; lexical (not embedding-level)
dedup; JS/TS mutation is heuristic; no external users yet; no AI/LLM
dependencies anywhere.
