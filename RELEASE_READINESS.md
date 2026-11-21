# Release readiness — EnvCert 0.3.0

Status as of 2026-11-22: **published.**
Public repo https://github.com/EricMaxwellnetizen/envcert (initially private, made public the same day). Versions 0.1.0, 0.2.0 and 0.3.0 are tagged, released on GitHub, and published to PyPI via Trusted Publishing.

| Item | Status |
|---|---|
| Current version | 0.3.0 (`envcert/__init__.py`, pyproject); 0.1.0, 0.2.0 and 0.3.0 published (public repo, tags, GitHub releases, PyPI via Trusted Publishing; each release verified by clean-venv pip install) |
| 0.3.0 features | EC065 NeMo verify() probing, EC055 Inspect scorer strength, `check --dataset` rollups, coverage-aware EC063, `--baseline`/SARIF suppressions/`envcert diff`, Inspect external-runner example — fixture-tested; Cosign registry round-trip verified live against a local OCI registry |
| 0.2.0 features | NeMo Gym + Inspect adapters, EC004 multi-step, Docker EC061/EC062/EC064, OCI image digests + Cosign OCI attestation/verify-attestation, external (VM) runner protocol, companion tools EC070–EC072, richer mutation operators — all fixture-tested; Docker + Hadolint paths verified live (Docker 29.7.2, Hadolint 2.12.0) |
| Installation method | `pip install .` from this repo now; `pip install envcert` after PyPI publication |
| Package build | ✅ `python -m build` succeeds; wheel+sdist in `dist/`; wheel verified in a clean venv (CLI runs, schema ships in the wheel) |
| Package name | `envcert` returned 404 from the PyPI JSON API on 2026-11-22 (appears available; re-check at upload time — names can be taken meanwhile) |
| Supported platforms | Python 3.11–3.13; developed/tested on Windows + CPython 3.12. CI matrix covers ubuntu/windows/macos × 3.11/3.12/3.13 (`.github/workflows/ci.yml`, not yet run on GitHub) |
| Supported environment formats | Harbor (incl. multi-step), generic Docker, NeMo Gym datasets, Inspect AI evaluations — all implemented and fixture-tested |
| Implemented checks | 33: EC001–EC054 + EC004 static, EC060–EC062 dynamic, EC063–EC064 mutation, EC070–EC072 external companions (`envcert list-checks`) |
| Deferred checks/features | NeMo Resources-Server live HTTP probing, Inspect dynamic runs, coverage-based equivalent-mutant reduction (docs/architecture/ROADMAP.md "Next") |
| GitHub Action | `action.yml` (composite) + examples prepared; **not exercised on GitHub** from this workspace |
| Attestation status | in-toto Test Result generation + DSSE envelope implemented and unit-tested; Cosign signing is optional and untested here (cosign not installed); unsigned output is labelled as such |
| Tests / lint / types | 66 passed, 1 skipped (Windows symlink privilege); coverage 80%; ruff clean; mypy clean — see docs/QUALITY_REPORT.md |
| GitHub CI | ✅ Passed on GitHub for the pushed `main` (run 44949955463: ubuntu/windows/macos × Python 3.11/3.12/3.13, plus package build/install smoke test); Security workflow run 44949955506 also passed |
| Docker dynamic run | ✅ Verified live on 2026-11-22 (Docker 29.7.2): example Dockerfiles now pin the real `python:3.12-slim` digest (`sha256:5e2bdb1b…a4fa5b`); `envcert check examples/safe-environment --execution docker` builds, runs the gold solution and verifier in the restricted runner, and captures `reward=1.0` -> EC060 PASS. Two runner bugs found and fixed in the process (absolute volume path; harness user/CRLF handling) |
| Public repo / tag / GitHub release | ✅ Repo made public, tag `v0.1.0` pushed, GitHub release created with wheel+sdist assets: https://github.com/EricMaxwellnetizen/envcert/releases/tag/v0.1.0 (all on 2026-11-22) |
| PyPI publication | ✅ Published 2026-11-22 via Trusted Publishing (pending publisher registered by the owner; release run 44952477017 `build`+`publish` succeeded). One fix was needed along the way: hatchling ≥1.28 emits Metadata-Version 2.5, which PyPI's uploader rejects, so the build backend is capped `hatchling<1.28` and the licence uses the legacy table form (wheel metadata 2.4). Verified from a clean venv: `pip install envcert` then `envcert check examples/safe-environment` exits 0. No PyPI token is stored anywhere in this project. |
| Not done (needs owner credentials/decision) | Making the repo public, version tag, GitHub release, PyPI upload, Cosign key management |

## Steps to publish (owner)

1. Make the private repository public when ready (Settings → General → Danger Zone), after confirming no sensitive material is in history.
2. Watch the CI workflow go green (all OS/Python cells + package smoke test).
3. On PyPI, create the `envcert` project with a Trusted Publisher pointing at
   this repo's `release.yml` + `pypi` environment.
4. Optionally replace the placeholder digest in the two example Dockerfiles
   (`docker buildx imagetools inspect python:3.12-slim`).
5. Tag `v0.1.0` and push the tag — `release.yml` builds, checks with twine,
   and publishes via Trusted Publishing.
6. Create the GitHub release from `docs/releases/v0.1.0.md`, attaching
   `dist/*` and example JSON/SARIF reports.
7. Verify from a clean machine: `pip install envcert && envcert check <task>`.
