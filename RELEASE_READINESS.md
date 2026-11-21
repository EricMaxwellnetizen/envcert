# Release readiness — EnvCert 0.1.0

Status as of 2026-11-22: **release candidate in a private GitHub repository; not published.**
The private repo https://github.com/EricMaxwellnetizen/envcert was created and the code pushed on 2026-11-22. No version tag, GitHub release or PyPI upload has been performed.

| Item | Status |
|---|---|
| Current version | 0.1.0 (`envcert/__init__.py`, pyproject) |
| Installation method | `pip install .` from this repo now; `pip install envcert` after PyPI publication |
| Package build | ✅ `python -m build` succeeds; wheel+sdist in `dist/`; wheel verified in a clean venv (CLI runs, schema ships in the wheel) |
| Package name | `envcert` returned 404 from the PyPI JSON API on 2026-11-22 (appears available; re-check at upload time — names can be taken meanwhile) |
| Supported platforms | Python 3.11–3.13; developed/tested on Windows + CPython 3.12. CI matrix covers ubuntu/windows/macos × 3.11/3.12/3.13 (`.github/workflows/ci.yml`, not yet run on GitHub) |
| Supported environment formats | Harbor task directories (implemented, fixture-tested); generic Docker bundles (heuristic). NeMo Gym/Inspect: not implemented |
| Implemented checks | 28: EC001–EC054 static (24), EC060–EC062 dynamic, EC063 mutation (`envcert list-checks`) |
| Deferred checks/features | Docker negative controls, OCI image digest subject, Cosign `attest` to a registry, multi-step per-step auditing, NeMo/Inspect adapters (docs/architecture/ROADMAP.md) |
| GitHub Action | `action.yml` (composite) + examples prepared; **not exercised on GitHub** from this workspace |
| Attestation status | in-toto Test Result generation + DSSE envelope implemented and unit-tested; Cosign signing is optional and untested here (cosign not installed); unsigned output is labelled as such |
| Tests / lint / types | 66 passed, 1 skipped (Windows symlink privilege); coverage 80%; ruff clean; mypy clean — see docs/QUALITY_REPORT.md |
| GitHub CI | ✅ Passed on GitHub for the pushed `main` (run 44949955463: ubuntu/windows/macos × Python 3.11/3.12/3.13, plus package build/install smoke test); Security workflow run 44949955506 also passed |
| Docker dynamic run | ✅ Verified live on 2026-11-22 (Docker 29.7.2): example Dockerfiles now pin the real `python:3.12-slim` digest (`sha256:5e2bdb1b…a4fa5b`); `envcert check examples/safe-environment --execution docker` builds, runs the gold solution and verifier in the restricted runner, and captures `reward=1.0` -> EC060 PASS. Two runner bugs found and fixed in the process (absolute volume path; harness user/CRLF handling) |
| Outstanding release blockers | Configure PyPI Trusted Publishing for `EricMaxwellnetizen/envcert` (one registration on pypi.org by the account owner — see "Steps to publish"), then let the `v0.1.0` tag workflow publish. |
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
