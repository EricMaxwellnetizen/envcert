# Quality report

Generated 2026-11-22 on Windows 11, Python 3.12.13 (uv venv), pytest 9.2.0.
All numbers below are from actually executed commands in this workspace.

## Tests

```
pytest tests -rs
66 passed, 1 skipped in ~23s   (67 collected)
SKIPPED: tests/security/test_security.py::test_symlink_inside_task_does_not_escape
         — symlink creation not permitted for this Windows user (environment limitation, not a product failure)
```

Coverage: **80% total** (`pytest --cov=envcert`), branch coverage on.
Lowest-covered module is `runners/docker_runner.py` (37%): the Docker daemon
was not running on this host (`docker ps` fails to connect), so the live
build/run path could not be exercised end-to-end here; its unavailable path
is tested and fails gracefully. The local-python runner, mutation engine,
CLI (in-process and via subprocess), reports, SARIF, attestations, config
and all static checks are covered.

Suite layout: `tests/unit` (dockerfile/.dockerignore parsing, models/config,
static checks with triggering + near-miss fixtures, reports, attestations,
dynamic/mutation, in-process CLI), `tests/integration` (installed-CLI
subprocess runs, example expected-results fixtures), `tests/security`
(malformed TOML/report, symlink escape, large files, shell-metachar paths).

## Lint / types

```
ruff check envcert tests   → All checks passed
mypy envcert               → Success: no issues found in 32 source files
```

## Package / installation

```
python -m build            → envcert-0.1.0.tar.gz + envcert-0.1.0-py3-none-any.whl (built successfully)
clean venv (uv, CPython 3.12) + pip install dist/*.whl + jsonschema:
  envcert version                      → envcert 0.1.0
  envcert check examples/safe-environment --format json  → exit 0
  envcert verify report.json --task examples/safe-environment → "report OK"
```

The wheel includes `envcert/schemas/report.schema.json`.

## End-to-end demonstrations (executed)

- `envcert check examples/safe-environment` → 24 PASS, 4 NOT_RUN, policy PASSED, exit 0.
- `envcert check examples/intentionally-vulnerable-environment` → EC010/EC011/EC052 FAIL + 12 WARN, policy FAILED, exit 1.
- `envcert check examples/unsupported-environment` → generic adapter, EC001/EC050 FAIL, honestly reported as unrecognised, exit 1.
- `envcert check examples/python-task --execution local-python --mutation` → EC060 PASS, EC061 PASS (no-op rejected), EC062 PASS (3/3 consistent), EC063 PASS (mutation rejection exercised on generated mutants).
- SARIF output generated for the vulnerable example (exit 1); `verify` detects bundle-digest mismatch after task tampering.
- Public pilot: 131 Harbor task-shaped dirs found in a shallow clone of
  harbor-framework/harbor; 12 scanned (see docs/research/PUBLIC_ENVIRONMENT_PILOT.md).

## Security self-review (summary)

Path traversal/symlinks: walker never follows directory symlinks; symlinks
hashed by target string; symlink-target content never enters reports
(tested, currently skipped on this Windows host for privilege reasons).
Command injection: no shell strings built from task data; subprocess calls
use argument arrays. Malformed input: bad TOML/config/report/attestation
inputs exit 2 with specific errors; a crashing check becomes an ERROR
finding and fails policy (tested). Resource exhaustion: 5000-file cap,
2 MB text cap, bounded subprocess output, execution timeouts. Untrusted
Docker builds: only in opt-in docker mode with the restrictions in
THREAT_MODEL.md; static mode never builds.

## Known bugs / limitations

1. Docker dynamic path not end-to-end verified on a live daemon in this
   environment (daemon down). Mitigation: graceful degradation tested;
   needs a run on a Docker-enabled host before 0.1.0 is tagged. (GitHub CI
   itself is green: run 44949955463 passed all 9 OS/Python jobs plus the
   package build/install smoke test on 2026-11-22.)
2. `.dockerignore` matching is a conservative simplification of Docker's
   semantics; affected findings state this.
3. Example Dockerfiles use a placeholder base-image digest (documented
   inline) — replace before actually building them.
4. Severity of some heuristics (EC013, EC021, EC041, EC054) is intentionally
   WARN/low-confidence; expect occasional false positives on unusual but
   legitimate layouts — report them via the bug template.
5. Windows: symlink security test skips without developer-mode privilege.
