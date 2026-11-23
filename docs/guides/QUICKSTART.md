# Quickstart

```bash
pip install envicert            # or: pipx install envicert / uv tool install envicert
envicert check ./examples/safe-environment
envicert check ./my-task --format json --output report.json
envicert verify report.json --task ./my-task
envicert check ./my-task --format sarif --output envicert.sarif   # GitHub code scanning
```

First run needs no Docker, no account, no network. Dynamic checks are opt-in:

```bash
envicert check ./my-task --execution docker                    # restricted container gold run
envicert check ./examples/python-task --execution local-python --mutation
```

`--execution local-python` runs task code as *you* (no sandbox) — only use it
on tasks you trust. See SECURITY.md and `docs/guides/DYNAMIC_EXECUTION.md`.

## Reading a report

- **FAIL** — the checked property is violated on available evidence.
- **WARN** — heuristic/potential issue, or hardening gap; read the evidence
  and confidence before acting.
- **NOT_RUN** — the check was not executed (e.g. dynamic without opt-in).
  NOT_RUN is never a pass.
- Policy (exit code) fails when any FAIL/WARN is at a `fail_on` severity
  (default CRITICAL/HIGH), or any check errors.

## Configuration

`envicert init` writes a starter `envicert.toml`; `check` picks up
`<task>/envicert.toml` automatically. See CONFIGURATION.md.
