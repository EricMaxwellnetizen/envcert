# Quickstart

```bash
pip install envcert            # or: pipx install envcert / uv tool install envcert
envcert check ./examples/safe-environment
envcert check ./my-task --format json --output report.json
envcert verify report.json --task ./my-task
envcert check ./my-task --format sarif --output envcert.sarif   # GitHub code scanning
```

First run needs no Docker, no account, no network. Dynamic checks are opt-in:

```bash
envcert check ./my-task --execution docker                    # restricted container gold run
envcert check ./examples/python-task --execution local-python --mutation
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

`envcert init` writes a starter `envcert.toml`; `check` picks up
`<task>/envcert.toml` automatically. See CONFIGURATION.md.
