# Dynamic execution — safety model

Dynamic checks are **opt-in** (`--execution ...`). Static analysis never
builds or runs task code.

## Modes

| Mode | What runs | Isolation | Use when |
|---|---|---|---|
| `none` (default) | Nothing. Dynamic checks return NOT_RUN. | n/a | CI static gates, untrusted bundles |
| `docker` | Builds `environment/Dockerfile`, runs solution + verifier in a container, reads the reward | Container with `--cap-drop ALL`, `no-new-privileges`, 2 CPU / 2 GB / 256 PIDs limits, timeout, network per flag (default none), read-only task mount, **no docker.sock**, image removed afterwards | Trusted-enough Harbor tasks on a host where Docker risk is accepted. Docker shares the host kernel — it is **not** a VM |
| `local-python` | `pytest tests/` in a temp copy of the task | **None** — code runs as your user | Only tasks you wrote/trust; EnvCert's mutation & negative-control demos |
| `external` | Your command: `<cmd> --task <dir> --variant gold\|noop --timeout <s>` → last stdout line is JSON `{"reward": ..., "exit_code": ...}` | Whatever your disposable VM/remote sandbox provides (recorded verbatim in the report) | Organisations with a real sandbox fleet; set `--runner-command` or `[execution] runner_command` |

Under Docker, EC061 runs the no-op variant (reference solution skipped) and
EC062 repeats the gold run comparing rewards; EC064 (with `--mutation`)
mutates string/number literals in `solution/solve.sh` and measures rejection.
The Docker gold run's image digest is captured automatically into
`environment.image_digest` (OCI subject binding); `--image` /
`--image-digest` bind a digest without a Docker run.

If Docker is unavailable, EC060 reports ERROR/NOT_RUN with the daemon's
reason — never a fabricated pass. The report records the runner and its
isolation description (`execution.runner.isolation`) so evidence consumers
can judge it.

## Negative controls & mutation semantics

- A no-op control (EC061) is a *warning* when it passes: some tasks
  legitimately need no action. EnvCert does not hard-fail semantics it cannot
  know.
- Mutation rate (EC063) = rejected incorrect variants / eligible variants.
  Equivalent mutants survive legitimately; the rate is a verifier-strength
  signal, not proof.

## High-risk workloads

For genuinely hostile bundles, run EnvCert's static mode on the host and do
dynamic runs inside a disposable VM or remote sandbox. The `Runner`
interface (`envcert/runners/base.py`) is the extension point — see
WRITING_A_RUNNER.md.
