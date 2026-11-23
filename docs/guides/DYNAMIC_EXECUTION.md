# Dynamic execution — safety model

Dynamic checks are **opt-in** (`--execution ...`). Static analysis never
builds or runs task code. `[checks.dynamic] enabled = true` in `envicert.toml`
does not select a mode: an explicit `[execution] mode` (or `--execution`) is
required, so configuration cannot silently fall back to unsandboxed
`local-python` execution.

## Modes

| Mode | What runs | Isolation | Use when |
|---|---|---|---|
| `none` (default) | Nothing. Dynamic checks return NOT_RUN. | n/a | CI static gates, untrusted bundles |
| `docker` | Builds `environment/Dockerfile` (or the compose project, or pulls a declared `docker_image`), runs solution + verifier, reads the reward | Container with `--cap-drop ALL`, `no-new-privileges`, 2 CPU / 2 GB / 256 PIDs limits, timeout, network per flag (default none), read-only task mount, **no docker.sock**, built images removed afterwards. Compose projects get the same limits via a generated override; with network none the default compose network is marked `internal` (services talk to each other, not the internet) | Trusted-enough Harbor tasks on a host where Docker risk is accepted. Docker shares the host kernel — it is **not** a VM |
| `local-python` | `pytest tests/` in a temp copy of the task | **None** — code runs as your user | Only tasks you wrote/trust; Envicert's mutation & negative-control demos. Requires `pytest` in the environment running Envicert |
| `external` | Your command: `<cmd> --task <dir> --variant gold\|noop --timeout <s>` → last stdout line is JSON `{"reward": ..., "exit_code": ...}` | Whatever your disposable VM/remote sandbox provides (recorded verbatim in the report) | Organisations with a real sandbox fleet; set `--runner-command` or `[execution] runner_command` |

Under Docker, EC061 runs the no-op variant (reference solution skipped) and
EC062 repeats the gold run comparing rewards; EC064 (with `--mutation`)
mutates string/number literals in `solution/solve.sh` and measures rejection.
The Docker gold run's image digest is captured automatically into
`environment.image_digest` (OCI subject binding); `--image` /
`--image-digest` bind a digest without a Docker run.

Three Harbor environment shapes execute:

1. `environment/Dockerfile` — built and tagged per invocation;
2. `environment/docker-compose.yaml|yml` — the project is built, the
   verifier runs in the `main` service (or the first service), and the
   project is torn down afterwards.  A generated override adds
   `cap_drop: [ALL]`, `no-new-privileges`, 2g/2cpu/256pid limits to every
   service; with network none the default network is `internal`, so
   dependencies can talk to each other but not egress;
3. `[environment] docker_image` — the declared image is pulled and used
   as-is (no build, never removed).

## NeMo verifier probing (EC065)

EC065 feeds a verifier its own expected answers (gold), mutated answers and
row-swapped answers.  Two opt-in transports:

```bash
envicert check ./nemo-dataset --execution local-python       # import verify() in a subprocess
envicert check ./nemo-dataset --nemo-endpoint https://gym.internal/verify
```

HTTP mode POSTs `{"response": ..., "task_data": row}` (Gym's convention) and
reads `{"reward": ...}` or `{"score": ...}`.  It is opt-in by supplying the
endpoint; up to 10 rows and a bounded wall-clock budget are used, responses
are size-capped, and the endpoint/headers are never echoed into evidence
(headers may carry credentials).  Configure headers in `envicert.toml`:

```toml
[checks.nemo]
endpoint = "https://gym.internal/verify"
headers = { Authorization = "Bearer ..." }
```

If Docker is unavailable, EC060 reports ERROR/NOT_RUN with the daemon's
reason — never a fabricated pass. The report records the runner and its
isolation description (`execution.runner.isolation`) so evidence consumers
can judge it. The same rule applies when `pytest` is missing on the host:
the local-python checks return ERROR rather than a test "failure", and the
negative control / repeatability checks never report PASS for a verifier
that did not run.

## Negative controls & mutation semantics

- A no-op control (EC061) is a *warning* when it passes: some tasks
  legitimately need no action. Envicert does not hard-fail semantics it cannot
  know.
- Mutation rate (EC063) = rejected incorrect variants / eligible variants.
  Equivalent mutants survive legitimately; the rate is a verifier-strength
  signal, not proof.  Python solutions are mutated via AST; JS/TS
  solutions (`solution/*.js|.mjs|.cjs|.ts`) via a comment/string-aware
  lexer, with tests run by `node` (`tsx`/`ts-node` for TypeScript when
  installed).

## High-risk workloads

For genuinely hostile bundles, run Envicert's static mode on the host and do
dynamic runs inside a disposable VM or remote sandbox. The `Runner`
interface (`envicert/runners/base.py`) is the extension point — see
WRITING_A_RUNNER.md.
