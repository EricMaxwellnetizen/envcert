# Configuration

`envicert.toml` (auto-discovered in the task directory, or `--config PATH`):

```toml
[envicert]
profile = "harbor"        # harbor | strict | minimal | ci

[checks]
# enabled = ["EC001", "EC011"]   # default: all checks in the profile
disabled = ["EC031"]             # skip specific stable check IDs

[checks.dynamic]
enabled = false                  # true requires an explicit [execution] mode (never implied)
repetitions = 3

[checks.nemo]
# endpoint = "https://gym.internal/verify"   # NeMo Gym Resources Server (EC065)
# headers = { Authorization = "Bearer ..." }  # never echoed into reports

[execution]
# mode = "local-python"          # trusted tasks only, NO sandbox
# mode = "docker"                # restricted container
# mode = "external"              # your disposable-VM runner
# runner_command = "C:\\tools\\runner.exe"

[policy]
fail_on = ["critical", "high"]   # severities that make the exit code 1
```

`enabled = true` under `[checks.dynamic]` does not choose an execution mode.
Envicert refuses to run task code unless `[execution] mode` or `--execution`
explicitly selects one, so a config cannot silently fall back to unsandboxed
local execution.

Profiles:

| Profile | Checks | fail_on |
|---|---|---|
| `minimal` | structure, leakage, boundary, verifier only | CRITICAL, HIGH |
| `harbor` (default) | all static (+ dynamic when opted in) | CRITICAL, HIGH |
| `strict` | all | CRITICAL, HIGH, MEDIUM |
| `ci` | all | CRITICAL, HIGH |

CLI flags override config; config overrides profile defaults. Invalid
profiles, severities, execution modes or repetition counts are rejected with
exit code 2 and a specific message — Envicert never silently ignores bad config.

Dynamic execution can also be set with `[execution] mode = "docker"`, but the
CLI flag is recommended so CI intent is explicit.

`[checks.nemo] endpoint` is independent of `[execution]`: an explicit HTTP
Resources-Server URL is itself the opt-in, so EC065 can probe a remote
grader without enabling any local execution mode. Invalid URLs (anything
other than `http://`/`https://`) and non-string header values are rejected
with exit code 2.
