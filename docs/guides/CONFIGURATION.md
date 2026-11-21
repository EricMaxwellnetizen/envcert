# Configuration

`envcert.toml` (auto-discovered in the task directory, or `--config PATH`):

```toml
[envcert]
profile = "harbor"        # harbor | strict | minimal | ci

[checks]
# enabled = ["EC001", "EC011"]   # default: all checks in the profile
disabled = ["EC031"]             # skip specific stable check IDs

[checks.dynamic]
enabled = false                  # true requires an explicit [execution] mode (never implied)
repetitions = 3

[execution]
# mode = "local-python"          # trusted tasks only, NO sandbox
# mode = "docker"                # restricted container
# mode = "external"              # your disposable-VM runner
# runner_command = "C:\\tools\\runner.exe"

[policy]
fail_on = ["critical", "high"]   # severities that make the exit code 1
```

`enabled = true` under `[checks.dynamic]` does not choose an execution mode.
EnvCert refuses to run task code unless `[execution] mode` or `--execution`
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
exit code 2 and a specific message — EnvCert never silently ignores bad config.

Dynamic execution can also be set with `[execution] mode = "docker"`, but the
CLI flag is recommended so CI intent is explicit.
