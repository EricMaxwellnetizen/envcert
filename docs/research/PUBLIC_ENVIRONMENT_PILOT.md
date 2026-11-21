# Public-environment pilot

Date: 2026-11-22. **Static analysis only** — no public task image was built
or executed. This pilot does not accuse any project of a vulnerability;
adapter *templates* are not runnable tasks, and findings on them are
reported as methodology observations, not defects.

## Method

1. Shallow-cloned the public Harbor repository
   (`github.com/harbor-framework/harbor`, default branch at pilot date).
2. Enumerated directories containing `task.toml` + `instruction.md` +
   `tests/` ("complete" task-shaped directories): **131 found**
   (mostly `adapters/*/task-template` and `adapters/*/template`).
3. Ran `envcert check <dir>` (profile `harbor`, static, execution `none`)
   on the first 12 in sorted order. Reproduce:

   ```bash
   git clone --depth 1 https://github.com/harbor-framework/harbor
   envcert check harbor/adapters/aa-lcr/template
   ```

4. Also ran EnvCert on this repo's four controlled examples
   (`examples/`), whose expected findings are fixture-locked in
   `tests/fixtures/expected-*.json`.

## Results (12 public template directories)

Raw machine results were recorded during the pilot run; summary:

| Outcome | Count | Notes |
|---|---|---|
| Report produced | 8 | policies: 5 passed, 3 failed (default fail_on CRITICAL/HIGH) |
| Invalid-TOML error (pre-improvement run) | 4 | `adebench`, `arc_agi_2`, `bird_bench`, `codepde` templates contain Jinja `{{...}}` placeholders |

Most frequent failing/warning checks on the 8 reports: EC020 (shared
verifier mode — the Harbor default), EC030 (base image not digest-pinned),
EC031 (root user), EC033 (no network_mode declared ⇒ Harbor default
public). EC040/EC041/EC023/EC053/EC002/EC050 appeared occasionally.

## Interpretation and false-positive observations

- These directories are **adapter templates** with placeholders
  (`{{image_name}}`-style values, templated instructions). Findings such as
  "no network_mode declared" or "verifier missing" on a template are
  *expected template gaps*, not benchmark vulnerabilities. EnvCert's WARN
  severity + confidence + limitations framing is doing its job here; a
  FAIL on a template (e.g. EC050) must be read as "not a runnable task".
- **Improvement made because of this pilot:** unrendered templated
  `task.toml` files (Jinja markers) no longer abort the whole run with a
  TOML parse error; the Harbor adapter now records a warning and proceeds
  with heuristic config checks. Genuinely malformed TOML still exits 2.
- The recurrence of EC020/EC030/EC031/EC033 across real templates confirms
  these defaults are common in the ecosystem and worth surfacing — while
  also confirming they must stay WARN (not FAIL) for templates/shared-mode
  tasks that legitimately need them.

## Controlled-fixture results (exact, test-locked)

| Fixture | Expected | Observed in test suite |
|---|---|---|
| `examples/safe-environment` | policy passes, all static checks PASS | yes (`tests/integration/test_examples.py`) |
| `examples/intentionally-vulnerable-environment` | EC010/EC011/EC052 FAIL; 10 further WARNs | yes |
| `examples/unsupported-environment` | generic adapter, EC001 FAIL, policy fails — reported, not "validated" | yes |
| `examples/python-task` (dynamic) | EC060–EC063 PASS under `--execution local-python --mutation` (gold passes, no-op rejected, repeatable, mutation rejection exercised) | yes |

## Limitations

- 12 of 131 directories, sorted-order sample, templates not rendered tasks;
  no dynamic execution of public code; no claim about any named benchmark's
  exploitability. A fuller campaign would render a diverse set of real
  registry tasks and hand-review each FAIL.
