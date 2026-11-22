# 0.4.0 real-world pilot

Date: 2026-11-22. Static analysis of public material plus live Docker
execution of EnvCert's own examples. No public project is accused of a
vulnerability: adapter *templates* are not runnable tasks, and findings
on them are methodology observations.

## Harbor repository (158 task folders, one command)

Shallow-cloned `github.com/harbor-framework/harbor` and ran
`envcert check <clone> --dataset` (static, default policy):

- 158 task folders found; 90 pass policy, 68 fail, 2 folders error
  gracefully (unrendered Jinja `task.toml` templates; the rollup records
  the error per folder instead of sinking the run).
- Most frequent failing checks: EC030 unpinned base image (145),
  EC020 shared verifier mode (142), EC031 root user (142), EC033 no
  declared network policy (127), EC040 unpinned dependencies (33),
  EC054 agent-derived reward (23), EC002 placeholder instruction (22).
  The first four are ecosystem defaults on templates, consistent with
  the 0.3.x pilot; they are WARN-level findings, and the rollup makes
  the pattern visible at benchmark scale in a single command.
- EC054 spot-check: hits are LLM-judge verifier templates whose reward
  is parsed from judge output over agent submissions. Flagging for
  review is intended; 0.4.0 therefore reports judge-mediated flows as
  WARN, reserving FAIL for direct agent-authored rewards.

## Terminal-Bench (51 real, rendered tasks)

Downloaded `harbor-framework/terminal-bench` (main, tarball) and ran
`envcert check tasks/ --dataset` over the 51 rendered tasks:

- Final: **32 pass / 19 fail** policy (static, default fail-on).
- Policy drivers: EC054 agent-derived reward without evident comparison
  (11, WARN/HIGH — review-level; cross-function validation is a stated
  static limitation), EC023 `chmod 777` (4), EC011 oracle material inside
  the build context (2), EC053 assertion-free test functions (2),
  EC010 `.git` inside a task subdirectory (1), EC032 pipe-to-shell
  install (1).
- **False positives found by this pilot and fixed the same day:**
  EC056 flagged every task because shell verifiers `source` a venv —
  now only `eval`/`sh -c` over interpolated content counts; EC054
  flagged data-loading helpers as reward sinks — returns are now sinks
  only when they parse a grade or sit in a grading entrypoint (EC056
  went 51→1 tasks, EC054 38→11); the Dockerfile parser mistook heredoc
  Python (`from pathlib import Path`) for a `FROM` instruction and
  EC030 flagged build-stage aliases as unpinned images. All three fixes
  carry regression tests. EC033 fires on all 51 (Terminal-Bench's older
  schema does not declare Harbor's `network_mode`; LOW severity,
  non-blocking).

### Hand-review round (every policy-driving finding inspected)

Each EC054/EC011/EC023/EC053/EC010/EC032 driver was read in the task
source before being believed. Outcome: **four more false-positive
classes found and fixed** (with regression tests), and no finding that
warrants a vulnerability disclosure:

- EC054 flagged RewardKit `tests/report.py` projectors that read the
  verifier-owned `/logs/verifier/reward.json` to re-emit it (7 tasks).
  Verifier-owned paths (`/logs/verifier`, `/tests`) are now trusted
  sources in the data-flow analysis, not agent input.
- EC011 flagged `ks-solver-cpp`'s oracle header — the instruction
  explicitly offers it as a public solve-time API. Instruction-declared
  public inputs are now excluded (disclosure remains EC014's job).
- EC010 counted `loadgen/.gitignore` as `.git` metadata (substring
  match); component-exact matching fixed it.
- EC053 called `require(...)`-style verifiers assertion-free; raising
  helpers (`require`/`expect`/`assert*`/`pytest.raises`) now count.
- EC023 flagged `chmod 777 /app /results` (the normal agent artifact
  channel in separate-verifier tasks); only verifier/test/reward/system
  targets now count.

After these fixes: **47/51 pass**. The 4 remaining failures are
review-level and were confirmed as such by reading them: two EC054s
whose validation happens in a caller (stated inter-procedural limit),
one EC053 existence-style test, one rustup pipe-to-shell installer.
Filing vulnerability reports against maintainers for these would be
noise; the correct disclosure outcome of a hand-review is sometimes
"nothing egregious", and that is the outcome here.

## Harbor Hub registry (15 real downloaded tasks)

Installed Harbor from source and ran `harbor download
letta-ai/frontier-memory@latest`, then `envcert check --dataset` over
the 15 rendered registry tasks: **8 pass / 7 fail**, all 7 driven by
WARN-level EC054/EC011 review findings (no FAILs after review fixes).
Hand-review of every driver:

- Six EC054s are graders that compute rewards through local helpers
  over agent end-state (automationbench `grade.py` pattern): review
  findings, correctly WARN once FAIL was reserved for the direct
  read-and-parse idiom. One (awilix) reads a reward file from an
  agent-output directory but gates it on exit codes and a second
  verifier — a genuine review prompt, as intended.
- One EC011 (`dapt-intrusion-detection`) exposed a real EnvCert bug:
  FAIL fired because *some* COPY existed, although both COPYs were
  narrow file copies that provably exclude the flagged scripts.
  Inclusion is now judged per-COPY (broad/directory coverage), with
  regression tests; the scripts are feature extractors over the agent's
  own input data and are not in the image.

## SWE-bench Lite (30 real rows)

Fetched live from the Hugging Face datasets server
(`princeton-nlp/SWE-bench_Lite`, test split, first 30 rows):

- Adapter detected prompt=`problem_statement`, answer=`patch`.
- EC080/EC081/EC083/EC084 PASS; EC085 not triggered on this slice in a
  failing direction (specs consistent); one low-confidence EC013 WARN
  on credential-shaped text inside an issue body (review-level by
  design, does not fail default policy).

## Live Docker execution (daemon 29.7.2)

- `examples/safe-environment --execution docker`: EC060 gold PASS,
  EC061 no-op rejected, EC062 repeatable, EC066 cheat battery PASS
  (both forge and tamper rejected) in real builds.
- A deliberately forgeable variant (verifier keeps a pre-existing
  reward file): EC066 **FAIL** — `cheat-reward-forge` ACCEPTED with
  reward 1.0, `cheat-test-tamper` rejected. Executed proof, replayable
  from the report evidence. Both directions are regression-tested in
  `tests/unit/test_docker_live.py` (skipped without a daemon).

## Limitations

Templates dominate the Harbor corpus; rendered registry tasks are the
next pilot target. Docker results cover EnvCert's documented harness
layout (verifier-owned pristine tests), not every Harbor runtime mode.
