# Datasets, the cheat battery, fixes and scaffolding

New in 0.4.0. Everything here is deterministic and offline; dynamic
modes execute task code only where you explicitly select them.

## Auditing a dataset file

```bash
envcert check ./train.jsonl
envcert check ./data/            # all .jsonl/.json/.csv below, split-aware
envcert check ./rows.csv --format markdown --output audit.md
envcert check ./rows.parquet     # needs optional pyarrow; without it the
                                 # file is reported uninspectable (WARN)
envcert check ./my-task --watch  # re-check whenever the bundle changes
```

The `dataset` adapter detects prompt fields (`prompt`,
`problem_statement`, `question`, `instruction`, `input`, `messages`, …)
and answer fields (`expected_answer`, `answer`, `target`, `label`,
`solution`, `patch`, …) across SWE-bench/NeMo/OpenAI-style conventions
and runs:

- EC080 — expected answer embedded verbatim in the agent-visible prompt;
- EC081 — exact duplicates, reused ids, near-duplicate prompts
  (word 5-gram Jaccard ≥ 0.9) plus deterministic token-set cosine
  semantic near-duplicates (≥ 0.82 over discriminative content tokens)
  and label conflicts;
- EC082 — the same prompt in more than one split (split inferred from
  `train`/`test`/`eval`/`dev`/`valid` in file names): contamination;
- EC083 — empty, constant or ≥98%-dominant labels;
- EC084 — unparseable rows and rows missing their prompt/label fields;
- EC085 — SWE-bench-style `FAIL_TO_PASS`/`PASS_TO_PASS` grading specs:
  empty must-pass sets and tests listed as both before and after.

Plus EC013 (hard-coded secrets in rows) and EC001 structure. Row caps
(20,000/file analysed, near-duplicate sampling) are recorded in the
evidence of every finding. Rows are data: they are never executed.
A directory with `verifier.py`/`dataset.toml` is a NeMo Gym dataset and
keeps that adapter.

## The cheat-agent battery (EC066)

Static checks infer weakness; EC066 *demonstrates* it. With an execution
mode selected, EnvCert requires gold to pass, then plays fixed cheats:

| Scenario | Runner | Attack |
|---|---|---|
| `cheat-stub` | local-python | gold API, every function returns a constant |
| `cheat-tamper` | local-python | no-op solution + agent-planted `conftest.py` that rewrites pytest outcomes to *passed* |
| `cheat-reward-forge` | docker | writes `reward.txt`/`reward.json` = 1 before the verifier runs, does no work |
| `cheat-test-tamper` | docker | replaces the writable `tests/test.sh` with unconditional success |

Any cheat obtaining a passing reward while gold passes is reported as
FAIL (CRITICAL, high confidence) with per-scenario evidence — an
executed exploit, replayable from the report. If gold does not pass,
the battery returns NOT_APPLICABLE rather than pretending rejected
cheats prove anything. `local-python` has **no sandbox** (trusted tasks
only); docker runs use the restricted DockerRunner.

## Deterministic fixes

```bash
envcert fix ./my-task           # dry-run plan
envcert fix ./my-task --apply   # write, then re-run `envcert check`
```

Fixes are mechanical and idempotent: `.dockerignore` entries that keep
`.git`, solution and answer material out of the build context
(EC010/EC011/EC012), and — labelled **[needs review]** because they
declare policy — `network_mode = "no-network"` (EC033) and verifier
`environment_mode = "separate"` (EC020) in `task.toml`. Anything that
needs judgement (weak assertions, leaked prose, unpinned images) stays
a finding for a human; EnvCert does not rewrite your task with an LLM.

## Scaffolding

```bash
envcert new ./my-task --name org/my-task
envcert check ./my-task         # passes
```

The scaffold starts from the safe shape — separate verifier, declared
no-network policy, digest-pinned base image, non-root user,
`.dockerignore`, verifier that writes reward 1 only after real pytest
assertions, reference solution, `envcert.toml` — so new tasks do not
inherit an old task's flaws by copy-paste.
