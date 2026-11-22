## EnvCert 0.4.1 — PASSED ✅

**Task:** `envcert/python-calc` · adapter `harbor` · profile `harbor` · execution `local-python`
**Bundle:** `sha256:97bec127b21955ec…` · fail-on: CRITICAL, HIGH

| Status | Check | Severity | Finding |
|---|---|---|---|
| ✅ PASS | EC001 | INFO | Task structure is recognisable and complete |
| ✅ PASS | EC002 | INFO | Instruction is present and non-trivial (`instruction.md`) |
| ✅ PASS | EC003 | INFO | Reference solution is present (or its absence is explicit) |
| ✅ PASS | EC010 | INFO | No exposed version-control metadata in agent-visible paths |
| ✅ PASS | EC011 | INFO | Reference solution is not copied into the agent environment |
| ✅ PASS | EC012 | INFO | No known answer / gold files in agent-visible paths |
| ✅ PASS | EC013 | INFO | No hard-coded secrets or credentials in task material |
| ✅ PASS | EC014 | INFO | Instruction does not disclose solution or hidden-test content |
| ✅ PASS | EC020 | INFO | Verifier runs separated from the agent where the framework supports it |
| ✅ PASS | EC021 | INFO | No agent-controlled Python import shadowing on verifier paths |
| ✅ PASS | EC022 | INFO | No executable shadowing of verifier tooling |
| ✅ PASS | EC023 | INFO | Verifier/test directories are not made world-writable in the image |
| ✅ PASS | EC024 | INFO | No shared writable mounts or Docker socket exposure |
| ✅ PASS | EC030 | INFO | Base images are pinned to a digest or specific tag |
| ✅ PASS | EC031 | INFO | Container does not default to root without justification |
| ✅ PASS | EC032 | INFO | No dangerous Dockerfile patterns (remote ADD, curl\|sh, privileged hints) |
| ✅ PASS | EC033 | INFO | Network policy is declared and not silently unrestricted |
| ✅ PASS | EC040 | INFO | Python dependencies are pinned / locked |
| ✅ PASS | EC041 | INFO | External downloads at build/run time are pinned or checksummed |
| ✅ PASS | EC050 | INFO | Verifier exists and is non-empty |
| ✅ PASS | EC051 | INFO | Verifier produces a reward in the framework's expected location |
| ✅ PASS | EC052 | INFO | No unconditional-success path in the verifier |
| ✅ PASS | EC053 | INFO | Verifier contains substantive assertions |
| ✅ PASS | EC054 | INFO | Verifier does not trust agent-controlled result files without validation |
| ✅ PASS | EC056 | INFO | Verifier does not execute or unsafely deserialise agent-influenced data |
| ✅ PASS | EC060 | INFO | Reference (gold) solution passes the verifier |
| ✅ PASS | EC061 | INFO | Negative control (no-op/empty) is rejected by the verifier |
| ✅ PASS | EC062 | INFO | Verifier outcome is repeatable across repetitions |
| ✅ PASS | EC063 | INFO | Mutation testing: verifier rejects mutated (incorrect) solutions |
| ✅ PASS | EC066 | INFO | Deterministic cheat-agent battery is rejected by the verifier |
| ⏭️ NOT_RUN | EC070 | INFO | Hadolint Dockerfile lint (external companion) |
| ⏭️ NOT_RUN | EC071 | INFO | Trivy filesystem vulnerability scan (external companion) |
| ⏭️ NOT_RUN | EC072 | INFO | Semgrep scan (external companion, task-provided rules only) |
| ➖ NOT_APPLICABLE | EC004 | INFO | Multi-step tasks: every step is complete (instruction, verifier, solution) |
| ➖ NOT_APPLICABLE | EC055 | INFO | Inspect scorer is not trivially satisfiable |
| ➖ NOT_APPLICABLE | EC064 | INFO | Shell-solution mutation: verifier rejects mutated reference solutions (docker) |
| ➖ NOT_APPLICABLE | EC065 | INFO | NeMo verifier probing with mutated inputs (gold/wrong/swapped answers) |
| ➖ NOT_APPLICABLE | EC080 | INFO | Dataset answers are not embedded in agent-visible prompts |
| ➖ NOT_APPLICABLE | EC081 | INFO | Dataset has no duplicate or near-duplicate rows |
| ➖ NOT_APPLICABLE | EC082 | INFO | Dataset splits do not share prompts (no train/test overlap) |
| ➖ NOT_APPLICABLE | EC083 | INFO | Dataset labels are not degenerate |
| ➖ NOT_APPLICABLE | EC084 | INFO | Dataset rows parse and carry their promised fields |
| ➖ NOT_APPLICABLE | EC085 | INFO | Dataset grading specifications are consistent (FAIL_TO_PASS/PASS_TO_PASS style) |

**Summary:** 43 findings {'PASS': 30, 'NOT_APPLICABLE': 10, 'NOT_RUN': 3} · policy **PASSED ✅**

_EnvCert reports evidence about checked properties; it is not a certification that an environment is unhackable._
