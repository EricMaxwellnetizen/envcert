## Envicert 0.4.1 — FAILED ❌

**Task:** `envicert/intentionally-vulnerable` · adapter `harbor` · profile `harbor` · execution `none`
**Bundle:** `sha256:6ec8cfe52c31688e…` · fail-on: CRITICAL, HIGH

| Status | Check | Severity | Finding |
|---|---|---|---|
| ❌ FAIL | EC010 | HIGH | No exposed version-control metadata in agent-visible paths (`environment/.git/config`) |
| ❌ FAIL | EC011 | CRITICAL | Reference solution is not copied into the agent environment (`environment/Dockerfile:3`) |
| ❌ FAIL | EC052 | CRITICAL | No unconditional-success path in the verifier (`tests/test.sh:3`) |
| ⚠️ WARN | EC012 | HIGH | No known answer / gold files in agent-visible paths (`environment/gold_patch.txt`) |
| ⚠️ WARN | EC013 | MEDIUM | No hard-coded secrets or credentials in task material (`task.toml:9`) |
| ⚠️ WARN | EC014 | MEDIUM | Instruction does not disclose solution or hidden-test content (`instruction.md`) |
| ⚠️ WARN | EC020 | MEDIUM | Verifier runs separated from the agent where the framework supports it |
| ⚠️ WARN | EC021 | HIGH | No agent-controlled Python import shadowing on verifier paths (`environment/conftest.py`) |
| ⚠️ WARN | EC022 | HIGH | No executable shadowing of verifier tooling |
| ⚠️ WARN | EC030 | HIGH | Base images are pinned to a digest or specific tag (`environment/Dockerfile:1`) |
| ⚠️ WARN | EC031 | LOW | Container does not default to root without justification |
| ⚠️ WARN | EC032 | HIGH | No dangerous Dockerfile patterns (remote ADD, curl\|sh, privileged hints) (`environment/Dockerfile:4`) |
| ⚠️ WARN | EC033 | LOW | Network policy is declared and not silently unrestricted |
| ⚠️ WARN | EC040 | MEDIUM | Python dependencies are pinned / locked |
| ⚠️ WARN | EC053 | HIGH | Verifier contains substantive assertions |
| ✅ PASS | EC001 | INFO | Task structure is recognisable and complete |
| ✅ PASS | EC002 | INFO | Instruction is present and non-trivial (`instruction.md`) |
| ✅ PASS | EC003 | INFO | Reference solution is present (or its absence is explicit) |
| ✅ PASS | EC023 | INFO | Verifier/test directories are not made world-writable in the image |
| ✅ PASS | EC024 | INFO | No shared writable mounts or Docker socket exposure |
| ✅ PASS | EC041 | INFO | External downloads at build/run time are pinned or checksummed |
| ✅ PASS | EC050 | INFO | Verifier exists and is non-empty |
| ✅ PASS | EC051 | INFO | Verifier produces a reward in the framework's expected location |
| ✅ PASS | EC054 | INFO | Verifier does not trust agent-controlled result files without validation |
| ✅ PASS | EC056 | INFO | Verifier does not execute or unsafely deserialise agent-influenced data |
| ⏭️ NOT_RUN | EC060 | INFO | Reference (gold) solution passes the verifier |
| ⏭️ NOT_RUN | EC061 | INFO | Negative control (no-op/empty) is rejected by the verifier |
| ⏭️ NOT_RUN | EC062 | INFO | Verifier outcome is repeatable across repetitions |
| ⏭️ NOT_RUN | EC063 | INFO | Mutation testing: verifier rejects mutated (incorrect) solutions |
| ⏭️ NOT_RUN | EC064 | INFO | Shell-solution mutation: verifier rejects mutated reference solutions (docker) |
| ⏭️ NOT_RUN | EC065 | INFO | NeMo verifier probing with mutated inputs (gold/wrong/swapped answers) |
| ⏭️ NOT_RUN | EC066 | INFO | Deterministic cheat-agent battery is rejected by the verifier |
| ⏭️ NOT_RUN | EC070 | INFO | Hadolint Dockerfile lint (external companion) |
| ⏭️ NOT_RUN | EC071 | INFO | Trivy filesystem vulnerability scan (external companion) |
| ⏭️ NOT_RUN | EC072 | INFO | Semgrep scan (external companion, task-provided rules only) |
| ➖ NOT_APPLICABLE | EC004 | INFO | Multi-step tasks: every step is complete (instruction, verifier, solution) |
| ➖ NOT_APPLICABLE | EC055 | INFO | Inspect scorer is not trivially satisfiable |
| ➖ NOT_APPLICABLE | EC080 | INFO | Dataset answers are not embedded in agent-visible prompts |
| ➖ NOT_APPLICABLE | EC081 | INFO | Dataset has no duplicate or near-duplicate rows |
| ➖ NOT_APPLICABLE | EC082 | INFO | Dataset splits do not share prompts (no train/test overlap) |
| ➖ NOT_APPLICABLE | EC083 | INFO | Dataset labels are not degenerate |
| ➖ NOT_APPLICABLE | EC084 | INFO | Dataset rows parse and carry their promised fields |
| ➖ NOT_APPLICABLE | EC085 | INFO | Dataset grading specifications are consistent (FAIL_TO_PASS/PASS_TO_PASS style) |

**Summary:** 43 findings {'PASS': 10, 'NOT_APPLICABLE': 8, 'FAIL': 3, 'WARN': 12, 'NOT_RUN': 10} · policy **FAILED ❌**

### What to fix

- **EC010** No exposed version-control metadata in agent-visible paths — Exclude .git via .dockerignore, do not COPY it into the image, and strip VCS data from published images.
- **EC011** Reference solution is not copied into the agent environment — Keep solution/ outside the build context, exclude it in .dockerignore, and never COPY solution material into the image.
- **EC052** No unconditional-success path in the verifier — Gate the success reward on real assertions; ensure failures write reward 0.
- **EC012** No known answer / gold files in agent-visible paths — Move expected outputs and gold patches into tests/ (uploaded only at verification time) or remove them.
- **EC013** No hard-coded secrets or credentials in task material — Use ${VAR} host-environment references (Harbor) or CI secrets; rotate any committed credential.
- **EC014** Instruction does not disclose solution or hidden-test content — Remove solution code / expected outputs from instruction.md; describe the task, not the answer.
- **EC020** Verifier runs separated from the agent where the framework supports it — Set [verifier] environment_mode = "separate" (with declared artifacts), or document why shared verification is required.
- **EC021** No agent-controlled Python import shadowing on verifier paths — Keep import-shadowing files out of the agent environment; run the verifier with a clean PYTHONPATH and isolated rootdir.
- **EC022** No executable shadowing of verifier tooling — Do not ship tool-named executables in the agent workdir; invoke verifiers by absolute path.
- **EC030** Base images are pinned to a digest or specific tag — Pin base images as name:tag@sha256:<digest>.
- **EC031** Container does not default to root without justification — Add a non-root USER for the agent phase where the task allows it.
- **EC032** No dangerous Dockerfile patterns (remote ADD, curl\|sh, privileged hints) — Download with a pinned URL + checksum verification, or vendor the artifact.
- **EC033** Network policy is declared and not silently unrestricted — Set [environment] network_mode = "no-network" or "allowlist" with allowed_hosts, unless the task truly needs public access.
- **EC040** Python dependencies are pinned / locked — Pin versions with == (or hashes) and commit a lockfile (uv.lock / poetry.lock / Pipfile.lock).
- **EC053** Verifier contains substantive assertions — Assert on computed outputs/behaviour, include negative cases, and compare against expected values.

_Envicert reports evidence about checked properties; it is not a certification that an environment is unhackable._
