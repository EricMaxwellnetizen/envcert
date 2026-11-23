# Check catalog

Stable check IDs are a public interface: IDs are never reused, and a retired check keeps its ID reserved. nvcert list-checks -v prints the same data from the installed package.

## EC001 - Task structure is recognisable and complete

- Category: structure  |  Default severity on failure: HIGH  |  Dynamic: False
- Description: Task has the files its framework requires (config, instruction, verifier, environment).
- Remediation: Add the missing task.toml / instruction.md / tests / environment files for your framework.
- Limitations: Only Harbor and generic Docker layouts are recognised in this version.

## EC002 - Instruction is present and non-trivial

- Category: structure  |  Default severity on failure: MEDIUM  |  Dynamic: False
- Description: instruction.md exists, is non-empty and contains no unresolved placeholders.
- Remediation: Write a complete instruction.md without TODO/placeholder text.
- Limitations: (none recorded)

## EC003 - Reference solution is present (or its absence is explicit)

- Category: structure  |  Default severity on failure: LOW  |  Dynamic: False
- Description: A reference/oracle solution exists so the verifier can be sanity-checked.
- Remediation: Add solution/solve.sh (Harbor) or document why no reference solution exists.
- Limitations: Some frameworks source solutions externally; then this is informational.

## EC004 - Multi-step tasks: every step is complete (instruction, verifier, solution)

- Category: structure  |  Default severity on failure: MEDIUM  |  Dynamic: False
- Description: Each Harbor step should carry its own instruction and verifier (or inherit the documented fallback), so every step is actually graded.
- Remediation: Add steps/<name>/instruction.md and steps/<name>/tests/test.sh (or document the fallback), plus a per-step solution where applicable.
- Limitations: Step-level environment sharing follows Harbor's multi-step rules; this checks presence, not per-step semantics.

## EC010 - No exposed version-control metadata in agent-visible paths

- Category: leakage  |  Default severity on failure: HIGH  |  Dynamic: False
- Description: .git data inside the build context or environment can leak hidden reference material and history.
- Remediation: Exclude .git via .dockerignore, do not COPY it into the image, and strip VCS data from published images.
- Limitations: Static analysis cannot prove the agent can read the path at runtime; exposure is assessed from the build context and COPY instructions.

## EC011 - Reference solution is not copied into the agent environment

- Category: leakage  |  Default severity on failure: CRITICAL  |  Dynamic: False
- Description: Solution/answer material must not be included in the Docker build context or copied into agent-visible paths.
- Remediation: Keep solution/ outside the build context, exclude it in .dockerignore, and never COPY solution material into the image.
- Limitations: Runtime mounts configured outside this task directory cannot be seen statically.

## EC012 - No known answer / gold files in agent-visible paths

- Category: leakage  |  Default severity on failure: HIGH  |  Dynamic: False
- Description: Files with answer-like names (gold patch, expected output, answers) inside the environment can be read by the agent.
- Remediation: Move expected outputs and gold patches into tests/ (uploaded only at verification time) or remove them.
- Limitations: Name-based heuristic; a file with an answer-like name may be an innocent fixture.

## EC013 - No hard-coded secrets or credentials in task material

- Category: leakage  |  Default severity on failure: HIGH  |  Dynamic: False
- Description: Hard-coded API keys/tokens/passwords in task files can leak and indicate exposed evaluation data.
- Remediation: Use ${VAR} host-environment references (Harbor) or CI secrets; rotate any committed credential.
- Limitations: Pattern-based; example/dummy values are flagged for human review, not asserted to be live credentials.

## EC014 - Instruction does not disclose solution or hidden-test content

- Category: leakage  |  Default severity on failure: MEDIUM  |  Dynamic: False
- Description: The instruction given to the agent must not contain the reference solution or hidden expected outputs.
- Remediation: Remove solution code / expected outputs from instruction.md; describe the task, not the answer.
- Limitations: Heuristic overlap detection; short common tokens are ignored.

## EC020 - Verifier runs separated from the agent where the framework supports it

- Category: boundary  |  Default severity on failure: MEDIUM  |  Dynamic: False
- Description: Shared agent/verifier execution lets agent state influence verification. Harbor supports verifier.environment_mode='separate'.
- Remediation: Set [verifier] environment_mode = "separate" (with declared artifacts), or document why shared verification is required.
- Limitations: Some tasks legitimately need shared state (live services); this is a warning, not proof of exploitability.

## EC021 - No agent-controlled Python import shadowing on verifier paths

- Category: boundary  |  Default severity on failure: HIGH  |  Dynamic: False
- Description: sitecustomize/usercustomize/conftest or shadow modules in agent-writable, verifier-imported paths can alter verifier behaviour.
- Remediation: Keep import-shadowing files out of the agent environment; run the verifier with a clean PYTHONPATH and isolated rootdir.
- Limitations: Whether pytest/Python actually imports the file depends on runtime cwd/PYTHONPATH, which is assessed heuristically.

## EC022 - No executable shadowing of verifier tooling

- Category: boundary  |  Default severity on failure: HIGH  |  Dynamic: False
- Description: Agent-placed executables named like verifier tools (pytest, python, test.sh) earlier on PATH can replace the real tool.
- Remediation: Do not ship tool-named executables in the agent workdir; invoke verifiers by absolute path.
- Limitations: PATH order at verification time is inferred from the Dockerfile/task config.

## EC023 - Verifier/test directories are not made world-writable in the image

- Category: boundary  |  Default severity on failure: HIGH  |  Dynamic: False
- Description: chmod 777 / a+w on verifier, test or system paths lets the agent tamper with verification.
- Remediation: Use least-privilege permissions; make /tests read-only where the framework allows.
- Limitations: Runtime framework uploads may reset permissions; this checks what the task itself declares.

## EC024 - No shared writable mounts or Docker socket exposure

- Category: boundary  |  Default severity on failure: CRITICAL  |  Dynamic: False
- Description: Host mounts, docker.sock or privileged settings in compose/task config collapse the agent/host boundary.
- Remediation: Remove docker.sock and host mounts; never run task containers privileged.
- Limitations: Only mounts declared inside this task directory are visible.

## EC030 - Base images are pinned to a digest or specific tag

- Category: docker  |  Default severity on failure: MEDIUM  |  Dynamic: False
- Description: Floating tags (latest / untagged) make builds non-reproducible and silently change the environment.
- Remediation: Pin base images as name:tag@sha256:<digest>.
- Limitations: Tag pinning without a digest is reported as a warning-level reproducibility issue, not a vulnerability.

## EC031 - Container does not default to root without justification

- Category: docker  |  Default severity on failure: LOW  |  Dynamic: False
- Description: Running as root widens the impact of agent code; a non-root USER is defence in depth.
- Remediation: Add a non-root USER for the agent phase where the task allows it.
- Limitations: Many benchmark tasks legitimately need root; classified as hardening, not benchmark-integrity failure.

## EC032 - No dangerous Dockerfile patterns (remote ADD, curl|sh, privileged hints)

- Category: docker  |  Default severity on failure: HIGH  |  Dynamic: False
- Description: Remote ADD and pipe-to-shell installs execute unreviewed remote code at build time.
- Remediation: Download with a pinned URL + checksum verification, or vendor the artifact.
- Limitations: Build-time network content cannot be inspected statically.

## EC033 - Network policy is declared and not silently unrestricted

- Category: docker  |  Default severity on failure: MEDIUM  |  Dynamic: False
- Description: Harbor defaults to public network when network_mode is omitted; unrestricted egress enables answer retrieval.
- Remediation: Set [environment] network_mode = "no-network" or "allowlist" with allowed_hosts, unless the task truly needs public access.
- Limitations: A task may legitimately need network access; the finding reports the declared policy and its risk.

## EC040 - Python dependencies are pinned / locked

- Category: dependencies  |  Default severity on failure: MEDIUM  |  Dynamic: False
- Description: Unpinned pip installs make the environment non-reproducible and vulnerable to silent upstream changes.
- Remediation: Pin versions with == (or hashes) and commit a lockfile (uv.lock / poetry.lock / Pipfile.lock).
- Limitations: A missing lockfile is a reproducibility signal, not a confirmed vulnerability.

## EC041 - External downloads at build/run time are pinned or checksummed

- Category: dependencies  |  Default severity on failure: MEDIUM  |  Dynamic: False
- Description: Unversioned downloads (git clone without commit, unversioned URLs) can change the environment silently.
- Remediation: Pin commits/versions and verify checksums for downloaded artifacts.
- Limitations: (none recorded)

## EC050 - Verifier exists and is non-empty

- Category: verifier  |  Default severity on failure: CRITICAL  |  Dynamic: False
- Description: A missing or empty verifier cannot distinguish correct from incorrect work.
- Remediation: Provide tests/test.sh (Harbor) that runs real assertions and writes a reward.
- Limitations: (none recorded)

## EC051 - Verifier produces a reward in the framework's expected location

- Category: verifier  |  Default severity on failure: HIGH  |  Dynamic: False
- Description: Harbor verifiers must write /logs/verifier/reward.txt or reward.json; otherwise every run scores 0 / is masked.
- Remediation: Write the numeric reward to /logs/verifier/reward.txt (or reward.json) on every code path.
- Limitations: Dynamic reward production is only proven by execution; this checks the code mentions the contract.

## EC052 - No unconditional-success path in the verifier

- Category: verifier  |  Default severity on failure: CRITICAL  |  Dynamic: False
- Description: A verifier that always reports success (echo 1 without conditions, assert True only, sys.exit(0)) accepts any submission.
- Remediation: Gate the success reward on real assertions; ensure failures write reward 0.
- Limitations: AST/text heuristics cannot prove semantic correctness; flagged patterns need human confirmation.

## EC053 - Verifier contains substantive assertions

- Category: verifier  |  Default severity on failure: HIGH  |  Dynamic: False
- Description: Verifiers that only check file existence or trivial substrings accept incorrect solutions (see BenchJack V-class flaws).
- Remediation: Assert on computed outputs/behaviour, include negative cases, and compare against expected values.
- Limitations: Assertion counting is a strength signal, not proof the assertions are semantically correct.

## EC054 - Verifier does not trust agent-controlled result files without validation

- Category: verifier  |  Default severity on failure: HIGH  |  Dynamic: False
- Description: Reading a score/reward the agent itself wrote, or parsing agent stdout loosely, lets the agent report its own grade.
- Remediation: Compute the reward inside the verifier from raw artifacts; validate any agent-produced file strictly.
- Limitations: Heuristic; some tasks legitimately read agent output files — they must validate content, which needs human review.
- Method (0.4.0): AST data-flow over Python verifiers (sources: file reads, environment, argv, stdin, subprocess stdout; sinks: return value, reward assignment, reward write). A reward *parsed* from agent-controlled content with no comparison against an expected value is FAIL with high confidence (e.g. `return float(open("result.txt").read())`); flows compared against expected/gold values before use are recognised as validation and pass. Shell verifiers use targeted patterns (reward read via `cat`, command substitution, copy/move into the reward file).

## EC055 - Inspect scorer is not trivially satisfiable

- Category: verifier  |  Default severity on failure: MEDIUM  |  Dynamic: False
- Description: Substring (includes) and loose match scorers accept outputs that merely mention the target; exact/structured or well-tested custom scorers are stronger.
- Remediation: Prefer exact()/pattern() with anchored extraction or a custom scorer with negative tests; if includes/match is intentional, document why substring acceptance is semantically correct here.
- Limitations: Scorer choice can be legitimate (e.g. short factual answers); this flags weakness patterns for review, not proof of exploitability.

## EC056 - Verifier does not execute or unsafely deserialise agent-influenced data

- Category: verifier  |  Default severity on failure: HIGH  |  Dynamic: False
- Description: eval/exec on dynamic input, pickle/yaml unsafe loading, os.system or subprocess shell=True inside the verifier turn agent-supplied data into code execution in the grading context.
- Remediation: Remove eval/exec from the verifier; use json/ast.literal_eval and yaml SafeLoader; call subprocess with argument arrays (shell=False).
- Limitations: Static AST inventory; whether the argument is agent-controlled at runtime needs the data-flow context in EC054 and human review.

## EC060 - Reference (gold) solution passes the verifier

- Category: dynamic  |  Default severity on failure: HIGH  |  Dynamic: True
- Description: Executing the reference solution should produce the expected (passing) reward.
- Remediation: Fix the reference solution or the verifier so a correct solution passes.
- Limitations: Only supported for docker (Harbor shell tasks) and local-python (pytest tasks) execution.

## EC061 - Negative control (no-op/empty) is rejected by the verifier

- Category: dynamic  |  Default severity on failure: HIGH  |  Dynamic: True
- Description: A no-op or empty submission should not pass, unless the task semantics say otherwise.
- Remediation: Strengthen the verifier so trivial submissions fail.
- Limitations: Some tasks legitimately pass with no action; then this returns NOT_APPLICABLE/WARN for human review, not a hard failure.

## EC062 - Verifier outcome is repeatable across repetitions

- Category: dynamic  |  Default severity on failure: MEDIUM  |  Dynamic: True
- Description: Re-running gold verification should give a consistent reward/exit outcome.
- Remediation: Remove nondeterminism (time, randomness, network, ordering) from the task or verifier.
- Limitations: Compares reward/exit outcome, not bitwise-identical stdout.

## EC063 - Mutation testing: verifier rejects mutated (incorrect) solutions

- Category: mutation  |  Default severity on failure: MEDIUM  |  Dynamic: True
- Description: Mutated variants of a correct solution should be rejected; the rejection rate is a verifier-strength signal.
- Remediation: Add assertions covering the mutated behaviour; do not treat the rate as proof of correctness.
- Limitations: Equivalent/invalid mutants and the small mutant set limit this signal. Python/pytest and JS/TS (node) tasks under --execution local-python.

## EC064 - Shell-solution mutation: verifier rejects mutated reference solutions (docker)

- Category: mutation  |  Default severity on failure: MEDIUM  |  Dynamic: True
- Description: Mutating literal outputs in solution/solve.sh should make the verifier reject the run; surviving mutants signal a weak verifier.
- Remediation: Strengthen verifier assertions on the mutated outputs.
- Limitations: Docker execution only; only literal-bearing shell solutions can be mutated. Mutant validity is heuristic.

## EC065 - NeMo verifier probing with mutated inputs (gold/wrong/swapped answers)

- Category: dynamic  |  Default severity on failure: HIGH  |  Dynamic: True
- Description: Feeding a NeMo Gym verifier its rows' expected answers should score 1; mutated and row-swapped answers should score < 1.
- Remediation: Fix the verifier so correct answers pass and incorrect/swapped answers fail for every probed row.
- Limitations: Probes up to 10 rows. Local mode imports verify() in a subprocess (trusted code, no sandbox); HTTP mode POSTs to an operator-supplied Resources-Server endpoint (--nemo-endpoint) and reads reward/score.

## EC066 - Deterministic cheat-agent battery is rejected by the verifier

- Category: dynamic  |  Default severity on failure: CRITICAL  |  Dynamic: True
- Description: Fixed cheat strategies (stub solution, verifier tampering, forged reward file) must not obtain a passing reward while the gold solution does.
- Remediation: Make the verifier compute its reward from verifier-owned logic over raw artifacts: run tests from a verifier-owned directory, overwrite (never read) the reward file, and reject stub/constant submissions with substantive assertions (see EC053/EC054).
- Limitations: Covers the listed deterministic strategies only; novel exploits need an adversarial (BenchJack-style) audit. local-python has no sandbox; docker scenarios assume the harness layout Envicert documents.
- Scenarios: `cheat-stub` and `cheat-tamper` (conftest outcome-faking) under local-python; `cheat-reward-forge` and `cheat-test-tamper` under docker. A cheat that passes while gold passes is an executed exploit (FAIL, high confidence), not a pattern match. When gold does not pass the battery is inconclusive (NOT_APPLICABLE).

## EC070 - Hadolint Dockerfile lint (external companion)

- Category: external  |  Default severity on failure: MEDIUM  |  Dynamic: False
- Description: Runs hadolint on the task Dockerfile when installed and --external-tools is given.
- Remediation: Fix the hadolint findings or document suppressions in a .hadolint.yaml.
- Limitations: External tool output is mapped, not re-derived; the tool's own version and ruleset determine coverage.

## EC071 - Trivy filesystem vulnerability scan (external companion)

- Category: external  |  Default severity on failure: MEDIUM  |  Dynamic: False
- Description: Runs `trivy fs` (vuln+secret scanners) on the task directory when installed and --external-tools is given. May need network for its DB on first run.
- Remediation: Update or replace flagged dependencies/images; do not treat a clean Envicert static run as a CVE verdict.
- Limitations: External tool output is mapped, not re-derived; the tool's own version and ruleset determine coverage.

## EC080 - Dataset answers are not embedded in agent-visible prompts

- Category: dataset  |  Default severity on failure: HIGH  |  Dynamic: False
- Description: An expected answer that also appears verbatim in the prompt is leaked ground truth: the agent can copy it instead of solving the task.
- Remediation: Remove the answer from the prompt/input fields; keep ground truth in verifier-owned fields only.
- Limitations: Verbatim/normalised containment only; paraphrased leakage needs semantic review. Very short answers use explicit disclosure phrasing ("answer is X") to avoid flagging multiple-choice option lists.

## EC081 - Dataset has no duplicate or near-duplicate rows

- Category: dataset  |  Default severity on failure: MEDIUM  |  Dynamic: False
- Description: Exact duplicates, reused ids and near-identical prompts (especially with conflicting labels) inflate scores, leak across splits and corrupt training signal.
- Remediation: Deduplicate prompts, make ids unique, and resolve label conflicts by re-adjudicating the row.
- Limitations: Near-duplicates use word 5-gram Jaccard >= 0.9 and deterministic token-set cosine >= 0.82 over a bounded prompt sample; embedding-level paraphrases still need review.

## EC082 - Dataset splits do not share prompts (no train/test overlap)

- Category: dataset  |  Default severity on failure: HIGH  |  Dynamic: False
- Description: The same prompt in a train split and a test/eval split is contamination: test performance partly measures memorisation.
- Remediation: Remove overlapping prompts from one split (conventionally from train) and re-issue the dataset version.
- Limitations: Split membership is inferred from file names containing train/test/eval/dev/valid; unlabelled files return NOT_APPLICABLE.

## EC083 - Dataset labels are not degenerate

- Category: dataset  |  Default severity on failure: MEDIUM  |  Dynamic: False
- Description: Constant, empty or single-class-dominated labels make any score meaningless and teach RLVR verifiers to accept anything.
- Remediation: Fix labelling, drop empty-label rows, and rebalance or document intentional skew.
- Limitations: Applies to the detected answer/label field; free-form generation datasets without labels return NOT_APPLICABLE.

## EC084 - Dataset rows parse and carry their promised fields

- Category: dataset  |  Default severity on failure: HIGH  |  Dynamic: False
- Description: Unparseable lines, missing prompts and missing labels silently shrink or corrupt the evaluated population.
- Remediation: Repair or drop broken rows; keep prompt and label fields present on every row.
- Limitations: Bounded to the first rows per file (cap recorded in evidence); field names are detected from common conventions.

## EC085 - Dataset grading specifications are consistent (FAIL_TO_PASS/PASS_TO_PASS style)

- Category: dataset  |  Default severity on failure: HIGH  |  Dynamic: False
- Description: Test-graded instances grade by running named tests: an empty must-pass set grades nothing, and a test listed as both must-pass-after and must-pass-before makes the instance ungradeable.
- Remediation: Give every instance a non-empty FAIL_TO_PASS set disjoint from PASS_TO_PASS; regenerate the instance if its test patch changed.
- Limitations: Applies to SWE-bench-style rows carrying FAIL_TO_PASS/PASS_TO_PASS fields (JSON-encoded lists); other datasets return NOT_APPLICABLE.

## EC072 - Semgrep scan (external companion, task-provided rules only)

- Category: external  |  Default severity on failure: MEDIUM  |  Dynamic: False
- Description: Runs semgrep only when the task ships a .semgrep.yml/.semgrep.yaml config, so rule choice stays with the task owner.
- Remediation: Address semgrep findings or curate the task's semgrep config.
- Limitations: External tool output is mapped, not re-derived; the tool's own version and ruleset determine coverage.
