\# MASTER BUILD PROMPT: EnvCert — Build a Production-Quality, Open-Source AI Environment Integrity and Assurance Tool



\## YOUR MISSION



Act as an autonomous founding engineering team tasked with researching, designing, building, testing, documenting and preparing an excellent open-source developer tool for public release.



You combine the responsibilities of:



\- A principal software architect.

\- A senior Python and infrastructure engineer.

\- An AI evaluation and reinforcement-learning researcher.

\- A security researcher specialising in sandbox isolation, reward hacking and benchmark vulnerabilities.

\- An open-source maintainer who understands what makes developer tools genuinely useful.

\- A product manager who understands developer adoption and usability.

\- A QA engineer responsible for proving that the software works.

\- A DevSecOps engineer responsible for supply-chain security and release automation.

\- A technical writer responsible for excellent documentation.



Your task is to build \*\*EnvCert\*\*, working name, into a genuinely useful, publish-ready open-source project.



Do not merely produce a proposal, architecture document, prototype or scaffold.



\*\*You must research, make decisions, design the architecture, implement the software, test it, document it and prepare all necessary release assets in the current working repository.\*\*



Continue until the open-source product is usable by an external developer who has never spoken to you.



Do not ask me questions. Make reasonable engineering and product decisions, document assumptions, and proceed autonomously.



\---



\# PART 1 — UNDERSTAND THE PRODUCT



\## 1.1 The problem



AI training and evaluation environments are increasingly packaged as Docker images, task bundles and verification systems.



These environments can contain:



\- A task description.

\- A Docker image or Dockerfile.

\- A reference solution.

\- Hidden tests.

\- A verifier or reward function.

\- Environment state.

\- Supporting datasets.

\- Agent execution instructions.



They are used in:



\- Reinforcement learning.

\- Agent training.

\- Coding benchmarks.

\- Tool-use evaluation.

\- Computer-use environments.

\- Software engineering benchmarks.

\- AI model evaluation.



However, these environments can contain defects that make their results misleading.



Examples include:



1\. Solutions or answers exposed to the agent.

2\. Git history containing hidden reference material.

3\. Agent-controlled files influencing the verifier.

4\. Weak tests accepting incorrect solutions.

5\. Reward functions that can be manipulated.

6\. Shared agent and evaluator processes.

7\. Dependency or executable shadowing.

8\. Flaky task execution.

9\. Non-reproducible environment builds.

10\. Insecure Docker configurations.

11\. Network access that permits answer retrieval or external interference.

12\. Incorrect reference solutions or broken verification logic.



A reference solution passing its tests does not establish that incorrect solutions will fail.



A Docker image building successfully does not establish that its environment is trustworthy.



A signed report does not establish that the checks behind that report were meaningful.



\## 1.2 Product vision



EnvCert is an open-source, vendor-neutral integrity assessment and evidence-generation tool for AI training and evaluation environments.



Its purpose is to help environment developers, AI researchers, benchmark maintainers and model developers determine:



\- What was checked.

\- Which checks passed or failed.

\- What vulnerabilities or weaknesses were discovered.

\- What could not be checked.

\- Which execution conditions were used.

\- Which exact environment artifacts were assessed.

\- Whether the results can be independently verified.



The intended workflow:



Environment source → EnvCert checks → Findings and evidence → Machine-readable report → Optional signed attestation → CI and policy enforcement.



\## 1.3 Product positioning



Do not position EnvCert as:



\- A generic Docker vulnerability scanner.

\- A replacement for Harbor.

\- A replacement for NVIDIA NeMo Gym.

\- A replacement for BenchJack.

\- A generic AI agent.

\- A tool that guarantees environments are unhackable.

\- A certification authority.

\- Another cloud dashboard.



Position it as:



\*\*An independent, extensible verification and evidence layer for the integrity of AI training and evaluation environments.\*\*



The key differentiators to investigate and pursue are:



1\. Deterministic and explainable checks.

2\. CI-native execution.

3\. Cross-framework compatibility.

4\. Reusable validation profiles.

5\. Structured evidence.

6\. Portable, digest-bound attestations.

7\. Clear limitations and reproducible findings.

8\. An offline-first, open-source implementation.



These are product hypotheses. Validate each before committing to an implementation.



\---



\# PART 2 — RESEARCH BEFORE BUILDING



You must complete a genuine competitive, technical and product investigation before deciding the final architecture.



Do not assume the original concept is completely novel.



\## 2.1 Investigate existing projects



At minimum, research these projects and their current implementations:



\### BenchJack

https://github.com/benchjack/benchjack



Understand:

\- Its vulnerability categories.

\- Its static analysis.

\- Its AI-assisted inspection.

\- Its proof-of-concept exploit generation.

\- Its current CLI and output formats.

\- Which checks overlap with EnvCert.

\- What it does not attempt to provide.



\### Trustworthy Env / Benchmark Audit Tool

Research the Berkeley-linked open-source trustworthy environment auditing project, including the repository at:



https://github.com/moogician/trustworthy-env



Verify that this repository and its current status are correct before relying on it.



Investigate:

\- Static and dynamic analysis.

\- AST analysis.

\- Z3 or formal verification.

\- Runtime checks.

\- Mutation testing.

\- Existing vulnerability classes.

\- Integration capabilities.



\### Harbor

https://github.com/harbor-framework/harbor



Research:

\- Task directory structure.

\- task.toml format.

\- Environment images.

\- Reference solutions.

\- Verifier execution.

\- Separate verifier sandboxing.

\- Available CLI commands and APIs.

\- Existing validation features.



Documentation starting point:



https://github.com/harbor-framework/docs



\### NVIDIA NeMo Gym

https://github.com/NVIDIA-NeMo/Gym



Research the latest:

\- Environment schemas.

\- Environment validation.

\- Environment tests.

\- Verifier fixtures.

\- Publishing workflow.

\- Repeated evaluation.

\- Reward verification.

\- Task-folder compatibility.

\- Sandboxing.

\- Harbor integration.



Documentation:



https://docs.nvidia.com/nemo/gym/



\### Inspect AI

https://github.com/UKGovernmentBEIS/inspect\_ai



Investigate:

\- Evaluation architecture.

\- Sandbox integrations.

\- Scorers.

\- Evaluation reproducibility.

\- Extensibility.



\### SWE-ABS



Research the SWE-ABS project and its test-strengthening capabilities.



Understand what is benchmark-specific and what could be generalised.



\### Supply-chain attestation



Research:



\- https://github.com/in-toto/attestation

\- https://github.com/sigstore/cosign

\- https://docs.sigstore.dev/



Explicitly investigate:



\- in-toto Test Result predicate.

\- in-toto Simple Verification Result (SVR).

\- DSSE.

\- Cosign image attestations.

\- OCI subject digest binding.

\- Attestation verification policies.



Do not create a new attestation standard unnecessarily.



\## 2.2 Research additional projects



Discover further tools solving:



\- Benchmark answer leakage.

\- Hidden-test leakage.

\- Reward hacking.

\- Mutation testing.

\- Test-suite quality measurement.

\- Container isolation.

\- Dockerfile static analysis.

\- Build reproducibility.

\- AI evaluation provenance.

\- Test-result attestations.

\- Reproducible research workflows.



Investigate whether established tools such as Semgrep, Hadolint, Syft, Grype, Trivy, pytest, Mutmut, Cosmic Ray or other suitable projects could be integrated.



Do not add dependencies simply because they are popular. Assess whether each tool contributes meaningful functionality.



\## 2.3 Competitive feature matrix



Create:



docs/research/COMPETITIVE\_ANALYSIS.md



Compare existing projects across:



\- Static analysis.

\- Dynamic validation.

\- Reward correctness.

\- Answer leakage.

\- Filesystem isolation.

\- Verifier integrity.

\- Mutation testing.

\- Reproducibility.

\- Docker support.

\- CI integration.

\- JSON reports.

\- SARIF reports.

\- Signed attestations.

\- Policy enforcement.

\- Framework compatibility.

\- Offline operation.

\- Extensibility.

\- Licensing.

\- Maintenance and release activity.



Clearly separate verified capabilities, absent capabilities and unknown capabilities.



Do not claim something is missing merely because it is not mentioned on a product website.



\## 2.4 Research output and decision



Produce:



docs/research/RESEARCH\_FINDINGS.md



Include:

\- Important research discoveries.

\- Source URLs.

\- Publication dates.

\- Relevant technical findings.

\- Competing implementations.

\- Where existing tools overlap.

\- What remains differentiated.

\- Unresolved questions.



Then produce:



docs/architecture/PRODUCT\_DECISIONS.md



Explain what EnvCert should build, what it should integrate and what it should deliberately not build.



\*\*Do not spend the entire assignment researching. Complete the research, make the decisions and implement the product.\*\*



\---



\# PART 3 — DEFINE THE MVP STRATEGY



\## 3.1 Choose a narrow initial scope



The initial supported environment format should be Harbor-compatible task directories.



Investigate the actual current Harbor format before implementing the parser.



Support an initial task structure resembling:



```text

my-task/

├── task.toml

├── instruction.md

├── environment/

│   └── Dockerfile

├── tests/

│   └── test.sh

└── solution/

&#x20;   └── solve.sh

```



The actual adapter must accommodate real variations in Harbor tasks.



Do not make assumptions based solely on this illustrative directory tree.



Design the architecture so other frameworks can be added through adapters without rewriting the core.



Potential future adapters:



\- NeMo Gym.

\- Inspect AI.

\- Other Docker-based evaluation systems.

\- Generic custom task bundles.



Do not promise support for frameworks that are not implemented and tested.



\## 3.2 Product priorities



Prioritise the following:



\*\*P0 — Essential\*\*



\- Standalone CLI.

\- Harbor task discovery and parsing.

\- Static environment-integrity checks.

\- Structured findings.

\- JSON reports.

\- Human-readable terminal output.

\- Useful exit codes.

\- Configuration and validation profiles.

\- Sample tasks and automated tests.

\- Comprehensive documentation.



\*\*P1 — Important\*\*



\- Dynamic validation through a safe execution abstraction.

\- Gold-solution sanity checks.

\- Task-appropriate negative controls.

\- Repeatability checks.

\- Isolation analysis.

\- SARIF output.

\- GitHub Actions integration.

\- JSON Schema for report validation.



\*\*P2 — Valuable but optional\*\*



\- Mutation testing.

\- OCI image digest integration.

\- in-toto attestation generation.

\- Cosign signing and verification.

\- Additional framework adapters.

\- Scheduled validation examples.



The exact order may change based on research and engineering feasibility.



Implement a complete, valuable vertical slice rather than superficial versions of every feature.



\---



\# PART 4 — ARCHITECTURE



Before implementation, design the architecture and record the important decisions.



Create:



\- docs/architecture/ARCHITECTURE.md

\- docs/architecture/THREAT\_MODEL.md

\- docs/architecture/CHECK\_CATALOG.md

\- docs/architecture/REPORT\_SCHEMA.md

\- docs/architecture/ROADMAP.md



\## 4.1 Architectural principles



The product must be:



\- Local-first.

\- Offline-capable for static analysis.

\- Deterministic wherever possible.

\- Vendor-neutral.

\- Extensible.

\- Modular.

\- Testable.

\- Cross-platform where technically reasonable.

\- Safe by default.

\- Easy to integrate into CI.

\- Independent of proprietary model APIs.



Avoid unnecessary microservices, Kubernetes, databases, hosted APIs and distributed infrastructure.



The initial product is a local developer tool, not a SaaS platform.



\## 4.2 Suggested architecture



Use this conceptual separation:



```text

envcert/

&#x20;   cli/

&#x20;   core/

&#x20;   adapters/

&#x20;   checks/

&#x20;       static/

&#x20;       dynamic/

&#x20;       mutation/

&#x20;   runners/

&#x20;   policies/

&#x20;   reports/

&#x20;   attestations/

&#x20;   schemas/

&#x20;   utils/

```



You may change this structure when research justifies a better design.



Define clean interfaces for:



\- EnvironmentAdapter.

\- Check.

\- Finding.

\- Evidence.

\- ExecutionRunner.

\- PolicyEvaluator.

\- ReportSerializer.

\- AttestationProvider.



Avoid creating abstractions for hypothetical future requirements.



A check should operate against an explicitly defined input context and return structured results rather than printing directly to the terminal.



\## 4.3 Finding model



Each finding should include appropriate fields such as:



\- Stable check ID.

\- Title.

\- Description.

\- Category.

\- Severity.

\- Status.

\- Affected artifact.

\- File and line reference, when applicable.

\- Evidence.

\- Reproduction information.

\- Remediation guidance.

\- Confidence or certainty.

\- Limitations.



Suggested statuses:



\- PASS

\- FAIL

\- WARN

\- NOT\_RUN

\- NOT\_APPLICABLE

\- ERROR



Use severity levels:



\- CRITICAL

\- HIGH

\- MEDIUM

\- LOW

\- INFO



Do not force a numerical environment quality score into the initial product.



A single score can conceal critical failures and give users a misleading impression of security.



Prefer explicit findings and policy-based results.



\## 4.4 Report model



Generate a versioned JSON report with:



\- EnvCert version.

\- Report schema version.

\- Environment identification.

\- Detected adapter.

\- Image digest when available.

\- Task bundle digest.

\- Verifier and test digests where applicable.

\- Execution configuration.

\- Checks executed.

\- Individual findings.

\- Skipped checks.

\- Errors.

\- Overall policy result.

\- Limitations.

\- Timestamps.



The report must distinguish a failed check from a check that was never executed.



Provide a published JSON Schema and validate generated reports against it in automated tests.



Make results machine-readable without requiring the user to purchase anything or connect to a cloud service.



\---



\# PART 5 — IMPLEMENT THE CHECK ENGINE



\## 5.1 Static checks



The first release must contain useful, implemented static checks.



Prioritise the following categories.



\### A. Reference material and answer exposure



Detect:



\- Exposed .git directories.

\- Reference solutions placed in agent-visible paths.

\- Gold patches or answer files copied into the environment.

\- Hidden evaluation data accidentally included in the Docker build context.

\- Solution files included through broad COPY or ADD instructions.

\- Exposed task metadata.

\- Known secret or reference filenames.

\- Potentially sensitive environment variables.



Important: Analyse the actual Docker build context, .dockerignore and COPY/ADD instructions where possible.



Do not flag a solution merely because it exists in the source repository.



Determine whether it is plausibly included in the image or agent-accessible environment.



Where the exact runtime visibility cannot be established statically, report a potential exposure rather than a confirmed leak.



Git history inspection should be a separate check or optional mode.



Do not automatically assume that all git history is exposed to the agent.



\### B. Agent/verifier boundary analysis



Inspect:



\- Shared writable directories.

\- Verifier directories accessible to agent processes.

\- Agent-controlled test configuration.

\- Writable Python import paths.

\- sitecustomize.py and usercustomize.py.

\- pytest conftest.py and plugin loading.

\- PATH shadowing.

\- Executable wrappers.

\- Verifier dependencies.

\- Shared filesystem risks.

\- Docker mounts.

\- Verifier execution configuration.



Identify plausible pathways through which agent-controlled content could influence verification.



Do not classify the mere presence of conftest.py or sitecustomize.py as an exploit.



Determine whether the file is within an applicable import or execution path and explain uncertainty.



\### C. Docker configuration



Inspect:



\- Floating base image tags.

\- Missing image digests.

\- Root-user execution.

\- Privileged mode.

\- Host filesystem mounts.

\- Docker socket mounts.

\- Unnecessary capabilities.

\- Host network access.

\- Unrestricted network exposure.

\- Insecure entrypoints.

\- Remote ADD instructions.

\- Dangerous shell execution patterns.

\- Dependency installation without suitable pinning.



Distinguish container-hardening recommendations from actual benchmark-integrity vulnerabilities.



\### D. Dependency and build reproducibility signals



Inspect:



\- Lockfiles.

\- Floating Python dependencies.

\- Unpinned packages.

\- External downloads.

\- Build arguments.

\- Unpinned base images.

\- Inconsistent environment manifests.



Do not equate a missing lockfile with a confirmed vulnerability.



\### E. Verifier structure



Inspect:



\- Missing verification code.

\- Empty tests.

\- Missing expected outputs.

\- Missing reward production.

\- Obvious unconditional success paths.

\- Unhandled error conditions.

\- Suspicious result parsing.

\- Tests that can silently skip critical assertions.

\- Known weak verifier patterns.



Use AST-based inspection where appropriate.



Every static rule must have:



\- A stable ID.

\- A description.

\- A detection implementation.

\- Severity.

\- Evidence generation.

\- A remediation.

\- Tests.

\- Documented limitations.



Do not create rules that only detect the existence of a filename without examining its relevance.



\## 5.2 Dynamic checks



Dynamic checks must be explicitly opt-in and capability-aware.



Build a runner abstraction so the core scanner does not assume that executing an arbitrary task inside a local Docker container is completely safe.



Research Harbor's own runtime and verification mechanisms and reuse them where possible rather than duplicating task execution.



Support only execution methods whose actual safety properties are understood and documented.



Potential checks:



\### Reference solution



When a compatible task and supported runner are available:



\- Execute the reference solution.

\- Verify that it receives the expected reward.

\- Capture execution evidence.

\- Repeat it where required.



\### Negative controls



Implement only task-appropriate negative controls.



Examples:



\- Empty patch.

\- No-op solution.

\- Reverted reference modification.

\- Incorrect output.

\- Deliberately invalid submission.



Do not assume that no-op must fail for every possible environment.



A check that is not semantically valid for a task must return NOT\_APPLICABLE, not PASS.



\### Repeatability



Run supported checks multiple times and compare meaningful outcomes.



Distinguish:

\- Reward consistency.

\- Exit status consistency.

\- Output consistency.

\- Execution-time variation.

\- Infrastructure-related failures.



Do not require bitwise-identical execution output when task semantics do not require it.



\### Isolation



Where the runner allows:



\- Evaluate agent and verifier separation.

\- Detect shared writable state.

\- Validate explicit artifact-transfer boundaries.

\- Inspect network policy.

\- Record container permissions.

\- Verify configured privilege restrictions.



Do not assert that Docker alone guarantees isolation.



\### Network restrictions



Test a declared network policy.



Do not universally require `--network none` for environments that legitimately require network-backed services.



Report the actual policy and its exceptions.



\### Mutation testing



Develop a small, well-documented mutation framework if a reliable supported use case exists.



For supported coding tasks, mutate reference solutions or known-correct implementations and measure whether the verifier rejects incorrect variants.



Calculate:



Mutation rejection rate =

Incorrect variants rejected / Eligible incorrect variants tested.



Report the number and type of mutants.



Account for equivalent mutants, invalid mutants and inconclusive execution.



Do not interpret a mutation score as proof of verifier correctness.



If general mutation support cannot be implemented reliably for the first release, document the extension interface and defer it instead of shipping a misleading implementation.



\## 5.3 Execution security is mandatory



EnvCert may inspect and execute malicious or compromised evaluation environments.



Treat task bundles and Dockerfiles as untrusted input.



Never silently build or run arbitrary submitted code with unrestricted access to the developer's host.



Never mount the host Docker socket into an untrusted task container.



For any supported execution mode:



\- Avoid privileged execution.

\- Drop unnecessary Linux capabilities.

\- Use no-new-privileges where supported.

\- Run as a non-root user where practical.

\- Restrict CPU, memory, PIDs and execution duration.

\- Control filesystem mounts.

\- Use read-only filesystems where compatible.

\- Restrict network access by declared policy.

\- Do not expose host credentials.

\- Do not execute arbitrary scripts in the EnvCert host process.

\- Use argument arrays rather than shell interpolation.

\- Apply execution timeouts.

\- Capture logs with bounded size.

\- Clean up resources after execution.



Document the difference between a restricted Docker execution mode and a stronger disposable VM or remote sandbox.



If the available execution boundary is insufficient for untrusted workloads, fail safely and explain the limitation.



Static analysis must remain usable without Docker or cloud credentials.



\---



\# PART 6 — DESIGN THE CLI



The CLI is the most important user interface.



Make it intuitive and predictable.



A first-time developer should be able to discover how to use it from the terminal.



Suggested interface:



```bash

envcert --help



envcert version



envcert list-checks



envcert check ./my-task



envcert check ./my-task --profile harbor



envcert check ./my-task --format json --output report.json



envcert check ./my-task --format sarif --output report.sarif



envcert check ./my-task --execution none



envcert check ./my-task --execution harbor



envcert verify report.json

```



These are proposed commands. Finalise them based on usability and the actual supported execution architecture.



Required qualities:



\- Helpful errors.

\- Clear progress output.

\- Clean terminal formatting.

\- Stable exit codes.

\- Non-interactive CI mode.

\- Explicit execution modes.

\- Sensible defaults.

\- Useful verbosity levels.

\- No required account.

\- No unnecessary telemetry.

\- No AI API requirement.

\- No internet requirement for static checks.



Support configuration such as:



```toml

\[envcert]

profile = "harbor"



\[checks]

enabled = \["all"]



\[checks.dynamic]

enabled = false

repetitions = 3



\[policy]

fail\_on = \["critical", "high"]

```



Treat this as illustrative configuration, not an immutable schema.



Validate all configuration and provide useful errors.



Implement:



\- Text output.

\- JSON output.

\- SARIF output if feasible.

\- Report schema validation.

\- Explicit failure thresholds.

\- Reproducible machine-readable evidence.



Define documented exit codes and test them.



A possible convention:



\- 0: Policy passed.

\- 1: Policy failed.

\- 2: Invalid input or configuration.

\- 3: Execution or internal error.



Choose and document the final convention.



\---



\# PART 7 — ATTESTATIONS AND VERIFICATION



The open-source implementation should support portable verification evidence.



Investigate and reuse established in-toto formats.



Prioritise:



\- in-toto Test Result.

\- in-toto Simple Verification Result.

\- DSSE.

\- Cosign.



Do not invent a new predicate unless a concrete missing requirement justifies it.



If the existing predicate can express the result, use it.



If an EnvCert-specific extension becomes necessary, document its version, schema, compatibility and rationale.



An attestation must bind to all relevant subject material, not merely an image tag.



Consider:



\- OCI image digest.

\- Task bundle digest.

\- Verifier digest.

\- Test-suite digest.

\- Dataset version.

\- Reference solution digest, where appropriate.

\- Validation profile.

\- Policy version.

\- EnvCert version.

\- Check results.

\- Execution identity and time.

\- Limitations.



Do not rely on mutable OCI labels as proof.



Support local report generation without signing dependencies.



Make cryptographic signing and verification optional integrations.



Where Cosign is unavailable, explain that signing or verification was not performed. Never claim an unsigned report is cryptographically verified.



The product must clearly distinguish:



1\. Supplier self-testing.

2\. Consumer-side independent testing.

3\. Third-party independent auditing.



Never call these equivalent forms of assurance.



\---



\# PART 8 — GITHUB ACTIONS AND DEVELOPER INTEGRATION



A release-ready open-source developer tool needs working CI integration.



Build a GitHub Action that can:



1\. Check out or access the task repository.

2\. Install a supported EnvCert version.

3\. Run the requested validation profile.

4\. Produce JSON and SARIF reports.

5\. Fail according to configured policy.

6\. Upload reports as workflow artifacts when configured.

7\. Optionally support signed attestations when credentials and configuration exist.



Provide:



\- action.yml.

\- Example workflows.

\- Versioned usage.

\- Required permissions.

\- Security guidance.

\- Supported runner information.

\- Examples for pull requests and releases.



Do not request unnecessary GitHub permissions.



Do not put credentials into logs.



Do not assume dynamic execution is safe merely because it occurs in a GitHub Actions runner.



Make the default workflow static-only unless a properly configured execution environment is explicitly selected.



Document how users can safely run the dynamic checks.



\---



\# PART 9 — OPEN-SOURCE PROJECT QUALITY



\## 9.1 Language and dependencies



Prefer Python for the initial product, given its compatibility with AI evaluation frameworks.



Choose a modern, maintainable project configuration.



Consider:



\- pyproject.toml.

\- uv.

\- A conventional Python build backend.

\- A reliable CLI framework or standard-library approach.

\- pytest.

\- Ruff.

\- Appropriate type checking.

\- Coverage reporting.

\- JSON Schema validation.



Research current package compatibility before selecting exact dependency versions.



Support a clearly documented Python version range.



Do not introduce heavyweight dependencies without justification.



Static analysis should have minimal dependencies.



Optional functionality should use optional dependency groups wherever reasonable.



Avoid unnecessary API calls or proprietary model dependencies.



\## 9.2 Repository structure



Create a clear structure similar to:



```text

envcert/

├── envcert/

│   ├── cli/

│   ├── core/

│   ├── adapters/

│   ├── checks/

│   │   ├── static/

│   │   ├── dynamic/

│   │   └── mutation/

│   ├── runners/

│   ├── policies/

│   ├── reports/

│   ├── attestations/

│   ├── schemas/

│   └── utils/

├── tests/

│   ├── unit/

│   ├── integration/

│   ├── fixtures/

│   └── security/

├── examples/

│   ├── safe-environment/

│   └── intentionally-vulnerable-environment/

├── docs/

│   ├── research/

│   ├── architecture/

│   ├── guides/

│   ├── checks/

│   └── contributing/

├── .github/

│   ├── workflows/

│   └── actions/

├── pyproject.toml

├── README.md

├── LICENSE

├── SECURITY.md

├── CONTRIBUTING.md

├── CODE\_OF\_CONDUCT.md

├── CHANGELOG.md

└── .gitignore

```



Modify this if a more sensible architecture emerges.



Avoid excessive fragmentation and unnecessary empty modules.



\## 9.3 Licensing



Use a permissive open-source licence, preferably Apache-2.0, unless research identifies a compelling reason to choose otherwise.



Review the licenses of all dependencies and any code used for inspiration or integration.



Do not copy code from other repositories without complying with their licences.



Include attribution when appropriate.



Do not introduce commercial restrictions into the open-source core.



\## 9.4 Documentation



Produce excellent documentation.



The root README must answer these questions within the first few minutes:



\- What problem does EnvCert solve?

\- Who should use it?

\- What can it actually detect?

\- What can it not detect?

\- How do I install it?

\- How do I run my first check?

\- How do I interpret the report?

\- How do I integrate it into GitHub Actions?

\- How do I contribute?



Include:



\- Clear value proposition.

\- Installation instructions.

\- Quick-start tutorial.

\- Actual CLI examples.

\- Example findings.

\- Example reports.

\- Supported frameworks.

\- Compatibility matrix.

\- Security limitations.

\- Architecture overview.

\- Roadmap.

\- Contribution guide.

\- Licence.

\- Release information.



Do not use fabricated screenshots or claim unsupported functionality.



A working terminal recording or actual tested output is preferable to decorative marketing material.



\## 9.5 Contributor experience



Make it easy for external developers to add checks.



Document:



\- How to write a check.

\- How to add an adapter.

\- How to implement a runner.

\- How to write fixtures.

\- How to add regression tests.

\- How to document severity and confidence.

\- How to validate report schemas.



Provide an example custom check.



Make stable check IDs part of the public interface.



\---



\# PART 10 — TESTING AND QUALITY ASSURANCE



Testing is not an afterthought.



A tool designed to test whether other systems are reliable must itself demonstrate high reliability.



\## 10.1 Unit tests



Test:



\- Task discovery.

\- Task parsing.

\- Dockerfile inspection.

\- .dockerignore handling.

\- COPY/ADD analysis.

\- Git metadata inspection.

\- Solution visibility detection.

\- Verifier-path analysis.

\- Finding creation.

\- Severity handling.

\- Policy evaluation.

\- Report serialization.

\- SARIF generation.

\- Configuration parsing.

\- Exit codes.

\- Error handling.



\## 10.2 Integration tests



Create realistic sample Harbor-format environments.



At minimum:



\### Safe environment



A legitimate example task that should not generate false critical findings.



\### Intentionally vulnerable environment



A controlled fixture containing known, deliberately introduced weaknesses.



Examples:



\- Exposed reference material.

\- Broad Docker COPY.

\- Unpinned image.

\- Writable verifier paths.

\- Suspicious pytest configuration.

\- Weak verification logic.

\- Overly permissive container configuration.



Provide an expected-results fixture for each.



The test suite must verify that the expected problems are detected and that unrelated checks are not incorrectly triggered.



\### Unsupported environment



A task whose format or configuration is intentionally unsupported.



Ensure EnvCert reports unsupported capabilities instead of pretending it has successfully validated them.



\## 10.3 False positives and false negatives



Create tests for:



\- Safe files that resemble reference solutions.

\- Legitimate conftest.py files.

\- Legitimate network access.

\- Tasks with no solution directory.

\- Missing Docker.

\- Invalid Dockerfiles.

\- Missing optional dependencies.

\- Symlinks.

\- Unusual file layouts.

\- Large task directories.

\- Permission errors.



Minimise false positives without hiding real issues.



\## 10.4 Test execution requirements



Run the actual test suite.



Run the linter.



Run type checking where configured.



Run coverage.



Test installation into a clean environment.



Test the installed CLI rather than only importing internal modules.



Test on supported operating systems or clearly document platform limitations.



Test GitHub Action configuration.



Run at least one complete end-to-end example.



Do not report successful tests unless they were actually executed.



\## 10.5 Security self-review



Review EnvCert as if it were itself a security-sensitive application.



Consider:



\- Path traversal.

\- Symlink attacks.

\- Malicious archive extraction.

\- Command injection.

\- Unsafe YAML parsing.

\- Shell injection.

\- Resource exhaustion.

\- Untrusted Docker builds.

\- Host credential exposure.

\- Temporary-file races.

\- Malicious report input.

\- Malformed attestations.

\- Dependency supply-chain attacks.



Implement appropriate safeguards and regression tests.



Do not execute unsafe test fixtures against the developer's host.



\---



\# PART 11 — REAL-WORLD VALIDATION



Do not assume that a working implementation means the product is useful.



Validate it against representative public environments.



\## 11.1 Public-environment test campaign



Identify a manageable set of public, legally accessible, preferably Harbor-format tasks.



Prioritise diversity:



\- A straightforward coding task.

\- A task with a reference solution.

\- A task with external dependencies.

\- A task using Python verification.

\- A task using shell-based verification.

\- A task with unusual Docker configuration.

\- A task with separate verification.

\- A deliberately vulnerable test fixture.



Do not blindly execute arbitrary public task images or Dockerfiles.



Begin with static analysis.



Use isolated execution only when appropriate and explicitly authorised.



\## 11.2 Findings validation



For each important finding:



\- Identify the exact affected artifact.

\- Reproduce the finding.

\- Determine whether it is a confirmed defect or heuristic warning.

\- Record false-positive cases.

\- Explain how to fix it.

\- Preserve a redacted, reproducible report.



Do not publicly accuse a named project of a security vulnerability without sufficient evidence.



Follow responsible disclosure for non-public vulnerabilities.



\## 11.3 Publish a transparent pilot report



Create:



docs/research/PUBLIC\_ENVIRONMENT\_PILOT.md



Include:



\- Number of environments examined.

\- Frameworks and versions.

\- Checks executed.

\- Findings and classifications.

\- False-positive observations.

\- Unsupported checks.

\- Methodology.

\- Reproduction instructions.

\- Limitations.



Do not invent results.



If the public-environment campaign cannot be completed, document the fixtures and experiments actually completed. Do not manufacture a benchmark report.



\---



\# PART 12 — PUBLIC RELEASE PREPARATION



Make the project suitable for its first public GitHub release.



\## 12.1 Required release assets



Prepare:



\- README.md.

\- Apache-2.0 LICENSE.

\- CHANGELOG.md.

\- CONTRIBUTING.md.

\- CODE\_OF\_CONDUCT.md.

\- SECURITY.md.

\- pyproject.toml.

\- Lockfile where appropriate.

\- Versioned CLI.

\- GitHub Actions workflows.

\- Test suite.

\- Documentation.

\- Example task bundles.

\- JSON report schema.

\- Installation instructions.

\- Release notes.

\- Package build configuration.



\## 12.2 CI



Create workflows for:



\- Tests.

\- Linting.

\- Type checking.

\- Coverage.

\- Build validation.

\- Package installation.

\- Documentation checks.

\- Security/dependency scanning.



Use current supported action versions.



Pin third-party actions to immutable commit SHAs where appropriate and document version updates.



\## 12.3 Packaging



Prepare a distributable Python package.



Research package-name availability before finalising the distribution name.



Check whether EnvCert is available or whether a different package name is necessary.



Prepare:



\- Build artifacts.

\- Package metadata.

\- License metadata.

\- Dependency declarations.

\- Python compatibility declarations.

\- Console entry point.

\- Installation tests.



Prepare for PyPI Trusted Publishing where practical.



Do not claim that the package has been published unless publication actually succeeded.



\## 12.4 GitHub presentation



Make the repository understandable at a glance.



Provide:



\- A professional README.

\- Clear installation instructions.

\- A useful demo.

\- Supported-check matrix.

\- Roadmap.

\- Issue templates.

\- Pull-request template.

\- Security reporting process.

\- Release workflow.



Do not add decorative badges that do not correspond to functioning checks.



\## 12.5 Release boundaries



Prepare the project for publication, but do not:



\- Push to a remote repository without explicit authorisation.

\- Publish a package without the necessary credentials and permission.

\- Create external accounts.

\- Claim a release exists when only local artifacts were generated.

\- Expose secrets.

\- Publish unreviewed security findings about third-party projects.



If credentials are unavailable, complete every local preparation step and explain precisely what remains for the owner to perform.



\---



\# PART 13 — DEVELOPMENT EXECUTION RULES



Follow these rules throughout the assignment.



1\. Inspect the existing repository and working environment before modifying anything.

2\. Preserve useful existing code and configuration.

3\. Do not delete unrelated files.

4\. Establish a clear build plan after research.

5\. Implement working functionality, not pseudocode.

6\. Do not leave core functionality as TODOs.

7\. Do not create fake implementations that always return PASS.

8\. Do not silently skip failed checks.

9\. Do not present heuristic warnings as confirmed vulnerabilities.

10\. Do not claim complete security or certification.

11\. Do not add AI dependencies unless a well-defined feature genuinely needs them.

12\. Do not require AWS, paid APIs or a hosted service to use the open-source core.

13\. Make static analysis useful without Docker.

14\. Make optional features fail gracefully.

15\. Prefer small, tested increments.

16\. Keep dependencies and installation requirements reasonable.

17\. Write documentation alongside the implementation.

18\. Use real test fixtures.

19\. Run tests after significant changes.

20\. Inspect your own work for security and usability problems.

21\. Do not stop after writing the architecture.

22\. Do not stop after writing a README.

23\. Do not stop after a minimal CLI prototype.

24\. Continue until the project is demonstrably functional and release-ready within the available environment.

25\. If a feature is not safely or reliably achievable, narrow the scope and document it rather than shipping a misleading stub.



Work autonomously and do not ask for approval between phases.



If internet access or some external tool is unavailable, continue with what can be done locally and disclose the limitation.



Do not spend excessive effort on speculative features when the core tool could be made substantially better.



\---



\# PART 14 — FINAL ACCEPTANCE CRITERIA



The project is complete only when the following can be demonstrated.



\## A. Installation



A new developer can install the package using the documented instructions.



\## B. First run



A developer can execute:



```bash

envcert check ./examples/safe-environment

```



and receive a meaningful report.



\## C. Vulnerability detection



A developer can execute:



```bash

envcert check ./examples/intentionally-vulnerable-environment

```



and see the expected findings.



\## D. Machine readability



The JSON output validates against the published schema.



\## E. CI readiness



A developer can copy the GitHub Actions example into a repository and successfully run static EnvCert checks.



\## F. Reliability



The automated tests pass in the actual development environment.



\## G. Security



The tool does not silently execute arbitrary untrusted Dockerfiles with unrestricted host access.



\## H. Transparency



Every check has a documented purpose, implementation, severity, evidence and limitations.



\## I. Extensibility



An external contributor can understand how to implement another check.



\## J. Open-source readiness



The repository contains all required source, documentation, licensing, CI and release assets.



\## K. Honest reporting



Every statement about functionality, compatibility, security or test results is supported by the implementation or an actual test.



\---



\# PART 15 — FINAL DELIVERABLES



At completion, produce the following.



\### 1. Working repository



All actual application code, tests, examples, configuration, documentation and release assets.



\### 2. Research and architecture



\- Competitive analysis.

\- Product decisions.

\- Architecture.

\- Threat model.

\- Check catalogue.

\- Report schema.

\- Roadmap.



\### 3. Demonstration



Provide real terminal output from:



\- Safe example task.

\- Intentionally vulnerable example task.

\- JSON report generation.

\- CI-style execution.



\### 4. Quality report



Document:



\- Tests executed.

\- Test results.

\- Coverage.

\- Lint results.

\- Type-check results.

\- Security-review findings.

\- Known bugs.

\- Known limitations.

\- Unsupported environments.



\### 5. Release readiness report



Create:



RELEASE\_READINESS.md



Include:



\- Current project version.

\- Installation method.

\- Package build status.

\- Supported platforms.

\- Supported environment formats.

\- Implemented checks.

\- Deferred checks.

\- GitHub Action status.

\- Attestation status.

\- Outstanding release blockers.

\- Steps needed to publish publicly.



\### 6. Final completion summary



At the end of the assignment, provide:



1\. What was researched.

2\. Which existing projects were considered.

3\. What was decided and why.

4\. What was actually built.

5\. How to install it.

6\. How to run it.

7\. How to run the tests.

8\. What works.

9\. What remains unimplemented.

10\. What remains before public publication.

11\. The most important next improvements.



Never describe planned functionality as implemented.



\---



\# FINAL PRODUCT STANDARD



Think about an independent developer who discovers EnvCert on GitHub.



They should be able to understand its purpose, install it, run it against a real supported environment, discover something useful, interpret the finding, integrate the tool into CI and contribute another check.



That experience matters more than the number of features.



Do not build an impressive architecture that has no practical user value.



Do not build a generic security scanner with an AI branding layer.



Do not duplicate the existing frameworks.



Build the smallest genuinely useful product that occupies a defensible position in the ecosystem.



\*\*The long-term vision is to make independently verifiable integrity evidence a normal part of creating, publishing, accepting and maintaining AI training and evaluation environments.\*\*



The first public release must earn the right to pursue that vision through actual utility, trustworthy results, excellent developer experience and technical credibility.



Now begin.



Research the ecosystem, inspect the existing workspace, formulate the product and architecture, implement the project, validate it and prepare it for public release. Do not stop at the planning stage.

