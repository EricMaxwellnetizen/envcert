"""Static checks. Every check returns at least one Finding; PASS is explicit.

Design rules enforced here (from the product spec):
- Do not flag a solution merely because it exists in the source tree; decide
  whether it is plausibly inside the Docker build context / agent-visible.
- Do not flag conftest.py / sitecustomize.py merely for existing; decide
  whether it sits on an import/execution path the verifier plausibly uses.
- Where runtime visibility cannot be proven statically, say so (WARN,
  medium/low confidence) instead of claiming a confirmed leak.
"""
from __future__ import annotations

import ast
import re

from envcert.adapters import harbor as harbor_adapter
from envcert.checks.base import CheckContext, CheckInfo, check, finding, not_applicable, passed
from envcert.core.models import Confidence, Severity, Status
from envcert.utils.dockerfile import copy_sources, image_ref_pinned
from envcert.utils.files import dockerignore_match

# ---------------------------------------------------------------- structure

EC001 = CheckInfo("EC001", "Task structure is recognisable and complete", "structure", Severity.HIGH,
                  "Task has the files its framework requires (config, instruction, verifier, environment).",
                  "Add the missing task.toml / instruction.md / tests / environment files for your framework.",
                  "Only Harbor and generic Docker layouts are recognised in this version.")
EC002 = CheckInfo("EC002", "Instruction is present and non-trivial", "structure", Severity.MEDIUM,
                  "instruction.md exists, is non-empty and contains no unresolved placeholders.",
                  "Write a complete instruction.md without TODO/placeholder text.")
EC003 = CheckInfo("EC003", "Reference solution is present (or its absence is explicit)", "structure", Severity.LOW,
                  "A reference/oracle solution exists so the verifier can be sanity-checked.",
                  "Add solution/solve.sh (Harbor) or document why no reference solution exists.",
                  "Some frameworks source solutions externally; then this is informational.")

# ---------------------------------------------------------------- leakage

EC010 = CheckInfo("EC010", "No exposed version-control metadata in agent-visible paths", "leakage", Severity.HIGH,
                  ".git data inside the build context or environment can leak hidden reference material and history.",
                  "Exclude .git via .dockerignore, do not COPY it into the image, and strip VCS data from published images.",
                  "Static analysis cannot prove the agent can read the path at runtime; exposure is assessed from the build context and COPY instructions.")
EC011 = CheckInfo("EC011", "Reference solution is not copied into the agent environment", "leakage", Severity.CRITICAL,
                  "Solution/answer material must not be included in the Docker build context or copied into agent-visible paths.",
                  "Keep solution/ outside the build context, exclude it in .dockerignore, and never COPY solution material into the image.",
                  "Runtime mounts configured outside this task directory cannot be seen statically.")
EC012 = CheckInfo("EC012", "No known answer / gold files in agent-visible paths", "leakage", Severity.HIGH,
                  "Files with answer-like names (gold patch, expected output, answers) inside the environment can be read by the agent.",
                  "Move expected outputs and gold patches into tests/ (uploaded only at verification time) or remove them.",
                  "Name-based heuristic; a file with an answer-like name may be an innocent fixture.")
EC013 = CheckInfo("EC013", "No hard-coded secrets or credentials in task material", "leakage", Severity.HIGH,
                  "Hard-coded API keys/tokens/passwords in task files can leak and indicate exposed evaluation data.",
                  "Use ${VAR} host-environment references (Harbor) or CI secrets; rotate any committed credential.",
                  "Pattern-based; example/dummy values are flagged for human review, not asserted to be live credentials.")
EC014 = CheckInfo("EC014", "Instruction does not disclose solution or hidden-test content", "leakage", Severity.MEDIUM,
                  "The instruction given to the agent must not contain the reference solution or hidden expected outputs.",
                  "Remove solution code / expected outputs from instruction.md; describe the task, not the answer.",
                  "Heuristic overlap detection; short common tokens are ignored.")

# ---------------------------------------------------------------- boundary

EC020 = CheckInfo("EC020", "Verifier runs separated from the agent where the framework supports it", "boundary", Severity.MEDIUM,
                  "Shared agent/verifier execution lets agent state influence verification. Harbor supports verifier.environment_mode='separate'.",
                  "Set [verifier] environment_mode = \"separate\" (with declared artifacts), or document why shared verification is required.",
                  "Some tasks legitimately need shared state (live services); this is a warning, not proof of exploitability.")
EC021 = CheckInfo("EC021", "No agent-controlled Python import shadowing on verifier paths", "boundary", Severity.HIGH,
                  "sitecustomize/usercustomize/conftest or shadow modules in agent-writable, verifier-imported paths can alter verifier behaviour.",
                  "Keep import-shadowing files out of the agent environment; run the verifier with a clean PYTHONPATH and isolated rootdir.",
                  "Whether pytest/Python actually imports the file depends on runtime cwd/PYTHONPATH, which is assessed heuristically.")
EC022 = CheckInfo("EC022", "No executable shadowing of verifier tooling", "boundary", Severity.HIGH,
                  "Agent-placed executables named like verifier tools (pytest, python, test.sh) earlier on PATH can replace the real tool.",
                  "Do not ship tool-named executables in the agent workdir; invoke verifiers by absolute path.",
                  "PATH order at verification time is inferred from the Dockerfile/task config.")
EC023 = CheckInfo("EC023", "Verifier/test directories are not made world-writable in the image", "boundary", Severity.HIGH,
                  "chmod 777 / a+w on verifier, test or system paths lets the agent tamper with verification.",
                  "Use least-privilege permissions; make /tests read-only where the framework allows.",
                  "Runtime framework uploads may reset permissions; this checks what the task itself declares.")
EC024 = CheckInfo("EC024", "No shared writable mounts or Docker socket exposure", "boundary", Severity.CRITICAL,
                  "Host mounts, docker.sock or privileged settings in compose/task config collapse the agent/host boundary.",
                  "Remove docker.sock and host mounts; never run task containers privileged.",
                  "Only mounts declared inside this task directory are visible.")

# ---------------------------------------------------------------- docker

EC030 = CheckInfo("EC030", "Base images are pinned to a digest or specific tag", "docker", Severity.MEDIUM,
                  "Floating tags (latest / untagged) make builds non-reproducible and silently change the environment.",
                  "Pin base images as name:tag@sha256:<digest>.",
                  "Tag pinning without a digest is reported as a warning-level reproducibility issue, not a vulnerability.")
EC031 = CheckInfo("EC031", "Container does not default to root without justification", "docker", Severity.LOW,
                  "Running as root widens the impact of agent code; a non-root USER is defence in depth.",
                  "Add a non-root USER for the agent phase where the task allows it.",
                  "Many benchmark tasks legitimately need root; classified as hardening, not benchmark-integrity failure.")
EC032 = CheckInfo("EC032", "No dangerous Dockerfile patterns (remote ADD, curl|sh, privileged hints)", "docker", Severity.HIGH,
                  "Remote ADD and pipe-to-shell installs execute unreviewed remote code at build time.",
                  "Download with a pinned URL + checksum verification, or vendor the artifact.",
                  "Build-time network content cannot be inspected statically.")
EC033 = CheckInfo("EC033", "Network policy is declared and not silently unrestricted", "docker", Severity.MEDIUM,
                  "Harbor defaults to public network when network_mode is omitted; unrestricted egress enables answer retrieval.",
                  "Set [environment] network_mode = \"no-network\" or \"allowlist\" with allowed_hosts, unless the task truly needs public access.",
                  "A task may legitimately need network access; the finding reports the declared policy and its risk.")

# ---------------------------------------------------------------- dependencies

EC040 = CheckInfo("EC040", "Python dependencies are pinned / locked", "dependencies", Severity.MEDIUM,
                  "Unpinned pip installs make the environment non-reproducible and vulnerable to silent upstream changes.",
                  "Pin versions with == (or hashes) and commit a lockfile (uv.lock / poetry.lock / Pipfile.lock).",
                  "A missing lockfile is a reproducibility signal, not a confirmed vulnerability.")
EC041 = CheckInfo("EC041", "External downloads at build/run time are pinned or checksummed", "dependencies", Severity.MEDIUM,
                  "Unversioned downloads (git clone without commit, unversioned URLs) can change the environment silently.",
                  "Pin commits/versions and verify checksums for downloaded artifacts.")

# ---------------------------------------------------------------- verifier

EC050 = CheckInfo("EC050", "Verifier exists and is non-empty", "verifier", Severity.CRITICAL,
                  "A missing or empty verifier cannot distinguish correct from incorrect work.",
                  "Provide tests/test.sh (Harbor) that runs real assertions and writes a reward.")
EC051 = CheckInfo("EC051", "Verifier produces a reward in the framework's expected location", "verifier", Severity.HIGH,
                  "Harbor verifiers must write /logs/verifier/reward.txt or reward.json; otherwise every run scores 0 / is masked.",
                  "Write the numeric reward to /logs/verifier/reward.txt (or reward.json) on every code path.",
                  "Dynamic reward production is only proven by execution; this checks the code mentions the contract.")
EC052 = CheckInfo("EC052", "No unconditional-success path in the verifier", "verifier", Severity.CRITICAL,
                  "A verifier that always reports success (echo 1 without conditions, assert True only, sys.exit(0)) accepts any submission.",
                  "Gate the success reward on real assertions; ensure failures write reward 0.",
                  "AST/text heuristics cannot prove semantic correctness; flagged patterns need human confirmation.")
EC053 = CheckInfo("EC053", "Verifier contains substantive assertions", "verifier", Severity.HIGH,
                  "Verifiers that only check file existence or trivial substrings accept incorrect solutions (see BenchJack V-class flaws).",
                  "Assert on computed outputs/behaviour, include negative cases, and compare against expected values.",
                  "Assertion counting is a strength signal, not proof the assertions are semantically correct.")
EC054 = CheckInfo("EC054", "Verifier does not trust agent-controlled result files without validation", "verifier", Severity.HIGH,
                  "Reading a score/reward the agent itself wrote, or parsing agent stdout loosely, lets the agent report its own grade.",
                  "Compute the reward inside the verifier from raw artifacts; validate any agent-produced file strictly.",
                  "Heuristic; some tasks legitimately read agent output files — they must validate content, which needs human review.")

ALL_STATIC = [EC001, EC002, EC003, EC010, EC011, EC012, EC013, EC014, EC020, EC021, EC022, EC023, EC024,
              EC030, EC031, EC032, EC033, EC040, EC041, EC050, EC051, EC052, EC053, EC054]

SECRET_PATTERNS = [
    (re.compile(r"(?i)(api[_-]?key|secret|token|password|passwd)\s*[:=]\s*['\"][^'\"${}\s]{8,}['\"]"), "credential assignment"),
    (re.compile(r"sk-[A-Za-z0-9]{20,}"), "OpenAI-style key"),
    (re.compile(r"ghp_[A-Za-z0-9]{30,}"), "GitHub token"),
    (re.compile(r"AKIA[0-9A-Z]{16}"), "AWS access key id"),
    (re.compile(r"-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----"), "private key"),
]
ANSWER_NAMES = re.compile(r"(?i)(gold|answer|answers|expected[_-]?output|solution|oracle|ground[_-]?truth|reference[_-]?patch)")
SHADOW_MODULES = {"sitecustomize.py", "usercustomize.py"}
TOOL_NAMES = {"pytest", "pytest.exe", "python", "python3", "python.exe", "pip", "pip3", "test.sh", "bash", "sh"}


def _verifier_files(ctx) -> list[str]:
    out: list = list(getattr(ctx, "verifier_paths", []) or [])
    for f in ctx.files:
        if (f.startswith("tests/") or "/tests/" in f) and f not in out:
            out.append(f)
    return out


def _verifier_texts(ctx):
    for f in _verifier_files(ctx):
        t = ctx.text(f)
        if t is not None:
            yield f, t


# ---------------------------------------------------------------- checks

EC004 = CheckInfo("EC004", "Multi-step tasks: every step is complete (instruction, verifier, solution)", "structure", Severity.MEDIUM,
                  "Each Harbor step should carry its own instruction and verifier (or inherit the documented fallback), so every step is actually graded.",
                  "Add steps/<name>/instruction.md and steps/<name>/tests/test.sh (or document the fallback), plus a per-step solution where applicable.",
                  "Step-level environment sharing follows Harbor's multi-step rules; this checks presence, not per-step semantics.")


@check(EC004)
def check_multistep(c: CheckContext) -> list:
    ctx = c.task
    if ctx.adapter != "harbor" or not ctx.steps:
        return [not_applicable(EC004, "Not a multi-step Harbor task (no steps/ directory).")]
    problems = []
    for step in ctx.steps:
        if not step.get("instruction"):
            problems.append(f"step '{step['name']}': missing instruction.md")
        if not step.get("test_entrypoints"):
            problems.append(f"step '{step['name']}': no tests/test.sh|test.bat|verifier.py" + (" (top-level tests/ fallback may apply)" if ctx.tests_dir else ""))
    if problems:
        return [finding(EC004, Status.WARN, "; ".join(problems), evidence={"steps": ctx.steps, "problems": problems}, confidence=Confidence.MEDIUM)]
    return [passed(EC004, f"All {len(ctx.steps)} steps have instructions and verifier entrypoints.", evidence={"steps": [s["name"] for s in ctx.steps]})]


@check(EC001)
def check_structure(c: CheckContext) -> list:
    ctx = c.task
    missing = []
    if ctx.adapter == "nemo-gym":
        if not ctx.dataset_files and not ctx.config_path:
            missing.append("dataset.toml or *.jsonl row files")
        if not ctx.verifier_paths and not any(f.startswith("tests/") for f in ctx.files):
            missing.append("verifier.py (dataset root) or per-task tests/")
        if missing:
            return [finding(EC001, Status.FAIL, f"Missing NeMo Gym dataset components: {', '.join(missing)}",
                            evidence={"missing": missing, "adapter": ctx.adapter})]
        return [passed(EC001, f"Recognised NeMo Gym dataset '{ctx.task_name}' (dataset files: {ctx.dataset_files}, verifier: {ctx.verifier_paths}).",
                       evidence={"adapter": ctx.adapter, "dataset_files": ctx.dataset_files})]
    if ctx.adapter == "inspect":
        if not ctx.verifier_paths:
            missing.append("a Python file defining @task with inspect_ai imports")
        if missing:
            return [finding(EC001, Status.FAIL, f"Missing Inspect components: {', '.join(missing)}",
                            evidence={"missing": missing, "adapter": ctx.adapter})]
        return [passed(EC001, f"Recognised Inspect evaluation '{ctx.task_name}' (task files: {', '.join(ctx.verifier_paths)}).",
                       evidence={"adapter": ctx.adapter, "scorers": (ctx.config or {}).get("scorers")})]
    if ctx.adapter == "harbor":
        if not ctx.config_path:
            missing.append("task.toml")
        if not ctx.instruction_path and not ctx.steps:
            missing.append("instruction.md")
        entries = harbor_adapter.verifier_entrypoints(ctx)
        if not entries:
            missing.append("tests/test.sh (or test.bat/verifier.py)")
        env_cfg = (ctx.config.get("environment") or {}) if isinstance(ctx.config.get("environment"), dict) else {}
        if not ctx.environment_dir and not env_cfg.get("docker_image"):
            missing.append("environment/ (or [environment].docker_image)")
    else:
        if not ctx.tests_dir and not ctx.solution_dir:
            missing.append("tests/ or solution/")
        if not ctx.dockerfile_path and not ctx.environment_dir:
            missing.append("Dockerfile / environment/")
    if missing:
        return [finding(EC001, Status.FAIL, f"Missing required task components: {', '.join(missing)}",
                        evidence={"missing": missing, "adapter": ctx.adapter})]
    return [passed(EC001, f"Recognised {ctx.adapter} task '{ctx.task_name}' with required components present.",
                   evidence={"adapter": ctx.adapter, "files": len(ctx.files)})]


@check(EC002)
def check_instruction(c: CheckContext) -> list:
    ctx = c.task
    if not ctx.instruction_path and ctx.steps:
        issues = []
        checked = 0
        for step in ctx.steps:
            rel = step.get("instruction")
            if not rel:
                issues.append(f"step '{step['name']}': missing instruction.md")
                continue
            checked += 1
            text = ctx.text(rel) or ""
            if len(text.strip()) < 40:
                issues.append(f"step '{step['name']}': instruction shorter than 40 characters")
            if re.search(r"(?i)\b(TODO|TBD|Lorem ipsum|placeholder)\b", text):
                issues.append(f"step '{step['name']}': instruction contains placeholder text")
        if issues:
            return [finding(EC002, Status.WARN, "; ".join(issues), evidence={"issues": issues, "steps_checked": checked})]
        return [passed(EC002, f"Per-step instructions present and non-trivial for {checked} step(s); no top-level instruction.md (multi-step task).", evidence={"steps_checked": checked})]
    if not ctx.instruction_path:
        if ctx.adapter in ("nemo-gym", "inspect"):
            return [not_applicable(EC002, f"{ctx.adapter} tasks carry prompts in dataset rows / Sample inputs, not instruction.md; prompt content is covered by EC014's dataset handling.")]
        return [not_applicable(EC002, "No top-level instruction.md (multi-step or generic layout); per-step instructions not audited.")]
    text = ctx.text("instruction.md") or ""
    issues = []
    if len(text.strip()) < 40:
        issues.append("instruction is shorter than 40 characters")
    if re.search(r"(?i)\b(TODO|TBD|Lorem ipsum|placeholder)\b", text):
        issues.append("instruction contains placeholder text")
    if issues:
        return [finding(EC002, Status.WARN, "; ".join(issues), path="instruction.md", evidence={"issues": issues})]
    return [passed(EC002, f"instruction.md present ({len(text)} chars, no placeholders).", path="instruction.md")]


@check(EC003)
def check_solution_present(c: CheckContext) -> list:
    ctx = c.task
    entries = harbor_adapter.solution_entrypoints(ctx) if ctx.adapter == "harbor" else (
        [f for f in ctx.files if f.startswith("solution/")])
    if entries:
        return [passed(EC003, f"Reference solution present: {', '.join(entries[:5])}", evidence={"entrypoints": entries})]
    return [finding(EC003, Status.WARN, "No reference solution found; verifier cannot be sanity-checked with a gold run.",
                    severity=Severity.LOW, evidence={"searched": "solution/"})]


@check(EC010)
def check_git_exposed(c: CheckContext) -> list:
    ctx = c.task
    # Files under .git are not enumerated by our walker if huge; also check dirs via known markers
    markers = [f for f in ctx.files if ".git/" in f or "/.git" in f or f.startswith(".git") or "/.git" in ("/" + f)]
    if ctx.build_context is not None:
        ctx_rel = ctx.build_context.relative_to(ctx.root).as_posix() if ctx.build_context != ctx.root else ""
        in_context = [f for f in markers if (ctx_rel == "" or f.startswith(ctx_rel + "/") or f == ctx_rel)]
    else:
        in_context = markers
    ctx_prefix = ""
    if ctx.build_context is not None and ctx.build_context != ctx.root:
        ctx_prefix = ctx.build_context.relative_to(ctx.root).as_posix() + "/"
    ignored = [f for f in in_context if dockerignore_match(f[len(ctx_prefix):] if ctx_prefix and f.startswith(ctx_prefix) else f, ctx.dockerignore_patterns)]
    exposed = [f for f in in_context if f not in ignored]
    if exposed:
        return [finding(EC010, Status.FAIL,
                        f".git metadata is inside the Docker build context and not excluded by .dockerignore ({len(exposed)} files, e.g. {exposed[0]}). Git history may contain reference material.",
                        path=exposed[0], evidence={"examples": exposed[:10], "dockerignore_checked": bool(ctx.dockerignore_patterns)},
                        confidence=Confidence.MEDIUM)]
    if markers and ignored:
        return [passed(EC010, ".git exists in the source tree but is excluded from the build context by .dockerignore.",
                       evidence={"excluded_examples": ignored[:5]})]
    if (ctx.root / ".git").exists():
        return [passed(EC010, "A .git directory exists at the task root but no .git files are inside the build context; agent exposure not established statically.",
                       evidence={"note": "root .git outside build context"})]
    return [passed(EC010, "No .git metadata found in the task bundle.")]


def _copied_into_image(ctx) -> list[dict]:
    """Analyse COPY/ADD: return list of {source, dest, line, instr}."""
    out: list = []
    if ctx.dockerfile is None:
        return out
    for instr in ctx.dockerfile.find("COPY", "ADD"):
        sources, dest = copy_sources(instr)
        for s in sources:
            out.append({"source": s, "dest": dest or "", "line": instr.line, "instr": instr.name})
    return out


def _context_rel(ctx, path_in_context: str) -> str:
    ctx_prefix = ""
    if ctx.build_context is not None and ctx.build_context != ctx.root:
        ctx_prefix = ctx.build_context.relative_to(ctx.root).as_posix() + "/"
    return ctx_prefix + path_in_context.strip("./")


@check(EC011)
def check_solution_in_image(c: CheckContext) -> list:
    ctx = c.task
    findings = []
    copies = _copied_into_image(ctx)
    ctx_prefix = ""
    if ctx.build_context is not None and ctx.build_context != ctx.root:
        ctx_prefix = ctx.build_context.relative_to(ctx.root).as_posix() + "/"
    # 1. solution-like files physically inside the build context
    in_context_solutions = []
    for f in ctx.files:
        if ctx_prefix and not f.startswith(ctx_prefix):
            continue
        rel_in_ctx = f[len(ctx_prefix):] if ctx_prefix else f
        base = f.rsplit("/", 1)[-1]
        if ("solution" in f.split("/") or ANSWER_NAMES.search(base)) and not f.startswith("tests/"):
            if not dockerignore_match(rel_in_ctx, ctx.dockerignore_patterns):
                in_context_solutions.append(f)
    broad_copies = [cp for cp in copies if cp["source"] in (".", "./", "*", "./*", "")]
    if in_context_solutions and (broad_copies or copies):
        cp = (broad_copies or copies)[0]
        findings.append(finding(EC011, Status.FAIL,
                                 f"Reference/answer material inside the build context ({in_context_solutions[0]}) is plausibly copied into the image by '{cp['instr']} {cp['source']}' (Dockerfile line {cp['line']}).",
                                 path="environment/Dockerfile" if ctx.dockerfile_path else None, line=cp["line"],
                                 evidence={"files": in_context_solutions[:10], "copy": cp}, confidence=Confidence.MEDIUM))
    elif in_context_solutions:
        findings.append(finding(EC011, Status.WARN,
                                f"Answer-like files exist inside the build context ({in_context_solutions[0]}) but no COPY/ADD clearly includes them; verify they are not baked into the image.",
                                evidence={"files": in_context_solutions[:10]}, confidence=Confidence.LOW))
    # 2. explicit COPY of solution paths
    for cp in copies:
        src = cp["source"].lstrip("./")
        if "solution" in src.split("/") or ANSWER_NAMES.search(src):
            findings.append(finding(EC011, Status.FAIL,
                                    f"Dockerfile explicitly copies solution/answer material into the image: '{cp['instr']} {cp['source']} {cp['dest']}' (line {cp['line']}).",
                                    line=cp["line"], evidence={"copy": cp}, confidence=Confidence.HIGH))
        if src.startswith("../"):
            findings.append(finding(EC011, Status.WARN,
                                    f"COPY source '{cp['source']}' escapes the build context (line {cp['line']}); Docker rejects this, but it signals an attempt to include external (possibly solution) material.",
                                    line=cp["line"], evidence={"copy": cp}, confidence=Confidence.MEDIUM))
    if findings:
        return findings
    sol = harbor_adapter.solution_entrypoints(ctx) if ctx.adapter == "harbor" else [f for f in ctx.files if f.startswith("solution/")]
    return [passed(EC011, "Reference solution exists outside the build context and no COPY/ADD includes solution material in the image."
                   if sol else "No solution material found in the build context or COPY/ADD instructions.",
                   evidence={"solution_entrypoints": sol, "copies_analysed": len(copies)})]


@check(EC012)
def check_answer_files_visible(c: CheckContext) -> list:
    ctx = c.task
    hits: list = []
    agent_areas = ("environment/",) if ctx.environment_dir else ()
    for f in ctx.files:
        if f.startswith("tests/") or "/tests/" in f or f.startswith("solution/"):
            continue
        if agent_areas and not any(f.startswith(a) for a in agent_areas) and ctx.adapter == "harbor":
            continue
        base = f.rsplit("/", 1)[-1]
        if ANSWER_NAMES.search(base) and base not in ("instruction.md",):
            hits.append(f)
    if hits:
        return [finding(EC012, Status.WARN,
                        f"Answer-like filenames in agent-visible areas: {', '.join(hits[:5])}. If these contain expected outputs/gold material the agent can read them.",
                        path=hits[0], evidence={"files": hits[:20]}, confidence=Confidence.LOW)]
    return [passed(EC012, "No answer/gold/expected-output filenames in agent-visible areas (outside tests/ and solution/).")]


@check(EC013)
def check_secrets(c: CheckContext) -> list:
    ctx = c.task
    hits: list = []
    skip_ext = (".png", ".jpg", ".gif", ".pdf", ".zip", ".lock")
    for f in ctx.files:
        if f.endswith(skip_ext):
            continue
        text = ctx.text(f)
        if not text:
            continue
        for i, line in enumerate(text.splitlines(), 1):
            for pat, label in SECRET_PATTERNS:
                if pat.search(line):
                    if "${" in line:  # host-env reference, not a literal secret
                        continue
                    hits.append({"path": f, "line": i, "kind": label})
                    break
    if hits:
        h = hits[0]
        sev = Severity.HIGH if h["kind"] != "credential assignment" else Severity.MEDIUM
        return [finding(EC013, Status.WARN, f"Possible hard-coded credential ({h['kind']}) at {h['path']}:{h['line']} plus {len(hits)-1} more; review and rotate if real.",
                        severity=sev, path=str(h["path"]), line=int(h["line"]), evidence={"hits": hits[:20]}, confidence=Confidence.LOW)]
    return [passed(EC013, "No hard-coded credential patterns found in text files.")]


@check(EC014)
def check_instruction_leak(c: CheckContext) -> list:
    ctx = c.task
    if ctx.adapter == "nemo-gym" and ctx.dataset_files:
        import json as _json

        leaks = []
        for rel in ctx.dataset_files:
            text = ctx.text(rel) or ""
            for lineno, line in enumerate(text.splitlines(), 1):
                try:
                    row = _json.loads(line)
                except ValueError:
                    continue
                expected = row.get("expected_answer") or row.get("answer") or row.get("target")
                prompt = _json.dumps(row.get("responses_create_params") or row.get("input") or "")
                if isinstance(expected, str) and len(expected) >= 3 and expected in prompt:
                    leaks.append({"dataset": rel, "line": lineno, "expected_answer_in_prompt": expected[:60]})
        if leaks:
            return [finding(EC014, Status.WARN, "Dataset row(s) embed the expected answer inside the agent-visible prompt (responses_create_params/input); the agent can read its own ground truth.",
                            evidence={"leaks": leaks[:10]}, confidence=Confidence.MEDIUM)]
        return [passed(EC014, "No expected_answer/target values found inside agent-visible prompt fields of dataset rows.", evidence={"dataset_files": ctx.dataset_files})]
    if not ctx.instruction_path:
        return [not_applicable(EC014, "No instruction.md to compare against the solution.")]
    instr = ctx.text("instruction.md") or ""
    sol_files = [f for f in ctx.files if f.startswith("solution/") or "/solution/" in f]
    leaked = []
    for f in sol_files:
        sol_text = ctx.text(f)
        if not sol_text:
            continue
        for raw in sol_text.splitlines():
            line = raw.strip()
            if len(line) >= 40 and line in instr and not line.startswith("#"):
                leaked.append({"solution_file": f, "line": line[:120]})
                break
    if leaked:
        return [finding(EC014, Status.WARN, "Instruction contains verbatim long lines from the reference solution; the answer may be disclosed to the agent.",
                        path="instruction.md", evidence={"matches": leaked[:5]}, confidence=Confidence.MEDIUM)]
    return [passed(EC014, "No verbatim solution lines (>=40 chars) found in instruction.md.")]


@check(EC020)
def check_verifier_separation(c: CheckContext) -> list:
    ctx = c.task
    if ctx.adapter != "harbor":
        return [not_applicable(EC020, "Verifier separation mode is a Harbor task.toml concept; generic adapter cannot assess it.")]
    verifier = ctx.config.get("verifier") or {}
    mode = verifier.get("environment_mode") if isinstance(verifier, dict) else None
    has_env = isinstance(verifier, dict) and "environment" in verifier
    if mode == "separate" or has_env:
        return [passed(EC020, "Verifier is configured for a separate environment (verifier.environment_mode='separate'), so agent filesystem state does not carry into verification except via declared artifacts.",
                       evidence={"environment_mode": mode or "implied-separate"})]
    return [finding(EC020, Status.WARN,
                    "Verifier runs in the shared agent environment (Harbor default). Agent processes/filesystem state can influence verification; prefer environment_mode='separate' unless live state must be inspected.",
                    severity=Severity.MEDIUM, evidence={"environment_mode": mode or "shared (default)"}, confidence=Confidence.MEDIUM)]


@check(EC021)
def check_import_shadowing(c: CheckContext) -> list:
    ctx = c.task
    risky: list = []
    for f in ctx.files:
        base = f.rsplit("/", 1)[-1]
        in_tests = f.startswith("tests/") or "/tests/" in f
        if in_tests:
            continue
        if base in SHADOW_MODULES:
            risky.append((f, "auto-imported by Python at startup"))
        elif base == "conftest.py" and (f.startswith("environment/") or ctx.adapter == "generic"):
            risky.append((f, "pytest auto-loads conftest.py from rootdir/parents of collected tests"))
        elif base in ("pytest.ini", "pyproject.toml", "setup.cfg", "tox.ini") and f.startswith("environment/"):
            text = ctx.text(f) or ""
            if "pytest" in text or base == "pytest.ini":
                risky.append((f, "pytest configuration in agent area can alter collection/plugins"))
    if risky:
        f, why = risky[0]
        return [finding(EC021, Status.WARN,
                        f"'{f}' is in an agent-visible area and {why}. If the verifier imports/collects from that path, agent code can alter verification.",
                        path=f, evidence={"files": [r[0] for r in risky], "reason": why}, confidence=Confidence.LOW)]
    return [passed(EC021, "No sitecustomize/usercustomize/conftest/pytest-config shadowing files in agent-visible areas (such files under tests/ are verifier-owned and expected).")]


@check(EC022)
def check_exe_shadowing(c: CheckContext) -> list:
    ctx = c.task
    hits: list = []
    for f in ctx.files:
        if f.startswith("tests/") or "/tests/" in f:
            continue
        base = f.rsplit("/", 1)[-1]
        if base in TOOL_NAMES and (f.startswith("environment/") or ctx.adapter == "generic"):
            hits.append(f)
    if ctx.dockerfile is not None:
        for instr in ctx.dockerfile.find("COPY", "ADD"):
            sources, dest = copy_sources(instr)
            for s in sources:
                if s.rsplit("/", 1)[-1] in TOOL_NAMES and dest and ("/bin/" in dest or dest.endswith("/bin")):
                    hits.append(f"Dockerfile:{instr.line} COPY {s} {dest}")
    if hits:
        return [finding(EC022, Status.WARN,
                        f"Tool-named executables in agent-visible locations could shadow verifier tooling on PATH: {', '.join(hits[:5])}.",
                        evidence={"files": hits[:10]}, confidence=Confidence.LOW)]
    return [passed(EC022, "No tool-named executables (pytest/python/pip/test.sh) in agent-visible areas or copied into bin directories.")]


@check(EC023)
def check_writable_verifier(c: CheckContext) -> list:
    ctx = c.task
    hits: list = []
    texts = []
    if ctx.dockerfile_path:
        texts.append(("environment/Dockerfile" if ctx.environment_dir else "Dockerfile", ctx.text(ctx.dockerfile_path.relative_to(ctx.root).as_posix()) or ""))
    for f in ctx.files:
        if f.endswith((".sh", ".toml", ".yaml", ".yml")) and not f.startswith("tests/"):
            t = ctx.text(f)
            if t:
                texts.append((f, t))
    for path, text in texts:
        for i, line in enumerate(text.splitlines(), 1):
            if re.search(r"chmod\s+(-[a-zA-Z]+\s+)*(777|a\+w|o\+w|ugo\+w)", line) or "privileged = true" in line:
                hits.append({"path": path, "line": i, "text": line.strip()[:160]})
    if hits:
        h = hits[0]
        return [finding(EC023, Status.WARN, f"World-writable permissions declared at {h['path']}:{h['line']} ('{h['text']}'); agent-writable verifier/system paths enable tampering.",
                        path=str(h["path"]), line=int(h["line"]), evidence={"hits": hits[:10]}, confidence=Confidence.MEDIUM)]
    return [passed(EC023, "No chmod 777 / a+w style world-writable declarations outside tests/.")]


@check(EC024)
def check_mounts_privileged(c: CheckContext) -> list:
    ctx = c.task
    hits: list = []
    for f in ctx.files:
        if not f.endswith((".toml", ".yaml", ".yml", ".json")) and "Dockerfile" not in f:
            continue
        text = ctx.text(f)
        if not text:
            continue
        for i, line in enumerate(text.splitlines(), 1):
            low = line.lower()
            if "docker.sock" in low or "/var/run/docker.sock" in low:
                hits.append((f, i, "Docker socket mount"))
            elif re.search(r"privileged\s*[:=]\s*true", low):
                hits.append((f, i, "privileged container"))
            elif re.search(r"cap_add\s*:", low) and "SYS_ADMIN" in line:
                hits.append((f, i, "SYS_ADMIN capability"))
    if hits:
        f, i, why = hits[0]
        return [finding(EC024, Status.FAIL, f"{why} declared at {f}:{i}; this collapses container isolation.",
                        severity=Severity.CRITICAL, path=f, line=i, evidence={"hits": [{"path": a, "line": b, "kind": c} for a, b, c in hits]})]
    return [passed(EC024, "No docker.sock mounts, privileged mode or SYS_ADMIN in task configuration files.")]


@check(EC030)
def check_image_pinning(c: CheckContext) -> list:
    ctx = c.task
    if ctx.dockerfile is None:
        env_cfg = ctx.config.get("environment") or {}
        img = env_cfg.get("docker_image") if isinstance(env_cfg, dict) else None
        if img:
            has_digest, specific = image_ref_pinned(str(img))
            if has_digest:
                return [passed(EC030, f"Prebuilt image '{img}' is digest-pinned.")]
            return [finding(EC030, Status.WARN, f"Prebuilt image '{img}' is not digest-pinned; the image can change silently.",
                            evidence={"image": img})]
        return [not_applicable(EC030, "No Dockerfile or prebuilt image reference to assess.")]
    if not ctx.dockerfile.froms:
        return [finding(EC030, Status.FAIL, "Dockerfile has no FROM instruction.", severity=Severity.MEDIUM)]
    bad: list[dict] = []
    for instr in ctx.dockerfile.froms:
        toks = [t for t in instr.tokens() if not t.startswith("--")]
        if not toks:
            continue
        ref = toks[0]
        if ref in ("scratch",) or "$" in ref:
            continue
        has_digest, specific = image_ref_pinned(ref)
        if not has_digest:
            bad.append({"image": ref, "line": instr.line, "specific_tag": specific})
    if bad:
        b = bad[0]
        sev = Severity.MEDIUM if b["specific_tag"] else Severity.HIGH
        return [finding(EC030, Status.WARN, f"Base image '{b['image']}' (line {b['line']}) is not pinned to a sha256 digest"
                        + ("" if b["specific_tag"] else " and uses a floating/absent tag") + "; builds are not fully reproducible.",
                        severity=sev, path=(ctx.dockerfile_path.relative_to(ctx.root).as_posix() if ctx.dockerfile_path else None), line=int(b["line"]), evidence={"unpinned": bad})]
    return [passed(EC030, "All base images are pinned to sha256 digests.")]


@check(EC031)
def check_root_user(c: CheckContext) -> list:
    ctx = c.task
    if ctx.dockerfile is None:
        return [not_applicable(EC031, "No Dockerfile to assess for USER.")]
    users = ctx.dockerfile.find("USER")
    if not users:
        return [finding(EC031, Status.WARN, "Dockerfile sets no USER; the container defaults to root. Consider a non-root agent user.",
                        severity=Severity.LOW, evidence={"user_instructions": 0})]
    last = users[-1]
    val = last.args.strip().split(":")[0]
    if val in ("root", "0"):
        return [finding(EC031, Status.WARN, f"Final USER is root (line {last.line}); hardening opportunity, not by itself a benchmark-integrity failure.",
                        severity=Severity.LOW, path=(ctx.dockerfile_path.relative_to(ctx.root).as_posix() if ctx.dockerfile_path else None), line=last.line, evidence={"user": val})]
    return [passed(EC031, f"Final USER is non-root ('{val}').", evidence={"user": val})]


@check(EC032)
def check_dangerous_dockerfile(c: CheckContext) -> list:
    ctx = c.task
    if ctx.dockerfile is None:
        return [not_applicable(EC032, "No Dockerfile to assess.")]
    hits: list = []
    for instr in ctx.dockerfile.instructions:
        if instr.name == "ADD" and re.search(r"https?://", instr.args):
            hits.append((instr.line, "remote ADD " + instr.args[:80]))
        if instr.name == "RUN" and re.search(r"(curl|wget)\b[^|]*\|\s*(sudo\s+)?(ba)?sh\b", instr.args):
            hits.append((instr.line, "pipe-to-shell install: " + instr.args[:100]))
        if instr.name == "RUN" and re.search(r"\bapt-get\b", instr.args) and "--allow-unauthenticated" in instr.args:
            hits.append((instr.line, "apt-get --allow-unauthenticated"))
    if hits:
        line, what = hits[0]
        return [finding(EC032, Status.WARN, f"Dangerous build pattern at Dockerfile line {line}: {what}. Remote code executed at build time is unreviewed and unpinned.",
                        severity=Severity.HIGH, path=(ctx.dockerfile_path.relative_to(ctx.root).as_posix() if ctx.dockerfile_path else None), line=line, evidence={"hits": [{"line": a, "pattern": b} for a, b in hits]})]
    return [passed(EC032, "No remote ADD, pipe-to-shell or unauthenticated package installs in the Dockerfile.")]


@check(EC033)
def check_network(c: CheckContext) -> list:
    ctx = c.task
    if ctx.adapter != "harbor":
        return [not_applicable(EC033, "Network policy declaration is framework-specific; generic adapter cannot assess it.")]
    env_cfg = ctx.config.get("environment") or {}
    if not isinstance(env_cfg, dict):
        env_cfg = {}
    mode = env_cfg.get("network_mode")
    allowed = env_cfg.get("allowed_hosts")
    if mode == "no-network":
        return [passed(EC033, "Network mode is 'no-network' for the agent environment.", evidence={"network_mode": mode})]
    if mode == "allowlist":
        return [passed(EC033, f"Network mode is 'allowlist' (hosts: {allowed}).", evidence={"network_mode": mode, "allowed_hosts": allowed})]
    if mode == "public":
        return [finding(EC033, Status.WARN, "Network mode is explicitly 'public': the agent has unrestricted egress and could retrieve answers or external help.",
                        evidence={"network_mode": mode}, confidence=Confidence.HIGH)]
    return [finding(EC033, Status.WARN, "No [environment] network_mode declared; Harbor defaults to public network. Declare no-network/allowlist unless public access is required.",
                    severity=Severity.LOW, evidence={"network_mode": None, "default": "public"}, confidence=Confidence.HIGH)]


def _dependency_texts(ctx):
    for f in ctx.files:
        base = f.rsplit("/", 1)[-1]
        if base in ("requirements.txt", "requirements-dev.txt", "Pipfile", "pyproject.toml", "setup.py", "setup.cfg") or f.endswith("Dockerfile"):
            t = ctx.text(f)
            if t is not None:
                yield f, t


@check(EC040)
def check_dependencies(c: CheckContext) -> list:
    ctx = c.task
    unpinned: list[dict] = []
    has_lock = any(f.rsplit("/", 1)[-1] in ("uv.lock", "poetry.lock", "Pipfile.lock", "requirements.lock") or f.endswith(".lock")
                   for f in ctx.files)
    for f, text in _dependency_texts(ctx):
        for i, line in enumerate(text.splitlines(), 1):
            s = line.strip()
            if f.endswith("Dockerfile"):
                m = re.search(r"pip3?\s+install\s+(.+)", s)
                if m:
                    for tok in m.group(1).split():
                        if tok.startswith("-") or tok in ("pip", "\\"):
                            continue
                        if "==" not in tok and ">=" not in tok and tok not in ("--upgrade",):
                            unpinned.append({"path": f, "line": i, "package": tok.strip("'\"")})
            elif f.endswith("requirements.txt") or f.endswith("requirements-dev.txt"):
                if s and not s.startswith(("#", "-")) and "==" not in s and "@" not in s:
                    unpinned.append({"path": f, "line": i, "package": s.split(";")[0][:60]})
    if unpinned:
        return [finding(EC040, Status.WARN,
                        f"{len(unpinned)} unpinned Python dependencies (e.g. '{unpinned[0]['package']}' at {unpinned[0]['path']}:{unpinned[0]['line']}); the environment can drift silently."
                        + ("" if has_lock else " No lockfile found."),
                        evidence={"unpinned": unpinned[:20], "lockfile_present": has_lock}, confidence=Confidence.MEDIUM)]
    if has_lock:
        return [passed(EC040, "Dependencies are pinned and a lockfile is present.", evidence={"lockfile_present": True})]
    return [passed(EC040, "No unpinned pip/requirements entries detected.", evidence={"lockfile_present": has_lock})]


@check(EC041)
def check_downloads(c: CheckContext) -> list:
    ctx = c.task
    hits: list = []
    for f in ctx.files:
        if not (f.endswith((".sh", "Dockerfile", ".py", ".toml")) or "Dockerfile" in f):
            continue
        text = ctx.text(f)
        if not text:
            continue
        for i, line in enumerate(text.splitlines(), 1):
            if re.search(r"git\s+clone\s", line) and not re.search(r"(--branch|--depth|checkout\s+[0-9a-f]{40})", line):
                # clone followed by checkout in same file counts as pinned; checked coarsely below
                if "checkout" not in text:
                    hits.append({"path": f, "line": i, "kind": "git clone without pinned commit/branch", "text": line.strip()[:120]})
            if re.search(r"(curl|wget)\s+.*https?://", line) and "sha256" not in text and "checksum" not in text.lower():
                if "|" not in line:  # pipe-to-shell handled by EC032
                    hits.append({"path": f, "line": i, "kind": "download without checksum verification in file", "text": line.strip()[:120]})
    if hits:
        h = hits[0]
        return [finding(EC041, Status.WARN, f"Unpinned/unverified external download at {h['path']}:{h['line']} ({h['kind']}).",
                        path=h["path"], line=h["line"], evidence={"hits": hits[:10]}, confidence=Confidence.LOW)]
    return [passed(EC041, "No unpinned git clones or unverified downloads detected.")]


@check(EC050)
def check_verifier_exists(c: CheckContext) -> list:
    ctx = c.task
    entries = harbor_adapter.verifier_entrypoints(ctx) if ctx.adapter == "harbor" else _verifier_files(ctx)[:5]
    if not entries:
        return [finding(EC050, Status.FAIL, "No verifier/scorer entrypoint found (Harbor: tests/test.sh|test.bat|verifier.py; NeMo Gym: verifier.py; Inspect: @task file with scorer=).",
                        severity=Severity.CRITICAL, evidence={"searched": "tests/, verifier.py, @task files"})]
    empty = [e for e in entries if not (ctx.text(e) or "").strip()]
    substantive = [e for e in entries if e not in empty]
    if empty and not substantive:
        return [finding(EC050, Status.FAIL, f"Verifier entrypoint(s) are empty: {', '.join(empty)}.", severity=Severity.CRITICAL, evidence={"empty": empty})]
    extra = f" (also empty: {', '.join(empty)})" if empty else ""
    return [passed(EC050, f"Verifier present and non-empty: {', '.join(substantive[:3])}{extra}", evidence={"entrypoints": entries})]


@check(EC051)
def check_reward_production(c: CheckContext) -> list:
    ctx = c.task
    if ctx.adapter == "nemo-gym":
        for rel in ctx.verifier_paths:
            text = ctx.text(rel) or ""
            try:
                tree = ast.parse(text)
            except SyntaxError:
                continue
            funcs = [n.name for n in ast.walk(tree) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))]
            if "verify" in funcs:
                return [passed(EC051, f"NeMo Gym Python verifier '{rel}' defines verify(), which returns the reward directly (no reward file needed).", evidence={"verifier": rel})]
        return [finding(EC051, Status.FAIL, "No verify() function found in the NeMo Gym verifier; Gym will score rows 0 / mask them.", severity=Severity.HIGH, evidence={"verifier_paths": ctx.verifier_paths})]
    if ctx.adapter == "inspect":
        scorers = (ctx.config or {}).get("scorers") or []
        if scorers:
            return [passed(EC051, f"Inspect scorer(s) declared ({', '.join(scorers)}); scorers return Score values directly, no reward file applies.", evidence={"scorers": scorers})]
        return [finding(EC051, Status.WARN, "No scorer= detected in the Inspect @task file; scoring may be implicit or missing.", severity=Severity.MEDIUM, evidence={"task_files": ctx.verifier_paths})]
    if ctx.adapter != "harbor":
        return [not_applicable(EC051, "Reward-file contract is Harbor-specific (/logs/verifier/reward.txt|json).")]
    entries = harbor_adapter.verifier_entrypoints(ctx)
    if not entries:
        return [finding(EC051, Status.FAIL, "No verifier exists, so no reward can be produced.", severity=Severity.CRITICAL)]
    mentions = []
    for e in entries:
        t = ctx.text(e) or ""
        if "reward.txt" in t or "reward.json" in t or "/logs/verifier" in t:
            mentions.append(e)
    # helpers in tests/ may write the reward on behalf of test.sh
    helper_mentions = [f for f, t in _verifier_texts(ctx) if "reward.txt" in t or "reward.json" in t]
    if mentions or helper_mentions:
        return [passed(EC051, f"Verifier code writes the Harbor reward file (found in {', '.join(list(dict.fromkeys(mentions + helper_mentions))[:3])}).",
                       evidence={"reward_writers": list(dict.fromkeys(mentions + helper_mentions))[:5]})]
    py_entries = [e for e in entries if e.endswith("verifier.py")]
    if py_entries:
        return [passed(EC051, "Python verifier (verifier.py) returns the reward directly; no reward file required under NeMo Gym/Harbor python-verifier conventions.",
                       evidence={"entrypoints": py_entries})]
    return [finding(EC051, Status.FAIL, "Verifier never mentions /logs/verifier/reward.txt or reward.json; Harbor will score every run 0 or mask it.",
                    severity=Severity.HIGH, evidence={"entrypoints": entries})]


def _python_verifier_analysis(ctx) -> dict:
    info: dict = {"asserts": 0, "test_funcs": 0, "empty_test_funcs": [], "assert_true_only": False, "files": []}
    for f, text in _verifier_texts(ctx):
        if not f.endswith(".py"):
            continue
        info["files"].append(f)
        try:
            tree = ast.parse(text)
        except SyntaxError:
            continue
        for node in ast.walk(tree):
            if isinstance(node, ast.Assert):
                info["asserts"] += 1
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name.startswith("test"):
                info["test_funcs"] += 1
                asserts_in = [n for n in ast.walk(node) if isinstance(n, ast.Assert)]
                # pytest style also uses plain calls that raise; count assert + raising helpers coarsely
                if not asserts_in:
                    info["empty_test_funcs"].append(f"{f}:{node.name}")
                elif all(isinstance(a.test, ast.Constant) and a.test.value is True for a in asserts_in):
                    info["assert_true_only"] = True
    return info


@check(EC052)
def check_unconditional_success(c: CheckContext) -> list:
    ctx = c.task
    hits: list = []
    for f, text in _verifier_texts(ctx):
        lines = text.splitlines()
        has_condition = bool(re.search(r"(?m)^\s*(if|elif|else|case|pytest|python3?\s|bash\s|\[|test\s|! )", text))
        for i, line in enumerate(lines, 1):
            s = line.strip()
            if re.search(r"echo\s+\"?1(\.0)?\"?\s*>\s*\S*reward\.txt", s) and not has_condition:
                hits.append({"path": f, "line": i, "pattern": "unconditional 'echo 1 > reward.txt'"})
            if re.search(r"sys\.exit\(0\)|exit\(0\)|return\s+1(\.0)?\s*$", s) and f.endswith("verifier.py"):
                # only suspicious if no assert in file
                if "assert" not in text:
                    hits.append({"path": f, "line": i, "pattern": "verifier returns success without assertions"})
            if re.match(r"assert\s+True\b", s):
                hits.append({"path": f, "line": i, "pattern": "assert True"})
    analysis = _python_verifier_analysis(ctx)
    if analysis["assert_true_only"] and analysis["asserts"] <= 1:
        hits.append({"path": analysis["files"][0] if analysis["files"] else "tests/", "line": None, "pattern": "only assertion is 'assert True'"})
    if hits:
        h = hits[0]
        return [finding(EC052, Status.FAIL, f"Possible unconditional-success path in verifier: {h['pattern']} at {h['path']}"
                        + (f":{h['line']}" if h["line"] else "") + ". Confirm manually; if real, any submission passes.",
                        severity=Severity.CRITICAL, path=str(h["path"]), line=int(h["line"]), evidence={"hits": hits[:10]}, confidence=Confidence.MEDIUM)]
    return [passed(EC052, "No unconditional-success patterns (bare echo 1, assert True only, success-without-assert) detected in the verifier.")] if _verifier_files(ctx) else [not_applicable(EC052, "No verifier files to analyse.")]


@check(EC053)
def check_assertion_strength(c: CheckContext) -> list:
    ctx = c.task
    if not _verifier_files(ctx):
        return [not_applicable(EC053, "No verifier files to analyse.")]
    analysis = _python_verifier_analysis(ctx)
    shell_text = "\n".join(t for _f, t in _verifier_texts(ctx))
    shell_checks = len(re.findall(r"(?m)(diff\s|cmp\s|\[\s|test\s|grep\s+-|==|pytest)", shell_text))
    total_signals = analysis["asserts"] + shell_checks
    if analysis["assert_true_only"]:
        return [finding(EC053, Status.WARN, "The only Python assertion(s) are 'assert True'; the verifier cannot reject incorrect solutions.", severity=Severity.HIGH, evidence={"python": analysis}, confidence=Confidence.MEDIUM)]
    weak_only = bool(re.search(r"os\.path\.exists|Path\(.*\)\.exists\(\)|\[\s+-f\s", shell_text)) and analysis["asserts"] <= 1 and shell_checks <= 1
    if analysis["empty_test_funcs"] and analysis["asserts"] == 0:
        return [finding(EC053, Status.FAIL, f"Python test functions contain no assertions (e.g. {analysis['empty_test_funcs'][0]}); they cannot reject incorrect solutions.",
                        severity=Severity.HIGH, evidence=analysis, confidence=Confidence.MEDIUM)]
    if weak_only:
        return [finding(EC053, Status.WARN, "Verifier appears to check mainly file existence; existence checks accept incorrect content (a known benchmark flaw pattern).",
                        severity=Severity.HIGH, evidence={"python": analysis, "shell_signals": shell_checks}, confidence=Confidence.LOW)]
    if total_signals == 0:
        return [finding(EC053, Status.WARN, "No assertions or comparison operations detected in the verifier; its ability to reject incorrect solutions is doubtful.",
                        severity=Severity.HIGH, evidence={"python": analysis, "shell_signals": shell_checks}, confidence=Confidence.LOW)]
    return [passed(EC053, f"Verifier contains substantive check signals (python asserts: {analysis['asserts']}, shell comparisons: {shell_checks}, test functions: {analysis['test_funcs']}).",
                   evidence={"python_asserts": analysis["asserts"], "shell_signals": shell_checks, "test_funcs": analysis["test_funcs"]})]


@check(EC054)
def check_self_reported_reward(c: CheckContext) -> list:
    ctx = c.task
    hits: list = []
    for f, text in _verifier_texts(ctx):
        for i, line in enumerate(text.splitlines(), 1):
            if re.search(r"cat\s+\S*(reward|score|result)\.(txt|json)", line) and "logs/verifier" not in line:
                hits.append({"path": f, "line": i, "text": line.strip()[:140]})
            if re.search(r"(reward|score)\s*=\s*(float|int)\(\s*(open|Path)\(", line):
                hits.append({"path": f, "line": i, "text": line.strip()[:140]})
    if hits:
        h = hits[0]
        return [finding(EC054, Status.WARN, f"Verifier appears to read a reward/score value from a file at {h['path']}:{h['line']} ('{h['text']}'); if that file is agent-writable, the agent can report its own grade. Verify the source is verifier-controlled and validated.",
                        severity=Severity.HIGH, path=str(h["path"]), line=int(h["line"]), evidence={"hits": hits[:10]}, confidence=Confidence.LOW)]
    return [passed(EC054, "Verifier does not obviously read its reward from an agent-produced file.")]


def register_all() -> list[CheckInfo]:
    return [REGISTRY[i][0] for i in
            ["EC001", "EC002", "EC003", "EC004", "EC010", "EC011", "EC012", "EC013", "EC014", "EC020", "EC021", "EC022",
             "EC023", "EC024", "EC030", "EC031", "EC032", "EC033", "EC040", "EC041", "EC050", "EC051", "EC052",
             "EC053", "EC054"]]


# importing this module registers checks; ensure registry import side-effect is explicit
from envcert.checks.base import REGISTRY  # noqa: E402
