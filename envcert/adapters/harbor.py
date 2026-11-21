"""Harbor adapter.

Verified against Harbor's current docs (docs.harborframework.com, schema 1.4):
a task is a directory with task.toml + instruction.md, environment/ (Dockerfile
or docker-compose.yaml, or [environment].docker_image instead), tests/test.sh
(or test.bat / verifier.py) writing /logs/verifier/reward.txt|json, and an
optional solution/solve.sh.  Multi-step tasks use steps/<name>/ with their own
instruction/tests/solution.  Variations handled: missing environment/ when a
prebuilt docker_image is declared, verifier.py, test.bat, steps/.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any

from envcert.adapters.base import TaskContext, load_dockerfile, scan_files
from envcert.core.errors import InvalidInputError

try:  # Python 3.11+
    import tomllib
except ModuleNotFoundError:  # pragma: no cover
    import tomli as tomllib  # type: ignore[no-redef]


def is_harbor_task(root: Path) -> bool:
    return (root / "task.toml").is_file()


def parse_toml(path: Path) -> dict[str, Any]:
    try:
        with path.open("rb") as fh:
            return tomllib.load(fh)
    except Exception as exc:
        raise InvalidInputError(f"invalid TOML in {path}: {exc}") from exc


def load(root: Path) -> TaskContext:
    root = root.resolve()
    if not root.is_dir():
        raise InvalidInputError(f"task path is not a directory: {root}")
    ctx = TaskContext(root=root, adapter="harbor")
    scan_files(ctx)
    cfg_path = root / "task.toml"
    if cfg_path.is_file():
        ctx.config_path = cfg_path
        raw = cfg_path.read_text(encoding="utf-8", errors="replace")
        import re as _re

        if "{{" in raw or "{%" in raw or _re.search(r"\{[A-Za-z_][A-Za-z0-9_]*\}", raw):
            # Adapter task-templates (e.g. in the Harbor repo) are unrendered
            # Jinja templates, not runnable tasks. Degrade honestly instead
            # of failing TOML parsing.
            ctx.config = {}
            ctx.warnings.append("task.toml appears to be an unrendered template (Jinja placeholders); config-dependent checks are heuristic until the template is rendered")
        else:
            ctx.config = parse_toml(cfg_path)
    task_table = ctx.config.get("task") or {}
    if isinstance(task_table, dict):
        ctx.task_name = str(task_table.get("name") or root.name)
    else:
        ctx.task_name = root.name
    if (root / "instruction.md").is_file():
        ctx.instruction_path = root / "instruction.md"
    elif (root / "steps").is_dir():
        ctx.warnings.append("multi-step task: top-level instruction.md absent; per-step instructions are not individually audited in this version")
    if (root / "tests").is_dir():
        ctx.tests_dir = root / "tests"
    if (root / "solution").is_dir():
        ctx.solution_dir = root / "solution"
    steps_dir = root / "steps"
    if steps_dir.is_dir():
        for step in sorted(p for p in steps_dir.iterdir() if p.is_dir()):
            rel = f"steps/{step.name}"
            ctx.steps.append({
                "name": step.name,
                "instruction": f"{rel}/instruction.md" if (step / "instruction.md").is_file() else None,
                "tests": f"{rel}/tests" if (step / "tests").is_dir() else None,
                "test_entrypoints": [f"{rel}/tests/{n}" for n in ("test.sh", "test.bat", "verifier.py") if (step / "tests" / n).is_file()],
                "solution": f"{rel}/solution" if (step / "solution").is_dir() else None,
            })
    env_dir = root / "environment"
    if env_dir.is_dir():
        ctx.environment_dir = env_dir
        if (env_dir / "Dockerfile").is_file():
            load_dockerfile(ctx, "environment/Dockerfile", "environment")
        elif (env_dir / "docker-compose.yaml").is_file() or (env_dir / "docker-compose.yml").is_file():
            ctx.warnings.append("environment uses docker-compose; Dockerfile-specific checks are limited")
    return ctx


def verifier_entrypoints(ctx: TaskContext) -> list[str]:
    names = ("tests/test.sh", "tests/test.bat", "tests/test.ps1", "tests/verifier.py")
    found = [n for n in names if ctx.has(n)]
    # per-step verifiers
    for f in ctx.files:
        if f.startswith("steps/") and f.rsplit("/", 1)[-1] in ("test.sh", "test.bat", "verifier.py"):
            found.append(f)
    return found


def solution_entrypoints(ctx: TaskContext) -> list[str]:
    names = ("solution/solve.sh", "solution/solve.bat", "solution/solve.ps1", "solution/solve.py", "solution/answer.md")
    found = [n for n in names if ctx.has(n)]
    for f in ctx.files:
        if f.startswith("steps/") and "/solution/" in f:
            found.append(f)
    return found
