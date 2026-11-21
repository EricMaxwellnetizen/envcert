"""Generic adapter for Docker-based task bundles that are not Harbor tasks.

It recognises a root Dockerfile plus tests/ and/or solution/ directories.  It
deliberately reports reduced confidence: framework-specific semantics (where
the verifier runs, what the agent can see) are unknown.
"""
from __future__ import annotations

from pathlib import Path

from envcert.adapters.base import TaskContext, load_dockerfile, scan_files
from envcert.core.errors import InvalidInputError


def load(root: Path) -> TaskContext:
    root = root.resolve()
    if not root.is_dir():
        raise InvalidInputError(f"task path is not a directory: {root}")
    ctx = TaskContext(root=root, adapter="generic", task_name=root.name)
    scan_files(ctx)
    if (root / "instruction.md").is_file():
        ctx.instruction_path = root / "instruction.md"
    if (root / "tests").is_dir():
        ctx.tests_dir = root / "tests"
    if (root / "solution").is_dir():
        ctx.solution_dir = root / "solution"
    if (root / "environment").is_dir():
        ctx.environment_dir = root / "environment"
    if (root / "Dockerfile").is_file():
        load_dockerfile(ctx, "Dockerfile", ".")
    elif (root / "environment" / "Dockerfile").is_file():
        load_dockerfile(ctx, "environment/Dockerfile", "environment")
    ctx.warnings.append("generic adapter: framework semantics unknown; boundary findings are heuristic")
    return ctx


def detect(root: Path) -> str:
    if (root / "task.toml").is_file():
        return "harbor"
    return "generic"
