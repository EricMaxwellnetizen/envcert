"""Inspect AI adapter.

Verified against inspect.aisi.org.uk (Tasks / Datasets / Scorers, 2026-11):
an Inspect evaluation is a Python file defining ``@task`` functions that
return ``Task(dataset=..., solver=..., scorer=...)``.  Samples carry
``input`` (shown to the model) and ``target`` (grading ground truth, not
shown as input).  Scorers include exact/includes/match/pattern and
model-graded scorers — the latter are non-deterministic and model-dependent,
which EnvCert flags as a reproducibility limitation rather than a defect.

This adapter statically locates ``@task`` files, records scorer usage, and
maps the task file as the verifier path so the generic verifier-structure
checks apply.  It never imports or executes the eval file.
"""
from __future__ import annotations

import re
from pathlib import Path

from envcert.adapters.base import TaskContext, scan_files
from envcert.core.errors import InvalidInputError

TASK_RE = re.compile(r"from\s+inspect_ai\s+import|import\s+inspect_ai|@task\b")
SCORER_RE = re.compile(r"scorer\s*=\s*([A-Za-z_][\w.]*)")
MODEL_GRADED = ("model_graded_qa", "model_graded_fact", "model_graded")


def find_task_files(root: Path, files: list[str]) -> list[str]:
    out = []
    for rel in files:
        if not rel.endswith(".py"):
            continue
        try:
            text = (root / rel).read_text(encoding="utf-8", errors="replace")[:20000]
        except OSError:
            continue
        if "inspect_ai" in text and ("@task" in text or "Task(" in text):
            out.append(rel)
    return out


def is_inspect(root: Path) -> bool:
    if not root.is_dir():
        return False
    files = [p.relative_to(root).as_posix() for p in root.rglob("*.py") if ".venv" not in p.parts]
    return bool(find_task_files(root, files[:200]))


def load(root: Path) -> TaskContext:
    root = root.resolve()
    if not root.is_dir():
        raise InvalidInputError(f"task path is not a directory: {root}")
    ctx = TaskContext(root=root, adapter="inspect", task_name=root.name)
    scan_files(ctx)
    task_files = find_task_files(root, ctx.files)
    ctx.verifier_paths = task_files
    ctx.dataset_files = [f for f in ctx.files if f.endswith((".jsonl", ".json", ".csv"))]
    if task_files:
        text = ctx.text(task_files[0]) or ""
        scorers = SCORER_RE.findall(text)
        ctx.config = {"scorers": scorers, "task_files": task_files}
        if any(any(s.startswith(m) for m in MODEL_GRADED) for s in scorers):
            ctx.warnings.append("model-graded scorer detected: grading is model-dependent and non-deterministic; results need scorer/model version pinning for reproducibility")
        if not scorers:
            ctx.warnings.append("no scorer= argument detected in the @task file; the Task may rely on a default solver/scorer or compose them elsewhere")
    else:
        ctx.warnings.append("no @task file with inspect_ai imports found; Inspect detection was heuristic")
    ctx.warnings.append("Inspect adapter is static-only: samples' targets are framework-hidden at runtime, so target-leakage verdicts are heuristic")
    return ctx
