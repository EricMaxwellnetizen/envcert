"""NVIDIA NeMo Gym adapter.

Verified against docs.nvidia.com/nemo/gym (2026-11): Gym reads tasks in two
forms — Harbor task folders (handled by the Harbor adapter) and *JSONL rows
plus a verifier*: a dataset directory / resources layout where a shared
Python ``verify()`` scores rows, plus ``dataset.toml`` with a ``[gym]`` table
at a dataset root whose root-level ``verifier.py`` grades every single-step
task without its own ``tests/``.  This adapter covers the non-Harbor forms:

- a dataset root with ``dataset.toml`` and/or ``verifier.py`` and task
  subfolders and/or ``*.jsonl`` row files;
- a JSONL dataset file directory whose rows carry
  ``responses_create_params`` (the prompt the agent sees) plus verifier
  fields such as ``expected_answer``.

Row files are data: ``expected_answer``-style fields are verifier-owned
ground truth.  EnvCert checks that they are not *also* embedded in the
agent-visible prompt (see EC014's framework note) and that a ``verify``
implementation exists and is substantive.  Resources Servers that run as
HTTP services are only partially visible statically — the adapter records
that warning.
"""
from __future__ import annotations

import json
from pathlib import Path

from envcert.adapters.base import TaskContext, scan_files
from envcert.adapters.harbor import parse_toml
from envcert.core.errors import InvalidInputError


def is_nemo_gym(root: Path) -> bool:
    if (root / "dataset.toml").is_file() or (root / "verifier.py").is_file():
        return True
    return any(p.suffix == ".jsonl" for p in root.glob("*.jsonl"))


def load(root: Path) -> TaskContext:
    root = root.resolve()
    if not root.is_dir():
        raise InvalidInputError(f"task path is not a directory: {root}")
    ctx = TaskContext(root=root, adapter="nemo-gym", task_name=root.name)
    scan_files(ctx)
    if (root / "dataset.toml").is_file():
        ctx.config_path = root / "dataset.toml"
        ctx.config = parse_toml(root / "dataset.toml")
        dataset = ctx.config.get("dataset") or {}
        if isinstance(dataset, dict) and dataset.get("name"):
            ctx.task_name = str(dataset["name"])
    if (root / "verifier.py").is_file():
        ctx.verifier_paths = ["verifier.py"]
        ctx.tests_dir = root  # verifier lives at dataset root in this layout
    ctx.dataset_files = [f for f in ctx.files if f.endswith(".jsonl")]
    # task subfolders graded by the shared verifier
    sub_tasks = [f for f in ctx.files if f.endswith("task.toml")]
    if sub_tasks:
        ctx.warnings.append(f"dataset contains {len(sub_tasks)} Harbor task subfolder(s); per-folder auditing is available by running envcert on each subfolder (dataset-level checks ran here)")
    if not ctx.verifier_paths:
        ctx.warnings.append("no root verifier.py found; verification may live in a Resources Server (HTTP service), which static analysis can only partially inspect")
    # validate JSONL rows cheaply and record row counts as evidence
    for rel in ctx.dataset_files:
        path = root / rel
        rows, bad = 0, 0
        try:
            for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
                if not line.strip():
                    continue
                rows += 1
                try:
                    json.loads(line)
                except ValueError:
                    bad += 1
        except OSError:
            bad += 1
        ctx.warnings.append(f"dataset file {rel}: {rows} rows, {bad} invalid JSON lines" if bad else f"dataset file {rel}: {rows} rows")
    return ctx
