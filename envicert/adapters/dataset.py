"""Dataset-file adapter: JSONL / JSON / CSV evaluation & training datasets.

Most evaluation and RLVR/GRPO training data does not live in a task bundle;
it lives in a data file -- SWE-bench-style instance files, NeMo/RLVR JSONL,
OpenAI-style fine-tune/eval JSONL, lm-eval-style exports, promptfoo CSV
exports.  This adapter lets ``envicert check data.jsonl`` (or a directory of
data files) audit that data directly: leaked answers inside prompts,
duplicate and near-duplicate rows, train/test overlap, degenerate labels
and broken rows.  Rows are data, never executed.
"""
from __future__ import annotations

from pathlib import Path

from envicert.adapters.base import TaskContext, scan_files
from envicert.core.errors import InvalidInputError

DATASET_SUFFIXES = (".jsonl", ".json", ".csv", ".parquet")


def is_dataset_path(path: Path) -> bool:
    path = Path(path)
    if path.is_file():
        return path.suffix.lower() in DATASET_SUFFIXES
    if path.is_dir():
        # NeMo Gym directories also hold JSONL rows, but they carry a shared
        # verifier (verifier.py / dataset.toml); those stay with nemo-gym.
        if (path / "task.toml").is_file() or (path / "verifier.py").is_file() or (path / "dataset.toml").is_file():
            return False
        return any(p.suffix.lower() in DATASET_SUFFIXES for p in path.iterdir() if p.is_file())
    return False


def load(root: Path) -> TaskContext:
    root = Path(root)
    if root.is_file():
        if root.suffix.lower() not in DATASET_SUFFIXES:
            raise InvalidInputError(f"not a dataset file (.jsonl/.json/.csv): {root}")
        parent = root.resolve().parent
        ctx = TaskContext(root=parent, adapter="dataset", task_name=root.name)
        ctx.files = [root.name]
        ctx.dataset_files = [root.name]
        ctx.bundle_files = [root.name]
        ctx.warnings.append("dataset adapter: row-level integrity checks only; no task bundle, Dockerfile or verifier was present to audit")
        return ctx
    root = root.resolve()
    if not root.is_dir():
        raise InvalidInputError(f"dataset path is not a file or directory: {root}")
    ctx = TaskContext(root=root, adapter="dataset", task_name=root.name)
    scan_files(ctx)
    ctx.dataset_files = [f for f in ctx.files if f.lower().endswith(DATASET_SUFFIXES)]
    ctx.bundle_files = list(ctx.dataset_files)
    if not ctx.dataset_files:
        raise InvalidInputError(f"no dataset files (.jsonl/.json/.csv) found under {root}")
    ctx.warnings.append("dataset adapter: row-level integrity checks only; no task bundle, Dockerfile or verifier was present to audit")
    return ctx
