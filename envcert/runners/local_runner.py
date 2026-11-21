"""Local Python runner — explicit opt-in, weakest isolation.

Runs `python -m pytest` in a *copy* of the task under a temp directory, with a
timeout, a scrubbed environment and bounded output.  It provides NO sandbox:
task code executes with the user's privileges.  It exists so the dynamic and
mutation logic can be exercised on trusted, Python/pytest-style tasks and in
EnvCert's own test-suite.  The CLI requires --execution local-python and the
report records this isolation level honestly.
"""
from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

from envcert.runners.base import Runner, RunnerInfo, RunResult

MAX_OUTPUT = 20000


class LocalPythonRunner(Runner):
    name = "local-python"

    def info(self) -> RunnerInfo:
        return RunnerInfo(name=self.name, available=True,
                          reason="local subprocess execution (no sandbox)",
                          isolation="none: task code runs as the current user in a temp copy; use only on trusted tasks")

    def prepare_workspace(self, task_root: Path, dest: Path, solution_variant: str = "gold") -> Path:
        """Copy tests/ (+ solution for gold) into dest. Variants: gold|noop|empty."""
        dest.mkdir(parents=True, exist_ok=True)
        for name in ("tests",):
            src = task_root / name
            if src.is_dir():
                shutil.copytree(src, dest / name, dirs_exist_ok=True)
        sol = task_root / "solution"
        if solution_variant == "gold" and sol.is_dir():
            for f in sol.rglob("*.py"):
                shutil.copy2(f, dest / f.name)
        elif solution_variant == "noop" and sol.is_dir():
            for f in sol.rglob("*.py"):
                (dest / f.name).write_text("# envcert no-op negative control\n", encoding="utf-8")
        elif solution_variant == "empty":
            pass
        # also copy plain python modules at task root that tests may import
        for f in task_root.glob("*.py"):
            if f.name not in ("conftest.py",):
                shutil.copy2(f, dest / f.name)
        return dest

    def run_python_verifier(self, workdir, timeout: int = 120) -> RunResult:
        workdir = Path(workdir)
        env = {"PATH": os.environ.get("PATH", ""), "SYSTEMROOT": os.environ.get("SYSTEMROOT", ""),
               "TEMP": str(workdir), "TMP": str(workdir), "PYTHONDONTWRITEBYTECODE": "1"}
        if os.name != "nt":
            env["HOME"] = str(workdir)
        start = time.time()
        try:
            proc = subprocess.run(
                [sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider", "tests"],
                cwd=str(workdir), env=env, capture_output=True, text=True, timeout=timeout)
            dur = time.time() - start
            out = (proc.stdout or "")[-MAX_OUTPUT:]
            err = (proc.stderr or "")[-MAX_OUTPUT:]
            return RunResult(ok=proc.returncode == 0, exit_code=proc.returncode, stdout=out, stderr=err,
                             reward=1.0 if proc.returncode == 0 else 0.0, duration_sec=round(dur, 3))
        except subprocess.TimeoutExpired:
            return RunResult(ok=False, error=f"verifier timed out after {timeout}s", duration_sec=float(timeout))
        except Exception as exc:  # noqa: BLE001
            return RunResult(ok=False, error=f"{type(exc).__name__}: {exc}", duration_sec=round(time.time() - start, 3))

    def run_task(self, task_root: Path, solution_variant: str = "gold", timeout: int = 120) -> RunResult:
        with tempfile.TemporaryDirectory(prefix="envcert-run-") as td:
            ws = self.prepare_workspace(task_root, Path(td) / "ws", solution_variant)
            return self.run_python_verifier(ws, timeout=timeout)
