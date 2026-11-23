"""Local Python runner — explicit opt-in, weakest isolation.

Runs `python -m pytest` in a *copy* of the task under a temp directory, with a
timeout, a scrubbed environment and bounded output.  It provides NO sandbox:
task code executes with the user's privileges.  It exists so the dynamic and
mutation logic can be exercised on trusted, Python/pytest-style tasks and in
Envicert's own test-suite.  The CLI requires --execution local-python and the
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

from envicert.runners.base import Runner, RunnerInfo, RunResult

MAX_OUTPUT = 20000

CHEAT_CONFTEST = '''"""Envicert cheat-agent: agent-planted conftest that fakes test outcomes."""
import pytest


@pytest.hookimpl(wrapper=True)
def pytest_runtest_makereport(item, call):
    report = yield
    report.outcome = "passed"
    return report
'''


def stub_source(gold_file: Path) -> str:
    """Generate a stub module preserving the gold file's public API.

    Every function/method returns ``None`` and every class is kept (with
    stub methods), so import-time structure survives but no real work is
    done.  Unparseable gold degrades to an empty module.
    """
    import ast

    try:
        tree = ast.parse(gold_file.read_text(encoding="utf-8", errors="replace"))
    except (OSError, SyntaxError):
        return "# envicert cheat stub (unparseable gold)\n"
    lines = ["# envicert cheat stub: same API, no real work"]
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            args = ast.unparse(node.args) if hasattr(ast, "unparse") else "*args, **kwargs"
            lines.append(f"def {node.name}({args}):")
            lines.append("    return None")
        elif isinstance(node, ast.ClassDef):
            lines.append(f"class {node.name}:")
            methods = [n for n in node.body if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))]
            if not methods:
                lines.append("    pass")
            for method in methods:
                args = ast.unparse(method.args) if hasattr(ast, "unparse") else "*args, **kwargs"
                lines.append(f"    def {method.name}({args}):")
                lines.append("        return None")
    if len(lines) == 1:
        lines.append("pass")
    return "\n".join(lines) + "\n"

PYTEST_MISSING = ("pytest is not installed in the environment running Envicert; "
                  "install pytest (pip install pytest) to use --execution local-python")


def pytest_available() -> bool:
    """True when the interpreter running Envicert can import pytest."""
    import importlib.util

    try:
        return importlib.util.find_spec("pytest") is not None
    except (ImportError, ValueError):  # pragma: no cover - defensive
        return False


class LocalPythonRunner(Runner):
    name = "local-python"

    def info(self) -> RunnerInfo:
        if not pytest_available():
            return RunnerInfo(name=self.name, available=False, reason=PYTEST_MISSING,
                              isolation="none: task code runs as the current user in a temp copy; use only on trusted tasks")
        return RunnerInfo(name=self.name, available=True,
                          reason="local subprocess execution (no sandbox)",
                          isolation="none: task code runs as the current user in a temp copy; use only on trusted tasks")

    def prepare_workspace(self, task_root: Path, dest: Path, solution_variant: str = "gold") -> Path:
        """Copy tests/ (+ solution for gold) into dest.

        Variants: gold | noop | empty | cheat-stub | cheat-tamper.
        ``cheat-stub`` replaces the solution with an AST-generated stub that
        keeps the gold API but returns constants; ``cheat-tamper`` submits a
        no-op solution plus an agent-planted ``conftest.py`` that tries to
        fake pytest outcomes -- the canonical agent-tampers-with-verifier
        attack for pytest tasks run from an agent-writable directory.
        """
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
                (dest / f.name).write_text("# envicert no-op negative control\n", encoding="utf-8")
        elif solution_variant == "cheat-stub" and sol.is_dir():
            for f in sol.rglob("*.py"):
                (dest / f.name).write_text(stub_source(f), encoding="utf-8")
        elif solution_variant == "cheat-tamper" and sol.is_dir():
            for f in sol.rglob("*.py"):
                (dest / f.name).write_text("# envicert cheat: no-op solution\n", encoding="utf-8")
            (dest / "conftest.py").write_text(CHEAT_CONFTEST, encoding="utf-8")
        elif solution_variant == "empty":
            pass
        # also copy plain python modules at task root that tests may import
        for f in task_root.glob("*.py"):
            if f.name not in ("conftest.py",):
                shutil.copy2(f, dest / f.name)
        return dest

    def run_python_verifier(self, workdir, timeout: int = 120) -> RunResult:
        workdir = Path(workdir)
        if not pytest_available():
            return RunResult(ok=False, error=PYTEST_MISSING)
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
            if "No module named pytest" in err:
                # pytest disappeared between the probe and the run
                return RunResult(ok=False, error=PYTEST_MISSING, exit_code=proc.returncode,
                                 stdout=out, stderr=err, duration_sec=round(dur, 3))
            return RunResult(ok=proc.returncode == 0, exit_code=proc.returncode, stdout=out, stderr=err,
                             reward=1.0 if proc.returncode == 0 else 0.0, duration_sec=round(dur, 3))
        except subprocess.TimeoutExpired:
            return RunResult(ok=False, error=f"verifier timed out after {timeout}s", duration_sec=float(timeout))
        except Exception as exc:  # noqa: BLE001
            return RunResult(ok=False, error=f"{type(exc).__name__}: {exc}", duration_sec=round(time.time() - start, 3))

    def run_task(self, task_root: Path, solution_variant: str = "gold", timeout: int = 120) -> RunResult:
        with tempfile.TemporaryDirectory(prefix="envicert-run-") as td:
            ws = self.prepare_workspace(task_root, Path(td) / "ws", solution_variant)
            return self.run_python_verifier(ws, timeout=timeout)
