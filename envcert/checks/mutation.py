"""Small AST mutation framework for Python solutions (pytest tasks).

Operators: arithmetic swap (+<->-, *<->/), comparison flip (==/!=, </>=),
numeric constant +1, boolean flip, return-None.  Each mutant is applied to a
temp copy and the verifier (pytest) is run; a mutant is *rejected* when the
verifier fails, *survived* when it still passes, *invalid* when it does not
parse/apply.  Equivalent mutants cannot be detected automatically — the
report says so and the rate must not be read as proof of correctness.
"""
from __future__ import annotations

import ast
import copy
import shutil
import tempfile
from pathlib import Path

from envcert.runners.local_runner import LocalPythonRunner

ARITH = {ast.Add: ast.Sub, ast.Sub: ast.Add, ast.Mult: ast.Div, ast.Div: ast.Mult}
CMP = {ast.Eq: ast.NotEq, ast.NotEq: ast.Eq, ast.Lt: ast.GtE, ast.Gt: ast.LtE, ast.LtE: ast.Gt, ast.GtE: ast.Lt}


PRINT_ONLY = {"print", "logging.info", "logging.debug", "logger.info", "logger.debug"}


class _Mutator(ast.NodeTransformer):
    def __init__(self, index: int):
        self.index = index
        self.count = -1
        self.applied = ""
        self.possible_equivalent = False
        self._print_depth = 0

    def _mark(self, what: str, lineno: int):
        self.applied = f"{what} (line {lineno})"
        if self._print_depth:
            self.possible_equivalent = True

    def visit_Call(self, node):
        is_print = False
        try:
            name = ast.unparse(node.func)
            is_print = name in PRINT_ONLY or name.endswith(".debug") or name.endswith(".info")
        except Exception:
            pass
        if is_print:
            self._print_depth += 1
            self.generic_visit(node)
            self._print_depth -= 1
            return node
        return self.generic_visit(node) or node

    def _hit(self) -> bool:
        self.count += 1
        return self.count == self.index

    def visit_BinOp(self, node):
        self.generic_visit(node)
        if type(node.op) in ARITH and self._hit():
            self._mark(f"{type(node.op).__name__}->{ARITH[type(node.op)].__name__}", node.lineno)
            node.op = ARITH[type(node.op)]()
        return node

    def visit_Compare(self, node):
        self.generic_visit(node)
        if node.ops and type(node.ops[0]) in CMP and self._hit():
            self._mark(f"compare {type(node.ops[0]).__name__}->{CMP[type(node.ops[0])].__name__}", node.lineno)
            node.ops[0] = CMP[type(node.ops[0])]()
        return node

    def visit_Constant(self, node):
        if isinstance(node.value, str) and node.value:
            if self._hit():
                self._mark(f"string {node.value[:20]!r} -> ''", node.lineno)
                node.value = ""
        elif isinstance(node.value, bool):
            if self._hit():
                self._mark(f"bool {node.value}->{not node.value}", node.lineno)
                node.value = not node.value
        elif isinstance(node.value, (int, float)) and node.value != 0:
            if self._hit():
                self._mark(f"constant {node.value}->{node.value + 1}", node.lineno)
                node.value = node.value + 1
        return node

    def visit_BoolOp(self, node):
        self.generic_visit(node)
        if isinstance(node.op, (ast.And, ast.Or)) and self._hit():
            new = "Or" if isinstance(node.op, ast.And) else "And"
            self._mark(f"boolop -> {new}", node.lineno)
            node.op = ast.Or() if new == "Or" else ast.And()
        return node

    def visit_AugAssign(self, node):
        self.generic_visit(node)
        swap = {ast.Add: ast.Sub, ast.Sub: ast.Add, ast.Mult: ast.Div, ast.Div: ast.Mult}
        if type(node.op) in swap and self._hit():
            self._mark(f"augassign {type(node.op).__name__}->{swap[type(node.op)].__name__}", node.lineno)
            node.op = swap[type(node.op)]()
        return node

    def visit_UnaryOp(self, node):
        self.generic_visit(node)
        if isinstance(node.op, ast.Not) and self._hit():
            self._mark("remove 'not'", node.lineno)
            return node.operand
        if isinstance(node.op, ast.USub) and self._hit():
            self._mark("remove unary '-'", node.lineno)
            return node.operand
        return node

    def visit_Return(self, node):
        self.generic_visit(node)
        if node.value is not None and self._hit():
            self._mark("return -> None", node.lineno)
            node.value = ast.Constant(value=None)
        return node


def _count_sites(tree: ast.AST) -> int:
    n = 0
    for node in ast.walk(tree):
        if isinstance(node, ast.BinOp) and type(node.op) in ARITH:
            n += 1
        elif isinstance(node, ast.Compare) and node.ops and type(node.ops[0]) in CMP:
            n += 1
        elif isinstance(node, ast.Constant) and (isinstance(node.value, bool) or (isinstance(node.value, (int, float)) and node.value != 0)):
            n += 1
        elif isinstance(node, ast.Return) and node.value is not None:
            n += 1
        elif isinstance(node, ast.BoolOp) and isinstance(node.op, (ast.And, ast.Or)):
            n += 1
        elif isinstance(node, ast.AugAssign) and type(node.op) in ARITH:
            n += 1
        elif isinstance(node, ast.UnaryOp) and isinstance(node.op, (ast.Not, ast.USub)):
            n += 1
        elif isinstance(node, ast.Constant) and isinstance(node.value, str) and node.value:
            n += 1
    return n


def _coverage_map(task_root: Path, runner: LocalPythonRunner, timeout: int = 60) -> dict | None:
    """Executed lines per solution filename from a gold run under coverage.py.

    Returns None when coverage.py is unavailable so mutation degrades to the
    pre-coverage behaviour instead of failing.
    """
    import json as _json
    import subprocess
    import sys

    try:
        import coverage  # noqa: F401
    except ImportError:
        return None
    with tempfile.TemporaryDirectory(prefix="envcert-cov-") as td:
        ws = runner.prepare_workspace(task_root, Path(td) / "ws", "gold")
        env = {"PATH": "", "PYTHONDONTWRITEBYTECODE": "1"}
        import os

        env["PATH"] = os.environ.get("PATH", "")
        if os.name == "nt":
            env["SYSTEMROOT"] = os.environ.get("SYSTEMROOT", "")
        try:
            r1 = subprocess.run([sys.executable, "-m", "coverage", "run", "-m", "pytest", "-q", "-p", "no:cacheprovider", "tests"],
                                cwd=str(ws), env=env, capture_output=True, text=True, timeout=timeout)
            if r1.returncode != 0:
                return None
            subprocess.run([sys.executable, "-m", "coverage", "json", "-o", "cov.json"],
                           cwd=str(ws), env=env, capture_output=True, text=True, timeout=timeout)
            data = _json.loads((ws / "cov.json").read_text(encoding="utf-8"))
        except Exception:
            return None
    out: dict[str, set] = {}
    for fname, fdata in (data.get("files") or {}).items():
        out[Path(fname).name] = set(fdata.get("executed_lines") or [])
    return out


def _site_line(applied: str) -> int | None:
    import re

    m = re.search(r"\(line (\d+)\)", applied)
    return int(m.group(1)) if m else None


def run_mutation(task_root: Path, max_mutants: int = 10, timeout: int = 60) -> dict:
    task_root = Path(task_root)
    runner = LocalPythonRunner()
    mutants: list[dict] = []
    eligible = rejected = survived = invalid = 0
    uncovered = 0
    notes = ""
    sol_files = sorted((task_root / "solution").rglob("*.py")) if (task_root / "solution").is_dir() else []
    coverage_map: dict | None = None
    if not sol_files:
        return {"eligible": 0, "rejected": 0, "survived": 0, "invalid": 0, "uncovered": 0, "rejection_rate": None,
                "mutants": [], "notes": "no solution/*.py files", "coverage_used": False}
    coverage_map = _coverage_map(task_root, runner, timeout=timeout)
    # gold must pass first, otherwise mutants are meaningless
    gold = runner.run_task(task_root, "gold", timeout=timeout)
    if not gold.ok:
        return {"eligible": 0, "rejected": 0, "survived": 0, "invalid": 0, "uncovered": 0, "rejection_rate": None,
                "mutants": [], "notes": "gold solution does not pass; mutation skipped", "coverage_used": coverage_map is not None}
    budget = max_mutants
    for sol in sol_files:
        if budget <= 0:
            break
        source = sol.read_text(encoding="utf-8", errors="replace")
        try:
            tree = ast.parse(source)
        except SyntaxError:
            invalid += 1
            continue
        sites = _count_sites(tree)
        for idx in range(sites):
            if budget <= 0:
                break
            mut = _Mutator(idx)
            new_tree = mut.visit(copy.deepcopy(tree))
            if not mut.applied:
                continue
            budget -= 1
            line_no = _site_line(mut.applied)
            if coverage_map is not None and line_no is not None and sol.name in coverage_map and line_no not in coverage_map[sol.name]:
                uncovered += 1
                mutants.append({"file": sol.name, "change": mut.applied, "outcome": "uncovered-inconclusive",
                                "possible_equivalent": mut.possible_equivalent,
                                "note": "mutated line is not executed by the verifier on the gold run (coverage); excluded from the rejection rate"})
                continue
            try:
                mutated = ast.unparse(ast.fix_missing_locations(new_tree))
                ast.parse(mutated)
            except Exception:  # noqa: BLE001
                invalid += 1
                mutants.append({"file": sol.name, "change": mut.applied, "outcome": "invalid"})
                continue
            eligible += 1
            possible_equiv = mut.possible_equivalent
            with tempfile.TemporaryDirectory(prefix="envcert-mut-") as td:
                ws = Path(td) / "ws"
                runner.prepare_workspace(task_root, ws, "gold")
                target = ws / sol.name
                # gold workspace copies solution files flat; overwrite the mutated one
                if not target.exists():  # nested layout fallback
                    shutil.copytree(task_root / "solution", ws / "solution", dirs_exist_ok=True)
                    target = ws / "solution" / sol.name
                target.write_text(mutated, encoding="utf-8")
                result = runner.run_python_verifier(ws, timeout=timeout)
            outcome = "survived" if result.ok else "rejected"
            if outcome == "rejected":
                rejected += 1
            else:
                survived += 1
            mutants.append({"file": sol.name, "change": mut.applied, "outcome": outcome,
                            "possible_equivalent": possible_equiv,
                            "note": "mutation is inside a print/logging call; survival may be equivalent" if possible_equiv else ""})
    rate = (rejected / eligible) if eligible else None
    return {"eligible": eligible, "rejected": rejected, "survived": survived, "invalid": invalid,
            "uncovered": uncovered,
            "rejection_rate": rate, "mutants": mutants, "coverage_used": coverage_map is not None,
            "notes": notes or "equivalent mutants may inflate the survived count; print/logging-only mutants are tagged possible_equivalent; interpret as a signal only"}
