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


class _Mutator(ast.NodeTransformer):
    def __init__(self, index: int):
        self.index = index
        self.count = -1
        self.applied = ""

    def _hit(self) -> bool:
        self.count += 1
        return self.count == self.index

    def visit_BinOp(self, node):
        self.generic_visit(node)
        if type(node.op) in ARITH and self._hit():
            self.applied = f"{type(node.op).__name__}->{ARITH[type(node.op)].__name__} (line {node.lineno})"
            node.op = ARITH[type(node.op)]()
        return node

    def visit_Compare(self, node):
        self.generic_visit(node)
        if node.ops and type(node.ops[0]) in CMP and self._hit():
            self.applied = f"compare {type(node.ops[0]).__name__}->{CMP[type(node.ops[0])].__name__} (line {node.lineno})"
            node.ops[0] = CMP[type(node.ops[0])]()
        return node

    def visit_Constant(self, node):
        if isinstance(node.value, bool):
            if self._hit():
                self.applied = f"bool {node.value}->{not node.value} (line {node.lineno})"
                node.value = not node.value
        elif isinstance(node.value, (int, float)) and node.value != 0:
            if self._hit():
                self.applied = f"constant {node.value}->{node.value + 1} (line {node.lineno})"
                node.value = node.value + 1
        return node

    def visit_Return(self, node):
        self.generic_visit(node)
        if node.value is not None and self._hit():
            self.applied = f"return -> None (line {node.lineno})"
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
    return n


def run_mutation(task_root: Path, max_mutants: int = 10, timeout: int = 60) -> dict:
    task_root = Path(task_root)
    runner = LocalPythonRunner()
    mutants: list[dict] = []
    eligible = rejected = survived = invalid = 0
    notes = ""
    sol_files = sorted((task_root / "solution").rglob("*.py")) if (task_root / "solution").is_dir() else []
    if not sol_files:
        return {"eligible": 0, "rejected": 0, "survived": 0, "invalid": 0, "rejection_rate": None,
                "mutants": [], "notes": "no solution/*.py files"}
    # gold must pass first, otherwise mutants are meaningless
    gold = runner.run_task(task_root, "gold", timeout=timeout)
    if not gold.ok:
        return {"eligible": 0, "rejected": 0, "survived": 0, "invalid": 0, "rejection_rate": None,
                "mutants": [], "notes": "gold solution does not pass; mutation skipped"}
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
            try:
                mutated = ast.unparse(ast.fix_missing_locations(new_tree))
                ast.parse(mutated)
            except Exception:  # noqa: BLE001
                invalid += 1
                mutants.append({"file": sol.name, "change": mut.applied, "outcome": "invalid"})
                continue
            eligible += 1
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
            mutants.append({"file": sol.name, "change": mut.applied, "outcome": outcome})
    rate = (rejected / eligible) if eligible else None
    return {"eligible": eligible, "rejected": rejected, "survived": survived, "invalid": invalid,
            "rejection_rate": rate, "mutants": mutants,
            "notes": notes or "equivalent mutants may inflate the survived count; interpret as a signal only"}
