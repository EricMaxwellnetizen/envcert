"""JS/TS solution mutation (node), the JavaScript counterpart of mutation.py.

A small hand-written lexer finds mutation sites outside comments and string
literals: string contents, numeric constants, booleans, comparison,
arithmetic and logical operators.  One site is mutated per run; the task's
``tests/**/*.js|mjs|cjs`` files are executed with node (``tsx``/``ts-node``
for TypeScript when installed).  A mutant is *rejected* when the tests fail,
*survived* when they still pass, *invalid* when it does not parse.  The
rejection rate is a strength signal, never proof of correctness.
"""
from __future__ import annotations

import os
import re
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path

JS_SUFFIXES = (".js", ".mjs", ".cjs")
TS_SUFFIXES = (".ts", ".mts", ".cts")
COPY_IGNORE = (".git", "node_modules", "__pycache__", ".pytest_cache", ".mypy_cache", ".venv")
CMP = {"===": "!==", "!==": "===", "==": "!=", "!=": "==",
       "<": ">=", ">": "<=", "<=": ">", ">=": "<"}
ARITH = {"+": "-", "-": "+", "*": "/", "/": "*", "%": "*"}
LOGIC = {"&&": "||", "||": "&&"}
MULTI = ("===", "!==", "==", "!=", "<=", ">=", "&&", "||", "=>", "++", "--",
         "+=", "-=", "*=", "/=", "%=")
REGEX_PRECEDERS = set("=(:,![&|?{};")


@dataclass
class Site:
    start: int
    end: int
    replacement: str
    description: str


def _looks_like_regex(source: str, i: int) -> bool:
    prev = source[:i].rstrip()
    if not prev:
        return True
    if prev[-1] in REGEX_PRECEDERS:
        return True
    return bool(re.search(r"\b(?:return|typeof|case|delete|void|in|of)\s*$", prev))


def mutation_sites(source: str) -> list[Site]:
    """Return ordered mutation sites outside comments/strings/module specifiers."""
    sites: list[Site] = []
    i, n = 0, len(source)
    while i < n:
        c = source[i]
        if c in "'\"`":
            j = i + 1
            while j < n:
                if source[j] == "\\":
                    j += 2
                    continue
                if source[j] == c:
                    break
                j += 1
            if j >= n:
                break
            content = source[i + 1:j]
            if not (c == "`" and "${" in content):
                back = source[max(0, i - 16):i].rstrip()
                is_module = bool(re.search(r"(?:\bfrom|\bimport|\brequire\s*\()\s*$", back))
                if content and not is_module and not content.startswith(".") \
                        and "/" not in content and content != "use strict":
                    sites.append(Site(i + 1, j, "", f"string {content[:20]!r} -> ''"))
            i = j + 1
            continue
        if c == "/" and i + 1 < n and source[i + 1] == "/":
            j = source.find("\n", i)
            i = n if j == -1 else j + 1
            continue
        if c == "/" and i + 1 < n and source[i + 1] == "*":
            j = source.find("*/", i + 2)
            i = n if j == -1 else j + 2
            continue
        if c.isdigit() and (i == 0 or not (source[i - 1].isalnum() or source[i - 1] in "_$")):
            m = re.match(r"\d+(?:\.\d+)?", source[i:])
            if m:
                token = m.group(0)
                try:
                    new = str(float(token) + 1.0) if "." in token else str(int(token) + 1)
                except ValueError:  # pragma: no cover - regex guarantees numeric
                    new = token
                sites.append(Site(i, i + len(token), new, f"number {token} -> {new}"))
                i += len(token)
                continue
        if c.isalpha() or c in "_$":
            m = re.match(r"[A-Za-z_$][A-Za-z0-9_$]*", source[i:])
            word = m.group(0) if m else c
            if word in ("true", "false"):
                new = "false" if word == "true" else "true"
                sites.append(Site(i, i + len(word), new, f"boolean {word} -> {new}"))
            i += len(word)
            continue
        matched = next((op for op in MULTI if source.startswith(op, i)), None)
        if matched:
            if matched in CMP:
                sites.append(Site(i, i + len(matched), CMP[matched],
                                  f"operator {matched} -> {CMP[matched]}"))
            elif matched in ARITH:
                sites.append(Site(i, i + len(matched), ARITH[matched],
                                  f"operator {matched} -> {ARITH[matched]}"))
            elif matched in LOGIC:
                sites.append(Site(i, i + len(matched), LOGIC[matched],
                                  f"operator {matched} -> {LOGIC[matched]}"))
            i += len(matched)
            continue
        if c in "+-*/%<>":
            if c in "+-" and i + 1 < n and source[i + 1] in "+-=":
                i += 2
                continue
            if c == "/" and _looks_like_regex(source, i):
                j, in_class = i + 1, False
                while j < n:
                    if source[j] == "\\":
                        j += 2
                        continue
                    if source[j] == "[":
                        in_class = True
                    elif source[j] == "]":
                        in_class = False
                    elif source[j] == "/" and not in_class:
                        break
                    j += 1
                i = j + 1
                continue
            replacement = ARITH.get(c)
            if replacement:
                sites.append(Site(i, i + 1, replacement, f"operator {c} -> {replacement}"))
            i += 1
            continue
        i += 1
    return sites


def _node_runner() -> tuple[str | None, str | None]:
    node = shutil.which("node")
    if not node:
        return None, None
    for ts in ("tsx", "ts-node"):
        exe = shutil.which(ts)
        if exe:
            return node, exe
    return node, None


def _test_files(root: Path) -> list[Path]:
    tests = root / "tests"
    if not tests.is_dir():
        return []
    return sorted(p.relative_to(root) for p in tests.rglob("*")
                  if p.is_file() and p.suffix in JS_SUFFIXES + TS_SUFFIXES
                  and "node_modules" not in p.parts)


def _run_tests(ws: Path, test_files: list[Path], node: str, ts_runner: str | None,
               timeout: int) -> tuple[bool, str]:
    env = {"PATH": os.environ.get("PATH", ""), "PYTHONDONTWRITEBYTECODE": "1"}
    if os.name == "nt":
        env["SYSTEMROOT"] = os.environ.get("SYSTEMROOT", "")
    for test in test_files:
        if test.suffix in TS_SUFFIXES:
            if not ts_runner:
                continue
            cmd = [ts_runner, str(test)]
        else:
            cmd = [node, str(test)]
        try:
            proc = subprocess.run(cmd, cwd=str(ws), env=env, capture_output=True, text=True,
                                  timeout=timeout)
        except subprocess.TimeoutExpired:
            return False, f"test timed out after {timeout}s: {test.name}"
        except Exception as exc:  # noqa: BLE001
            return False, f"{type(exc).__name__}: {exc}"
        if proc.returncode != 0:
            tail = ((proc.stdout or "") + (proc.stderr or ""))[-500:]
            return False, f"{test.name}: {tail.strip()}"
    return True, ""


def run_js_mutation(task_root: Path, max_mutants: int = 10, timeout: int = 60) -> dict:
    task_root = Path(task_root)
    node, ts_runner = _node_runner()
    base: dict = {"eligible": 0, "rejected": 0, "survived": 0, "invalid": 0, "uncovered": 0,
                  "errors": 0, "rejection_rate": None, "mutants": [], "coverage_used": False,
                  "language": "js"}
    if not node:
        return {**base, "notes": "node executable not found on PATH",
                "error": "node executable not found on PATH"}
    sol_files = sorted(p for p in (task_root / "solution").rglob("*")
                       if p.is_file() and p.suffix in JS_SUFFIXES + TS_SUFFIXES) \
        if (task_root / "solution").is_dir() else []
    if not sol_files:
        return {**base, "notes": "no solution/*.js|.mjs|.cjs|.ts files"}
    tests = _test_files(task_root)
    if not tests:
        return {**base, "notes": "no tests/**/*.js|.mjs|.cjs|.ts files to run"}
    runnable = [t for t in tests if t.suffix in JS_SUFFIXES or ts_runner]
    if not runnable:
        return {**base, "notes": "TypeScript tests need tsx or ts-node on PATH"}
    mutants: list[dict] = []
    eligible = rejected = survived = invalid = errors = 0
    budget = max_mutants
    with tempfile.TemporaryDirectory(prefix="envicert-jsmut-") as td:
        ws = Path(td) / "ws"
        shutil.copytree(task_root, ws, ignore=shutil.ignore_patterns(*COPY_IGNORE))
        # Gold must pass before mutants mean anything.
        ok, detail = _run_tests(ws, runnable, node, ts_runner, timeout)
        if not ok:
            return {**base, "notes": f"gold solution does not pass: {detail}",
                    "error": detail}
        for sol in sol_files:
            if budget <= 0:
                break
            source = sol.read_text(encoding="utf-8", errors="replace")
            target = ws / sol.relative_to(task_root)
            for site in mutation_sites(source):
                if budget <= 0:
                    break
                mutated = source[:site.start] + site.replacement + source[site.end:]
                budget -= 1
                target.write_text(mutated, encoding="utf-8")
                try:
                    if sol.suffix in JS_SUFFIXES:
                        try:
                            check = subprocess.run([node, "--check", str(target)], capture_output=True,
                                                   text=True, timeout=min(timeout, 30))
                        except Exception:  # noqa: BLE001
                            check = None
                        if check is not None and check.returncode != 0:
                            invalid += 1
                            mutants.append({"file": str(sol.relative_to(task_root)),
                                            "change": site.description, "outcome": "invalid"})
                            continue
                    ok, detail = _run_tests(ws, runnable, node, ts_runner, timeout)
                finally:
                    target.write_text(source, encoding="utf-8")
                if ok:
                    survived += 1
                    mutants.append({"file": str(sol.relative_to(task_root)),
                                    "change": site.description, "outcome": "survived"})
                elif detail.startswith("test timed out") or detail.startswith(
                        ("FileNotFoundError", "PermissionError", "OSError")):
                    # A harness failure is not evidence that the verifier rejected
                    # the mutant; keep it out of the rejection rate.
                    errors += 1
                    mutants.append({"file": str(sol.relative_to(task_root)),
                                    "change": site.description, "outcome": "execution-error",
                                    "note": detail})
                else:
                    rejected += 1
                    eligible += 1
                    mutants.append({"file": str(sol.relative_to(task_root)),
                                    "change": site.description, "outcome": "rejected"})
    # survived mutants are eligible observations too
    eligible += survived
    rate = (rejected / eligible) if eligible else None
    return {"eligible": eligible, "rejected": rejected, "survived": survived, "invalid": invalid,
            "uncovered": 0, "errors": errors, "rejection_rate": rate, "mutants": mutants,
            "coverage_used": False, "language": "js",
            "notes": ("JS/TS mutation is a heuristic strength signal; equivalent mutants may survive "
                      "and mutants in unused code are not executed by the tests")}
