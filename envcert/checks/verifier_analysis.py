"""AST data-flow analysis of Python verifiers.

The regex-only verifier checks could not see the most direct form of
self-grading -- ``return float(open("result.txt").read())`` -- because the
reward is *parsed from agent-controlled content* rather than assigned to a
variable literally named ``reward``.  This module tracks, with the standard
library ``ast`` only, how agent-controlled data flows through a verifier:

- **sources**: file reads (``open()``, ``Path.read_text()``, ``json.load``),
  process environment, ``sys.argv``, stdin/``input()``, subprocess stdout and
  network responses -- all data an agent can influence or fabricate;
- **propagation**: assignments, conversions (``float()``/``int()``/``str()``),
  parsing (``json.loads``), string formatting and container access;
- **sinks**: returning the value, assigning it to a reward/score variable, or
  writing it to a reward file;
- **validation**: a comparison/assertion of the tainted value against an
  expected/gold/reference value inside the same function, which is the
  legitimate pattern (compute-or-compare, never trust).

It also inventories dangerous verifier primitives (``eval``/``exec``,
unsafe deserialisation, ``shell=True``) whose arguments may be
agent-controlled.  Everything is intra-procedural and deliberately
conservative: hits carry the evidence a human needs to confirm them.
"""
from __future__ import annotations

import ast
from dataclasses import dataclass, field

SOURCE_CALLS = {"open", "input", "eval", "exec"}  # eval/exec handled separately too
PARSE_CALLS = {"float", "int"}
EXPECTED_WORDS = ("expected", "gold", "reference", "target", "answer", "correct", "truth")
REWARD_WORDS = ("reward", "score", "grade")
# Paths owned by the verifier/framework, not the agent: RewardKit-style
# projectors legitimately read /logs/verifier/reward.json to re-emit it,
# and verifiers read their own /tests assets.  Reads from these are
# trusted sources, never agent-controlled input.
TRUSTED_PATH_MARKERS = ("/logs/verifier", "/tests/", "tests/", "/verifier/")


def _path_is_trusted(node: ast.AST, trusted_vars: frozenset[str] = frozenset()) -> bool:
    for child in ast.walk(node):
        if isinstance(child, ast.Constant) and isinstance(child.value, str):
            if any(m in child.value.replace("\\", "/") for m in TRUSTED_PATH_MARKERS):
                return True
        if isinstance(child, ast.Name) and child.id in trusted_vars:
            return True
    return False


@dataclass
class FlowHit:
    path: str
    line: int | None
    kind: str
    detail: str
    function: str = ""
    numeric_parse: bool = False
    validated: bool = False
    direct_parse: bool = False  # reward parsed in the same expression that reads it

    def to_dict(self) -> dict:
        return {
            "path": self.path, "line": self.line, "kind": self.kind,
            "detail": self.detail, "function": self.function,
            "numeric_parse": self.numeric_parse, "validated": self.validated,
            "direct_parse": self.direct_parse,
        }


def _contains_direct_parse(node: ast.AST, tainted: set[str], trusted: frozenset[str] = frozenset()) -> bool:
    """float/int applied to an expression that itself performs the read
    (``float(open(f).read())``), as opposed to parsing a value returned by
    a local helper, which may have validated it in between."""
    for child in ast.walk(node):
        if isinstance(child, ast.Call) and _call_name(child) in PARSE_CALLS and child.args:
            arg = child.args[0]
            reads = [n for n in ast.walk(arg)
                     if isinstance(n, ast.Call) and _call_name(n) in ("open", "read_text", "read", "load", "loads")
                     and not (n.args and _path_is_trusted(n.args[0], trusted))]
            if reads:
                return True
    return False


@dataclass
class Analysis:
    self_reported: list[FlowHit] = field(default_factory=list)
    dangerous: list[FlowHit] = field(default_factory=list)
    files_parsed: list[str] = field(default_factory=list)
    syntax_errors: list[str] = field(default_factory=list)


def _call_name(node: ast.Call) -> str:
    fn = node.func
    if isinstance(fn, ast.Name):
        return fn.id
    if isinstance(fn, ast.Attribute):
        return fn.attr
    return ""


def _func_qualname(node: ast.Call) -> str:
    fn = node.func
    if isinstance(fn, ast.Attribute) and isinstance(fn.value, ast.Name):
        return f"{fn.value.id}.{fn.attr}"
    return _call_name(node)


def _is_source_expr(node: ast.AST, tainted: set[str], trusted: frozenset[str] = frozenset()) -> bool:
    """True when the expression reads agent-controlled data."""
    if isinstance(node, ast.Name):
        return node.id in tainted and node.id not in trusted
    if isinstance(node, ast.Subscript):
        base = node.value
        if isinstance(base, ast.Attribute) and base.attr == "environ":
            return True
        if isinstance(base, ast.Name) and base.id == "environ":
            return True
        return _is_source_expr(base, tainted, trusted)
    if isinstance(node, ast.Attribute):
        if node.attr in ("stdout", "stderr", "argv", "stdin"):
            return True
        return _is_source_expr(node.value, tainted, trusted)
    if isinstance(node, ast.Call):
        # Reads from verifier-owned paths (/logs/verifier, /tests) are the
        # verifier reading its own artifacts, not agent input.
        if node.args and _path_is_trusted(node.args[0], trusted):
            return False
        name = _call_name(node)
        qual = _func_qualname(node)
        # os.environ[...] / os.environ.get(...) anywhere inside the call
        if any(isinstance(n, ast.Attribute) and n.attr == "environ" for n in ast.walk(node)):
            return True
        if name in ("open", "input", "getenv", "read_text", "read_bytes", "read", "readline",
                    "readlines", "load", "loads", "reader", "DictReader", "check_output",
                    "getoutput", "urlopen", "request", "get", "post"):
            # json.load / Path.read_text / open().read / subprocess output / env
            if name in ("get", "post") and not qual.startswith(("requests", "urllib")):
                return any(_is_source_expr(a, tainted, trusted) for a in node.args)
            return True
        if name in ("float", "int", "str", "bool", "len", "strip", "split", "decode",
                    "loads", "dumps", "join", "format", "replace", "lower", "upper"):
            return any(_is_source_expr(a, tainted, trusted) for a in node.args) or \
                (isinstance(node.func, ast.Attribute) and _is_source_expr(node.func.value, tainted, trusted))
        return any(_is_source_expr(a, tainted, trusted) for a in node.args) or \
            (isinstance(node.func, ast.Attribute) and _is_source_expr(node.func.value, tainted, trusted))
    if isinstance(node, ast.IfExp):
        # `1.0 if content == expected else 0.0` returns verifier-chosen
        # constants; only the value branches can carry a self-reported reward.
        return _is_source_expr(node.body, tainted, trusted) or _is_source_expr(node.orelse, tainted, trusted)
    if isinstance(node, ast.Compare):
        # A comparison is a verdict the verifier computes, not a value the
        # agent reports; `return content == expected` is legitimate grading.
        return False
    if isinstance(node, (ast.BinOp, ast.BoolOp, ast.UnaryOp, ast.JoinedStr, ast.FormattedValue,
                         ast.List, ast.Tuple, ast.Set, ast.Dict, ast.Starred, ast.Await)):
        return any(_is_source_expr(child, tainted, trusted) for child in ast.iter_child_nodes(node)
                   if isinstance(child, ast.expr))
    return False


def _contains_numeric_parse(node: ast.AST, tainted: set[str], trusted: frozenset[str] = frozenset()) -> bool:
    for child in ast.walk(node):
        if isinstance(child, ast.Call) and _call_name(child) in PARSE_CALLS:
            if any(_is_source_expr(a, tainted, trusted) for a in child.args):
                return True
    return False


def _mentions_expected(node: ast.AST) -> bool:
    for child in ast.walk(node):
        if isinstance(child, ast.Name) and any(w in child.id.lower() for w in EXPECTED_WORDS):
            return True
        if isinstance(child, ast.Constant) and isinstance(child.value, str):
            continue
    return False


def _function_validates(fn: ast.FunctionDef | ast.AsyncFunctionDef, tainted: set[str]) -> bool:
    """A function validates tainted data when it compares/asserts it against
    an expected value (or membership in an expected set) before trusting it."""
    for node in ast.walk(fn):
        if isinstance(node, ast.Compare):
            sides = [node.left, *node.comparators]
            if any(_is_source_expr(s, tainted) for s in sides) and (
                    _mentions_expected(node) or any(isinstance(s, ast.Constant) for s in sides)):
                return True
        if isinstance(node, ast.Assert):
            if _is_source_expr(node.test, tainted) and (
                    _mentions_expected(node) or isinstance(node.test, ast.Compare)):
                return True
    return False


def _tainted_vars(fn: ast.FunctionDef | ast.AsyncFunctionDef) -> tuple[set[str], frozenset[str]]:
    tainted: set[str] = set()
    trusted: set[str] = set()
    assigns: list[ast.Assign | ast.AnnAssign] = [
        n for n in ast.walk(fn) if isinstance(n, (ast.Assign, ast.AnnAssign)) and n.value is not None
    ]
    assigns.sort(key=lambda n: getattr(n, "lineno", 0))
    for _ in range(len(assigns) + 1):
        changed = False
        for node in assigns:
            targets = [n.id for targets in (node.targets if isinstance(node, ast.Assign) else [node.target])
                       for n in ast.walk(targets) if isinstance(n, ast.Name)]
            if _path_is_trusted(node.value, frozenset(trusted)):  # type: ignore[arg-type]
                for name in targets:
                    if name not in trusted:
                        trusted.add(name)
                        changed = True
                continue
            if _is_source_expr(node.value, tainted, frozenset(trusted)):  # type: ignore[arg-type]
                for name in targets:
                    if name not in tainted and name not in trusted:
                        tainted.add(name)
                        changed = True
        if not changed:
            break
    return tainted, frozenset(trusted)


def _flows_through_validator(node: ast.AST, local_funcs: dict[str, bool],
                             tainted: set[str], trusted: frozenset[str]) -> bool:
    """True when agent data passes through a local helper that itself
    contains comparison/assertion logic before reaching the sink -- the
    inter-procedural shape of validation (grade.py-style graders)."""
    for child in ast.walk(node):
        if isinstance(child, ast.Call):
            name = _call_name(child)
            if local_funcs.get(name) and any(_is_source_expr(a, tainted, trusted) for a in child.args):
                return True
    return False


def _analyse_function(path: str, fn: ast.FunctionDef | ast.AsyncFunctionDef,
                      out: Analysis, local_funcs: dict[str, bool] | None = None) -> None:
    local_funcs = local_funcs or {}
    tainted, trusted = _tainted_vars(fn)
    validated = _function_validates(fn, tainted)
    for node in ast.walk(fn):
        if isinstance(node, ast.Return) and node.value is not None and _is_source_expr(node.value, tainted, trusted):
            hit_validated = validated or _flows_through_validator(node.value, local_funcs, tainted, trusted)
            numeric = _contains_numeric_parse(node.value, tainted, trusted)
            # Data-loading helpers return agent data for later comparison;
            # they are not reward sinks.  A return is a self-report sink
            # only when it parses the value into a number (a grade) or the
            # function itself is the grading entrypoint.
            grading_fn = any(w in fn.name.lower() for w in ("verify", "grade", "scor", "reward", "evaluat", "main"))
            if not numeric and not grading_fn:
                continue
            out.self_reported.append(FlowHit(
                path=path, line=node.lineno, kind="return-agent-controlled",
                detail=f"{fn.name}() returns a value derived from agent-controlled input",
                function=fn.name, numeric_parse=numeric, validated=hit_validated, direct_parse=_contains_direct_parse(node.value, tainted, trusted)))
        elif isinstance(node, ast.Assign):
            names = [n.id for targets in node.targets for n in ast.walk(targets) if isinstance(n, ast.Name)]
            if any(any(w in name.lower() for w in REWARD_WORDS) for name in names) \
                    and _is_source_expr(node.value, tainted, trusted):
                out.self_reported.append(FlowHit(
                    path=path, line=node.lineno, kind="assign-agent-controlled-reward",
                    detail=f"reward variable assigned from agent-controlled input in {fn.name}()",
                    function=fn.name, numeric_parse=_contains_numeric_parse(node.value, tainted, trusted),
                    validated=validated or _flows_through_validator(node.value, local_funcs, tainted, trusted),
                    direct_parse=_contains_direct_parse(node.value, tainted, trusted)))
        elif isinstance(node, ast.Call):
            name = _call_name(node)
            if name in ("write", "writelines") and node.args and _is_source_expr(node.args[0], tainted, trusted):
                receiver = node.func.value if isinstance(node.func, ast.Attribute) else None
                recv_text = ast.dump(receiver) if receiver is not None else ""
                if "reward" in recv_text.lower() or not receiver:
                    out.self_reported.append(FlowHit(
                        path=path, line=node.lineno, kind="write-agent-controlled-reward",
                        detail=f"agent-controlled value written out in {fn.name}()",
                        function=fn.name, numeric_parse=_contains_numeric_parse(node.args[0], tainted, trusted), validated=validated, direct_parse=_contains_direct_parse(node.args[0], tainted, trusted)))


def _dangerous_hits(path: str, tree: ast.Module, out: Analysis) -> None:
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        name = _call_name(node)
        qual = _func_qualname(node)
        dynamic = not all(isinstance(a, ast.Constant) for a in node.args)
        if name in ("eval", "exec") and dynamic:
            out.dangerous.append(FlowHit(path, node.lineno, f"{name}-dynamic",
                                         f"{name}() called on a non-constant expression in the verifier"))
        elif qual in ("os.system", "os.popen") or name in ("system", "popen"):
            out.dangerous.append(FlowHit(path, node.lineno, "os-shell",
                                         "verifier shells out via os.system/os.popen"))
        elif name in ("load", "loads") and qual.startswith("pickle"):
            out.dangerous.append(FlowHit(path, node.lineno, "pickle-load",
                                         "verifier unpickles data (arbitrary code execution if agent-controlled)"))
        elif name == "load" and qual.startswith("yaml"):
            safe = any(k.arg == "Loader" and "Safe" in ast.dump(k.value) for k in node.keywords)
            if not safe:
                out.dangerous.append(FlowHit(path, node.lineno, "yaml-unsafe-load",
                                             "yaml.load without SafeLoader in the verifier"))
        elif qual.startswith("subprocess.") or name in ("run", "Popen", "call", "check_output"):
            if any(k.arg == "shell" and isinstance(k.value, ast.Constant) and k.value.value is True
                   for k in node.keywords):
                out.dangerous.append(FlowHit(path, node.lineno, "subprocess-shell-true",
                                             "subprocess called with shell=True in the verifier"))


def analyse_python(files: list[tuple[str, str]]) -> Analysis:
    """Analyse ``(path, source)`` verifier files and return flow findings."""
    out = Analysis()
    for path, text in files:
        try:
            tree = ast.parse(text)
        except SyntaxError:
            out.syntax_errors.append(path)
            continue
        out.files_parsed.append(path)
        _dangerous_hits(path, tree, out)
        local_funcs: dict[str, bool] = {}
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                local_funcs[node.name] = any(isinstance(n, (ast.Compare, ast.Assert)) for n in ast.walk(node))
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                _analyse_function(path, node, out, local_funcs)
    return out
