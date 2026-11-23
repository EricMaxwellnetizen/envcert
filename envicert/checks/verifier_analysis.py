"""AST data-flow analysis of Python verifiers.

The regex-only verifier checks could not see the most direct form of
self-grading -- ``return float(open("result.txt").read())`` -- because the
reward is *parsed from agent-controlled content* rather than assigned to a
variable literally named ``reward``.  This module tracks, with the standard
library ``ast`` only, how agent-controlled data flows through a verifier:

- **sources**: file reads (``open()``, ``Path.read_text()``, ``json.load``),
  process environment, ``sys.argv``, stdin/``input()``, subprocess stdout and
  network responses -- all data an agent can influence or fabricate -- plus
  calls to helper functions that themselves return agent-controlled data;
- **propagation**: assignments, conversions (``float()``/``int()``/``str()``),
  parsing (``json.loads``), string formatting and container access;
- **sinks**: returning the value, assigning it to a reward/score variable, or
  writing it to a reward file;
- **validation**: a comparison/assertion of the tainted value against an
  expected/gold/reference value, either directly or through a helper chain,
  including helpers in other verifier modules (``grader.py`` importing
  ``checks.compare_deep``).

Function summaries (validates / returns-agent-data) are computed across every
analysed file, so validation and source provenance propagate through
``A -> B -> compare`` call chains and across module imports.  Everything is
deliberately conservative: hits carry the evidence a human needs to confirm
them.
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

# AST traversal is the hot path of this module: the same subtree is walked
# many times (per assignment, per fixed-point iteration).  The descendant
# lists are cached per node for the duration of one analysis run; the parsed
# trees stay alive for the whole run, so node ids stay valid.
_WALK_CACHE: dict[int, list[ast.AST]] = {}


def _walk(node: ast.AST) -> list[ast.AST]:
    key = id(node)
    cached = _WALK_CACHE.get(key)
    if cached is None:
        cached = list(ast.walk(node))
        _WALK_CACHE[key] = cached
    return cached


def _path_is_trusted(node: ast.AST, trusted_vars: frozenset[str] = frozenset()) -> bool:
    for child in _walk(node):
        if isinstance(child, ast.Constant) and isinstance(child.value, str):
            if any(m in child.value.replace("\\", "/") for m in TRUSTED_PATH_MARKERS):
                return True
        if isinstance(child, ast.Name) and child.id in trusted_vars:
            return True
    return False


# Absolute paths owned by the agent/workspace rather than the verifier
# framework.  A constant command that references one of these is executing an
# agent-controlled artifact and stays HIGH; an unrelated constant command is
# downgraded to MEDIUM (risky, but not demonstrably agent-influenced).
AGENT_PATH_ROOTS = (
    "/app", "/workspace", "/testbed", "/solution", "/root", "/home",
)


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
    severity: str = "HIGH"  # "HIGH" | "MEDIUM"

    def to_dict(self) -> dict:
        return {
            "path": self.path, "line": self.line, "kind": self.kind,
            "detail": self.detail, "function": self.function,
            "numeric_parse": self.numeric_parse, "validated": self.validated,
            "direct_parse": self.direct_parse, "severity": self.severity,
        }


@dataclass
class _Summary:
    """Cross-file function summaries used to resolve call targets."""

    validates: dict[tuple[str, str], bool] = field(default_factory=dict)
    returns_source: dict[tuple[str, str], bool] = field(default_factory=dict)
    module_of: dict[str, str] = field(default_factory=dict)          # path -> canonical module
    module_lookup: dict[str, str] = field(default_factory=dict)      # import name -> canonical module
    imports: dict[str, dict[str, tuple[str, str]]] = field(default_factory=dict)
    module_aliases: dict[str, dict[str, str]] = field(default_factory=dict)

    def resolve(self, module: str, call: ast.Call) -> tuple[str, str] | None:
        """Resolve a call to a ``(module, function)`` summary key, if known."""
        fn = call.func
        if isinstance(fn, ast.Name):
            imported = self.imports.get(module, {}).get(fn.id)
            if imported is not None:
                return imported
            key = (module, fn.id)
            return key if key in self.validates else None
        if isinstance(fn, ast.Attribute) and isinstance(fn.value, ast.Name):
            alias_mod = self.module_aliases.get(module, {}).get(fn.value.id)
            if alias_mod is not None:
                target = self.module_lookup.get(alias_mod, alias_mod)
                key = (target, fn.attr)
                if key in self.validates:
                    return key
        return None

    def is_source_call(self, module: str, call: ast.Call) -> bool:
        target = self.resolve(module, call)
        return bool(target and self.returns_source.get(target) and not self.validates.get(target))


def _contains_direct_parse(node: ast.AST, tainted: set[str], trusted: frozenset[str] = frozenset(),
                           summary: _Summary | None = None, module: str = "") -> bool:
    """float/int applied to an expression that itself performs the read
    (``float(open(f).read())``), as opposed to parsing a value returned by
    a local helper, which may have validated it in between."""
    for child in _walk(node):
        if isinstance(child, ast.Call) and _call_name(child) in PARSE_CALLS and child.args:
            arg = child.args[0]
            reads = [n for n in _walk(arg)
                     if isinstance(n, ast.Call) and (
                         (_call_name(n) in ("open", "read_text", "read", "load", "loads")
                          and not (n.args and _path_is_trusted(n.args[0], trusted)))
                         or (summary is not None and summary.is_source_call(module, n)))]
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


def _is_source_expr(node: ast.AST, tainted: set[str], trusted: frozenset[str] = frozenset(),
                    summary: _Summary | None = None, module: str = "") -> bool:
    """True when the expression reads agent-controlled data."""
    if isinstance(node, ast.Name):
        return node.id in tainted and node.id not in trusted
    if isinstance(node, ast.Subscript):
        base = node.value
        if isinstance(base, ast.Attribute) and base.attr == "environ":
            return True
        if isinstance(base, ast.Name) and base.id == "environ":
            return True
        return _is_source_expr(base, tainted, trusted, summary, module)
    if isinstance(node, ast.Attribute):
        if node.attr in ("stdout", "stderr", "argv", "stdin"):
            return True
        return _is_source_expr(node.value, tainted, trusted, summary, module)
    if isinstance(node, ast.Call):
        # Reads from verifier-owned paths (/logs/verifier, /tests) are the
        # verifier reading its own artifacts, not agent input.
        if node.args and _path_is_trusted(node.args[0], trusted):
            return False
        name = _call_name(node)
        qual = _func_qualname(node)
        # os.environ[...] / os.environ.get(...) anywhere inside the call
        if any(isinstance(n, ast.Attribute) and n.attr == "environ" for n in _walk(node)):
            return True
        if name in ("open", "input", "getenv", "read_text", "read_bytes", "read", "readline",
                    "readlines", "load", "loads", "reader", "DictReader", "check_output",
                    "getoutput", "urlopen", "request", "get", "post"):
            # json.load / Path.read_text / open().read / subprocess output / env
            if name in ("get", "post") and not qual.startswith(("requests", "urllib")):
                return any(_is_source_expr(a, tainted, trusted, summary, module) for a in node.args)
            return True
        if name in ("float", "int", "str", "bool", "len", "strip", "split", "decode",
                    "loads", "dumps", "join", "format", "replace", "lower", "upper"):
            return any(_is_source_expr(a, tainted, trusted, summary, module) for a in node.args) or \
                (isinstance(node.func, ast.Attribute) and
                 _is_source_expr(node.func.value, tainted, trusted, summary, module))
        # A call to a helper whose summary says it returns agent-controlled
        # data is a source, even when the read happened in another module.
        if summary is not None and summary.is_source_call(module, node):
            return True
        return any(_is_source_expr(a, tainted, trusted, summary, module) for a in node.args) or \
            (isinstance(node.func, ast.Attribute) and
             _is_source_expr(node.func.value, tainted, trusted, summary, module))
    if isinstance(node, ast.IfExp):
        # `1.0 if content == expected else 0.0` returns verifier-chosen
        # constants; only the value branches can carry a self-reported reward.
        return _is_source_expr(node.body, tainted, trusted, summary, module) or \
            _is_source_expr(node.orelse, tainted, trusted, summary, module)
    if isinstance(node, ast.Compare):
        # A comparison is a verdict the verifier computes, not a value the
        # agent reports; `return content == expected` is legitimate grading.
        return False
    if isinstance(node, (ast.BinOp, ast.BoolOp, ast.UnaryOp, ast.JoinedStr, ast.FormattedValue,
                         ast.List, ast.Tuple, ast.Set, ast.Dict, ast.Starred, ast.Await)):
        return any(_is_source_expr(child, tainted, trusted, summary, module) for child in ast.iter_child_nodes(node)
                   if isinstance(child, ast.expr))
    return False


def _contains_numeric_parse(node: ast.AST, tainted: set[str], trusted: frozenset[str] = frozenset(),
                            summary: _Summary | None = None, module: str = "") -> bool:
    for child in _walk(node):
        if isinstance(child, ast.Call) and _call_name(child) in PARSE_CALLS:
            if any(_is_source_expr(a, tainted, trusted, summary, module) for a in child.args):
                return True
    return False


def _mentions_expected(node: ast.AST) -> bool:
    for child in _walk(node):
        if isinstance(child, ast.Name) and any(w in child.id.lower() for w in EXPECTED_WORDS):
            return True
        if isinstance(child, ast.Constant) and isinstance(child.value, str):
            continue
    return False


def _function_validates(fn: ast.FunctionDef | ast.AsyncFunctionDef, tainted: set[str],
                        summary: _Summary | None = None, module: str = "") -> bool:
    """A function validates tainted data when it compares/asserts it against
    an expected value (or membership in an expected set) before trusting it."""
    for node in _walk(fn):
        if isinstance(node, ast.Compare):
            sides = [node.left, *node.comparators]
            if any(_is_source_expr(s, tainted, summary=summary, module=module) for s in sides) and (
                    _mentions_expected(node) or any(isinstance(s, ast.Constant) for s in sides)):
                return True
        if isinstance(node, ast.Assert):
            if _is_source_expr(node.test, tainted, summary=summary, module=module) and (
                    _mentions_expected(node) or isinstance(node.test, ast.Compare)):
                return True
    return False


def _tainted_vars(fn: ast.FunctionDef | ast.AsyncFunctionDef, summary: _Summary | None = None,
                  module: str = "") -> tuple[set[str], frozenset[str]]:
    tainted: set[str] = set()
    trusted: set[str] = set()
    assigns: list[ast.Assign | ast.AnnAssign] = [
        n for n in _walk(fn) if isinstance(n, (ast.Assign, ast.AnnAssign)) and n.value is not None
    ]
    assigns.sort(key=lambda n: getattr(n, "lineno", 0))
    for _ in range(len(assigns) + 1):
        changed = False
        for node in assigns:
            targets = [n.id for targets in (node.targets if isinstance(node, ast.Assign) else [node.target])
                       for n in _walk(targets) if isinstance(n, ast.Name)]
            if _path_is_trusted(node.value, frozenset(trusted)):  # type: ignore[arg-type]
                for name in targets:
                    if name not in trusted:
                        trusted.add(name)
                        changed = True
                continue
            if _is_source_expr(node.value, tainted, frozenset(trusted), summary, module):  # type: ignore[arg-type]
                for name in targets:
                    if name not in tainted and name not in trusted:
                        tainted.add(name)
                        changed = True
        if not changed:
            break
    return tainted, frozenset(trusted)


def _flows_through_validator(node: ast.AST, summary: _Summary | None, module: str,
                             tainted: set[str], trusted: frozenset[str]) -> bool:
    """True when agent data passes through a helper that itself contains
    comparison/assertion logic before reaching the sink -- the
    inter-procedural shape of validation (grade.py-style graders)."""
    for child in _walk(node):
        if isinstance(child, ast.Call):
            target = summary.resolve(module, child) if summary is not None else None
            validates = bool(target and summary and summary.validates.get(target))
            if validates and any(_is_source_expr(a, tainted, trusted, summary, module) for a in child.args):
                return True
    return False


def _analyse_function(path: str, fn: ast.FunctionDef | ast.AsyncFunctionDef,
                      out: Analysis, summary: _Summary | None = None, module: str = "") -> None:
    tainted, trusted = _tainted_vars(fn, summary, module)
    validated = _function_validates(fn, tainted, summary, module)
    # Variables assigned from a validating flow carry that validation to
    # their sinks (`reward = grade(state); return reward`).
    validated_vars: set[str] = set()
    for assign in (n for n in _walk(fn) if isinstance(n, (ast.Assign, ast.AnnAssign)) and n.value is not None):
        if _flows_through_validator(assign.value, summary, module, tainted, trusted):  # type: ignore[arg-type]
            for target in (assign.targets if isinstance(assign, ast.Assign) else [assign.target]):
                validated_vars.update(n.id for n in _walk(target) if isinstance(n, ast.Name))
    for node in _walk(fn):
        if isinstance(node, ast.Return) and node.value is not None and \
                _is_source_expr(node.value, tainted, trusted, summary, module):
            hit_validated = validated or _flows_through_validator(node.value, summary, module, tainted, trusted) \
                or any(isinstance(n, ast.Name) and n.id in validated_vars for n in _walk(node.value))
            numeric = _contains_numeric_parse(node.value, tainted, trusted, summary, module)
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
                function=fn.name, numeric_parse=numeric, validated=hit_validated,
                direct_parse=_contains_direct_parse(node.value, tainted, trusted, summary, module)))
        elif isinstance(node, ast.Assign):
            names = [n.id for targets in node.targets for n in _walk(targets) if isinstance(n, ast.Name)]
            if any(any(w in name.lower() for w in REWARD_WORDS) for name in names) \
                    and _is_source_expr(node.value, tainted, trusted, summary, module):
                out.self_reported.append(FlowHit(
                    path=path, line=node.lineno, kind="assign-agent-controlled-reward",
                    detail=f"reward variable assigned from agent-controlled input in {fn.name}()",
                    function=fn.name, numeric_parse=_contains_numeric_parse(node.value, tainted, trusted, summary, module),
                    validated=validated or _flows_through_validator(node.value, summary, module, tainted, trusted),
                    direct_parse=_contains_direct_parse(node.value, tainted, trusted, summary, module)))
        elif isinstance(node, ast.Call):
            name = _call_name(node)
            if name in ("write", "writelines") and node.args and \
                    _is_source_expr(node.args[0], tainted, trusted, summary, module):
                receiver = node.func.value if isinstance(node.func, ast.Attribute) else None
                recv_text = ast.dump(receiver) if receiver is not None else ""
                if "reward" in recv_text.lower() or not receiver:
                    out.self_reported.append(FlowHit(
                        path=path, line=node.lineno, kind="write-agent-controlled-reward",
                        detail=f"agent-controlled value written out in {fn.name}()",
                        function=fn.name,
                        numeric_parse=_contains_numeric_parse(node.args[0], tainted, trusted, summary, module),
                        validated=validated,
                        direct_parse=_contains_direct_parse(node.args[0], tainted, trusted, summary, module)))


def _constant_string(node: ast.AST) -> str | None:
    """Return the string value if ``node`` is a constant string literal."""
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def _references_agent_path(text: str) -> bool:
    """True if a constant command text references an agent-writable path."""
    low = text.replace("\\", "/")
    return any(root in low for root in AGENT_PATH_ROOTS)


def _dangerous_hits(path: str, tree: ast.Module, out: Analysis) -> None:
    for node in _walk(tree):
        if not isinstance(node, ast.Call):
            continue
        name = _call_name(node)
        qual = _func_qualname(node)
        dynamic = not all(isinstance(a, ast.Constant) for a in node.args)
        if name in ("eval", "exec") and dynamic:
            out.dangerous.append(FlowHit(path, node.lineno, f"{name}-dynamic",
                                         f"{name}() called on a non-constant expression in the verifier"))
        elif qual in ("os.system", "os.popen") or name in ("system", "popen"):
            cmd = _constant_string(node.args[0]) if node.args else None
            if cmd is None:
                out.dangerous.append(FlowHit(path, node.lineno, "os-shell",
                                             "verifier shells out via os.system/os.popen with a non-constant command"))
            elif _references_agent_path(cmd):
                out.dangerous.append(FlowHit(path, node.lineno, "os-shell-agent",
                                             f"constant shell command references an agent-writable path: {cmd[:80]}"))
            else:
                h = FlowHit(path, node.lineno, "os-shell-constant",
                            f"constant shell command (not agent-influenced): {cmd[:80]}")
                h.severity = "MEDIUM"
                out.dangerous.append(h)
        elif name in ("load", "loads") and qual.startswith("pickle"):
            arg = _constant_string(node.args[0]) if node.args else None
            if arg is None or _references_agent_path(arg):
                out.dangerous.append(FlowHit(path, node.lineno, "pickle-load",
                                             "verifier unpickles data (arbitrary code execution if agent-controlled)"))
            else:
                h = FlowHit(path, node.lineno, "pickle-load-constant",
                            "verifier unpickles a constant path not under an agent-writable root")
                h.severity = "MEDIUM"
                out.dangerous.append(h)
        elif name == "load" and qual.startswith("yaml"):
            safe = any(k.arg == "Loader" and "Safe" in ast.dump(k.value) for k in node.keywords)
            if not safe:
                out.dangerous.append(FlowHit(path, node.lineno, "yaml-unsafe-load",
                                             "yaml.load without SafeLoader in the verifier"))
        elif qual.startswith("subprocess.") or name in ("run", "Popen", "call", "check_output"):
            if any(k.arg == "shell" and isinstance(k.value, ast.Constant) and k.value.value is True
                   for k in node.keywords):
                cmd = _constant_string(node.args[0]) if node.args else None
                if cmd is None:
                    out.dangerous.append(FlowHit(path, node.lineno, "subprocess-shell-true",
                                                 "subprocess called with shell=True and a non-constant command"))
                elif _references_agent_path(cmd):
                    out.dangerous.append(FlowHit(path, node.lineno, "subprocess-shell-true-agent",
                                                 f"subprocess shell=True references an agent-writable path: {cmd[:80]}"))
                else:
                    h = FlowHit(path, node.lineno, "subprocess-shell-true-constant",
                                f"subprocess shell=True with a constant command: {cmd[:80]}")
                    h.severity = "MEDIUM"
                    out.dangerous.append(h)


def _module_names(path: str) -> list[str]:
    """Import names a file can be addressed by (stem and dotted path)."""
    clean = path.replace("\\", "/")
    if clean.endswith(".py"):
        clean = clean[:-3]
    dotted = clean.strip("/").replace("/", ".")
    stem = dotted.rsplit(".", 1)[-1]
    return [stem] if stem == dotted else [stem, dotted]


def _collect_imports(tree: ast.Module, module: str, summary: _Summary) -> None:
    for node in _walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                local = alias.asname or alias.name.split(".")[0]
                summary.module_aliases.setdefault(module, {})[local] = alias.name
        elif isinstance(node, ast.ImportFrom):
            base = node.module or ""
            if node.level:
                # Relative import: best-effort, resolve by the final component.
                base = base.rsplit(".", 1)[-1] if base else ""
            for alias in node.names:
                if alias.name == "*":
                    continue
                local = alias.asname or alias.name
                target_mod = summary.module_lookup.get(base, base)
                summary.imports.setdefault(module, {})[local] = (target_mod, alias.name)


def analyse_python(files: list[tuple[str, str]]) -> Analysis:
    """Analyse ``(path, source)`` verifier files and return flow findings.

    Call-graph summaries are built across all supplied files, so validation
    and source provenance propagate through helper chains and module imports
    (``A -> B -> compare``), not only inside one function.
    """
    out = Analysis()
    summary = _Summary()
    _WALK_CACHE.clear()
    parsed: list[tuple[str, ast.Module]] = []
    for path, text in files:
        try:
            tree = ast.parse(text)
        except SyntaxError:
            out.syntax_errors.append(path)
            continue
        parsed.append((path, tree))
        out.files_parsed.append(path)
        module = _module_names(path)[0]
        summary.module_of[path] = module
        for name in _module_names(path):
            summary.module_lookup.setdefault(name, module)

    funcs: dict[tuple[str, str], tuple[str, ast.FunctionDef | ast.AsyncFunctionDef]] = {}
    direct_logic: dict[tuple[str, str], bool] = {}
    calls: dict[tuple[str, str], list[ast.Call]] = {}
    for path, tree in parsed:
        module = summary.module_of[path]
        _collect_imports(tree, module, summary)
        for node in _walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                key = (module, node.name)
                funcs.setdefault(key, (path, node))
                direct_logic[key] = any(isinstance(n, (ast.Compare, ast.Assert)) for n in _walk(node))
                calls[key] = [n for n in _walk(node) if isinstance(n, ast.Call)]

    # Fixed point: validation propagates through the call graph.
    for key in funcs:
        summary.validates[key] = direct_logic.get(key, False)
    for _ in range(len(funcs) + 1):
        changed = False
        for key, call_nodes in calls.items():
            if summary.validates.get(key):
                continue
            for call in call_nodes:
                target = summary.resolve(key[0], call)
                if target is not None and summary.validates.get(target):
                    summary.validates[key] = True
                    changed = True
                    break
        if not changed:
            break

    # Fixed point: helper functions that return agent-controlled data are
    # sources for their callers, across files.
    for _ in range(len(funcs) + 1):
        changed = False
        for key, (_path, fn) in funcs.items():
            if summary.returns_source.get(key) or summary.validates.get(key):
                continue
            tainted, trusted = _tainted_vars(fn, summary, key[0])
            if any(isinstance(n, ast.Return) and n.value is not None and
                   _is_source_expr(n.value, tainted, trusted, summary, key[0]) for n in _walk(fn)):
                summary.returns_source[key] = True
                changed = True
        if not changed:
            break

    for path, tree in parsed:
        _dangerous_hits(path, tree, out)
        module = summary.module_of[path]
        for node in _walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                _analyse_function(path, node, out, summary, module)
    return out
