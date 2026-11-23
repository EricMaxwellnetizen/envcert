"""Deterministic auto-remediation (``envicert fix``).

LLM-driven repair loops rewrite tasks unpredictably; Envicert's fixes are
the opposite: a small set of mechanical, idempotent, diff-reviewable edits
that close exactly the finding they name, applied only with ``--apply``
(the default is a dry-run plan).  Fixes that change task *semantics*
(declaring a network policy, switching the verifier to a separate
environment) are labelled ``needs_review`` so a human confirms the task
still means what it meant.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

from envicert.core.engine import load_task
from envicert.utils.files import dockerignore_match


@dataclass
class Fix:
    check_id: str
    path: str  # task-relative file that will change
    action: str
    needs_review: bool = False
    _apply: object = field(default=None, repr=False)

    def to_dict(self) -> dict:
        return {"check_id": self.check_id, "file": self.path, "action": self.action,
                "needs_review": self.needs_review}


def _dockerignore_fixes(ctx) -> list[Fix]:
    fixes: list[Fix] = []
    if ctx.build_context is None:
        return fixes
    context = ctx.build_context
    context_rel = context.relative_to(ctx.root).as_posix() if context != ctx.root else ""
    ignore_path = context / ".dockerignore"
    needed: list[tuple[str, str]] = []  # (entry, check_id)
    rel_files = []
    for f in ctx.files:
        if context_rel and not f.startswith(context_rel + "/"):
            continue
        rel = f[len(context_rel) + 1:] if context_rel else f
        rel_files.append((f, rel))
    if any(rel.startswith(".git/") or rel == ".git" for _f, rel in rel_files) or (ctx.root / ".git").exists():
        if not dockerignore_match(".git/config", ctx.dockerignore_patterns):
            needed.append((".git", "EC010"))
    for f, rel in rel_files:
        parts = rel.split("/")
        base = parts[-1]
        if ("solution" in parts or re.search(r"(?i)(gold|answer|expected[_-]?output|oracle|solution)", base)) \
                and not f.startswith("tests/") and not dockerignore_match(rel, ctx.dockerignore_patterns):
            needed.append((rel, "EC011"))
    if not needed:
        return fixes
    entries = list(dict.fromkeys(e for e, _c in needed))
    checks = sorted({c for _e, c in needed})

    def apply(ignore_path=ignore_path, entries=entries):
        existing = ignore_path.read_text(encoding="utf-8") if ignore_path.is_file() else ""
        lines = existing.splitlines()
        for entry in entries:
            if entry not in lines:
                lines.append(entry)
        header = "" if existing.strip() else "# Written by envicert fix: keep agent-invisible material out of the image\n"
        ignore_path.write_text(header + "\n".join(lines).rstrip() + "\n", encoding="utf-8")

    rel_display = (context_rel + "/" if context_rel else "") + ".dockerignore"
    fixes.append(Fix(",".join(checks), rel_display,
                     f"add .dockerignore entr{'y' if len(entries) == 1 else 'ies'}: {', '.join(entries)}",
                     _apply=apply))
    return fixes


def _insert_toml_key(text: str, section: str, key: str, value: str) -> str | None:
    """Insert ``key = value`` into ``[section]``; None when already present."""
    if re.search(rf"(?m)^\s*{re.escape(key)}\s*=", text):
        return None
    header = re.compile(rf"(?m)^\[{re.escape(section)}\]\s*$")
    m = header.search(text)
    if m:
        return text[:m.end()] + f'\n{key} = {value}' + text[m.end():]
    sep = "" if text.endswith("\n") else "\n"
    return text + f"{sep}\n[{section}]\n{key} = {value}\n"


def _task_toml_fixes(ctx) -> list[Fix]:
    fixes: list[Fix] = []
    if ctx.adapter != "harbor" or ctx.config_path is None:
        return fixes
    config_rel = ctx.config_path.relative_to(ctx.root).as_posix()
    text = ctx.text(config_rel)
    if text is None:
        return fixes
    # Normalise line endings: writing \n-insertions into CRLF text on Windows
    # would otherwise produce \r\r\n and corrupt the TOML.
    text = text.replace("\r\n", "\n")
    env_cfg = ctx.config.get("environment") or {}
    if isinstance(env_cfg, dict) and not env_cfg.get("network_mode"):
        new_text = _insert_toml_key(text, "environment", "network_mode", '"no-network"')
        if new_text is not None:
            def apply(path=ctx.config_path, content=new_text):
                path.write_text(content, encoding="utf-8")

            fixes.append(Fix("EC033", config_rel,
                             'declare network_mode = "no-network" in [environment] (Harbor currently defaults to public); '
                             "change to \"allowlist\" with allowed_hosts if the task needs specific hosts",
                             needs_review=True, _apply=apply))
            text = new_text
    verifier = ctx.config.get("verifier") or {}
    if isinstance(verifier, dict) and verifier.get("environment_mode") != "separate" and "environment" not in verifier:
        new_text = _insert_toml_key(text, "verifier", "environment_mode", '"separate"')
        if new_text is not None:
            def apply2(path=ctx.config_path, content=new_text):
                path.write_text(content, encoding="utf-8")

            fixes.append(Fix("EC020", config_rel,
                             'set environment_mode = "separate" in [verifier] so agent filesystem state cannot reach the verifier; '
                             "declare [verifier.environment] artifacts if the verifier needs agent outputs",
                             needs_review=True, _apply=apply2))
    return fixes


def plan_fixes(task_path: Path) -> list[Fix]:
    ctx = load_task(Path(task_path), "auto")
    fixes: list[Fix] = []
    fixes.extend(_dockerignore_fixes(ctx))
    fixes.extend(_task_toml_fixes(ctx))
    return fixes


def apply_fixes(fixes: list[Fix]) -> list[Fix]:
    applied = []
    for fix in fixes:
        if fix._apply is not None:
            fix._apply()  # type: ignore[operator]
            applied.append(fix)
    return applied
