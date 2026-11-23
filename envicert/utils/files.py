from __future__ import annotations

import fnmatch
from pathlib import Path

MAX_TEXT_BYTES = 2_000_000
SKIP_DIRS = {"__pycache__", ".pytest_cache", ".mypy_cache", "node_modules"}


def iter_task_files(root: Path, max_files: int = 5000, stats: dict | None = None):
    """Yield (relative_posix_path, absolute_path, is_symlink) without following dir symlinks.

    When the file cap is reached, ``stats["truncated"]`` is set so callers can
    report that the digest/listing is incomplete instead of silently treating
    the first N files as the whole task.
    """
    root = root.resolve()
    count = 0
    for p in sorted(root.rglob("*")):
        rel_parts = p.relative_to(root).parts
        if any(part in SKIP_DIRS for part in rel_parts):
            continue
        is_link = p.is_symlink()
        if p.is_dir() and not is_link:
            continue
        if p.is_dir():
            continue
        if count >= max_files:
            if stats is not None:
                stats["truncated"] = True
                stats["max_files"] = max_files
            break
        count += 1
        yield p.relative_to(root).as_posix(), p, is_link


def read_text_safe(path: Path, limit: int = MAX_TEXT_BYTES) -> str | None:
    try:
        data = path.read_bytes()[: limit + 1]
    except OSError:
        return None
    if len(data) > limit:
        data = data[:limit]
    if b"\x00" in data[:4096]:
        return None  # binary
    return data.decode("utf-8", errors="replace")


def dockerignore_match(relpath: str, patterns: list[str]) -> bool:
    """Simplified .dockerignore evaluation (supports !, **, *, dir prefixes).

    Docker's semantics are subtle; this is intentionally conservative and is
    only used to decide whether a path is *plausibly* excluded from a build
    context.  Findings based on it state that limitation.
    """
    ignored = False
    rel = relpath.strip("/")
    for raw in patterns:
        pat = raw.strip()
        if not pat or pat.startswith("#"):
            continue
        negate = pat.startswith("!")
        if negate:
            pat = pat[1:]
        pat = pat.strip("/")
        if not pat:
            continue
        matched = _match_one(rel, pat)
        if matched:
            ignored = not negate
    return ignored


def _match_one(rel: str, pat: str) -> bool:
    if fnmatch.fnmatch(rel, pat) or fnmatch.fnmatch(rel, pat + "/*"):
        return True
    # `**/name`, `dir/**`, `**`
    if pat == "**":
        return True
    if pat.startswith("**/") and fnmatch.fnmatch(rel, pat[3:]) or (
        pat.startswith("**/") and any(fnmatch.fnmatch("/".join(rel.split("/")[i:]), pat[3:]) for i in range(len(rel.split("/"))))
    ):
        return True
    if pat.endswith("/**") and (rel == pat[:-3] or rel.startswith(pat[:-3] + "/")):
        return True
    # directory pattern without glob matches everything below it
    if "*" not in pat and "?" not in pat and (rel == pat or rel.startswith(pat + "/")):
        return True
    parts_rel, parts_pat = rel.split("/"), pat.split("/")
    if len(parts_pat) <= len(parts_rel) and all(fnmatch.fnmatch(r, p) for r, p in zip(parts_rel, parts_pat, strict=False)):
        # only a prefix match if pat names a directory component-wise without trailing file glob mismatch
        if len(parts_pat) < len(parts_rel) and "*" not in parts_pat[-1]:
            return True
    return False
