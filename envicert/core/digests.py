from __future__ import annotations

import hashlib
from pathlib import Path

from envicert.utils.files import iter_task_files

HASH_CHUNK = 65536


def sha256_file(path: Path) -> str:
    """Hash a file; OSError propagates so callers never mistake unreadable
    content for an empty file."""
    h = hashlib.sha256()
    with path.open("rb") as fh:
        while True:
            chunk = fh.read(HASH_CHUNK)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def bundle_digest(root: Path, exclude_top: frozenset[str] = frozenset({".git"}),
                  warnings: list[str] | None = None, max_files: int = 5000,
                  only: list[str] | None = None) -> tuple[str, int]:
    """Deterministic digest over relative paths + file contents (symlinks hashed by target string).

    Unreadable files and truncation of the file listing are recorded in
    ``warnings`` when provided; they are never silently hashed as empty.
    ``only`` restricts the digest to the named relative files (dataset
    adapter: the bundle is the data files, not their whole parent directory).
    """
    h = hashlib.sha256()
    count = 0
    stats: dict = {}
    if only is not None:
        entries = [(rel, root / rel, (root / rel).is_symlink()) for rel in sorted(only)]
    else:
        entries = list(iter_task_files(root, max_files=max_files, stats=stats))
    for rel, path, is_link in entries:
        if rel.split("/")[0] in exclude_top:
            continue
        count += 1
        h.update(rel.encode())
        h.update(b"\0")
        if is_link:
            try:
                target = str(path.readlink())
            except OSError as exc:
                if warnings is not None:
                    warnings.append(f"could not read symlink target for {rel}: {exc}")
                target = "unreadable"
            h.update(b"link:")
            h.update(target.encode())
        else:
            try:
                file_digest = sha256_file(path)
            except OSError as exc:
                if warnings is not None:
                    warnings.append(f"could not read {rel} for the bundle digest: {exc}")
                file_digest = "unreadable"
            h.update(file_digest.encode())
        h.update(b"\n")
    if stats.get("truncated") and warnings is not None:
        warnings.append(
            f"task contains more than {stats.get('max_files', max_files)} files; the bundle digest and file "
            "count cover only the first files in sorted order (increase the limit or reduce generated files)"
        )
    return h.hexdigest(), count
