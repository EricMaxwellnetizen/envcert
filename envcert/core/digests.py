from __future__ import annotations

import hashlib
from pathlib import Path

from envcert.utils.files import iter_task_files

HASH_CHUNK = 65536


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    try:
        with path.open("rb") as fh:
            while True:
                chunk = fh.read(HASH_CHUNK)
                if not chunk:
                    break
                h.update(chunk)
    except OSError:
        return ""
    return h.hexdigest()


def bundle_digest(root: Path, exclude_top: frozenset[str] = frozenset({".git"})) -> tuple[str, int]:
    """Deterministic digest over relative paths + file contents (symlinks hashed by target string)."""
    h = hashlib.sha256()
    count = 0
    for rel, path, is_link in iter_task_files(root):
        if rel.split("/")[0] in exclude_top:
            continue
        count += 1
        h.update(rel.encode())
        h.update(b"\0")
        if is_link:
            try:
                target = str(path.readlink())
            except OSError:
                target = ""
            h.update(b"link:")
            h.update(target.encode())
        else:
            h.update(sha256_file(path).encode())
        h.update(b"\n")
    return h.hexdigest(), count
