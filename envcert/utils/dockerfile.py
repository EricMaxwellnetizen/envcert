from __future__ import annotations

import re
import shlex
from dataclasses import dataclass, field


@dataclass
class Instruction:
    name: str
    args: str
    line: int

    def tokens(self) -> list[str]:
        try:
            return shlex.split(self.args, posix=True)
        except ValueError:
            return self.args.split()


@dataclass
class Dockerfile:
    instructions: list[Instruction] = field(default_factory=list)
    parse_errors: list[str] = field(default_factory=list)

    def find(self, *names: str) -> list[Instruction]:
        wanted = {n.upper() for n in names}
        return [i for i in self.instructions if i.name in wanted]

    @property
    def froms(self) -> list[Instruction]:
        return self.find("FROM")

    @property
    def text(self) -> str:
        return "\n".join(f"{i.name} {i.args}" for i in self.instructions)


HEREDOC_RE = re.compile(r"<<-?\s*['\"]?([A-Za-z_][A-Za-z0-9_]*)['\"]?")


def parse_dockerfile(text: str) -> Dockerfile:
    df = Dockerfile()
    logical: list[tuple[int, str]] = []
    buf, start = "", 0
    heredoc_end: str | None = None
    for lineno, raw in enumerate(text.splitlines(), 1):
        line = raw.rstrip()
        if heredoc_end is not None:
            # Heredoc bodies are file content (often embedded Python/shell),
            # never Dockerfile instructions: `from pathlib import Path`
            # must not become a FROM instruction.
            if line.strip() == heredoc_end:
                heredoc_end = None
            continue
        if not buf:
            start = lineno
            if not line.strip() or line.lstrip().startswith("#"):
                continue
        if line.endswith("\\"):
            buf += line[:-1] + " "
            continue
        buf += line
        logical.append((start, buf.strip()))
        marker = HEREDOC_RE.search(buf)
        if marker:
            heredoc_end = marker.group(1)
        buf = ""
    if buf.strip():
        logical.append((start, buf.strip()))
    for lineno, line in logical:
        m = re.match(r"([A-Za-z]+)\s+(.*)", line, re.S)
        if not m:
            df.parse_errors.append(f"line {lineno}: unparseable instruction: {line[:80]!r}")
            continue
        df.instructions.append(Instruction(m.group(1).upper(), m.group(2).strip(), lineno))
    return df


def copy_sources(instr: Instruction) -> tuple[list[str], str | None]:
    """Return (sources, dest) for COPY/ADD, handling --flags and JSON form."""
    args = instr.args.strip()
    if args.startswith("["):
        import json

        try:
            parts = json.loads(args)
            if isinstance(parts, list) and len(parts) >= 2:
                return [str(p) for p in parts[:-1]], str(parts[-1])
        except ValueError:
            return [], None
    toks = [t for t in instr.tokens() if not t.startswith("--")]
    # flags with values e.g. --from=stage are already = form; --chown user:group would leave value token
    cleaned: list[str] = []
    skip = False
    for t in instr.tokens():
        if skip:
            skip = False
            continue
        if t in ("--chown", "--chmod", "--from", "--link"):
            skip = True
            continue
        if t.startswith("--"):
            continue
        cleaned.append(t)
    toks = cleaned
    if len(toks) < 2:
        return [], None
    return toks[:-1], toks[-1]


def image_ref_pinned(ref: str) -> tuple[bool, bool]:
    """Return (has_digest, has_specific_tag)."""
    if "@sha256:" in ref:
        return True, True
    name = ref.split("/")[-1]
    if ":" in name:
        return False, name.rsplit(":", 1)[1] not in ("latest", "")
    return False, False
