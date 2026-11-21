from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from envcert.utils.dockerfile import Dockerfile, parse_dockerfile
from envcert.utils.files import iter_task_files, read_text_safe


@dataclass
class TaskContext:
    root: Path
    adapter: str
    task_name: str = ""
    config: dict[str, Any] = field(default_factory=dict)
    config_path: Path | None = None
    files: list[str] = field(default_factory=list)
    symlinks: list[str] = field(default_factory=list)
    instruction_path: Path | None = None
    dockerfile_path: Path | None = None
    dockerfile: Dockerfile | None = None
    dockerignore_patterns: list[str] = field(default_factory=list)
    build_context: Path | None = None
    tests_dir: Path | None = None
    solution_dir: Path | None = None
    environment_dir: Path | None = None
    warnings: list[str] = field(default_factory=list)
    verifier_paths: list[str] = field(default_factory=list)  # framework-specific verifier/scorer files (non-Harbor)
    steps: list[dict] = field(default_factory=list)  # multi-step: [{name, instruction, tests, solution}]
    dataset_files: list[str] = field(default_factory=list)
    _text_cache: dict[str, str | None] = field(default_factory=dict, repr=False)

    def text(self, rel: str) -> str | None:
        if rel not in self._text_cache:
            self._text_cache[rel] = read_text_safe(self.root / rel)
        return self._text_cache[rel]

    def abs(self, rel: str) -> Path:
        return self.root / rel

    def files_under(self, prefix: str) -> list[str]:
        prefix = prefix.strip("/") + "/"
        return [f for f in self.files if f == prefix[:-1] or f.startswith(prefix)]

    def has(self, rel: str) -> bool:
        return rel in self.files


def load_dockerfile(ctx: TaskContext, dockerfile_rel: str, context_rel: str) -> None:
    ctx.dockerfile_path = ctx.root / dockerfile_rel
    text = ctx.text(dockerfile_rel)
    if text is not None:
        ctx.dockerfile = parse_dockerfile(text)
    ctx.build_context = ctx.root / context_rel if context_rel else ctx.root
    ignore = ctx.build_context / ".dockerignore"
    if ignore.is_file():
        content = read_text_safe(ignore) or ""
        ctx.dockerignore_patterns = [ln.strip() for ln in content.splitlines() if ln.strip() and not ln.strip().startswith("#")]
    env_ignore = ctx.root / ".dockerignore"
    if not ctx.dockerignore_patterns and env_ignore.is_file():
        content = read_text_safe(env_ignore) or ""
        ctx.dockerignore_patterns = [ln.strip() for ln in content.splitlines() if ln.strip() and not ln.strip().startswith("#")]


def scan_files(ctx: TaskContext) -> None:
    for rel, _path, is_link in iter_task_files(ctx.root):
        ctx.files.append(rel)
        if is_link:
            ctx.symlinks.append(rel)
