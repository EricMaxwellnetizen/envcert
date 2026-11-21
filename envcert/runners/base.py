from __future__ import annotations

from dataclasses import dataclass


@dataclass
class RunResult:
    ok: bool
    exit_code: int | None = None
    stdout: str = ""
    stderr: str = ""
    reward: float | None = None
    error: str = ""
    duration_sec: float = 0.0
    image_digest: str | None = None


@dataclass
class RunnerInfo:
    name: str
    available: bool
    reason: str = ""
    isolation: str = ""


class Runner:
    name = "base"

    def info(self) -> RunnerInfo:  # pragma: no cover - interface
        raise NotImplementedError

    def run_python_verifier(self, workdir, timeout: int = 120) -> RunResult:  # pragma: no cover - interface
        raise NotImplementedError
