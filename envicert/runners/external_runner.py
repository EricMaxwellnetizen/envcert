"""External runner — plug in a disposable VM / remote sandbox provider.

Envicert deliberately does not ship an SSH/VM orchestrator: providers differ
too much.  Instead this runner implements a small, documented protocol so an
operator can point Envicert at *their* disposable-VM/remote-sandbox script:

  Invocation:  <command> --task <dir> --variant gold|noop --timeout <sec>
  Stdout:      one JSON object: {"reward": <number|null>, "exit_code": <int>,
                                 "image_digest": "sha256:..." (optional)}
  Exit code:   0 if the provider itself ran (the task's own success is the
               reward), non-zero / invalid JSON = provider error.

Set it with `--execution external --runner-command /path/to/provider` or
`[execution] runner_command` in envicert.toml.  The provider owns isolation;
Envicert records that honestly in the report.  The command is split with
platform-appropriate quoting and executed without a shell, so Windows paths
with backslashes and spaces work when quoted.
"""
from __future__ import annotations

import json
import os
import shlex
import shutil
import subprocess
import time
from pathlib import Path

from envicert.runners.base import Runner, RunnerInfo, RunResult

MAX_OUTPUT = 20000


def split_runner_command(command: str, windows: bool | None = None) -> list[str]:
    """Split a runner command without invoking a shell.

    POSIX quoting treats backslash as an escape, which mangles Windows paths
    such as ``.venv\\Scripts\\python.exe``.  On Windows use non-POSIX splitting
    and strip the surrounding quotes that shlex leaves on quoted arguments.
    """
    if windows is None:
        windows = os.name == "nt"
    if not windows:
        return shlex.split(command, posix=True)
    parts = shlex.split(command, posix=False)
    cleaned = []
    for part in parts:
        if len(part) >= 2 and part[0] == part[-1] and part[0] in ("'", '"'):
            part = part[1:-1]
        cleaned.append(part)
    return cleaned


class ExternalRunner(Runner):
    name = "external"

    def __init__(self, command: str = ""):
        self.command = command or os.environ.get("ENVCERT_RUNNER_COMMAND", "")

    def info(self) -> RunnerInfo:
        if not self.command:
            return RunnerInfo(self.name, False,
                              "no external runner command configured (use --runner-command or ENVCERT_RUNNER_COMMAND)",
                              "external provider (operator-configured); not used")
        try:
            argv = split_runner_command(self.command)
        except ValueError as exc:
            return RunnerInfo(self.name, False, f"unparseable external runner command: {exc}",
                              "external provider (operator-configured); not used")
        if not argv:
            return RunnerInfo(self.name, False, "empty external runner command",
                              "external provider (operator-configured); not used")
        if shutil.which(argv[0]) is None:
            return RunnerInfo(self.name, False, f"external runner command not found: {argv[0]}",
                              "external provider (operator-configured); not used")
        return RunnerInfo(self.name, True, f"external runner command: {self.command}",
                          "external provider: isolation is whatever the operator's disposable VM/remote sandbox provides — Envicert cannot vouch for it and records the provider command in the report")

    def run_harbor_task(self, task_root, timeout: int = 600, variant: str = "gold") -> RunResult:
        info = self.info()
        if not info.available:
            return RunResult(ok=False, error=info.reason)
        try:
            argv = split_runner_command(self.command) + ["--task", str(Path(task_root).resolve()),
                                                         "--variant", variant, "--timeout", str(timeout)]
        except ValueError as exc:
            return RunResult(ok=False, error=f"unparseable runner command: {exc}")
        start = time.time()
        try:
            proc = subprocess.run(argv, capture_output=True, text=True, timeout=timeout + 60)
        except Exception as exc:  # noqa: BLE001
            return RunResult(ok=False, error=f"external runner failed to start: {exc}")
        dur = round(time.time() - start, 3)
        if proc.returncode != 0:
            return RunResult(ok=False, exit_code=proc.returncode, stdout=(proc.stdout or "")[-MAX_OUTPUT:],
                             stderr=(proc.stderr or "")[-MAX_OUTPUT:],
                             error=f"external runner exited {proc.returncode}", duration_sec=dur)
        try:
            payload = json.loads((proc.stdout or "").strip().splitlines()[-1])
            reward = payload.get("reward")
            return RunResult(ok=True, exit_code=payload.get("exit_code", 0),
                             stdout=(proc.stdout or "")[-MAX_OUTPUT:], stderr=(proc.stderr or "")[-MAX_OUTPUT:],
                             reward=float(reward) if reward is not None else None,
                             image_digest=payload.get("image_digest"), duration_sec=dur)
        except Exception as exc:  # noqa: BLE001
            return RunResult(ok=False, stdout=(proc.stdout or "")[-MAX_OUTPUT:],
                             stderr=(proc.stderr or "")[-MAX_OUTPUT:],
                             error=f"external runner returned invalid JSON result: {exc}", duration_sec=dur)
