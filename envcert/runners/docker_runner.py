"""Docker runner — restricted, opt-in.

Builds the task image and runs solution + verifier inside a container with:
--network (per task policy, default none for the check), --cap-drop ALL,
--security-opt no-new-privileges, CPU/memory/PID limits, a timeout, bounded
logs and cleanup.  It never mounts the host Docker socket and never runs
privileged.  Docker is a shared-kernel boundary, NOT a VM: the report and
docs state this.  If the daemon is unavailable the runner reports itself
unavailable and dynamic checks return NOT_RUN/ERROR — never a fake PASS.
"""
from __future__ import annotations

import shutil
import subprocess
import time

from envcert.runners.base import Runner, RunnerInfo, RunResult

MAX_OUTPUT = 20000


def _run(cmd: list[str], timeout: int) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)


class DockerRunner(Runner):
    name = "docker"

    def info(self) -> RunnerInfo:
        exe = shutil.which("docker")
        if not exe:
            return RunnerInfo(self.name, False, "docker executable not found on PATH",
                              "docker (shared-kernel container); not used")
        try:
            proc = _run([exe, "version", "--format", "{{.Server.Version}}"], 15)
            if proc.returncode != 0:
                return RunnerInfo(self.name, False, f"docker daemon unavailable: {(proc.stderr or proc.stdout).strip()[:200]}",
                                  "docker (shared-kernel container); not used")
            return RunnerInfo(self.name, True, f"docker daemon {proc.stdout.strip()}",
                              "docker container: cap-drop ALL, no-new-privileges, resource limits, no docker.sock mount; shared host kernel — not a VM")
        except Exception as exc:  # noqa: BLE001
            return RunnerInfo(self.name, False, f"docker probe failed: {exc}", "docker; not used")

    def run_harbor_task(self, task_root, timeout: int = 600, network: str = "none") -> RunResult:
        """Build environment/, run solution/solve.sh then tests/test.sh, read reward."""
        from pathlib import Path

        info = self.info()
        if not info.available:
            return RunResult(ok=False, error=info.reason)
        root = Path(task_root)
        dockerfile = root / "environment" / "Dockerfile"
        if not dockerfile.is_file():
            return RunResult(ok=False, error="no environment/Dockerfile to build")
        exe = shutil.which("docker") or "docker"
        tag = f"envcert-check-{int(time.time())}"
        start = time.time()
        try:
            build = _run([exe, "build", "-t", tag, "-f", str(dockerfile), str(root / "environment")],
                         min(timeout, 900))
            if build.returncode != 0:
                return RunResult(ok=False, error="docker build failed", stderr=(build.stderr or "")[-MAX_OUTPUT:],
                                 duration_sec=round(time.time() - start, 3))
            script = (
                "mkdir -p /tmp/envcert-task /logs/verifier && cp -a /envcert-task/. /tmp/envcert-task/ 2>/dev/null || true; "
                "if [ -f /tmp/envcert-task/solution/solve.sh ]; then bash /tmp/envcert-task/solution/solve.sh; fi; "
                "cp -a /tmp/envcert-task/tests /tests 2>/dev/null || true; "
                "bash /tests/test.sh; cat /logs/verifier/reward.txt 2>/dev/null || cat /logs/verifier/reward.json 2>/dev/null || echo NO_REWARD"
            )
            run = _run([exe, "run", "--rm", "--network", network, "--cap-drop", "ALL",
                        "--security-opt", "no-new-privileges", "--memory", "2g", "--cpus", "2",
                        "--pids-limit", "256", "-v", f"{root}:/envcert-task:ro", tag,
                        "bash", "-lc", script], timeout)
            out = (run.stdout or "")[-MAX_OUTPUT:]
            reward = None
            for line in reversed(out.strip().splitlines()):
                try:
                    reward = float(line.strip().strip("{}").split(":")[-1].strip().strip('"'))
                    break
                except ValueError:
                    continue
            return RunResult(ok=run.returncode == 0, exit_code=run.returncode, stdout=out,
                             stderr=(run.stderr or "")[-MAX_OUTPUT:], reward=reward,
                             duration_sec=round(time.time() - start, 3))
        except subprocess.TimeoutExpired:
            return RunResult(ok=False, error=f"docker execution timed out after {timeout}s",
                             duration_sec=float(timeout))
        except Exception as exc:  # noqa: BLE001
            return RunResult(ok=False, error=f"{type(exc).__name__}: {exc}")
        finally:
            try:
                _run([exe, "rmi", "-f", tag], 60)
            except Exception:  # noqa: BLE001
                pass
