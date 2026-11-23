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

import os
import shutil
import subprocess
import time
import uuid

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
            proc = _run([exe, "version", "--format", "{{.Server.Os}} {{.Server.Version}}"], 15)
            if proc.returncode != 0:
                return RunnerInfo(self.name, False, f"docker daemon unavailable: {(proc.stderr or proc.stdout).strip()[:200]}",
                                  "docker (shared-kernel container); not used")
            server_os, _, server_version = proc.stdout.strip().partition(" ")
            if server_os and server_os != "linux":
                # e.g. GitHub windows-latest runners expose a Windows
                # containers engine: present, but it cannot build or run
                # the Linux task images this runner exists for.
                return RunnerInfo(self.name, False,
                                  f"docker daemon is a {server_os} containers engine; EnvCert's restricted runner needs Linux containers",
                                  "docker (shared-kernel container); not used")
            return RunnerInfo(self.name, True, f"docker daemon {server_version or proc.stdout.strip()} (linux)",
                              "docker container: cap-drop ALL, no-new-privileges, resource limits, no docker.sock mount, harness runs as root inside the disposable container to create /logs and /tests (as Harbor does); shared host kernel — not a VM")
        except Exception as exc:  # noqa: BLE001
            return RunnerInfo(self.name, False, f"docker probe failed: {exc}", "docker; not used")

    @staticmethod
    def _solve_step(variant: str) -> str:
        """Shell executed as 'the agent' before the verifier runs.

        Cheat variants are deterministic attacks an agent could attempt in a
        shared agent/verifier environment: forging the reward file before
        verification, and replacing the verifier entrypoint in the writable
        task copy.  A sound verifier overwrites/ignores the forged reward and
        runs verifier-owned tests, so both must score 0.
        """
        if variant == "gold":
            return ("if [ -f /tmp/envcert-task/solution/solve.sh ]; then bash /tmp/envcert-task/solution/solve.sh; fi; ")
        if variant == "cheat-reward-forge":
            return ("mkdir -p /logs/verifier && echo 1 > /logs/verifier/reward.txt && "
                    "printf '{\"reward\": 1}' > /logs/verifier/reward.json; "
                    "echo 'envcert cheat: reward forged, no task work done'; ")
        if variant == "cheat-test-tamper":
            return ("for d in /tmp/envcert-task/tests /tests; do "
                    "if [ -d \"$d\" ] && [ -w \"$d\" ]; then "
                    "printf '#!/bin/bash\\nmkdir -p /logs/verifier\\necho 1 > /logs/verifier/reward.txt\\n' > \"$d/test.sh\"; "
                    "chmod +x \"$d/test.sh\"; fi; done; "
                    "echo 'envcert cheat: verifier tamper attempted, no task work done'; ")
        return "echo 'envcert: no-op variant (solution skipped)'; "

    def run_harbor_task(self, task_root, timeout: int = 600, network: str = "none",
                        variant: str = "gold", image: str | None = None) -> RunResult:
        """Build environment/, run solution (gold only) then tests/test.sh, read reward.

        variant="noop" skips the reference solution entirely — the negative
        control: whatever the untouched environment scores is what a
        do-nothing agent would get.  With ``image`` (a task-declared
        prebuilt image), no Dockerfile is built: the image is pulled and
        used as-is, which is how Harbor tasks that declare
        ``[environment] docker_image`` run.
        """
        from pathlib import Path

        info = self.info()
        if not info.available:
            return RunResult(ok=False, error=info.reason)
        root = Path(task_root).resolve()
        dockerfile = root / "environment" / "Dockerfile"
        if not image and not dockerfile.is_file():
            return RunResult(ok=False, error="no environment/Dockerfile to build and no prebuilt image declared")
        exe = shutil.which("docker") or "docker"
        # Unique per process and invocation: two concurrent checks in the same
        # second must not build/run/delete the same tag.
        tag = image or f"envcert-check-{os.getpid()}-{uuid.uuid4().hex[:12]}"
        built = image is None
        start = time.time()
        try:
            if image:
                pull = _run([exe, "pull", image], min(timeout, 900))
                if pull.returncode != 0:
                    return RunResult(ok=False, error=f"docker pull failed for prebuilt image {image!r}",
                                     stderr=(pull.stderr or "")[-MAX_OUTPUT:],
                                     duration_sec=round(time.time() - start, 3))
            else:
                build = _run([exe, "build", "-t", tag, "-f", str(dockerfile), str(root / "environment")],
                             min(timeout, 900))
                if build.returncode != 0:
                    return RunResult(ok=False, error="docker build failed", stderr=(build.stderr or "")[-MAX_OUTPUT:],
                                     duration_sec=round(time.time() - start, 3))
            image_digest = None
            try:
                insp = _run([exe, "image", "inspect", "--format", "{{.Id}}", tag], 30)
                if insp.returncode == 0 and insp.stdout.strip().startswith("sha256:"):
                    image_digest = insp.stdout.strip()
            except Exception:  # noqa: BLE001
                image_digest = None
            solve_step = self._solve_step(variant)
            # Tests are snapshotted to a pristine location BEFORE the agent
            # step runs and restored from it afterwards: the verifier owns
            # its tests (as Harbor's upload does), so agent tampering with
            # the writable task copy cannot reach verification.  EC066's
            # cheat-test-tamper scenario proves this property per run.
            script = (
                "mkdir -p /tmp/envcert-task /logs/verifier /tests /tmp/envcert-pristine-tests && cp -a /envcert-task/. /tmp/envcert-task/ && "
                "find /tmp/envcert-task -name '*.sh' -type f -exec sed -i 's/\\r$//' {} +; "
                "cp -a /tmp/envcert-task/tests/. /tmp/envcert-pristine-tests/; "
                + solve_step +
                "cp -a /tmp/envcert-pristine-tests/. /tests/; "
                "bash /tests/test.sh; cat /logs/verifier/reward.txt 2>/dev/null || cat /logs/verifier/reward.json 2>/dev/null || echo NO_REWARD"
            )
            run = _run([exe, "run", "--rm", "--user", "root", "--network", network, "--cap-drop", "ALL",
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
                             duration_sec=round(time.time() - start, 3), image_digest=image_digest,
                             image_digest_note=(
                                 "docker runner image is the task-declared prebuilt image; image_digest is the local image ID, "
                                 "not a registry manifest digest"
                             ) if image else (
                                 "docker runner image is locally built; image_digest is the local image ID, "
                                 "not a registry manifest digest"
                             ) if image_digest else "")
        except subprocess.TimeoutExpired:
            return RunResult(ok=False, error=f"docker execution timed out after {timeout}s",
                             duration_sec=float(timeout))
        except Exception as exc:  # noqa: BLE001
            return RunResult(ok=False, error=f"{type(exc).__name__}: {exc}")
        finally:
            if built:
                try:
                    _run([exe, "rmi", "-f", tag], 60)
                except Exception:  # noqa: BLE001
                    pass
