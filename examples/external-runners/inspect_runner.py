#!/usr/bin/env python3
"""EnvCert external-runner example: run an Inspect AI evaluation dynamically.

Protocol (see envcert/runners/external_runner.py):
  inspect_runner.py --task <dir> --variant gold|noop --timeout <sec>
  -> last stdout line: {"reward": <float|null>, "exit_code": <int>}

Requires inspect_ai installed and a task whose scorer produces accuracy.
Uses Inspect's mockllm provider only when ENVCERT_INSPECT_MODEL is unset —
set ENVCERT_INSPECT_MODEL to a real model id for meaningful runs. The
reward reported here is the eval accuracy from the Inspect log, which is a
*gold-run analogue for solver-equipped evals*, not a Harbor reward; treat
variant != gold as unsupported (returns an error) rather than faking a
negative control for a framework whose negative semantics differ.
"""
import argparse
import glob
import json
import os
import subprocess
import sys
from pathlib import Path


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--task", required=True)
    p.add_argument("--variant", default="gold")
    p.add_argument("--timeout", type=int, default=600)
    a = p.parse_args()
    if a.variant != "gold":
        print(json.dumps({"error": "inspect runner supports gold only"}))
        return 2
    task_dir = Path(a.task)
    task_files = [f for f in task_dir.rglob("*.py") if "inspect_ai" in f.read_text(encoding="utf-8", errors="replace")]
    if not task_files:
        print(json.dumps({"error": "no Inspect @task file found"}))
        return 2
    model = os.environ.get("ENVCERT_INSPECT_MODEL", "mockllm/model")
    log_dir = task_dir / ".envcert-inspect-logs"
    log_dir.mkdir(exist_ok=True)
    try:
        proc = subprocess.run(
            [sys.executable, "-m", "inspect_ai", "eval", str(task_files[0]), "--model", model, "--log-dir", str(log_dir)],
            capture_output=True, text=True, timeout=a.timeout)
    except Exception as exc:
        print(json.dumps({"error": f"inspect eval failed to start: {exc}"}))
        return 2
    logs = sorted(glob.glob(str(log_dir / "*.json")), key=os.path.getmtime)
    reward = None
    if logs:
        try:
            data = json.loads(Path(logs[-1]).read_text(encoding="utf-8"))
            metrics = ((data.get("results") or {}).get("scores") or [{}])[0].get("metrics") or {}
            acc = metrics.get("accuracy") or {}
            reward = acc.get("value") if isinstance(acc, dict) else acc
        except Exception:
            reward = None
    print(json.dumps({"reward": reward, "exit_code": proc.returncode}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
