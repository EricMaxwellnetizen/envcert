"""Live probing of a NeMo Gym-style ``verify()`` (local-python, trusted only).

Imports the dataset's verifier module in a *subprocess* (never in the
EnvCert process), then for each JSONL row probes:
  gold:   verify(response=<expected>)          -> should be >= 1.0 (or truthy pass)
  mutant: verify(response=<expected + wrong>)  -> should be < 1.0
  swap:   verify(response=<next row's answer>) -> should be < 1.0

This is verifier-input mutation: the verifier, not the solution, is fed
mutated inputs.  Only declared verify() parameters among
response/task_data/workspace/state are passed, mirroring Gym's convention.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import time
from pathlib import Path

from envcert.runners.base import RunResult

PROBE_SCRIPT = r'''
import inspect, json, sys
from pathlib import Path
import importlib.util

verifier_path, rows_path, workspace = sys.argv[1], sys.argv[2], sys.argv[3]
rows = [json.loads(l) for l in Path(rows_path).read_text(encoding="utf-8").splitlines() if l.strip()]
spec = importlib.util.spec_from_file_location("envcert_probe_verifier", verifier_path)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)
verify = getattr(mod, "verify", None)
if verify is None:
    print(json.dumps({"error": "verifier module defines no verify()"})); sys.exit(0)
params = set(inspect.signature(verify).parameters)

def call(row, response):
    kwargs = {}
    if "response" in params: kwargs["response"] = response
    if "task_data" in params: kwargs["task_data"] = row
    if "workspace" in params: kwargs["workspace"] = Path(workspace)
    if "state" in params: kwargs["state"] = {"workspace": Path(workspace)}
    try:
        out = verify(**kwargs)
        if inspect.isawaitable(out):
            import asyncio; out = asyncio.run(out)
        if isinstance(out, dict):
            out = out.get("reward", 0.0)
        return float(out), ""
    except Exception as exc:
        return None, f"{type(exc).__name__}: {exc}"

results = []
for i, row in enumerate(rows):
    expected = row.get("expected_answer", row.get("answer", row.get("target")))
    if expected is None:
        results.append({"row": i, "skipped": "no expected answer field"}); continue
    expected = str(expected)
    gold, e1 = call(row, expected)
    mutant, e2 = call(row, expected + "-WRONG")
    swap_val = None
    if len(rows) > 1:
        nxt = rows[(i + 1) % len(rows)]
        swap_val = str(nxt.get("expected_answer", nxt.get("answer", nxt.get("target", ""))))
    swap, e3 = call(row, swap_val) if swap_val and swap_val != expected else (None, "")
    results.append({"row": i, "gold": gold, "mutant": mutant, "swap": swap,
                    "errors": [e for e in (e1, e2, e3) if e]})
print(json.dumps({"results": results}))
'''


def probe_verifier(task_root: Path, verifier_rel: str, dataset_rel: str, timeout: int = 120) -> RunResult:
    task_root = Path(task_root)
    start = time.time()
    with tempfile.TemporaryDirectory(prefix="envcert-probe-") as td:
        td_path = Path(td)
        script = td_path / "probe.py"
        script.write_text(PROBE_SCRIPT, encoding="utf-8")
        rows_src = task_root / dataset_rel
        rows = [ln for ln in rows_src.read_text(encoding="utf-8", errors="replace").splitlines() if ln.strip()][:10]
        rows_path = td_path / "rows.jsonl"
        rows_path.write_text("\n".join(rows), encoding="utf-8")
        env = {"PATH": os.environ.get("PATH", ""), "SYSTEMROOT": os.environ.get("SYSTEMROOT", ""),
               "PYTHONDONTWRITEBYTECODE": "1"}
        try:
            proc = subprocess.run([sys.executable, str(script), str(task_root / verifier_rel),
                                   str(rows_path), str(td_path)],
                                  capture_output=True, text=True, timeout=timeout, env=env, cwd=str(td_path))
        except subprocess.TimeoutExpired:
            return RunResult(ok=False, error=f"verifier probe timed out after {timeout}s", duration_sec=float(timeout))
        except Exception as exc:  # noqa: BLE001
            return RunResult(ok=False, error=f"probe failed to start: {exc}")
        dur = round(time.time() - start, 3)
        out = (proc.stdout or "").strip()
        if not out:
            return RunResult(ok=False, error=f"probe produced no output: {(proc.stderr or '')[-500:]}",
                             stderr=(proc.stderr or "")[-2000:], duration_sec=dur)
        try:
            payload = json.loads(out.splitlines()[-1])
        except ValueError:
            return RunResult(ok=False, error="probe output was not JSON", stdout=out[-2000:], duration_sec=dur)
        if payload.get("error"):
            return RunResult(ok=False, error=str(payload["error"]), duration_sec=dur)
        results = payload.get("results", [])
        scored = [r for r in results if r.get("gold") is not None]
        gold_ok = sum(1 for r in scored if r["gold"] >= 1.0)
        mutant_rejected = sum(1 for r in scored if r.get("mutant") is not None and r["mutant"] < 1.0)
        reward = 1.0 if scored and gold_ok == len(scored) and mutant_rejected == len(scored) else 0.0
        return RunResult(ok=reward == 1.0, exit_code=proc.returncode, stdout=json.dumps(payload)[:20000],
                         reward=reward, duration_sec=dur,
                         error="" if scored else "no rows with expected answers could be scored")
