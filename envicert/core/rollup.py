"""Dataset rollup: run Envicert over every task folder in a dataset.

A dataset root (e.g. a NeMo Gym dataset root with dataset.toml, or any
directory tree of Harbor tasks) contains many task folders.  The rollup
runs the normal single-task engine per folder and aggregates — it never
invents a dataset score: policy is the conjunction of per-task policies,
and every per-task finding remains available in its own report fields.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any

from envicert import REPORT_SCHEMA_VERSION, __version__
from envicert.core.config import Settings
from envicert.core.engine import run_checks, validate_check_selection

MAX_DEPTH = 6


def find_task_folders(root: Path, max_depth: int = MAX_DEPTH) -> list[Path]:
    root = Path(root).resolve()
    folders: list[Path] = []
    for toml in sorted(root.rglob("task.toml")):
        depth = len(toml.relative_to(root).parts) - 1
        if depth > max_depth:
            continue
        folder = toml.parent
        if ".git" in folder.parts or ".venv" in folder.parts:
            continue
        folders.append(folder)
    return folders


def run_dataset_rollup(dataset_root: Path, settings: Settings, adapter_name: str = "auto") -> dict[str, Any]:
    validate_check_selection(settings)
    folders = find_task_folders(dataset_root)
    tasks: list[dict[str, Any]] = []
    for folder in folders:
        try:
            report = run_checks(folder, settings, adapter_name=adapter_name)
            failing = sorted({f["check_id"] for f in report["findings"]
                              if f["status"] in ("FAIL", "WARN") and not f.get("baseline_suppressed")})
            tasks.append({
                "task": report["environment"]["task_name"],
                "path": str(folder),
                "adapter": report["environment"]["adapter"],
                "bundle_digest_sha256": report["environment"]["bundle_digest_sha256"],
                "policy_passed": report["policy"]["passed"],
                "by_status": report["summary"]["by_status"],
                "failing_checks": failing,
                "report": report,
            })
        except Exception as exc:  # one bad folder must not sink the rollup
            tasks.append({"task": folder.name, "path": str(folder), "adapter": "unknown",
                          "bundle_digest_sha256": None, "policy_passed": False,
                          "by_status": {"ERROR": 1}, "failing_checks": [],
                          "error": f"{type(exc).__name__}: {exc}", "report": None})
    passed = sum(1 for t in tasks if t["policy_passed"])
    return {
        "kind": "envicert-dataset-rollup",
        "schema_version": REPORT_SCHEMA_VERSION,
        "envicert_version": __version__,
        "dataset": str(Path(dataset_root).resolve()),
        "task_folders_found": len(folders),
        "tasks": [{k: v for k, v in t.items() if k != "report"} | {"report_included": t["report"] is not None}
                  for t in tasks],
        "reports": {t["path"]: t["report"] for t in tasks if t["report"] is not None},
        "summary": {"tasks": len(tasks), "policy_passed_tasks": passed,
                    "policy_failed_tasks": len(tasks) - passed,
                    "overall_policy_passed": bool(tasks) and passed == len(tasks)},
        "limitations": [
            "Rollup policy is the conjunction of per-task policies; there is no dataset score.",
            "Each entry's full single-task report is under reports[<path>] and validates against the report schema.",
        ],
    }


def rollup_to_markdown(rollup: dict[str, Any]) -> str:
    s = rollup["summary"]
    verdict = "PASSED ✅" if s["overall_policy_passed"] else "FAILED ❌"
    lines = [f"## Envicert {rollup['envicert_version']} dataset rollup — {verdict}", "",
             f"**Dataset:** `{rollup['dataset']}` · {rollup['task_folders_found']} task folders · "
             f"{s['policy_passed_tasks']}/{s['tasks']} pass policy", "",
             "| Task | Adapter | Policy | Findings | Failing checks |", "|---|---|---|---|---|"]
    for t in rollup["tasks"]:
        findings = ", ".join(f"{k}:{v}" for k, v in sorted(t["by_status"].items()))
        lines.append(f"| `{t['task']}` | {t['adapter']} | {'✅ PASS' if t['policy_passed'] else '❌ FAIL'} | "
                     f"{findings} | {', '.join(t['failing_checks']) or '—'} |")
    lines += ["", "_Rollup policy is the conjunction of per-task policies; there is no dataset score._", ""]
    return "\n".join(lines)


def rollup_to_text(rollup: dict[str, Any]) -> str:
    lines = [f"Envicert {rollup['envicert_version']} dataset rollup",
             f"Dataset: {rollup['dataset']}  task folders: {rollup['task_folders_found']}", ""]
    for t in rollup["tasks"]:
        status = "PASS" if t["policy_passed"] else "FAIL"
        lines.append(f"[{status}] {t['task']} ({t['adapter']}) {t['by_status']}"
                     + (f" failing: {', '.join(t['failing_checks'])}" if t["failing_checks"] else "")
                     + (f" ERROR: {t['error']}" if t.get("error") else ""))
    s = rollup["summary"]
    lines.append("")
    lines.append(f"Summary: {s['policy_passed_tasks']}/{s['tasks']} tasks pass policy; overall: "
                 f"{'PASSED' if s['overall_policy_passed'] else 'FAILED'}")
    return "\n".join(lines) + "\n"
