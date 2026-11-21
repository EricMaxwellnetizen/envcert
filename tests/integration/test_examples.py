import json
import pathlib

from envcert.core.config import load_settings
from envcert.core.engine import run_checks

ROOT = pathlib.Path(__file__).resolve().parents[2]
FIXTURES = ROOT / "tests" / "fixtures"


def check_expected(name):
    expected = json.loads((FIXTURES / f"expected-{name}.json").read_text(encoding="utf-8"))
    report = run_checks(ROOT / "examples" / name, load_settings(None, None, None))
    by = {}
    for f in report["findings"]:
        by.setdefault(f["check_id"], set()).add(f["status"])
    for cid, want in expected["checks"].items():
        assert want in by.get(cid, set()), f"{name} {cid}: expected {want}, got {by.get(cid)}"
    assert report["policy"]["passed"] is expected["policy_passed"]
    return report


def test_safe_environment_expected():
    check_expected("safe-environment")


def test_vulnerable_environment_expected():
    check_expected("intentionally-vulnerable-environment")


def test_unsupported_environment_is_reported_not_validated():
    report = run_checks(ROOT / "examples" / "unsupported-environment", load_settings(None, None, None))
    assert report["environment"]["adapter"] == "generic"
    assert report["policy"]["passed"] is False
    ec001 = [f for f in report["findings"] if f["check_id"] == "EC001"][0]
    assert ec001["status"] == "FAIL"
