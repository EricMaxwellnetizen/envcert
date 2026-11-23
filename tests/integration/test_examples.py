import json
import pathlib

from envicert.core.config import load_settings
from envicert.core.engine import run_checks

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


def test_vulnerable_environment_expected(tmp_path):
    # Git cannot track files under a nested .git/ directory, so the fixture
    # materialises the exposed-.git files here (they also exist on disk in a
    # local checkout of examples/, where git simply leaves them untracked).
    import shutil

    dest = tmp_path / "vulnerable"
    shutil.copytree(ROOT / "examples" / "intentionally-vulnerable-environment", dest,
                    ignore=shutil.ignore_patterns(".git"))
    gitdir = dest / "environment" / ".git"
    gitdir.mkdir(exist_ok=True)
    (gitdir / "HEAD").write_text("ref: refs/heads/main\n", encoding="utf-8")
    (gitdir / "config").write_text("[core]\n", encoding="utf-8")
    expected = json.loads((FIXTURES / "expected-intentionally-vulnerable-environment.json").read_text(encoding="utf-8"))
    report = run_checks(dest, load_settings(None, None, None))
    by = {}
    for f in report["findings"]:
        by.setdefault(f["check_id"], set()).add(f["status"])
    for cid, want in expected["checks"].items():
        assert want in by.get(cid, set()), f"{cid}: expected {want}, got {by.get(cid)}"
    assert report["policy"]["passed"] is expected["policy_passed"]


def test_unsupported_environment_is_reported_not_validated():
    report = run_checks(ROOT / "examples" / "unsupported-environment", load_settings(None, None, None))
    assert report["environment"]["adapter"] == "generic"
    assert report["policy"]["passed"] is False
    ec001 = [f for f in report["findings"] if f["check_id"] == "EC001"][0]
    assert ec001["status"] == "FAIL"
