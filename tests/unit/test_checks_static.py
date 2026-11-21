from envcert.core.config import load_settings
from envcert.core.engine import run_checks


def by_id(report):
    out = {}
    for f in report["findings"]:
        out.setdefault(f["check_id"], []).append(f)
    return out


def statuses(report, cid):
    return [f["status"] for f in by_id(report).get(cid, [])]


def test_safe_basic_task_passes_policy(basic_task):
    report = run_checks(basic_task, load_settings(None, None, None))
    assert report["policy"]["passed"] is True
    assert statuses(report, "EC001") == ["PASS"]
    assert statuses(report, "EC011") == ["PASS"]
    assert statuses(report, "EC051") == ["PASS"]


def test_solution_in_build_context_detected(task_factory):
    files = {
        "task.toml": '[environment]\nnetwork_mode = "no-network"\n',
        "instruction.md": "# Task\n\nDo the thing properly and completely now.\n",
        "environment/Dockerfile": "FROM python:latest\nCOPY . /app\n",
        "environment/solution.py": "print('gold')\n",
        "tests/test.sh": "#!/bin/bash\necho 1 > /logs/verifier/reward.txt\n",
        "solution/solve.sh": "#!/bin/bash\ntrue\n",
    }
    report = run_checks(task_factory(files), load_settings(None, None, None))
    assert "FAIL" in statuses(report, "EC011")
    assert "FAIL" in statuses(report, "EC052")  # unconditional echo 1
    assert report["policy"]["passed"] is False


def test_solution_outside_context_not_flagged(basic_task):
    # solution/ exists in source tree but is outside environment/ build context
    report = run_checks(basic_task, load_settings(None, None, None))
    assert statuses(report, "EC011") == ["PASS"]


def test_legit_conftest_in_tests_not_flagged(task_factory, basic_task):
    (basic_task / "tests" / "conftest.py").write_text("import pytest\n", encoding="utf-8")
    report = run_checks(basic_task, load_settings(None, None, None))
    assert statuses(report, "EC021") == ["PASS"]


def test_conftest_in_environment_flagged(task_factory):
    from tests.conftest import BASIC

    files = dict(BASIC)
    files["environment/conftest.py"] = "import os\n"
    report = run_checks(task_factory(files), load_settings(None, None, None))
    assert "WARN" in statuses(report, "EC021")


def test_missing_verifier_is_critical(task_factory):
    files = {
        "task.toml": '[task]\nname = "x/y"\n',
        "instruction.md": "# T\n\nDo something meaningful and verifiable here.\n",
        "environment/Dockerfile": "FROM python:3.12\n",
    }
    report = run_checks(task_factory(files), load_settings(None, None, None))
    ec050 = by_id(report)["EC050"][0]
    assert ec050["status"] == "FAIL" and ec050["severity"] == "CRITICAL"


def test_no_solution_is_not_critical(task_factory):
    from tests.conftest import BASIC

    files = {k: v for k, v in BASIC.items() if not k.startswith("solution/")}
    report = run_checks(task_factory(files), load_settings(None, None, None))
    assert statuses(report, "EC003") == ["WARN"]
    assert by_id(report)["EC003"][0]["severity"] == "LOW"


def test_floating_image_and_root(task_factory):
    from tests.conftest import BASIC

    files = dict(BASIC)
    files["environment/Dockerfile"] = "FROM ubuntu\nCOPY . /app\n"
    report = run_checks(task_factory(files), load_settings(None, None, None))
    assert "WARN" in statuses(report, "EC030")
    assert "WARN" in statuses(report, "EC031")


def test_unpinned_dependencies(task_factory):
    from tests.conftest import BASIC

    files = dict(BASIC)
    files["environment/requirements.txt"] = "requests\nflask==3.0.0\n"
    files["environment/Dockerfile"] = BASIC["environment/Dockerfile"] + "RUN pip install requests\n"
    report = run_checks(task_factory(files), load_settings(None, None, None))
    assert "WARN" in statuses(report, "EC040")


def test_docker_socket_flagged(task_factory):
    from tests.conftest import BASIC

    files = dict(BASIC)
    files["environment/docker-compose.yaml"] = "services:\n  main:\n    volumes:\n      - /var/run/docker.sock:/var/run/docker.sock\n"
    report = run_checks(task_factory(files), load_settings(None, None, None))
    assert "FAIL" in statuses(report, "EC024")


def test_git_excluded_by_dockerignore_passes(task_factory):
    from tests.conftest import BASIC

    files = dict(BASIC)
    files["environment/.git/HEAD"] = "ref: refs/heads/main\n"
    files["environment/.dockerignore"] = ".git\n"
    report = run_checks(task_factory(files), load_settings(None, None, None))
    assert statuses(report, "EC010") == ["PASS"]


def test_secret_detected(task_factory):
    from tests.conftest import BASIC

    files = dict(BASIC)
    files["environment/app.py"] = 'API_KEY = "sk-1234567890abcdefghijklmnop"\n'
    report = run_checks(task_factory(files), load_settings(None, None, None))
    assert "WARN" in statuses(report, "EC013")


def test_env_var_reference_not_secret(task_factory):
    from tests.conftest import BASIC

    files = dict(BASIC)
    files["task.toml"] = BASIC["task.toml"].replace("[environment]", '[verifier.env]\nAPI_KEY = "${API_KEY}"\n[environment]')
    report = run_checks(task_factory(files), load_settings(None, None, None))
    assert statuses(report, "EC013") == ["PASS"]


def test_disabled_check_not_run(basic_task):
    s = load_settings(None, None, {"disable": ["EC031"]})
    report = run_checks(basic_task, s)
    assert "EC031" in report["checks_not_executed"]
    assert "EC031" not in by_id(report)


def test_crashing_check_becomes_error_not_pass(monkeypatch, basic_task):
    from envcert.checks.base import REGISTRY

    _info, _fn = REGISTRY["EC002"]

    def boom(ctx):
        raise RuntimeError("boom")

    monkeypatch.setitem(REGISTRY, "EC002", (_info, boom))
    report = run_checks(basic_task, load_settings(None, None, None))
    assert statuses(report, "EC002") == ["ERROR"]
    assert report["policy"]["passed"] is False
    assert report["errors"]
