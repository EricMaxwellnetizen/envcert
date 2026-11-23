"""EnvCert 0.4.0: AST verifier analysis, cheat battery, dataset adapter,
deterministic fix/scaffold, markdown/HTML formats."""
import json
import shutil

from envcert.cli.main import main
from envcert.core.config import load_settings
from envcert.core.engine import run_checks
from tests.conftest import BASIC


def by_id(report):
    out = {}
    for f in report["findings"]:
        out.setdefault(f["check_id"], []).append(f)
    return out


def statuses(report, cid):
    return [f["status"] for f in by_id(report).get(cid, [])]


def _task_with_verifier(task_factory, verifier_py: str):
    files = dict(BASIC)
    files["tests/verifier.py"] = verifier_py
    return task_factory(files)


# ---------------------------------------------------------------- EC054/EC056

def test_ec054_catches_return_float_of_agent_file(task_factory):
    # The idiom the 0.3.x regex missed: reward parsed straight from a file.
    task = _task_with_verifier(task_factory, (
        "def verify(response=None, task_data=None):\n"
        "    return float(open('result.txt').read())\n"
    ))
    report = run_checks(task, load_settings(None, None, None))
    assert statuses(report, "EC054") == ["FAIL"]


def test_ec054_catches_env_and_subprocess_derived_rewards(task_factory):
    task = _task_with_verifier(task_factory, (
        "import os, subprocess\n"
        "def grade():\n"
        "    score = int(os.environ.get('AGENT_SCORE', '0'))\n"
        "    return score\n"
    ))
    report = run_checks(task, load_settings(None, None, None))
    assert "FAIL" in statuses(report, "EC054") or "WARN" in statuses(report, "EC054")


def test_ec054_allows_compared_agent_output(task_factory):
    # Legitimate grading: read the agent's output, compare to expected, then
    # return a verifier-chosen constant.
    task = _task_with_verifier(task_factory, (
        "EXPECTED = 'done\\n'\n"
        "def verify(response=None, task_data=None):\n"
        "    content = open('/app/output.txt').read()\n"
        "    return 1.0 if content == EXPECTED else 0.0\n"
    ))
    report = run_checks(task, load_settings(None, None, None))
    assert statuses(report, "EC054") == ["PASS"]


def test_ec054_llm_judge_flow_is_warn_not_fail(task_factory):
    files = dict(BASIC)
    files["tests/llm_judge.py"] = (
        "import json\n"
        "def main():\n"
        "    judge_output = open('/tmp/judge_response.txt').read()\n"
        "    reward = float(json.loads(judge_output)['score'])\n"
        "    return reward\n"
    )
    report = run_checks(task_factory(files), load_settings(None, None, None))
    assert statuses(report, "EC054") == ["WARN"]


def test_ec054_data_loading_helper_not_flagged(task_factory):
    # A helper that loads agent data for later comparison is not a reward sink.
    task = _task_with_verifier(task_factory, (
        "def load_output():\n"
        "    return open('/app/output.txt').read()\n"
        "def verify(response=None, task_data=None):\n"
        "    content = load_output()\n"
        "    return 1.0 if content == 'expected\\n' else 0.0\n"
    ))
    report = run_checks(task, load_settings(None, None, None))
    assert statuses(report, "EC054") == ["PASS"]


def test_ec056_sourcing_venv_is_not_dynamic_eval(task_factory):
    files = dict(BASIC)
    files["tests/test.sh"] = (
        "#!/bin/bash\n"
        "source /app/.venv/bin/activate\n"
        "mkdir -p /logs/verifier\n"
        "if python3 -m pytest -q /tests/test_x.py; then echo 1 > /logs/verifier/reward.txt; else echo 0 > /logs/verifier/reward.txt; fi\n"
    )
    report = run_checks(task_factory(files), load_settings(None, None, None))
    assert statuses(report, "EC056") == ["PASS"]


def test_ec056_flags_eval_of_variable(task_factory):
    files = dict(BASIC)
    files["tests/test.sh"] = (
        "#!/bin/bash\n"
        "mkdir -p /logs/verifier\n"
        "eval \"$AGENT_CMD\"\n"
        "echo 0 > /logs/verifier/reward.txt\n"
    )
    report = run_checks(task_factory(files), load_settings(None, None, None))
    assert statuses(report, "EC056") == ["WARN"]


def test_dockerfile_heredoc_and_stage_alias_not_froms():
    from envcert.utils.dockerfile import parse_dockerfile

    df = parse_dockerfile(
        "FROM python:3.12 AS base\n"
        "RUN python3 - <<'EOF'\n"
        "from pathlib import Path\n"
        "print(Path.cwd())\n"
        "EOF\n"
        "FROM base AS final\n"
        "COPY . /app\n")
    refs = [i.args.split()[0] for i in df.froms]
    assert refs == ["python:3.12", "base"]


def test_ec030_stage_alias_not_flagged(task_factory):
    files = dict(BASIC)
    files["environment/Dockerfile"] = (
        "FROM python:3.12-slim@sha256:" + "a" * 64 + " AS base\n"
        "FROM base\nWORKDIR /app\nUSER nobody\n")
    report = run_checks(task_factory(files), load_settings(None, None, None))
    assert statuses(report, "EC030") == ["PASS"]


def test_ec054_rewardkit_projector_not_flagged(task_factory):
    # Reads the verifier-owned /logs/verifier/reward.json to re-emit it:
    # trusted source, not agent-controlled input (Terminal-Bench RewardKit).
    task = _task_with_verifier(task_factory, (
        "import json\n"
        "from pathlib import Path\n"
        "def main():\n"
        "    logs = Path('/logs/verifier')\n"
        "    reward = json.loads((logs / 'reward.json').read_text())['reward']\n"
        "    (logs / 'reward.txt').write_text(f'{reward}\\n')\n"
    ))
    report = run_checks(task, load_settings(None, None, None))
    assert statuses(report, "EC054") == ["PASS"]


def test_ec011_instruction_declared_oracle_not_flagged(task_factory):
    files = dict(BASIC)
    files["instruction.md"] = "# Solve the equation\n\nA public oracle header is available at /app/oracle.hpp. Your solution may include oracle.hpp and call its functions. Create the required output file with the correct content.\n"
    files["environment/Dockerfile"] = "FROM python:3.12-slim@sha256:" + "a" * 64 + "\nWORKDIR /app\nCOPY oracle.hpp /app/oracle.hpp\nUSER nobody\n"
    files["environment/oracle.hpp"] = "// public forcing-term oracle\n"
    report = run_checks(task_factory(files), load_settings(None, None, None))
    assert statuses(report, "EC011") == ["PASS"]


def test_ec010_gitignore_is_not_git_metadata(task_factory):
    files = dict(BASIC)
    files["environment/loadgen/.gitignore"] = "target/\n"
    report = run_checks(task_factory(files), load_settings(None, None, None))
    assert statuses(report, "EC010") == ["PASS"]


def test_ec053_require_helper_counts_as_assertion(task_factory):
    files = dict(BASIC)
    files["tests/test_x.py"] = (
        "def require(cond, msg):\n"
        "    if not cond:\n"
        "        raise AssertionError(msg)\n\n"
        "def test_hardened():\n"
        "    require(1 + 1 == 2, 'math broke')\n"
        "    require('abc'.upper() == 'ABC', 'case broke')\n"
    )
    report = run_checks(task_factory(files), load_settings(None, None, None))
    assert statuses(report, "EC053") == ["PASS"]


def test_ec023_workspace_chmod_not_flagged_but_tests_chmod_is(task_factory):
    files = dict(BASIC)
    files["environment/Dockerfile"] = (
        "FROM python:3.12-slim@sha256:" + "a" * 64 + "\nWORKDIR /app\n"
        "RUN chmod -R 777 /app /results\nUSER nobody\n")
    root = task_factory(files)
    report = run_checks(root, load_settings(None, None, None))
    assert statuses(report, "EC023") == ["PASS"]
    (root / "environment" / "Dockerfile").write_text(
        "FROM python:3.12-slim@sha256:" + "a" * 64 + "\nWORKDIR /app\n"
        "RUN chmod -R 777 /tests /logs/verifier\nUSER nobody\n", encoding="utf-8")
    report = run_checks(root, load_settings(None, None, None))
    assert statuses(report, "EC023") == ["WARN"]


def test_ec054_parse_only_helper_is_still_self_grading(task_factory):
    # Factoring the parse into a helper does not validate it: compute_score
    # reads agent data and returns it as a number with no comparison.
    task = _task_with_verifier(task_factory, (
        "def compute_score(path):\n"
        "    return float(open(path).read())\n"
        "def verify(response=None, task_data=None):\n"
        "    reward = compute_score('/app/score.txt')\n"
        "    return reward\n"
    ))
    report = run_checks(task, load_settings(None, None, None))
    assert statuses(report, "EC054") == ["FAIL"]


def test_ec054_grading_helper_result_is_validated(task_factory):
    # automationbench-style: the reward is a float of a local grading
    # helper's verdict over agent state, and the helper itself compares
    # against expected state -- inter-procedural validation, not trust.
    task = _task_with_verifier(task_factory, (
        "import json\n"
        "def task_completed_correctly(state):\n"
        "    return 1.0 if state.get('done') == state.get('want') else 0.0\n"
        "def main():\n"
        "    state = json.loads(open('/app/end_state.json').read())\n"
        "    reward = float(task_completed_correctly(state))\n"
        "    return reward\n"
    ))
    report = run_checks(task, load_settings(None, None, None))
    assert statuses(report, "EC054") == ["PASS"]


def test_ec011_no_build_context_no_leak_claim(task_factory):
    files = dict(BASIC)
    del files["environment/Dockerfile"]
    files["task.toml"] = BASIC["task.toml"].replace(
        '[environment]\nnetwork_mode = "no-network"',
        '[environment]\ndocker_image = "example/prebuilt@sha256:' + "b" * 64 + '"')
    report = run_checks(task_factory(files), load_settings(None, None, None))
    assert statuses(report, "EC011") == ["PASS"]


def test_ec011_narrow_copies_do_not_include_solution_material(task_factory):
    files = dict(BASIC)
    files["environment/Dockerfile"] = (
        "FROM python:3.12-slim@sha256:" + "a" * 64 + "\nWORKDIR /root\n"
        "COPY packets.pcap /root/packets.pcap\nCOPY data.csv /root/data.csv\nUSER nobody\n")
    files["environment/packets.pcap"] = "fake"
    files["environment/data.csv"] = "a,b\n"
    files["environment/scripts/extract_groundtruth.py"] = "# computes reference metrics from the pcap\n"
    report = run_checks(task_factory(files), load_settings(None, None, None))
    assert statuses(report, "EC011") == ["PASS"]
    # A directory copy that does cover the material still fails.
    files["environment/Dockerfile"] = (
        "FROM python:3.12-slim@sha256:" + "a" * 64 + "\nWORKDIR /root\n"
        "COPY scripts/ /root/scripts/\nUSER nobody\n")
    import pathlib
    import tempfile

    from tests.conftest import make_task

    root2 = make_task(pathlib.Path(tempfile.mkdtemp()), files)
    report = run_checks(root2, load_settings(None, None, None))
    assert statuses(report, "EC011") == ["FAIL"]


def test_ec056_flags_js_eval_in_verifier(task_factory):
    files = dict(BASIC)
    files["tests/verify.js"] = "const out = eval(process.env.AGENT_CODE);\nconsole.log(out);\n"
    report = run_checks(task_factory(files), load_settings(None, None, None))
    assert statuses(report, "EC056") == ["WARN"]


def test_ec023_testbed_workspace_not_flagged(task_factory):
    files = dict(BASIC)
    files["environment/Dockerfile"] = (
        "FROM python:3.12-slim@sha256:" + "a" * 64 + "\nWORKDIR /testbed\n"
        "RUN chmod -R 777 /testbed\nUSER nobody\n")
    report = run_checks(task_factory(files), load_settings(None, None, None))
    assert statuses(report, "EC023") == ["PASS"]


def test_ec032_versioned_installer_is_medium(task_factory):
    files = dict(BASIC)
    files["environment/Dockerfile"] = (
        "FROM python:3.12-slim@sha256:" + "a" * 64 + "\n"
        "RUN curl -LsSf https://astral.sh/uv/0.7.13/install.sh | sh\nUSER nobody\n")
    report = run_checks(task_factory(files), load_settings(None, None, None))
    hit = by_id(report)["EC032"][0]
    assert hit["status"] == "WARN" and hit["severity"] == "MEDIUM"
    files["environment/Dockerfile"] = (
        "FROM python:3.12-slim@sha256:" + "a" * 64 + "\n"
        "RUN curl -sSf https://sh.rustup.rs | sh -s -- -y\nUSER nobody\n")
    import pathlib
    import tempfile

    from tests.conftest import make_task

    root2 = make_task(pathlib.Path(tempfile.mkdtemp()), files)
    hit = by_id(run_checks(root2, load_settings(None, None, None)))["EC032"][0]
    assert hit["severity"] == "HIGH"


def test_ec054_transitive_validation_through_helper_chain(task_factory):
    # main -> load_and_grade (no comparison) -> compare_deep (compares):
    # validation is transitive through the call graph.
    task = _task_with_verifier(task_factory, (
        "import json\n"
        "def compare_deep(state, want):\n"
        "    return 1.0 if state.get('value') == want else 0.0\n"
        "def load_and_grade(path, want):\n"
        "    state = json.loads(open(path).read())\n"
        "    return compare_deep(state, want)\n"
        "def main():\n"
        "    reward = load_and_grade('/app/state.json', 42)\n"
        "    return reward\n"
    ))
    report = run_checks(task, load_settings(None, None, None))
    assert statuses(report, "EC054") == ["PASS"]


def test_ec054_chain_without_any_comparison_still_flagged(task_factory):
    task = _task_with_verifier(task_factory, (
        "import json\n"
        "def passthrough(state):\n"
        "    return state['score']\n"
        "def load_and_grade(path):\n"
        "    state = json.loads(open(path).read())\n"
        "    return passthrough(state)\n"
        "def main():\n"
        "    reward = load_and_grade('/app/state.json')\n"
        "    return reward\n"
    ))
    report = run_checks(task, load_settings(None, None, None))
    assert statuses(report, "EC054") in (["WARN"], ["FAIL"])


def test_ec054_cross_file_validation_through_import(task_factory):
    # helpers.py owns the comparison; verifier.py imports it.  Validation
    # must propagate across module boundaries (issue #1).
    files = dict(BASIC)
    files["tests/helpers.py"] = (
        "def compare_deep(state, want):\n"
        "    return 1.0 if state.get('value') == want else 0.0\n"
    )
    files["tests/verifier.py"] = (
        "import json\n"
        "from helpers import compare_deep\n"
        "def load_and_grade(path, want):\n"
        "    state = json.loads(open(path).read())\n"
        "    return compare_deep(state, want)\n"
        "def main():\n"
        "    reward = load_and_grade('/app/state.json', 42)\n"
        "    return reward\n"
    )
    report = run_checks(task_factory(files), load_settings(None, None, None))
    assert statuses(report, "EC054") == ["PASS"]


def test_ec054_cross_file_unvalidated_chain_still_flagged(task_factory):
    files = dict(BASIC)
    files["tests/helpers.py"] = (
        "def passthrough(state):\n"
        "    return state['score']\n"
    )
    files["tests/verifier.py"] = (
        "import json\n"
        "from helpers import passthrough\n"
        "def main():\n"
        "    state = json.loads(open('/app/state.json').read())\n"
        "    reward = passthrough(state)\n"
        "    return reward\n"
    )
    report = run_checks(task_factory(files), load_settings(None, None, None))
    assert statuses(report, "EC054") in (["WARN"], ["FAIL"])


def test_ec054_cross_file_source_helper_is_agent_controlled(task_factory):
    # The read happens in another module; the caller parses its return
    # value straight into the reward.
    files = dict(BASIC)
    files["tests/io_helpers.py"] = (
        "def read_state():\n"
        "    return open('/app/state.json').read()\n"
    )
    files["tests/verifier.py"] = (
        "from io_helpers import read_state\n"
        "def verify(response=None, task_data=None):\n"
        "    return float(read_state())\n"
    )
    report = run_checks(task_factory(files), load_settings(None, None, None))
    assert statuses(report, "EC054") == ["FAIL"]


def test_ec065_http_resources_server_probe(tmp_path):
    import json as _json
    import threading
    from http.server import BaseHTTPRequestHandler, HTTPServer

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):  # noqa: N802 - stdlib handler API
            length = int(self.headers.get("Content-Length", "0"))
            body = _json.loads(self.rfile.read(length) or b"{}")
            reward = 1.0 if body.get("response") == "42" else 0.0
            payload = _json.dumps({"reward": reward}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        def log_message(self, *args):  # silence test output
            pass

    server = HTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        endpoint = f"http://127.0.0.1:{server.server_port}/verify?token=secret"
        task = tmp_path / "nemo-http"
        task.mkdir()
        (task / "dataset.toml").write_text("[dataset]\nname = \"nemo-http\"\n", encoding="utf-8")
        (task / "rows.jsonl").write_text(
            _json.dumps({"question": "What is 6*7?", "expected_answer": "42"}) + "\n",
            encoding="utf-8")
        settings = load_settings(None, None, {"nemo_endpoint": endpoint, "enable": ["EC065"]})
        report = run_checks(task, settings)
        assert statuses(report, "EC065") == ["PASS"]
        evidence = by_id(report)["EC065"][0]["evidence"]
        assert evidence["runner"] == "http resources server"
        assert "token" not in evidence["endpoint"]
    finally:
        server.shutdown()
        server.server_close()


def test_ec065_http_error_on_mutant_counts_as_rejection(tmp_path):
    """A grader that refuses to score a wrong answer awarded no reward: rejection."""
    import json as _json
    import threading
    from http.server import BaseHTTPRequestHandler, HTTPServer

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):  # noqa: N802 - stdlib handler API
            length = int(self.headers.get("Content-Length", "0"))
            body = _json.loads(self.rfile.read(length) or b"{}")
            if body.get("response") != "42":
                self.send_response(422)
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            payload = _json.dumps({"reward": 1.0}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        def log_message(self, *args):  # silence test output
            pass

    server = HTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        endpoint = f"http://127.0.0.1:{server.server_port}/verify"
        task = tmp_path / "nemo-http-err"
        task.mkdir()
        (task / "dataset.toml").write_text("[dataset]\nname = \"nemo-http-err\"\n", encoding="utf-8")
        (task / "rows.jsonl").write_text(
            _json.dumps({"question": "q", "expected_answer": "42"}) + "\n", encoding="utf-8")
        settings = load_settings(None, None, {"nemo_endpoint": endpoint, "enable": ["EC065"]})
        report = run_checks(task, settings)
        assert statuses(report, "EC065") == ["PASS"]
    finally:
        server.shutdown()
        server.server_close()


def test_ec065_local_verifier_raising_on_mutant_counts_as_rejection(task_factory):
    """A verifier that raises on a wrong answer awarded no reward: rejection."""
    task = task_factory({
        "verifier.py": (
            "def verify(response=None, task_data=None):\n"
            "    if response != '42':\n"
            "        raise ValueError('cannot score this response')\n"
            "    return 1.0\n"
        ),
        "rows.jsonl": '{"question": "q", "expected_answer": "42"}\n',
    })
    settings = load_settings(None, None, {"execution": "local-python", "enable": ["EC065"]})
    report = run_checks(task, settings, adapter_name="nemo-gym")
    assert statuses(report, "EC065") == ["PASS"]


def test_config_rejects_bad_nemo_endpoint(tmp_path):
    import pytest

    from envcert.core.errors import ConfigError

    cfg = tmp_path / "envcert.toml"
    cfg.write_text("[checks.nemo]\nendpoint = \"ftp://example.com/verify\"\n", encoding="utf-8")
    with pytest.raises(ConfigError):
        load_settings(cfg, None, None)


def test_js_mutation_sites_skip_comments_strings_and_regex():
    from envcert.checks.mutation_js import mutation_sites

    src = ("// a + b\n/* c - d */\nconst s = 'a + b';\n"
           "const r = /a+b/g;\nconst x = 1 + 2;\n")
    descriptions = [site.description for site in mutation_sites(src)]
    assert len([d for d in descriptions if d.startswith("operator +")]) == 1
    assert any(d.startswith("string") for d in descriptions)
    assert any(d.startswith("number 1 -> 2") for d in descriptions)


def test_ec063_js_mutation_rejects_wrong_solutions(task_factory):
    if shutil.which("node") is None:
        import pytest

        pytest.skip("node not available")
    files = dict(BASIC)
    files["solution/add.js"] = (
        "function add(a, b) {\n"
        "  return a + b + 1 - 1;\n"
        "}\n"
        "module.exports = { add };\n"
    )
    files["tests/add.test.js"] = (
        "const assert = require('assert');\n"
        "const { add } = require('../solution/add.js');\n"
        "assert.strictEqual(add(2, 3), 5);\n"
    )
    settings = load_settings(None, None, {
        "execution": "local-python", "mutation": True, "enable": ["EC063"]})
    report = run_checks(task_factory(files), settings)
    assert statuses(report, "EC063") == ["PASS"]
    ev = by_id(report)["EC063"][0]["evidence"]
    assert ev["language"] == "js"
    assert ev["rejected"] >= 1
    assert ev["rejection_rate"] == 1.0


def test_ec056_flags_eval_and_pickle_in_verifier(task_factory):
    task = _task_with_verifier(task_factory, (
        "import pickle\n"
        "def verify(response=None, task_data=None):\n"
        "    data = pickle.loads(open('submission.pkl', 'rb').read())\n"
        "    return 1.0 if eval(str(data)) else 0.0\n"
    ))
    report = run_checks(task, load_settings(None, None, None))
    assert statuses(report, "EC056") == ["WARN"]


def test_ec052_guarded_echo_not_unconditional(task_factory):
    # BASIC test.sh writes echo 1 inside an if/else: not unconditional.
    report = run_checks(task_factory(dict(BASIC)), load_settings(None, None, None))
    assert statuses(report, "EC052") == ["PASS"]


def test_ec052_unconditional_echo_despite_other_conditionals(task_factory):
    files = dict(BASIC)
    files["tests/test.sh"] = (
        "#!/bin/bash\n"
        "if [ -f /app/maybe.txt ]; then echo present; fi\n"
        "echo 1 > /logs/verifier/reward.txt\n"
    )
    report = run_checks(task_factory(files), load_settings(None, None, None))
    assert statuses(report, "EC052") == ["FAIL"]


def test_ec012_instruction_referenced_input_not_flagged(task_factory):
    files = dict(BASIC)
    files["instruction.md"] = "# Do a thing\n\nRead environment/expected_output_format.txt for the required format, then create the output.\n"
    files["environment/expected_output_format.txt"] = "key=value\n"
    report = run_checks(task_factory(files), load_settings(None, None, None))
    assert statuses(report, "EC012") == ["PASS"]


# ---------------------------------------------------------------- dataset

def _write_jsonl(path, rows):
    path.write_text("\n".join(json.dumps(r) for r in rows) + "\n", encoding="utf-8")
    return path


def test_dataset_clean_file_passes(tmp_path):
    data = _write_jsonl(tmp_path / "eval.jsonl", [
        {"id": "1", "prompt": "What is 2+2?", "answer": "4"},
        {"id": "2", "prompt": "Capital of France?", "answer": "Paris"},
        {"id": "3", "prompt": "Colour of the sky on a clear day?", "answer": "blue"},
    ])
    assert main(["check", str(data)]) == 0


def test_dataset_answer_leak_detected(tmp_path, capsys):
    data = _write_jsonl(tmp_path / "eval.jsonl", [
        {"id": "1", "prompt": "Repeat after me: the answer is Paris", "answer": "Paris"},
        {"id": "2", "prompt": "What is 2+2?", "answer": "4"},
    ])
    rc = main(["check", str(data), "--format", "json", "--output", str(tmp_path / "r.json")])
    report = json.loads((tmp_path / "r.json").read_text(encoding="utf-8"))
    assert statuses(report, "EC080") == ["WARN"]
    assert rc == 1  # HIGH warning fails default policy


def test_dataset_duplicates_and_degenerate_labels(tmp_path):
    data = _write_jsonl(tmp_path / "train.jsonl", [
        {"id": "1", "prompt": "same prompt here", "label": "yes"},
        {"id": "1", "prompt": "same prompt here", "label": "yes"},
        {"id": "2", "prompt": "another prompt entirely", "label": "yes"},
        {"id": "3", "prompt": "third distinct prompt", "label": "yes"},
        {"id": "4", "prompt": "fourth distinct prompt", "label": "yes"},
        {"id": "5", "prompt": "fifth distinct prompt", "label": "yes"},
    ])
    report = run_checks(data, load_settings(None, None, None), adapter_name="dataset")
    assert report["environment"]["adapter"] == "dataset"
    assert statuses(report, "EC081") == ["WARN"]
    assert statuses(report, "EC083") == ["WARN"]


def test_dataset_semantic_near_duplicate_detected(tmp_path):
    # Reordered/lightly reworded prompts: 5-gram Jaccard misses these, the
    # deterministic TF-IDF cosine catches them (issue #2).
    data = _write_jsonl(tmp_path / "eval.jsonl", [
        {"id": "1", "prompt": "Calculate the total of the given numbers and return the sum.", "answer": "42"},
        {"id": "2", "prompt": "Return the sum by calculating the total of the numbers given.", "answer": "43"},
        {"id": "3", "prompt": "Name the capital city of France.", "answer": "Paris"},
    ])
    report = run_checks(data, load_settings(None, None, None), adapter_name="dataset")
    assert statuses(report, "EC081") == ["WARN"]
    ev = by_id(report)["EC081"][0]["evidence"]
    assert ev["semantic_duplicate_pairs_sampled"] >= 1
    assert ev["semantic_conflicting_label_pairs"] >= 1
    assert ev["semantic_examples"][0]["similarity"] >= 0.82


def test_dataset_distinct_prompts_have_no_semantic_duplicates(tmp_path):
    data = _write_jsonl(tmp_path / "eval.jsonl", [
        {"id": "1", "prompt": "Summarise the causes of the French Revolution.", "answer": "a"},
        {"id": "2", "prompt": "Compute the derivative of x squared plus three x.", "answer": "b"},
        {"id": "3", "prompt": "Translate this sentence into German.", "answer": "c"},
    ])
    report = run_checks(data, load_settings(None, None, None), adapter_name="dataset")
    ev = by_id(report)["EC081"][0]["evidence"]
    assert ev["semantic_duplicate_pairs_sampled"] == 0


def test_dataset_semantic_detects_paraphrase_of_long_prompt(tmp_path):
    """Realistic case: a long prompt, lightly reworded and reordered."""
    sentences = [
        "The parser raises an unexpected error when the configuration file is empty.",
        "It happens during the first validation pass of the loader.",
        "The traceback points at the default value branch of the settings class.",
        "This regression appeared after the options were moved to a new module.",
        "A workaround is to pass an explicit fallback list on the command line.",
    ]
    original = "\n\n".join(sentences)
    paraphrased = "\n\n".join([sentences[1], sentences[0].replace("raises an unexpected error",
                                                                 "fails with an unexpected failure"),
                                sentences[2], sentences[3], sentences[4]])
    data = _write_jsonl(tmp_path / "eval.jsonl", [
        {"id": "1", "prompt": original, "answer": "patch-a"},
        {"id": "2", "prompt": paraphrased, "answer": "patch-b"},
        {"id": "3", "prompt": "Summarise the causes of the French Revolution.", "answer": "c"},
        {"id": "4", "prompt": "Compute the derivative of x squared plus three x.", "answer": "d"},
    ])
    report = run_checks(data, load_settings(None, None, None), adapter_name="dataset")
    assert statuses(report, "EC081") == ["WARN"]
    ev = by_id(report)["EC081"][0]["evidence"]
    assert ev["semantic_duplicate_pairs_sampled"] >= 1
    assert ev["semantic_conflicting_label_pairs"] >= 1


def test_dataset_split_overlap(tmp_path):
    _write_jsonl(tmp_path / "train.jsonl", [{"prompt": "shared question text", "answer": "a"}])
    _write_jsonl(tmp_path / "test.jsonl", [{"prompt": "shared question text", "answer": "a"},
                                          {"prompt": "unique test question", "answer": "b"}])
    report = run_checks(tmp_path, load_settings(None, None, None), adapter_name="dataset")
    assert statuses(report, "EC082") == ["WARN"]


def test_dataset_broken_rows(tmp_path):
    (tmp_path / "eval.jsonl").write_text('{"prompt": "ok?", "answer": "x"}\n{not json}\n{}\n', encoding="utf-8")
    report = run_checks(tmp_path / "eval.jsonl", load_settings(None, None, None), adapter_name="dataset")
    assert statuses(report, "EC084") == ["WARN"]


def test_nemo_directory_still_uses_nemo_adapter(tmp_path):
    (tmp_path / "verifier.py").write_text("def verify(response=None, task_data=None):\n    return 1.0\n", encoding="utf-8")
    _write_jsonl(tmp_path / "rows.jsonl", [{"prompt": "q", "expected_answer": "a"}])
    report = run_checks(tmp_path, load_settings(None, None, None))
    assert report["environment"]["adapter"] == "nemo-gym"


# ---------------------------------------------------------------- cheat battery

def _python_task(tmp_path, test_body: str, solution: str):
    root = tmp_path / "ptask"
    (root / "tests").mkdir(parents=True)
    (root / "solution").mkdir(parents=True)
    (root / "tests" / "test_solution.py").write_text(test_body, encoding="utf-8")
    (root / "solution" / "solution.py").write_text(solution, encoding="utf-8")
    return root


STRONG_TEST = (
    "from solution import add\n\n"
    "def test_add():\n"
    "    assert add(2, 3) == 5\n"
    "    assert add(-1, 1) == 0\n"
    "    assert add(10, 5) == 15\n"
)
GOLD_SOLUTION = "def add(a, b):\n    return a + b\n"


def test_cheat_battery_rejects_stub_for_strong_verifier(tmp_path):
    root = _python_task(tmp_path, STRONG_TEST, GOLD_SOLUTION)
    settings = load_settings(None, None, {"execution": "local-python", "enable": ["EC060", "EC066"]})
    report = run_checks(root, settings)
    assert statuses(report, "EC066") == ["PASS"]


def test_cheat_battery_proves_weak_verifier(tmp_path):
    # Existence-only verifier: the stub module imports fine, so it passes.
    weak_test = "import solution\n\ndef test_exists():\n    assert solution is not None\n"
    root = _python_task(tmp_path, weak_test, GOLD_SOLUTION)
    settings = load_settings(None, None, {"execution": "local-python", "enable": ["EC060", "EC066"]})
    report = run_checks(root, settings)
    assert statuses(report, "EC066") == ["FAIL"]


def test_cheat_battery_not_run_by_default(tmp_path):
    root = _python_task(tmp_path, STRONG_TEST, GOLD_SOLUTION)
    report = run_checks(root, load_settings(None, None, None))
    assert statuses(report, "EC066") == ["NOT_RUN"]


def test_ec085_swebench_grading_spec(tmp_path):
    data = _write_jsonl(tmp_path / "instances.jsonl", [
        {"instance_id": "a", "problem_statement": "Fix the bug in module x", "patch": "diff...", "FAIL_TO_PASS": '["test_one"]', "PASS_TO_PASS": '["test_two"]'},
        {"instance_id": "b", "problem_statement": "Fix the bug in module y", "patch": "diff...", "FAIL_TO_PASS": "[]", "PASS_TO_PASS": '["test_two"]'},
        {"instance_id": "c", "problem_statement": "Fix the bug in module z", "patch": "diff...", "FAIL_TO_PASS": '["test_one"]', "PASS_TO_PASS": '["test_one"]'},
    ])
    report = run_checks(data, load_settings(None, None, None), adapter_name="dataset")
    assert statuses(report, "EC085") == ["WARN"]


def test_ec085_not_applicable_without_grading_fields(tmp_path):
    data = _write_jsonl(tmp_path / "eval.jsonl", [{"prompt": "q?", "answer": "a"}])
    report = run_checks(data, load_settings(None, None, None), adapter_name="dataset")
    assert statuses(report, "EC085") == ["NOT_APPLICABLE"]


def test_ec080_answer_in_hints_text(tmp_path):
    data = _write_jsonl(tmp_path / "instances.jsonl", [
        {"instance_id": "a", "problem_statement": "Fix it", "hints_text": "the expected output is correct-horse-battery", "patch": "correct-horse-battery"},
    ])
    report = run_checks(data, load_settings(None, None, None), adapter_name="dataset")
    assert statuses(report, "EC080") == ["WARN"]


def test_ec061_standalone_establishes_gold(tmp_path):
    root = _python_task(tmp_path, STRONG_TEST, GOLD_SOLUTION)
    settings = load_settings(None, None, {"execution": "local-python", "enable": ["EC061"]})
    report = run_checks(root, settings)
    assert statuses(report, "EC061") == ["PASS"]


def test_ec061_standalone_inconclusive_when_gold_broken(tmp_path):
    root = _python_task(tmp_path, STRONG_TEST, "def add(a, b):\n    return a - b\n")
    settings = load_settings(None, None, {"execution": "local-python", "enable": ["EC061"]})
    report = run_checks(root, settings)
    assert statuses(report, "EC061") == ["NOT_APPLICABLE"]


def test_rollup_markdown_format(tmp_path, capsys):
    assert main(["check", "examples/dataset-rollup", "--dataset", "--format", "markdown"]) in (0, 1)
    out = capsys.readouterr().out
    assert out.startswith("## EnvCert") and "| Task |" in out


def test_max_mutants_setting_validated():
    from envcert.core.errors import ConfigError

    try:
        load_settings(None, None, {"max_mutants": 0})
    except ConfigError:
        pass
    else:
        raise AssertionError("max_mutants=0 must be rejected")
    assert load_settings(None, None, {"max_mutants": 25}).max_mutants == 25


def test_dataset_csv_and_json_array_formats(tmp_path):
    csv_path = tmp_path / "eval.csv"
    csv_path.write_text("prompt,answer\nWhat is 2+2?,4\nCapital of France?,Paris\n", encoding="utf-8")
    report = run_checks(csv_path, load_settings(None, None, None), adapter_name="dataset")
    assert statuses(report, "EC001") == ["PASS"]
    json_path = tmp_path / "eval.json"
    json_path.write_text(json.dumps([{"question": "q one here", "target": "a"}, {"question": "q two here", "target": "b"}]), encoding="utf-8")
    report = run_checks(json_path, load_settings(None, None, None), adapter_name="dataset")
    assert statuses(report, "EC084") == ["PASS"]


def test_scaffold_refuses_nonempty_destination(tmp_path):
    dest = tmp_path / "occupied"
    dest.mkdir()
    (dest / "file.txt").write_text("x", encoding="utf-8")
    assert main(["new", str(dest)]) == 2


def test_fix_no_fixes_for_clean_task(capsys):
    assert main(["fix", "examples/safe-environment"]) == 0
    assert "no deterministic fixes" in capsys.readouterr().out


def test_plugin_checks_load_via_entry_points(tmp_path, monkeypatch):
    import envcert.core.engine as engine
    from envcert.checks.base import REGISTRY

    plugin = tmp_path / "myplugin.py"
    plugin.write_text(
        "from envcert.checks.base import CheckInfo, check, passed\n"
        "from envcert.core.models import Severity\n"
        "INFO = CheckInfo('EC900', 'Plugin demo check', 'plugin', Severity.LOW, 'demo', 'none')\n"
        "@check(INFO)\n"
        "def demo(c):\n"
        "    return [passed(INFO, 'plugin ran')]\n",
        encoding="utf-8")

    monkeypatch.syspath_prepend(str(tmp_path))
    monkeypatch.setattr(engine, "_PLUGINS_LOADED", False)
    monkeypatch.setattr(engine, "PLUGIN_LOAD_ERRORS", [])

    class FakeEP:
        name = "demo"

        def load(self):
            import myplugin  # noqa: F401
            return myplugin

    import importlib.metadata as md

    monkeypatch.setattr(md, "entry_points", lambda group=None: [FakeEP()])
    try:
        assert engine.load_plugin_checks() == []
        assert "EC900" in REGISTRY
        report = run_checks("examples/safe-environment", load_settings(None, None, {"enable": ["EC900"]}))
        assert statuses(report, "EC900") == ["PASS"]
    finally:
        REGISTRY.pop("EC900", None)


def test_dataset_streaming_beyond_text_cap(tmp_path):
    # A JSONL far past the 2MB bundle-text cap must be audited in full,
    # not silently truncated to its head.
    data = tmp_path / "big.jsonl"
    filler = "x" * 3000
    with data.open("w", encoding="utf-8") as fh:
        for i in range(900):
            fh.write(json.dumps({"id": str(i), "prompt": f"unique question {i} {filler}", "answer": f"a{i}"}) + "\n")
    assert data.stat().st_size > 2_000_000
    report = run_checks(data, load_settings(None, None, None), adapter_name="dataset")
    ec001 = by_id(report)["EC001"][0]
    assert "900 rows" in ec001["description"]
    assert statuses(report, "EC084") == ["PASS"]


def test_inspect_scorer_in_sibling_module_is_analysed(tmp_path):
    root = tmp_path / "myeval"
    root.mkdir()
    (root / "myeval.py").write_text(
        "from inspect_ai import Task, task\n"
        "from inspect_ai.dataset import MemoryDataset, Sample\n"
        "from inspect_ai.solver import generate\n"
        "from scorer import strict_scorer\n\n"
        "@task\n"
        "def myeval():\n"
        "    return Task(dataset=MemoryDataset([Sample(input='q', target='a')]), solver=generate(), scorer=strict_scorer())\n",
        encoding="utf-8")
    (root / "scorer.py").write_text(
        "from inspect_ai.scorer import scorer, Score, Target\n\n"
        "@scorer(metrics={'accuracy': 'mean'})\n"
        "def strict_scorer():\n"
        "    async def score(state, target):\n"
        "        assert state.output.completion.strip() == target.text\n"
        "        return Score(value=1.0)\n"
        "    return score\n",
        encoding="utf-8")
    report = run_checks(root, load_settings(None, None, None), adapter_name="inspect")
    assert statuses(report, "EC053") == ["PASS"]


def test_dataset_example_files_pass():
    assert main(["check", "examples/dataset-files"]) == 0


def test_docker_cheat_solve_steps_are_deterministic():
    from envcert.runners.docker_runner import DockerRunner

    forge = DockerRunner._solve_step("cheat-reward-forge")
    assert "reward.txt" in forge and "echo 1" in forge
    tamper = DockerRunner._solve_step("cheat-test-tamper")
    assert "test.sh" in tamper
    assert DockerRunner._solve_step("noop") != DockerRunner._solve_step("gold")


# ---------------------------------------------------------------- fix / new

def test_fix_dockerignore_dry_run_then_apply(tmp_path):
    files = dict(BASIC)
    files["environment/.git/config"] = "[core]\n"
    files["environment/solution.py"] = "print('gold')\n"
    from tests.conftest import make_task

    root = make_task(tmp_path, files)
    assert main(["fix", str(root)]) == 0
    assert not (root / "environment" / ".dockerignore").exists()
    assert main(["fix", str(root), "--apply"]) == 0
    content = (root / "environment" / ".dockerignore").read_text(encoding="utf-8")
    assert ".git" in content
    report = run_checks(root, load_settings(None, None, None))
    assert statuses(report, "EC010") == ["PASS"]
    assert statuses(report, "EC011") == ["PASS"]


def test_fix_handles_crlf_task_toml(tmp_path):
    files = dict(BASIC)
    files["task.toml"] = BASIC["task.toml"].replace("\n", "\r\n")
    from tests.conftest import make_task

    root = make_task(tmp_path, files)
    # BASIC already declares both policies, so remove declarations to fix.
    (root / "task.toml").write_bytes(
        b'schema_version = "1.4"\r\n[task]\r\nname = "t/t"\r\n[verifier]\r\ntimeout_sec = 120.0\r\n[environment]\r\ndocker_image = "python:3.12"\r\n')
    assert main(["fix", str(root), "--apply"]) == 0
    import tomllib

    with (root / "task.toml").open("rb") as fh:
        parsed = tomllib.load(fh)
    assert parsed["environment"]["network_mode"] == "no-network"
    assert parsed["verifier"]["environment_mode"] == "separate"
    assert main(["check", str(root)]) in (0, 1)  # parses, no exit-2 TOML error


def test_new_scaffold_passes_check(tmp_path):
    dest = tmp_path / "my-task"
    assert main(["new", str(dest), "--name", "envcert/my-task"]) == 0
    assert main(["check", str(dest)]) == 0


# ---------------------------------------------------------------- formats

def test_markdown_and_html_formats(tmp_path, capsys):
    out_md = tmp_path / "r.md"
    assert main(["check", "examples/safe-environment", "--format", "markdown", "--output", str(out_md)]) == 0
    md = out_md.read_text(encoding="utf-8")
    assert md.startswith("## EnvCert") and "EC011" in md
    out_html = tmp_path / "r.html"
    assert main(["check", "examples/safe-environment", "--format", "html", "--output", str(out_html)]) == 0
    html = out_html.read_text(encoding="utf-8")
    assert html.startswith("<!DOCTYPE html>") and "envcert/hello-file" in html
