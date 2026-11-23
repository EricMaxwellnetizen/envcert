"""Tests for the 0.4.5 additions: HTTP verifier probing, JS/TS mutation."""
import json

import pytest
from test_v4_features import BASIC, by_id, statuses  # noqa: F401

from envcert.checks.mutation_js import mutation_sites, run_js_mutation
from envcert.core.config import load_settings
from envcert.core.engine import run_checks
from envcert.runners.nemo_probe import probe_http_verifier

# --------------------------------------------------------------- HTTP probe

class _Server:
    """Tiny HTTP resources server used by the probe tests."""

    def __init__(self, handler):
        import threading
        from http.server import HTTPServer

        self.handler = handler
        self.server = HTTPServer(("127.0.0.1", 0), handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.server.server_port}/verify"

    def close(self):
        self.server.shutdown()
        self.server.server_close()


def _make_task(tmp_path, rows=1):
    task = tmp_path / "nemo-http"
    task.mkdir(exist_ok=True)
    (task / "dataset.toml").write_text('[dataset]\nname = "nemo-http"\n', encoding="utf-8")
    data = [{"question": f"q{i}", "expected_answer": f"a{i}"} for i in range(rows)]
    (task / "rows.jsonl").write_text("\n".join(json.dumps(r) for r in data) + "\n", encoding="utf-8")
    return task


def test_http_probe_reports_unreadable_dataset(tmp_path):
    result = probe_http_verifier("http://127.0.0.1:1/verify", tmp_path, "missing.jsonl")
    assert result.ok is False
    assert "unreadable" in (result.error or "")


def test_http_probe_without_reward_field_is_inconclusive(tmp_path):
    from http.server import BaseHTTPRequestHandler

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):  # noqa: N802 - stdlib handler API
            length = int(self.headers.get("Content-Length", "0"))
            self.rfile.read(length)
            payload = b'{"ok": true}'
            self.send_response(200)
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        def log_message(self, *args):
            pass

    server = _Server(Handler)
    try:
        task = _make_task(tmp_path)
        result = probe_http_verifier(server.url, task, "rows.jsonl")
        assert result.ok is False
    finally:
        server.close()


def test_http_probe_sends_configured_headers(tmp_path):
    from http.server import BaseHTTPRequestHandler

    seen = {}

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):  # noqa: N802 - stdlib handler API
            length = int(self.headers.get("Content-Length", "0"))
            self.rfile.read(length)
            seen["auth"] = self.headers.get("Authorization")
            payload = b'{"reward": 1.0}'
            self.send_response(200)
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        def log_message(self, *args):
            pass

    server = _Server(Handler)
    try:
        task = _make_task(tmp_path)
        result = probe_http_verifier(server.url, task, "rows.jsonl",
                                     headers={"Authorization": "Bearer secret"})
        assert result.reward is not None
        assert seen["auth"] == "Bearer secret"
    finally:
        server.close()


def test_http_probe_unreachable_endpoint_yields_error_finding(tmp_path):
    task = _make_task(tmp_path)
    settings = load_settings(None, None, {"nemo_endpoint": "http://127.0.0.1:1/verify",
                                          "enable": ["EC065"]})
    report = run_checks(task, settings)
    assert statuses(report, "EC065") == ["ERROR"]


def test_config_nemo_headers_must_be_strings(tmp_path):
    from envcert.core.errors import ConfigError

    cfg = tmp_path / "envcert.toml"
    cfg.write_text('[checks.nemo]\nendpoint = "https://example.com/v"\nheaders = { A = 1 }\n',
                   encoding="utf-8")
    with pytest.raises(ConfigError):
        load_settings(cfg, None, None)


def test_config_nemo_endpoint_from_file(tmp_path):
    cfg = tmp_path / "envcert.toml"
    cfg.write_text('[checks.nemo]\nendpoint = "https://example.com/verify"\n'
                   'headers = { Authorization = "Bearer x" }\n', encoding="utf-8")
    settings = load_settings(cfg, None, None)
    assert settings.nemo_endpoint == "https://example.com/verify"
    assert settings.nemo_headers == {"Authorization": "Bearer x"}


def test_cli_rejects_bad_nemo_endpoint(tmp_path):
    from envcert.cli.main import main

    task = _make_task(tmp_path)
    rc = main(["check", str(task), "--nemo-endpoint", "ftp://example.com/verify"])
    assert rc == 2


# ------------------------------------------------------------- JS mutation

def test_js_mutation_without_solution_files(tmp_path):
    report = run_js_mutation(tmp_path)
    assert report["eligible"] == 0
    assert "no solution" in report["notes"]


def test_js_mutation_without_tests(tmp_path):
    (tmp_path / "solution").mkdir()
    (tmp_path / "solution" / "a.js").write_text("const a = 1;\n", encoding="utf-8")
    report = run_js_mutation(tmp_path)
    assert report["eligible"] == 0
    assert "no tests" in report["notes"]


def test_js_mutation_requires_node(monkeypatch, tmp_path):
    monkeypatch.setattr("envcert.checks.mutation_js.shutil.which", lambda name: None)
    report = run_js_mutation(tmp_path)
    assert report["eligible"] == 0
    assert "node" in report["error"]


def test_js_mutation_reports_failing_gold(tmp_path):
    import shutil

    if shutil.which("node") is None:
        pytest.skip("node not available")
    (tmp_path / "solution").mkdir()
    (tmp_path / "tests").mkdir()
    (tmp_path / "solution" / "a.js").write_text("module.exports = 1;\n", encoding="utf-8")
    (tmp_path / "tests" / "a.test.js").write_text(
        "const assert = require('assert');\nassert.strictEqual(require('../solution/a.js'), 2);\n",
        encoding="utf-8")
    report = run_js_mutation(tmp_path)
    assert report["eligible"] == 0
    assert "gold solution does not pass" in report["notes"]


def test_js_mutation_sites_cover_operators_booleans_and_strings():
    src = "const s = 'text'; const t = true; const n = 42; const x = a === b; const y = a && b;\n"
    descriptions = [site.description for site in mutation_sites(src)]
    assert any(d.startswith("string") for d in descriptions)
    assert any(d.startswith("boolean") for d in descriptions)
    assert any(d.startswith("number 42") for d in descriptions)
    assert any("===" in d for d in descriptions)
    assert any("&&" in d for d in descriptions)


def test_ec063_not_applicable_without_mutation_flag(task_factory):
    settings = load_settings(None, None, {"execution": "local-python", "enable": ["EC063"]})
    report = run_checks(task_factory(dict(BASIC)), settings)
    assert statuses(report, "EC063") == ["NOT_RUN"]
