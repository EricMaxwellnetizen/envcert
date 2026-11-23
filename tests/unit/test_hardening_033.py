"""Regression tests for the 0.3.3 review fixes.

Covers: schema parity without jsonschema, report selection/partition binding,
recheck forgery and in-place tampering, diff severity escalation, image digest
validation, malformed input handling, config type errors, explicit enable
semantics, output-path errors, attestation report binding, and fail-closed
signature verification.
"""
import json
import sys

import pytest

from envicert.attestations.intoto import (
    build_statement,
    dsse_envelope_unsigned,
    dsse_pae,
)
from envicert.checks.base import REGISTRY
from envicert.cli.main import main, validate_report
from envicert.core.config import load_settings
from envicert.core.engine import run_checks, selected_checks
from envicert.core.report import (
    KNOWN_REGISTRY_SNAPSHOTS,
    registry_snapshot,
    validate_report_consistency,
)
from envicert.runners.external_runner import ExternalRunner

ROOT = "examples"
SAFE = f"{ROOT}/safe-environment"
VULN = f"{ROOT}/intentionally-vulnerable-environment"


def _report(tmp_path, task=SAFE, name="report.json"):
    out = tmp_path / name
    rc = main(["check", task, "--format", "json", "--output", str(out), "--quiet"])
    assert rc in (0, 1)
    return json.loads(out.read_text(encoding="utf-8"))


def _mutated(report, change):
    data = json.loads(json.dumps(report))
    change(data)
    return data


# ---------------------------------------------------------------------------
# Schema parity: the stdlib fallback must reject what jsonschema rejects.
# ---------------------------------------------------------------------------


def test_fallback_schema_rejects_structurally_invalid_reports(tmp_path, monkeypatch):
    report = _report(tmp_path)
    # Force the dependency-free path even if jsonschema is installed.
    monkeypatch.setitem(sys.modules, "jsonschema", None)
    assert validate_report(report) == []

    cases = {
        "missing generated_at": lambda r: r.pop("generated_at"),
        "generated_at not a string": lambda r: r.__setitem__("generated_at", 42),
        "missing task_name": lambda r: r["environment"].pop("task_name"),
        "invalid adapter": lambda r: r["environment"].__setitem__("adapter", "evil"),
        "warnings not a list": lambda r: r["environment"].__setitem__("warnings", "x"),
        "bad check id": lambda r: r["checks_executed"].append("FOO"),
        "not_executed not a list": lambda r: r.__setitem__("checks_not_executed", "x"),
        "finding title missing": lambda r: r["findings"][0].pop("title"),
        "finding line is a string": lambda r: r["findings"][0].__setitem__("line", "12"),
        "bad confidence": lambda r: r["findings"][0].__setitem__("confidence", "certain"),
        "policy missing": lambda r: r.pop("policy"),
        "negative file_count": lambda r: r["environment"].__setitem__("file_count", -1),
    }
    for name, change in cases.items():
        problems = validate_report(_mutated(report, change))
        assert problems, f"fallback accepted invalid report: {name}"


def test_fallback_schema_accepts_a_real_report_without_jsonschema(tmp_path, monkeypatch):
    report = _report(tmp_path)
    monkeypatch.setitem(sys.modules, "jsonschema", None)
    assert validate_report(report) == []


# ---------------------------------------------------------------------------
# Check selection must be recorded and must partition the registry.
# ---------------------------------------------------------------------------


def test_new_reports_record_selection_and_full_registry(tmp_path):
    report = _report(tmp_path)
    assert report["checks_available"] == sorted(REGISTRY)
    selection = report["execution"]["selection"]
    assert selection["enabled"] is None
    assert selection["disabled"] == []
    # None means "all categories" for the harbor profile.
    assert selection["categories"] is None or isinstance(selection["categories"], list)
    assert set(report["checks_executed"]) | set(report["checks_not_executed"]) == set(REGISTRY)
    assert not set(report["checks_executed"]) & set(report["checks_not_executed"])
    assert validate_report_consistency(report) == []


def test_report_cannot_silently_omit_checks_from_both_lists(tmp_path):
    report = _report(tmp_path)
    omitted = report["checks_executed"].pop()
    problems = validate_report_consistency(report)
    assert any("does not account for checks available" in p for p in problems), (omitted, problems)


def test_report_cannot_claim_checks_from_another_version(tmp_path):
    report = _report(tmp_path)
    report["checks_available"] = report["checks_available"] + ["EC999"]
    problems = validate_report_consistency(report)
    assert any("unknown to this Envicert version" in p for p in problems), problems


def test_registry_snapshots_are_stable():
    assert len(KNOWN_REGISTRY_SNAPSHOTS[(0, 1)]) == 28
    assert len(KNOWN_REGISTRY_SNAPSHOTS[(0, 2)]) == 33
    assert len(KNOWN_REGISTRY_SNAPSHOTS[(0, 3)]) == 35
    assert len(KNOWN_REGISTRY_SNAPSHOTS[(0, 4)]) == 43
    assert set(REGISTRY) == set(KNOWN_REGISTRY_SNAPSHOTS[(0, 4)])
    assert registry_snapshot({"envicert_version": "0.2.0"}) == KNOWN_REGISTRY_SNAPSHOTS[(0, 2)]
    assert registry_snapshot({"envicert_version": "0.3.2"}) == KNOWN_REGISTRY_SNAPSHOTS[(0, 3)]
    assert registry_snapshot({"envicert_version": "9.9.9"}) is None


def test_pre_030_reports_still_skip_partition_checks():
    old = {
        "envicert_version": "0.2.0",
        "environment": {"bundle_digest_sha256": "a" * 64, "file_count": 3},
        "execution": {"fail_on": ["CRITICAL", "HIGH"]},
        "policy": {"passed": True, "fail_on": ["CRITICAL", "HIGH"]},
        "summary": {"total_findings": 1, "by_status": {"PASS": 1}},
        "findings": [{"check_id": "EC001", "status": "PASS", "severity": "INFO"}],
        "checks_executed": ["EC001"],
        "checks_not_executed": [],
    }
    assert validate_report_consistency(old) == []


def test_explicit_enable_overrides_profile_categories():
    settings = load_settings(None, "minimal", {"enable": ["EC030"]})
    assert selected_checks(settings) == ["EC030"]
    # An explicit external check is a request to run it, not a NOT_RUN stub.
    external = load_settings(None, "minimal", {"enable": ["EC070"]})
    report = run_checks(SAFE, external)
    assert "EC070" in report["checks_executed"]
    assert report["execution"]["external_tools"] is True


def test_minimal_profile_can_enable_a_check_outside_its_categories(tmp_path):
    out = tmp_path / "r.json"
    rc = main(["check", SAFE, "--profile", "minimal", "--enable", "EC030",
               "--format", "json", "--output", str(out), "--quiet"])
    assert rc == 0
    report = json.loads(out.read_text(encoding="utf-8"))
    assert report["checks_executed"] == ["EC030"]
    assert report["execution"]["selection"]["enabled"] == ["EC030"]


# ---------------------------------------------------------------------------
# Recheck: forged subsets, tampered findings, baseline suppression.
# ---------------------------------------------------------------------------


def test_recheck_rejects_a_forged_subset_even_when_internally_consistent(tmp_path, capsys):
    report = _report(tmp_path)
    subset = _mutated(report, lambda r: r.update({
        "findings": [f for f in r["findings"] if f["check_id"] == "EC001"],
        "checks_executed": ["EC001"],
        "checks_not_executed": sorted(set(r["checks_executed"]) - {"EC001"}),
    }))
    # Recompute the summary/policy so only the selection is dishonest.
    statuses = {}
    for finding in subset["findings"]:
        statuses[finding["status"]] = statuses.get(finding["status"], 0) + 1
    subset["summary"] = {
        "total_findings": len(subset["findings"]),
        "by_status": statuses,
        "by_severity_failing": {},
        "baseline_suppressed": 0,
        "baseline": None,
    }
    subset["policy"]["passed"] = True
    path = tmp_path / "subset.json"
    path.write_text(json.dumps(subset), encoding="utf-8")

    # Without re-running checks, an internally consistent subset is accepted.
    assert main(["verify", str(path)]) == 0
    capsys.readouterr()
    # Recheck reconstructs the recorded selection and rejects the omission.
    assert main(["verify", str(path), "--task", SAFE, "--recheck"]) == 1
    out = capsys.readouterr().out
    assert "omits checks selected by its recorded configuration" in out


def test_recheck_detects_in_place_finding_tampering(tmp_path, capsys):
    report = _report(tmp_path)
    target = next(f for f in report["findings"] if f["status"] in ("PASS", "FAIL", "WARN"))
    target["description"] = "TAMPERED"
    path = tmp_path / "tampered.json"
    path.write_text(json.dumps(report), encoding="utf-8")
    assert main(["verify", str(path), "--task", SAFE, "--recheck"]) == 1
    out = capsys.readouterr().out
    assert "finding reported but not reproduced" in out


def test_recheck_accepts_a_baseline_suppressed_report(tmp_path, capsys):
    baseline = tmp_path / "baseline.json"
    baseline.write_text(json.dumps(run_checks(VULN, load_settings(None, None, None))), encoding="utf-8")
    suppressed = tmp_path / "suppressed.json"
    assert main(["check", VULN, "--baseline", str(baseline), "--format", "json",
                 "--output", str(suppressed), "--quiet"]) == 0
    assert main(["verify", str(suppressed), "--baseline", str(baseline),
                 "--task", VULN, "--recheck"]) == 0
    out = capsys.readouterr().out
    assert "re-check OK" in out


def test_recheck_rejects_a_report_that_omits_its_own_availability(tmp_path, capsys):
    report = _report(tmp_path)
    report.pop("checks_available")
    omitted = report["checks_executed"].pop()
    path = tmp_path / "no-available.json"
    path.write_text(json.dumps(report), encoding="utf-8")
    # Schema/consistency rejects the silent omission before recheck even starts.
    assert main(["verify", str(path)]) == 2
    assert omitted in capsys.readouterr().out


# ---------------------------------------------------------------------------
# Diff: severity is part of a finding's identity.
# ---------------------------------------------------------------------------


def _diff_report(severity):
    return {
        "environment": {"task_name": "t", "bundle_digest_sha256": "a" * 64},
        "policy": {"passed": False},
        "findings": [{
            "check_id": "EC011", "title": "t", "description": "d", "category": "c",
            "severity": severity, "status": "FAIL", "path": "Dockerfile", "line": 1,
        }],
    }


def test_diff_counts_a_low_to_high_escalation(tmp_path, capsys):
    old = tmp_path / "old.json"
    new = tmp_path / "new.json"
    old.write_text(json.dumps(_diff_report("LOW")), encoding="utf-8")
    new.write_text(json.dumps(_diff_report("HIGH")), encoding="utf-8")
    assert main(["diff", str(old), str(new), "--format", "json"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["new_critical_or_high"] == 1
    assert len(payload["new_findings"]) == 1
    assert main(["diff", str(old), str(new), "--strict"]) == 1


# ---------------------------------------------------------------------------
# Image digests: malformed and contradictory references are input errors.
# ---------------------------------------------------------------------------


def test_conflicting_image_digest_is_rejected(capsys):
    rc = main(["check", SAFE, "--image", "name@sha256:" + "a" * 64,
               "--image-digest", "sha256:" + "b" * 64, "--quiet"])
    assert rc == 2
    assert "conflicts" in capsys.readouterr().err


@pytest.mark.parametrize("image", ["name@sha256:deadbeef", "name:latest"])
def test_attest_rejects_malformed_or_mutable_images(tmp_path, image, capsys):
    report = tmp_path / "report.json"
    assert main(["check", SAFE, "--format", "json", "--output", str(report), "--quiet"]) == 0
    att = tmp_path / "att.json"
    assert main(["attest", str(report), "--output", str(att), "--image", image]) == 2
    assert not att.exists()
    capsys.readouterr()


def test_verify_attestation_rejects_malformed_image_before_work(tmp_path, capsys):
    report = tmp_path / "report.json"
    assert main(["check", SAFE, "--format", "json", "--output", str(report), "--quiet"]) == 0
    att = tmp_path / "att.json"
    assert main(["attest", str(report), "--output", str(att), "--dsse"]) == 0
    assert main(["verify-attestation", str(att), "--allow-unsigned",
                 "--image", "name@sha256:deadbeef"]) == 2
    capsys.readouterr()


# ---------------------------------------------------------------------------
# Malformed JSON inputs are exit 2, never an internal error.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("payload", [
    [],
    "x",
    42,
    None,
    {"findings": "not-a-list"},
    {"environment": [], "findings": []},
    {"policy": "x", "findings": []},
    {"findings": [{"check_id": "EC001", "path": ["x"]}]},
])
def test_malformed_report_roots_are_input_errors(tmp_path, payload, capsys):
    path = tmp_path / "bad.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    assert main(["verify", str(path)]) == 2
    capsys.readouterr()
    assert main(["attest", str(path), "--output", str(tmp_path / "out.json")]) == 2
    capsys.readouterr()
    assert main(["diff", str(path), str(path)]) == 2
    capsys.readouterr()


def test_malformed_baseline_findings_are_input_errors(tmp_path, capsys):
    baseline = tmp_path / "baseline.json"
    baseline.write_text(json.dumps({"findings": "not-a-list"}), encoding="utf-8")
    assert main(["check", VULN, "--baseline", str(baseline), "--quiet"]) == 2
    assert "findings list" in capsys.readouterr().err


# ---------------------------------------------------------------------------
# Config: wrong table/field types are input errors, not crashes.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("text", [
    "checks = 5\n",
    "policy = 'x'\n",
    "execution = 'x'\n",
    "[checks]\ndynamic = 'yes'\n",
    "[checks]\ndisabled = 'EC001'\n",
    "[checks.dynamic]\nrepetitions = 'x'\n",
    "[checks.dynamic]\nrepetitions = 1.5\n",
    "[checks.dynamic]\nrepetitions = true\n",
    "[checks.dynamic]\nenabled = 'false'\n",
    "[execution]\nmode = 5\n",
    "[execution]\nrunner_command = []\n",
    "[execution]\nimage = 5\n",
])
def test_malformed_config_is_an_input_error(tmp_path, text, capsys):
    config = tmp_path / "bad.toml"
    config.write_text(text, encoding="utf-8")
    assert main(["check", SAFE, "--config", str(config), "--quiet"]) == 2
    capsys.readouterr()


def test_zero_repetitions_is_rejected_not_silently_defaulted(capsys):
    assert main(["check", f"{ROOT}/python-task", "--execution", "local-python",
                 "--repetitions", "0", "--quiet"]) == 2
    assert "repetitions" in capsys.readouterr().err


# ---------------------------------------------------------------------------
# Output paths and init.
# ---------------------------------------------------------------------------


def test_output_into_missing_directory_is_an_input_error(tmp_path, capsys):
    missing = tmp_path / "missing" / "report.json"
    assert main(["check", SAFE, "--format", "json", "--output", str(missing), "--quiet"]) == 2
    assert "cannot write" in capsys.readouterr().err


def test_attest_output_into_missing_directory_is_an_input_error(tmp_path, capsys):
    report = tmp_path / "report.json"
    assert main(["check", SAFE, "--format", "json", "--output", str(report), "--quiet"]) == 0
    assert main(["attest", str(report), "--output", str(tmp_path / "missing" / "att.json")]) == 2
    assert "cannot write" in capsys.readouterr().err


def test_init_refuses_a_file_path(tmp_path, capsys):
    target = tmp_path / "not-a-dir"
    target.write_text("x", encoding="utf-8")
    assert main(["init", str(target)]) == 2
    assert "not a directory" in capsys.readouterr().err


# ---------------------------------------------------------------------------
# Dataset selection is validated before the rollup starts.
# ---------------------------------------------------------------------------


def test_dataset_unknown_check_id_is_an_input_error(capsys):
    assert main(["check", f"{ROOT}/dataset-rollup", "--dataset", "--enable", "EC999"]) == 2
    assert "unknown check ID" in capsys.readouterr().err


# ---------------------------------------------------------------------------
# Attestation binding and signature verification.
# ---------------------------------------------------------------------------


def test_verify_attestation_binds_to_a_report(tmp_path, capsys):
    report = tmp_path / "report.json"
    assert main(["check", SAFE, "--format", "json", "--output", str(report), "--quiet"]) == 0
    att = tmp_path / "att.json"
    assert main(["attest", str(report), "--output", str(att), "--dsse"]) == 0
    assert main(["verify-attestation", str(att), "--allow-unsigned", "--report", str(report)]) == 0
    capsys.readouterr()

    data = json.loads(report.read_text(encoding="utf-8"))
    data["generated_at"] = "2020-01-01T00:00:00Z"
    other = tmp_path / "other.json"
    other.write_text(json.dumps(data), encoding="utf-8")
    assert main(["verify-attestation", str(att), "--allow-unsigned", "--report", str(other)]) == 1
    assert "does not bind" in capsys.readouterr().out


def test_fake_dsse_signature_fails_closed(tmp_path, capsys):
    report = tmp_path / "report.json"
    assert main(["check", SAFE, "--format", "json", "--output", str(report), "--quiet"]) == 0
    att = tmp_path / "att.json"
    assert main(["attest", str(report), "--output", str(att), "--dsse"]) == 0
    envelope = json.loads(att.read_text(encoding="utf-8"))
    envelope["signatures"] = [{"sig": "ZmFrZQ==", "keyid": "k"}]
    forged = tmp_path / "forged.json"
    forged.write_text(json.dumps(envelope), encoding="utf-8")

    assert main(["verify-attestation", str(forged)]) == 1
    assert "could not be verified" in capsys.readouterr().out
    assert main(["verify-attestation", str(forged), "--allow-unverified-signature"]) == 0
    out = capsys.readouterr().out
    assert "signature_verified=False" in out


def test_build_statement_excludes_baseline_suppressed_failures():
    report = {
        "envicert_version": "0.3.3",
        "schema_version": "1.0.0",
        "generated_at": "2026-01-01T00:00:00Z",
        "assurance_context": "test",
        "environment": {"task_name": "t", "bundle_digest_sha256": "a" * 64},
        "execution": {"profile": "harbor"},
        "policy": {"passed": True},
        "limitations": [],
        "findings": [{
            "check_id": "EC011", "status": "FAIL", "severity": "CRITICAL",
            "title": "t", "description": "d", "category": "c", "baseline_suppressed": True,
        }],
    }
    statement = build_statement(report, b"{}")
    assert statement["predicate"]["x-envicert"]["failing_check_ids"] == []
    assert statement["predicate"]["result"] == "PASSED"


def test_dsse_pae_matches_the_specification():
    assert dsse_pae("application/vnd.in-toto+json", b"{}") == (
        b"DSSEv1 28 application/vnd.in-toto+json 2 {}"
    )
    envelope = dsse_envelope_unsigned({"a": 1})
    assert envelope["signatures"] == []
    assert "UNSIGNED" in envelope["_envicert_note"]


def test_external_runner_reports_a_missing_command():
    info = ExternalRunner("definitely-not-a-real-runner-command-033").info()
    assert info.available is False
    assert "not found" in info.reason
