from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

from envicert import __version__
from envicert.attestations.intoto import (
    build_statement,
    cosign_attest_image,
    cosign_verify_attestation,
    cosign_verify_blob,
    cosign_verify_dsse,
    dsse_envelope_unsigned,
    sign_dsse_with_cosign,
    sign_with_cosign,
    verify_statement_local,
)
from envicert.checks.base import REGISTRY
from envicert.core.config import PROFILES, load_settings
from envicert.core.engine import run_checks
from envicert.core.errors import ConfigError, EnvicertError, InvalidInputError
from envicert.core.images import parse_image_digest
from envicert.core.json_schema import validate as validate_json_schema
from envicert.core.report import (
    suppressed_findings,
    validate_baseline_suppression,
    validate_report_consistency,
)
from envicert.core.rollup import rollup_to_markdown, rollup_to_text, run_dataset_rollup
from envicert.reports.html import to_html
from envicert.reports.markdown import to_markdown
from envicert.reports.sarif import to_sarif
from envicert.reports.text import to_text

EXIT_OK, EXIT_POLICY, EXIT_INVALID, EXIT_ERROR = 0, 1, 2, 3

SCHEMA_PATH = Path(__file__).resolve().parent.parent / "schemas" / "report.schema.json"


def _schema() -> dict:
    result: dict = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    return result


def validate_report(report: dict) -> list[str]:
    """Validate against the published JSON Schema.

    The default install has no third-party dependencies, so the stdlib
    fallback implements the schema keywords used by the bundled schema rather
    than checking only a few top-level keys.  Both paths must reject the same
    structurally invalid reports.
    """
    if not isinstance(report, dict):
        return ["report root is not a JSON object"]
    try:
        import jsonschema  # type: ignore
    except ImportError:
        try:
            return validate_json_schema(report, _schema())
        except Exception as exc:  # noqa: BLE001 - a missing/broken schema must not pass
            return [f"cannot load the report schema: {type(exc).__name__}: {exc}"]
    validator = jsonschema.Draft202012Validator(_schema())
    return [f"{'/'.join(str(p) for p in e.absolute_path) or '<root>'}: {e.message}" for e in validator.iter_errors(report)]


def _write_text(path: Path, text: str) -> None:
    """Write an output file, turning filesystem errors into exit-code-2 input errors."""
    try:
        path.write_text(text, encoding="utf-8")
    except OSError as exc:
        raise InvalidInputError(f"cannot write {path}: {exc}") from exc


def _report_problems(report: dict) -> list[str]:
    """Schema + consistency problems, without repeating the same message."""
    problems = validate_report(report) + validate_report_consistency(report)
    seen: set[str] = set()
    unique: list[str] = []
    for problem in problems:
        if problem not in seen:
            seen.add(problem)
            unique.append(problem)
    return unique


def _watch_check(args, task: Path, settings) -> int:
    """Re-run the check when the bundle digest changes (Ctrl-C to stop)."""
    import time

    interval = max(1, int(getattr(args, "watch_interval", 5) or 5))
    iterations = int(getattr(args, "watch_iterations", 0) or 0)
    last_digest: str | None = None
    rc = EXIT_OK
    run = 0
    print(f"watching {task} every {interval}s (Ctrl-C to stop)")
    try:
        while True:
            run += 1
            report = run_checks(task, settings, adapter_name=args.adapter)
            digest = (report.get("environment") or {}).get("bundle_digest_sha256")
            rc = EXIT_OK if report["policy"]["passed"] else EXIT_POLICY
            if digest != last_digest:
                print(to_text(report), end="")
                last_digest = digest
            else:
                print(f"[watch] no change (digest {str(digest)[:12]}…), policy {'PASSED' if rc == 0 else 'FAILED'}")
            if iterations and run >= iterations:
                return rc
            time.sleep(interval)
    except KeyboardInterrupt:
        print("\nwatch stopped")
        return rc


def cmd_check(args) -> int:
    task = Path(args.path)
    if not task.exists():
        print(f"error: task path does not exist: {task}", file=sys.stderr)
        return EXIT_INVALID
    if task.is_file() and task.suffix.lower() not in (".jsonl", ".json", ".csv", ".parquet"):
        print(f"error: task path is not a directory (single-file input is supported for dataset files .jsonl/.json/.csv/.parquet): {task}", file=sys.stderr)
        return EXIT_INVALID
    config_path = Path(args.config) if args.config else (task / "envicert.toml" if (task / "envicert.toml").is_file() else None)
    settings = load_settings(config_path, args.profile, {
        "fail_on": [s.strip() for s in args.fail_on.split(",")] if args.fail_on else None,
        "execution": args.execution, "enable": args.enable, "disable": args.disable,
        "repetitions": args.repetitions, "mutation": args.mutation,
        "max_mutants": getattr(args, "max_mutants", None),
        "image": getattr(args, "image", None), "image_digest": getattr(args, "image_digest", None),
        "runner_command": getattr(args, "runner_command", None),
        "external_tools": getattr(args, "external_tools", False),
        "baseline": getattr(args, "baseline", None),
        "nemo_endpoint": getattr(args, "nemo_endpoint", None),
    })
    if getattr(args, "watch", False):
        if getattr(args, "dataset", False):
            print("error: --watch is per-task; run it on a single task directory", file=sys.stderr)
            return EXIT_INVALID
        if args.output:
            print("error: --watch prints to the terminal; --output is not supported with --watch", file=sys.stderr)
            return EXIT_INVALID
        return _watch_check(args, task, settings)
    if getattr(args, "dataset", False):
        if args.format in ("sarif", "html"):
            print("error: SARIF/HTML are per-task; run rollups with --format json, text or markdown (per-task reports are embedded in the JSON rollup)", file=sys.stderr)
            return EXIT_INVALID
        rollup = run_dataset_rollup(task, settings, adapter_name=args.adapter)
        if not rollup["task_folders_found"]:
            print(f"error: no task folders (task.toml) found under {task}", file=sys.stderr)
            return EXIT_INVALID
        if args.format == "json":
            out = json.dumps(rollup, indent=2)
        elif args.format == "markdown":
            out = rollup_to_markdown(rollup)
        else:
            out = rollup_to_text(rollup)
        if args.output:
            _write_text(Path(args.output), out if out.endswith("\n") else out + "\n")
            if not args.quiet:
                print(rollup_to_text(rollup), file=sys.stderr)
        else:
            print(out, end="" if out.endswith("\n") else "\n")
        return EXIT_OK if rollup["summary"]["overall_policy_passed"] else EXIT_POLICY
    report = run_checks(task, settings, adapter_name=args.adapter)
    fmt = args.format
    if fmt == "json":
        out = json.dumps(report, indent=2)
    elif fmt == "sarif":
        out = json.dumps(to_sarif(report), indent=2)
    elif fmt == "markdown":
        out = to_markdown(report)
    elif fmt == "html":
        out = to_html(report)
    else:
        out = to_text(report)
    if args.output:
        _write_text(Path(args.output), out if out.endswith("\n") else out + "\n")
        if not args.quiet:
            print(f"wrote {fmt} report to {args.output}", file=sys.stderr)
            if fmt != "text":
                print(to_text(report), file=sys.stderr)
    else:
        print(out, end="" if out.endswith("\n") else "\n")
    return EXIT_OK if report["policy"]["passed"] else EXIT_POLICY


def cmd_list_checks(args) -> int:
    for cid, (info, _fn) in sorted(REGISTRY.items()):
        kind = "dynamic" if info.dynamic else "static"
        print(f"{cid}  [{info.category}/{kind}]  default-severity={info.severity.value}  {info.title}")
        if args.verbose:
            print(f"      {info.description}")
            print(f"      remediation: {info.remediation}")
            if info.limitations:
                print(f"      limitations: {info.limitations}")
    return EXIT_OK


def cmd_explain(args) -> int:
    entry = REGISTRY.get(args.check_id.upper())
    if not entry:
        print(f"error: unknown check id {args.check_id!r}; run 'envicert list-checks'", file=sys.stderr)
        return EXIT_INVALID
    info, _fn = entry
    print(f"{info.check_id}: {info.title}")
    print(f"category: {info.category}  default severity: {info.severity.value}  dynamic: {info.dynamic}")
    print(f"description: {info.description}")
    print(f"remediation: {info.remediation}")
    print(f"limitations: {info.limitations or '(none recorded)'}")
    return EXIT_OK


def cmd_verify(args) -> int:
    path = Path(args.report)
    if not path.is_file():
        print(f"error: report not found: {path}", file=sys.stderr)
        return EXIT_INVALID
    try:
        report = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        print(f"error: report is not valid JSON: {exc}", file=sys.stderr)
        return EXIT_INVALID
    problems = _report_problems(report)
    if problems:
        print("report validation FAILED:")
        for p in problems:
            print(f"  - {p}")
        return EXIT_INVALID
    suppressed = suppressed_findings(report)
    if suppressed:
        baseline_path = Path(args.baseline) if getattr(args, "baseline", None) else None
        if baseline_path is None:
            recorded = (report.get("summary") or {}).get("baseline")
            print("report validation FAILED:", file=sys.stderr)
            print(f"  - the report suppresses {len(suppressed)} finding(s) via a baseline "
                  f"({recorded or 'baseline not recorded'}) but no baseline was supplied; "
                  f"pass --baseline {recorded or '<baseline.json>'} to verify the suppression", file=sys.stderr)
            return EXIT_INVALID
        if not baseline_path.is_file():
            print(f"error: baseline report not found: {baseline_path}", file=sys.stderr)
            return EXIT_INVALID
        try:
            baseline_report = json.loads(baseline_path.read_text(encoding="utf-8"))
        except Exception as exc:
            print(f"error: baseline report is not valid JSON: {exc}", file=sys.stderr)
            return EXIT_INVALID
        baseline_problems = validate_baseline_suppression(report, baseline_report)
        if baseline_problems:
            print("report validation FAILED (baseline suppression does not match the baseline report):")
            for p in baseline_problems:
                print(f"  - {p}")
            return EXIT_INVALID
    failures: list[str] = []
    if getattr(args, "fail_on", None) is not None:
        from envicert.core.config import parse_fail_on

        severities = parse_fail_on([s.strip() for s in args.fail_on.split(",") if s.strip()], "--fail-on")
        failing = [
            f for f in report.get("findings") or []
            if f.get("status") in ("FAIL", "WARN")
            and f.get("severity") in {s.value for s in severities}
            and not f.get("baseline_suppressed")
        ]
        errored = [f for f in report.get("findings") or [] if f.get("status") == "ERROR"]
        if failing or errored:
            failures.append(
                f"policy fails under --fail-on {args.fail_on}: {len(failing)} failing finding(s), "
                f"{len(errored)} errored check(s)"
            )
    if args.task:
        from envicert.core.digests import bundle_digest

        digest_warnings: list[str] = []
        digest, _n = bundle_digest(Path(args.task), warnings=digest_warnings)
        for warning in digest_warnings:
            print(f"note: {warning}", file=sys.stderr)
        recorded = (report.get("environment") or {}).get("bundle_digest_sha256")
        if recorded != digest:
            failures.append(
                f"bundle digest mismatch: report={recorded} recomputed={digest} (task changed since the report was generated)"
            )
    if getattr(args, "recheck", False):
        if not args.task:
            print("error: --recheck requires --task (the task directory to re-run the checks against)",
                  file=sys.stderr)
            return EXIT_INVALID
        from envicert.core.engine import recheck_report

        recheck_problems = recheck_report(report, Path(args.task))
        if recheck_problems:
            failures.extend(recheck_problems)
        else:
            print("re-check OK: the report's static findings reproduce from the task")
    if failures:
        print("report verification FAILED:")
        for f in failures:
            print(f"  - {f}")
        return EXIT_POLICY
    print(f"report OK: schema {report.get('schema_version')}, Envicert {report.get('envicert_version')}, "
          f"task {(report.get('environment') or {}).get('task_name')}, policy passed={ (report.get('policy') or {}).get('passed')}")
    print("note: this verifies report schema/consistency by recomputing policy and summary from the findings"
          + (", the bundle digest" if args.task else "")
          + ". It does NOT re-run the checks (use --recheck --task for that), does NOT verify a cryptographic"
            " signature, and a report that omits findings entirely cannot be detected without --recheck.")
    return EXIT_OK


def cmd_attest(args) -> int:
    path = Path(args.report)
    if not path.is_file():
        print(f"error: report not found: {path}", file=sys.stderr)
        return EXIT_INVALID
    raw = path.read_bytes()
    try:
        report = json.loads(raw)
    except Exception as exc:
        print(f"error: report is not valid JSON: {exc}", file=sys.stderr)
        return EXIT_INVALID
    problems = _report_problems(report)
    if problems:
        print("error: refusing to attest an invalid or inconsistent report:", file=sys.stderr)
        for p in problems:
            print(f"  - {p}", file=sys.stderr)
        return EXIT_INVALID
    suppressed = suppressed_findings(report)
    if suppressed:
        baseline_path = Path(args.baseline) if getattr(args, "baseline", None) else None
        if baseline_path is None:
            recorded = (report.get("summary") or {}).get("baseline")
            print("error: refusing to attest a report whose policy depends on unverifiable baseline suppression:",
                  file=sys.stderr)
            print(f"  - {len(suppressed)} finding(s) are marked baseline_suppressed via "
                  f"{recorded or 'an unrecorded baseline'}; pass --baseline {recorded or '<baseline.json>'} "
                  "so the suppression can be checked", file=sys.stderr)
            return EXIT_INVALID
        if not baseline_path.is_file():
            print(f"error: baseline report not found: {baseline_path}", file=sys.stderr)
            return EXIT_INVALID
        try:
            baseline_report = json.loads(baseline_path.read_text(encoding="utf-8"))
        except Exception as exc:
            print(f"error: baseline report is not valid JSON: {exc}", file=sys.stderr)
            return EXIT_INVALID
        baseline_problems = validate_baseline_suppression(report, baseline_report)
        if baseline_problems:
            print("error: refusing to attest: baseline suppression does not match the baseline report:", file=sys.stderr)
            for p in baseline_problems:
                print(f"  - {p}", file=sys.stderr)
            return EXIT_INVALID
    if getattr(args, "image", None):
        try:
            _image_name, image_digest = parse_image_digest(args.image)
        except ConfigError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return EXIT_INVALID
        report_digest = (report.get("environment") or {}).get("image_digest")
        if report_digest and image_digest != report_digest:
            print(f"error: refusing to attest {args.image!r}: its digest {image_digest} does not match the report's "
                  f"image_digest {report_digest}", file=sys.stderr)
            return EXIT_INVALID
    statement = build_statement(report, raw, signed=bool(args.dsse and args.sign))
    out_obj: object = dsse_envelope_unsigned(statement) if args.dsse else statement
    out_path = Path(args.output)
    failures: list[str] = []
    dsse_signed = False
    if args.dsse and args.sign:
        ok, msg = sign_dsse_with_cosign(out_obj, args.key)  # type: ignore[arg-type]
        print(msg)
        if ok:
            dsse_signed = True
        else:
            # Do not leave a payload claiming signed=True when signing failed.
            statement = build_statement(report, raw, signed=False)
            out_obj = dsse_envelope_unsigned(statement)
            failures.append("DSSE signing")
    _write_text(out_path, json.dumps(out_obj, indent=2) + "\n")
    if args.dsse:
        print(f"wrote {'signed' if dsse_signed else 'DSSE envelope (UNSIGNED)'} to {out_path}")
    else:
        print(f"wrote in-toto statement (unsigned) to {out_path}")
    if getattr(args, "image", None):
        import tempfile

        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False, encoding="utf-8") as tf:
            json.dump(statement["predicate"], tf)
            predicate_path = Path(tf.name)
        try:
            ok, msg = cosign_attest_image(predicate_path, args.image, args.key)
        finally:
            predicate_path.unlink(missing_ok=True)
        print(msg)
        if not ok:
            failures.append("OCI image attestation")
    print(f"predicateType: {statement['predicateType']}  result: {statement['predicate']['result']}")
    if args.sign and not args.dsse:
        ok, msg = sign_with_cosign(out_path, args.key)
        print(msg)
        if not ok:
            failures.append("signing")
    elif not args.sign:
        print("signing: not performed. To sign: install cosign and re-run with --sign [--key cosign.key], "
              "or use `cosign sign-blob`. An unsigned attestation is NOT cryptographic evidence.")
    if failures:
        print(f"error: requested {', '.join(failures)} did not complete; the statement file was written but is not "
              "cryptographically signed/attested.", file=sys.stderr)
        return EXIT_ERROR
    return EXIT_OK


def _finding_key(f: dict) -> tuple:
    # Severity is part of the identity: a LOW -> HIGH escalation at the same
    # check/path/line/status must appear as a new finding, not vanish.
    return (f.get("check_id"), f.get("path"), f.get("line"), f.get("status"), f.get("severity"))


def cmd_diff(args) -> int:
    def load(path_str: str):
        path = Path(path_str)
        if not path.is_file():
            print(f"error: report not found: {path}", file=sys.stderr)
            return None
        try:
            obj = json.loads(path.read_text(encoding="utf-8"))
        except Exception as exc:
            print(f"error: {path} is not valid JSON: {exc}", file=sys.stderr)
            return None
        if not isinstance(obj, dict):
            print(f"error: {path} root is not a JSON object", file=sys.stderr)
            return None
        for key in ("environment", "policy"):
            value = obj.get(key)
            if value is not None and not isinstance(value, dict):
                print(f"error: {path} {key} is not an object", file=sys.stderr)
                return None
        findings = obj.get("findings", [])
        if not isinstance(findings, list) or not all(isinstance(item, dict) for item in findings):
            print(f"error: {path} findings is not a list of objects", file=sys.stderr)
            return None
        for index, finding in enumerate(findings):
            for field in ("check_id", "path", "status", "severity"):
                value = finding.get(field)
                if value is not None and not isinstance(value, str):
                    print(f"error: {path} findings[{index}].{field} is not a string", file=sys.stderr)
                    return None
            line = finding.get("line")
            if line is not None and (not isinstance(line, int) or isinstance(line, bool)):
                print(f"error: {path} findings[{index}].line is not an integer", file=sys.stderr)
                return None
        return obj

    old, new = load(args.old), load(args.new)
    if old is None or new is None:
        return EXIT_INVALID
    old_keys = {_finding_key(f): f for f in old.get("findings", [])}
    new_keys = {_finding_key(f): f for f in new.get("findings", [])}
    added = [new_keys[k] for k in new_keys.keys() - old_keys.keys()]
    resolved = [old_keys[k] for k in old_keys.keys() - new_keys.keys()]
    new_bad = [f for f in added if f.get("status") in ("FAIL", "WARN") and f.get("severity") in ("CRITICAL", "HIGH")]
    if args.format == "json":
        print(json.dumps({
            "old": {"task": (old.get("environment") or {}).get("task_name"), "bundle_digest": (old.get("environment") or {}).get("bundle_digest_sha256"),
                    "policy_passed": (old.get("policy") or {}).get("passed"), "summary": old.get("summary")},
            "new": {"task": (new.get("environment") or {}).get("task_name"), "bundle_digest": (new.get("environment") or {}).get("bundle_digest_sha256"),
                    "policy_passed": (new.get("policy") or {}).get("passed"), "summary": new.get("summary")},
            "new_findings": added, "resolved_findings": resolved,
            "new_critical_or_high": len(new_bad),
        }, indent=2))
    else:
        print(f"old: {(old.get('environment') or {}).get('task_name')} policy_passed={(old.get('policy') or {}).get('passed')} digest={(old.get('environment') or {}).get('bundle_digest_sha256', '')[:12]}")
        print(f"new: {(new.get('environment') or {}).get('task_name')} policy_passed={(new.get('policy') or {}).get('passed')} digest={(new.get('environment') or {}).get('bundle_digest_sha256', '')[:12]}")
        print(f"new findings: {len(added)} ({len(new_bad)} CRITICAL/HIGH), resolved findings: {len(resolved)}")
        for f in added:
            print(f"  + {f.get('check_id')} {f.get('severity')}/{f.get('status')} {f.get('path') or ''} {f.get('title', '')}")
        for f in resolved:
            print(f"  - {f.get('check_id')} {f.get('severity')}/{f.get('status')} {f.get('path') or ''} {f.get('title', '')}")
    if args.strict and new_bad:
        return EXIT_POLICY
    return EXIT_OK


def cmd_verify_attestation(args) -> int:
    path = Path(args.attestation)
    if not path.is_file():
        print(f"error: attestation not found: {path}", file=sys.stderr)
        return EXIT_INVALID
    try:
        obj = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        print(f"error: attestation is not valid JSON: {exc}", file=sys.stderr)
        return EXIT_INVALID
    if not isinstance(obj, dict):
        print("error: attestation root is not a JSON object", file=sys.stderr)
        return EXIT_INVALID
    if getattr(args, "image", None):
        try:
            parse_image_digest(args.image)
        except ConfigError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return EXIT_INVALID
    statement = obj
    signed = False
    envelope: dict | None = None
    if "payloadType" in obj or "payload" in obj:
        import base64

        payload_type = obj.get("payloadType")
        payload = obj.get("payload")
        if not isinstance(payload_type, str) or not payload_type.startswith("application/vnd.in-toto"):
            print("error: DSSE envelope has a missing or unsupported payloadType", file=sys.stderr)
            return EXIT_INVALID
        if not isinstance(payload, str):
            print("error: DSSE payload is not a base64 string", file=sys.stderr)
            return EXIT_INVALID
        try:
            statement = json.loads(base64.b64decode(payload, validate=True))
        except Exception as exc:
            print(f"error: cannot decode DSSE payload: {exc}", file=sys.stderr)
            return EXIT_INVALID
        if not isinstance(statement, dict):
            print("error: DSSE payload is not a JSON object", file=sys.stderr)
            return EXIT_INVALID
        signatures = obj.get("signatures", [])
        if not isinstance(signatures, list):
            print("error: DSSE envelope signatures is not a list", file=sys.stderr)
            return EXIT_INVALID
        for index, signature in enumerate(signatures):
            if not isinstance(signature, dict) or not isinstance(signature.get("sig"), str) or not signature["sig"]:
                print(f"error: DSSE signature {index} is not an object with a non-empty 'sig'", file=sys.stderr)
                return EXIT_INVALID
        signed = bool(signatures)
        envelope = obj
    problems = verify_statement_local(statement)
    if problems:
        print("attestation structural verification FAILED:")
        for pr in problems:
            print(f"  - {pr}")
        return EXIT_POLICY
    if getattr(args, "report", None):
        report_path = Path(args.report)
        if not report_path.is_file():
            print(f"error: report not found: {report_path}", file=sys.stderr)
            return EXIT_INVALID
        try:
            report_digest = hashlib.sha256(report_path.read_bytes()).hexdigest()
        except OSError as exc:
            print(f"error: cannot read report {report_path}: {exc}", file=sys.stderr)
            return EXIT_INVALID
        predicate = statement.get("predicate") or {}
        recorded: set[str] = set()
        configuration_source = predicate.get("configurationSource")
        if isinstance(configuration_source, dict):
            digest = configuration_source.get("digest")
            if isinstance(digest, dict) and isinstance(digest.get("sha256"), str):
                recorded.add(digest["sha256"])
        extension = predicate.get("x-envicert")
        if isinstance(extension, dict) and isinstance(extension.get("report_digest_sha256"), str):
            recorded.add(extension["report_digest_sha256"])
        if report_digest not in recorded:
            print("attestation verification FAILED: the attestation does not bind to the supplied report.")
            print(f"  - report sha256 {report_digest} is not among the predicate report digests {sorted(recorded)}")
            return EXIT_POLICY
    signature_path = path.with_name(path.name + ".sig")
    signature_verified = False
    if signature_path.is_file():
        ok, msg = cosign_verify_blob(path, signature_path, args.key)
        print(msg)
        if not ok:
            return EXIT_POLICY
        signature_verified = True
        signed = True
    if not signature_verified and envelope is not None and envelope.get("signatures"):
        ok, msg = cosign_verify_dsse(envelope, args.key)
        print(msg)
        if ok:
            signature_verified = True
            signed = True
        elif not getattr(args, "allow_unverified_signature", False):
            print("attestation verification FAILED: embedded DSSE signatures could not be verified.")
            print("  - pass --key <cosign.pub>, or --allow-unverified-signature for structural-only inspection.")
            return EXIT_POLICY
    if args.image:
        ok, msg = cosign_verify_attestation(args.image, args.key, args.policy)
        print(msg)
        if not ok:
            return EXIT_POLICY
        print(f"attestation OK: OCI image attestation verified for {args.image}; "
              f"predicateType={statement.get('predicateType')}, result={statement['predicate'].get('result')}")
        return EXIT_OK
    if not signed:
        if not args.allow_unsigned:
            print("attestation verification FAILED: the statement/envelope carries no signatures.")
            print("  - structural validity alone is not cryptographic evidence; pass --allow-unsigned to check structure only,")
            print("    or verify a signed attestation attached to an image with --image name@sha256:...")
            return EXIT_POLICY
    elif not signature_verified and not getattr(args, "allow_unverified_signature", False):
        print("attestation verification FAILED: signatures are present but none could be verified cryptographically.")
        print("  - a signature list is not evidence by itself. Provide the detached .sig and --key, use")
        print("    --image name@sha256:..., or pass --allow-unverified-signature for structural-only inspection.")
        return EXIT_POLICY
    print(f"attestation structure OK: signed={signed}, signature_verified={signature_verified}, "
          f"predicateType={statement.get('predicateType')}, result={statement['predicate'].get('result')}, "
          f"subjects={len(statement.get('subject') or [])}")
    if not signed:
        print("note: --allow-unsigned given, so this is structural verification only; it is NOT cryptographic evidence")
    elif not signature_verified:
        print("note: --allow-unverified-signature given; the DSSE signatures were NOT verified cryptographically")
    return EXIT_OK


def cmd_fix(args) -> int:
    from envicert.core.fix import apply_fixes, plan_fixes

    task = Path(args.path)
    if not task.is_dir():
        print(f"error: fix path is not a task directory: {task}", file=sys.stderr)
        return EXIT_INVALID
    fixes = plan_fixes(task)
    if not fixes:
        print("no deterministic fixes available for this task (run 'envicert check' for findings that need manual remediation)")
        return EXIT_OK
    print(f"{'applying' if args.apply else 'planned'} {len(fixes)} deterministic fix(es) for {task}:")
    for fix in fixes:
        marker = " [needs review]" if fix.needs_review else ""
        print(f"  - {fix.check_id} {fix.path}: {fix.action}{marker}")
    if not args.apply:
        print("dry-run only: re-run with --apply to write these changes, then re-run 'envicert check'")
        return EXIT_OK
    apply_fixes(fixes)
    print("applied. Re-run 'envicert check' to verify the findings are closed and review any [needs review] change.")
    return EXIT_OK


def cmd_new(args) -> int:
    from envicert.core.scaffold import scaffold_task

    dest = Path(args.path)
    if dest.exists() and any(dest.iterdir()):
        print(f"error: scaffold destination already exists and is not empty: {dest}", file=sys.stderr)
        return EXIT_INVALID
    name = args.name or f"envicert/{dest.resolve().name}"
    written = scaffold_task(dest, name)
    print(f"scaffolded Harbor task '{name}' in {dest}:")
    for rel in written:
        print(f"  - {rel}")
    print("next: envicert check " + str(dest))
    return EXIT_OK


def cmd_init(args) -> int:
    root = Path(args.path)
    if root.exists() and not root.is_dir():
        print(f"error: init path is not a directory: {root}", file=sys.stderr)
        return EXIT_INVALID
    dest = root / "envicert.toml"
    if dest.exists() and not args.force:
        print(f"error: {dest} already exists (use --force to overwrite)", file=sys.stderr)
        return EXIT_INVALID
    if dest.exists() and dest.is_dir():
        print(f"error: {dest} is a directory, not a config file", file=sys.stderr)
        return EXIT_INVALID
    try:
        root.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        print(f"error: cannot create {root}: {exc}", file=sys.stderr)
        return EXIT_INVALID
    _write_text(dest,
                '# Envicert configuration — see docs/guides/CONFIGURATION.md\n'
                '[envicert]\nprofile = "harbor"\n\n'
                '[checks]\n# enabled = ["EC001", "EC011"]  # default: all in profile\n# disabled = ["EC031"]\n\n'
                '[checks.dynamic]\nenabled = false\nrepetitions = 3\n\n'
                '[policy]\nfail_on = ["critical", "high"]\n')
    print(f"wrote {dest}")
    return EXIT_OK


def cmd_schema(args) -> int:
    print(json.dumps(_schema(), indent=2))
    return EXIT_OK


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="envicert", description="Integrity verification and evidence for AI training/evaluation environments. Static analysis is offline and needs no Docker or account.")
    p.add_argument("--version", action="version", version=f"envicert {__version__}")
    sub = p.add_subparsers(dest="command")

    pv = sub.add_parser("version", help="print version")
    pv.set_defaults(fn=lambda a: (print(f"envicert {__version__}"), EXIT_OK)[1])

    plc = sub.add_parser("list-checks", help="list all checks with IDs, categories and severities")
    plc.add_argument("-v", "--verbose", action="store_true")
    plc.set_defaults(fn=cmd_list_checks)

    pe = sub.add_parser("explain", help="explain a single check")
    pe.add_argument("check_id")
    pe.set_defaults(fn=cmd_explain)

    pc = sub.add_parser("check", help="check a task directory")
    pc.add_argument("path", help="path to the task directory (e.g. ./my-task)")
    pc.add_argument("--profile", choices=sorted(PROFILES), default=None, help="validation profile (default: harbor, or from envicert.toml)")
    pc.add_argument("--adapter", choices=["auto", "harbor", "generic", "nemo-gym", "inspect", "dataset"], default="auto")
    pc.add_argument("--format", choices=["text", "json", "sarif", "markdown", "html"], default="text")
    pc.add_argument("--output", "-o", default=None, help="write report to this file (text summary still goes to stderr)")
    pc.add_argument("--config", default=None, help="path to envicert.toml (default: <task>/envicert.toml if present)")
    pc.add_argument("--execution", choices=["none", "docker", "local-python", "external"], default=None,
                    help="dynamic execution mode (default: none = static only). docker = restricted container run; local-python = trusted pytest tasks only, NO sandbox; external = operator's disposable-VM runner command (see --runner-command)")
    pc.add_argument("--runner-command", default=None, help="external runner executable implementing Envicert's runner protocol (execution=external)")
    pc.add_argument("--image", default=None, help="OCI image reference whose digest should be bound into the report (resolved via docker inspect, or use name@sha256:...)")
    pc.add_argument("--image-digest", default=None, help="explicit sha256:<64 hex> image digest to bind into the report/attestation")
    pc.add_argument("--external-tools", action="store_true", help="also run installed companion tools (hadolint/trivy/semgrep) as EC070-EC072")
    pc.add_argument("--baseline", default=None, help="previous JSON report; identical FAIL/WARN findings are marked baseline_suppressed and excluded from policy (shown in JSON + SARIF suppressions)")
    pc.add_argument("--dataset", action="store_true", help="treat PATH as a dataset root: run every task folder (task.toml) beneath it and emit an aggregated rollup report")
    pc.add_argument("--fail-on", default=None, help="comma-separated severities that fail policy, e.g. critical,high")
    pc.add_argument("--enable", action="append", default=None, help="only run this check ID (repeatable)")
    pc.add_argument("--disable", action="append", default=None, help="skip this check ID (repeatable)")
    pc.add_argument("--repetitions", type=int, default=None, help="repetitions for dynamic repeatability (default 3)")
    pc.add_argument("--mutation", action="store_true", help="enable mutation testing (local-python; Python/pytest or JS/TS node tasks)")
    pc.add_argument("--max-mutants", type=int, default=None, help="mutant budget for mutation testing (1-200, default 10)")
    pc.add_argument("--nemo-endpoint", default=None,
                    help="NeMo Gym Resources-Server URL for HTTP verifier probing (EC065; sends gold/mutated answers to the endpoint)")
    pc.add_argument("--quiet", action="store_true", help="suppress the stderr summary when --output is used")
    pc.add_argument("--watch", action="store_true", help="re-run the check whenever the task bundle changes (terminal output, Ctrl-C to stop)")
    pc.add_argument("--watch-interval", type=int, default=5, help="seconds between watch polls (default 5)")
    pc.add_argument("--watch-iterations", type=int, default=0, help=argparse.SUPPRESS)
    pc.set_defaults(fn=cmd_check)

    pver = sub.add_parser("verify", help="validate a JSON report against the published schema, recompute policy/summary, and optionally re-check the task")
    pver.add_argument("report")
    pver.add_argument("--task", default=None, help="task directory to recompute the bundle digest from")
    pver.add_argument("--baseline", default=None,
                      help="baseline report the report claims to rely on (required when the report suppresses findings)")
    pver.add_argument("--recheck", action="store_true",
                      help="re-run the report's static checks against --task and compare the findings")
    pver.add_argument("--fail-on", default=None,
                      help="evaluate the policy under these severities (comma-separated) instead of the report's own fail_on")
    pver.set_defaults(fn=cmd_verify)

    pa = sub.add_parser("attest", help="create an in-toto Test Result attestation from a JSON report")
    pa.add_argument("report")
    pa.add_argument("--output", "-o", default="attestation.json")
    pa.add_argument("--dsse", action="store_true", help="wrap the statement in a DSSE envelope (unsigned unless --sign succeeds)")
    pa.add_argument("--sign", action="store_true", help="sign with cosign sign-blob if cosign is installed")
    pa.add_argument("--image", default=None, help="also attach the attestation to this OCI image (name@sha256:<digest>) via cosign attest; requires cosign")
    pa.add_argument("--key", default=None, help="cosign private key path")
    pa.add_argument("--baseline", default=None,
                    help="baseline report the report relies on (required when the report suppresses findings)")
    pa.set_defaults(fn=cmd_attest)

    pdf = sub.add_parser("diff", help="compare two JSON reports: new vs resolved findings (trend diffing)")
    pdf.add_argument("old")
    pdf.add_argument("new")
    pdf.add_argument("--format", choices=["text", "json"], default="text")
    pdf.add_argument("--strict", action="store_true", help="exit 1 when new CRITICAL/HIGH findings appear")
    pdf.set_defaults(fn=cmd_diff)

    pva = sub.add_parser("verify-attestation", help="verify an in-toto attestation: structural checks locally, plus cosign verify-attestation with --image")
    pva.add_argument("attestation")
    pva.add_argument("--image", default=None, help="OCI image reference to verify the attestation against with cosign")
    pva.add_argument("--key", default=None, help="cosign public key (omit for keyless with permissive identity regexp)")
    pva.add_argument("--policy", default=None, help="CUE/Rego policy file passed to cosign verify-attestation")
    pva.add_argument("--allow-unsigned", action="store_true",
                     help="allow structural-only verification of an unsigned statement/envelope (never cryptographic evidence)")
    pva.add_argument("--allow-unverified-signature", action="store_true",
                     help="allow structural-only verification when a DSSE envelope lists signatures that cannot be verified locally")
    pva.add_argument("--report", default=None,
                     help="report JSON the attestation must bind to (compares sha256(report) with the predicate's recorded report digest)")
    pva.set_defaults(fn=cmd_verify_attestation)

    pfix = sub.add_parser("fix", help="plan (or with --apply, write) deterministic fixes for fixable findings (.dockerignore, declared policies)")
    pfix.add_argument("path", help="path to the task directory")
    pfix.add_argument("--apply", action="store_true", help="write the planned fixes (default is a dry-run plan)")
    pfix.set_defaults(fn=cmd_fix)

    pnew = sub.add_parser("new", help="scaffold a new Harbor task that passes Envicert's static checks")
    pnew.add_argument("path", help="directory to create the task in")
    pnew.add_argument("--name", default=None, help="task name for task.toml (default: envicert/<directory name>)")
    pnew.set_defaults(fn=cmd_new)

    pi = sub.add_parser("init", help="write a starter envicert.toml")
    pi.add_argument("path", nargs="?", default=".")
    pi.add_argument("--force", action="store_true")
    pi.set_defaults(fn=cmd_init)

    ps = sub.add_parser("schema", help="print the JSON Schema for Envicert reports")
    ps.set_defaults(fn=cmd_schema)
    return p


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if not getattr(args, "fn", None):
        parser.print_help()
        return EXIT_INVALID
    try:
        return int(args.fn(args))
    except EnvicertError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return exc.exit_code
    except BrokenPipeError:
        return EXIT_OK
    except Exception as exc:  # noqa: BLE001
        print(f"error: internal error: {type(exc).__name__}: {exc}", file=sys.stderr)
        return EXIT_ERROR


# ensure checks are registered even when CLI imported without engine
import envicert.checks.cheat_checks  # noqa: E402,F401
import envicert.checks.dataset_checks  # noqa: E402,F401
import envicert.checks.dynamic_checks  # noqa: E402,F401
import envicert.checks.external_checks  # noqa: E402,F401
import envicert.checks.static_checks  # noqa: E402,F401

if __name__ == "__main__":
    sys.exit(main())
