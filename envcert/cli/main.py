from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from envcert import __version__
from envcert.attestations.intoto import (
    build_statement,
    cosign_attest_image,
    cosign_verify_attestation,
    cosign_verify_blob,
    dsse_envelope_unsigned,
    sign_with_cosign,
    verify_statement_local,
)
from envcert.checks.base import REGISTRY
from envcert.core.config import PROFILES, load_settings
from envcert.core.engine import run_checks
from envcert.core.errors import EnvCertError
from envcert.core.report import (
    suppressed_findings,
    validate_baseline_suppression,
    validate_report_consistency,
)
from envcert.core.rollup import rollup_to_text, run_dataset_rollup
from envcert.reports.sarif import to_sarif
from envcert.reports.text import to_text

EXIT_OK, EXIT_POLICY, EXIT_INVALID, EXIT_ERROR = 0, 1, 2, 3

SCHEMA_PATH = Path(__file__).resolve().parent.parent / "schemas" / "report.schema.json"


def _schema() -> dict:
    result: dict = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    return result


def validate_report(report: dict) -> list[str]:
    """Validate against the published JSON Schema when jsonschema is installed;
    otherwise fall back to required-field checks (never silently pass)."""
    try:
        import jsonschema  # type: ignore
    except ImportError:
        problems = []
        for key in ("schema_version", "envcert_version", "environment", "execution", "findings", "policy", "limitations"):
            if key not in report:
                problems.append(f"missing required field: {key}")
        if report.get("schema_version") != "1.0.0":
            problems.append(f"unsupported schema_version: {report.get('schema_version')!r}")
        return problems
    validator = jsonschema.Draft202012Validator(_schema())
    return [f"{'/'.join(str(p) for p in e.absolute_path) or '<root>'}: {e.message}" for e in validator.iter_errors(report)]


def cmd_check(args) -> int:
    task = Path(args.path)
    if not task.exists():
        print(f"error: task path does not exist: {task}", file=sys.stderr)
        return EXIT_INVALID
    if not task.is_dir():
        print(f"error: task path is not a directory: {task}", file=sys.stderr)
        return EXIT_INVALID
    config_path = Path(args.config) if args.config else (task / "envcert.toml" if (task / "envcert.toml").is_file() else None)
    settings = load_settings(config_path, args.profile, {
        "fail_on": [s.strip() for s in args.fail_on.split(",")] if args.fail_on else None,
        "execution": args.execution, "enable": args.enable, "disable": args.disable,
        "repetitions": args.repetitions, "mutation": args.mutation,
        "image": getattr(args, "image", None), "image_digest": getattr(args, "image_digest", None),
        "runner_command": getattr(args, "runner_command", None),
        "external_tools": getattr(args, "external_tools", False),
        "baseline": getattr(args, "baseline", None),
    })
    if getattr(args, "dataset", False):
        if args.format == "sarif":
            print("error: SARIF is per-task; run rollups with --format json or text (per-task reports are embedded in the JSON rollup)", file=sys.stderr)
            return EXIT_INVALID
        rollup = run_dataset_rollup(task, settings, adapter_name=args.adapter)
        if not rollup["task_folders_found"]:
            print(f"error: no task folders (task.toml) found under {task}", file=sys.stderr)
            return EXIT_INVALID
        out = json.dumps(rollup, indent=2) if args.format == "json" else rollup_to_text(rollup)
        if args.output:
            Path(args.output).write_text(out if out.endswith("\n") else out + "\n", encoding="utf-8")
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
    else:
        out = to_text(report)
    if args.output:
        Path(args.output).write_text(out if out.endswith("\n") else out + "\n", encoding="utf-8")
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
        print(f"error: unknown check id {args.check_id!r}; run 'envcert list-checks'", file=sys.stderr)
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
    problems = validate_report(report) + validate_report_consistency(report)
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
        from envcert.core.config import parse_fail_on

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
        from envcert.core.digests import bundle_digest

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
        from envcert.core.engine import recheck_report

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
    print(f"report OK: schema {report.get('schema_version')}, EnvCert {report.get('envcert_version')}, "
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
    problems = validate_report(report) + validate_report_consistency(report)
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
        if "@sha256:" not in args.image:
            print(f"error: --image must be an immutable reference name@sha256:<64 hex>, got {args.image!r}", file=sys.stderr)
            return EXIT_INVALID
        image_digest = "sha256:" + args.image.rsplit("@sha256:", 1)[1]
        report_digest = (report.get("environment") or {}).get("image_digest")
        if report_digest and image_digest != report_digest:
            print(f"error: refusing to attest {args.image!r}: its digest {image_digest} does not match the report's "
                  f"image_digest {report_digest}", file=sys.stderr)
            return EXIT_INVALID
    statement = build_statement(report, raw)
    out_obj: object = dsse_envelope_unsigned(statement) if args.dsse else statement
    out_path = Path(args.output)
    out_path.write_text(json.dumps(out_obj, indent=2) + "\n", encoding="utf-8")
    print(f"wrote {'DSSE envelope (UNSIGNED)' if args.dsse else 'in-toto statement (unsigned)'} to {out_path}")
    failures: list[str] = []
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
    if args.sign:
        ok, msg = sign_with_cosign(out_path, args.key)
        print(msg)
        if not ok:
            failures.append("signing")
    else:
        print("signing: not performed. To sign: install cosign and re-run with --sign [--key cosign.key], "
              "or use `cosign sign-blob`. An unsigned attestation is NOT cryptographic evidence.")
    if failures:
        print(f"error: requested {', '.join(failures)} did not complete; the statement file was written but is not "
              "cryptographically signed/attested.", file=sys.stderr)
        return EXIT_ERROR
    return EXIT_OK


def _finding_key(f: dict) -> tuple:
    return (f.get("check_id"), f.get("path"), f.get("line"), f.get("status"))


def cmd_diff(args) -> int:
    def load(path_str: str):
        path = Path(path_str)
        if not path.is_file():
            print(f"error: report not found: {path}", file=sys.stderr)
            return None
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except Exception as exc:
            print(f"error: {path} is not valid JSON: {exc}", file=sys.stderr)
            return None

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
    statement = obj
    signed = False
    if isinstance(obj, dict) and obj.get("payload") and str(obj.get("payloadType", "")).startswith("application/vnd.in-toto"):
        import base64

        try:
            statement = json.loads(base64.b64decode(obj["payload"]))
        except Exception as exc:
            print(f"error: cannot decode DSSE payload: {exc}", file=sys.stderr)
            return EXIT_INVALID
        signatures = obj.get("signatures")
        if signatures is None:
            signatures = []
        if not isinstance(signatures, list):
            print("error: DSSE envelope signatures is not a list", file=sys.stderr)
            return EXIT_INVALID
        signed = bool(signatures)
    problems = verify_statement_local(statement)
    if problems:
        print("attestation structural verification FAILED:")
        for pr in problems:
            print(f"  - {pr}")
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
    if not signed and not args.allow_unsigned and not args.image:
        print("attestation verification FAILED: the statement/envelope carries no signatures.")
        print("  - structural validity alone is not cryptographic evidence; pass --allow-unsigned to check structure only,")
        print("    or verify a signed attestation attached to an image with --image name@sha256:...")
        return EXIT_POLICY
    print(f"attestation structure OK: signed={signed}, signature_verified={signature_verified}, "
          f"predicateType={statement.get('predicateType')}, result={statement['predicate'].get('result')}, "
          f"subjects={len(statement.get('subject') or [])}")
    if args.image:
        ok, msg = cosign_verify_attestation(args.image, args.key, args.policy)
        print(msg)
        return EXIT_OK if ok else EXIT_POLICY
    if not signed:
        print("note: --allow-unsigned given, so this is structural verification only; it is NOT cryptographic evidence")
    elif not signature_verified:
        print("note: signatures are present, but local structural verification does not verify them cryptographically; "
              "use --image name@sha256:... or cosign verify-blob with the signer's key")
    return EXIT_OK


def cmd_init(args) -> int:
    dest = Path(args.path) / "envcert.toml"
    if dest.exists() and not args.force:
        print(f"error: {dest} already exists (use --force to overwrite)", file=sys.stderr)
        return EXIT_INVALID
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(
        '# EnvCert configuration — see docs/guides/CONFIGURATION.md\n'
        '[envcert]\nprofile = "harbor"\n\n'
        '[checks]\n# enabled = ["EC001", "EC011"]  # default: all in profile\n# disabled = ["EC031"]\n\n'
        '[checks.dynamic]\nenabled = false\nrepetitions = 3\n\n'
        '[policy]\nfail_on = ["critical", "high"]\n', encoding="utf-8")
    print(f"wrote {dest}")
    return EXIT_OK


def cmd_schema(args) -> int:
    print(json.dumps(_schema(), indent=2))
    return EXIT_OK


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="envcert", description="Integrity verification and evidence for AI training/evaluation environments. Static analysis is offline and needs no Docker or account.")
    p.add_argument("--version", action="version", version=f"envcert {__version__}")
    sub = p.add_subparsers(dest="command")

    pv = sub.add_parser("version", help="print version")
    pv.set_defaults(fn=lambda a: (print(f"envcert {__version__}"), EXIT_OK)[1])

    plc = sub.add_parser("list-checks", help="list all checks with IDs, categories and severities")
    plc.add_argument("-v", "--verbose", action="store_true")
    plc.set_defaults(fn=cmd_list_checks)

    pe = sub.add_parser("explain", help="explain a single check")
    pe.add_argument("check_id")
    pe.set_defaults(fn=cmd_explain)

    pc = sub.add_parser("check", help="check a task directory")
    pc.add_argument("path", help="path to the task directory (e.g. ./my-task)")
    pc.add_argument("--profile", choices=sorted(PROFILES), default=None, help="validation profile (default: harbor, or from envcert.toml)")
    pc.add_argument("--adapter", choices=["auto", "harbor", "generic", "nemo-gym", "inspect"], default="auto")
    pc.add_argument("--format", choices=["text", "json", "sarif"], default="text")
    pc.add_argument("--output", "-o", default=None, help="write report to this file (text summary still goes to stderr)")
    pc.add_argument("--config", default=None, help="path to envcert.toml (default: <task>/envcert.toml if present)")
    pc.add_argument("--execution", choices=["none", "docker", "local-python", "external"], default=None,
                    help="dynamic execution mode (default: none = static only). docker = restricted container run; local-python = trusted pytest tasks only, NO sandbox; external = operator's disposable-VM runner command (see --runner-command)")
    pc.add_argument("--runner-command", default=None, help="external runner executable implementing EnvCert's runner protocol (execution=external)")
    pc.add_argument("--image", default=None, help="OCI image reference whose digest should be bound into the report (resolved via docker inspect, or use name@sha256:...)")
    pc.add_argument("--image-digest", default=None, help="explicit sha256:<64 hex> image digest to bind into the report/attestation")
    pc.add_argument("--external-tools", action="store_true", help="also run installed companion tools (hadolint/trivy/semgrep) as EC070-EC072")
    pc.add_argument("--baseline", default=None, help="previous JSON report; identical FAIL/WARN findings are marked baseline_suppressed and excluded from policy (shown in JSON + SARIF suppressions)")
    pc.add_argument("--dataset", action="store_true", help="treat PATH as a dataset root: run every task folder (task.toml) beneath it and emit an aggregated rollup report")
    pc.add_argument("--fail-on", default=None, help="comma-separated severities that fail policy, e.g. critical,high")
    pc.add_argument("--enable", action="append", default=None, help="only run this check ID (repeatable)")
    pc.add_argument("--disable", action="append", default=None, help="skip this check ID (repeatable)")
    pc.add_argument("--repetitions", type=int, default=None, help="repetitions for dynamic repeatability (default 3)")
    pc.add_argument("--mutation", action="store_true", help="enable mutation testing (local-python pytest tasks only)")
    pc.add_argument("--quiet", action="store_true", help="suppress the stderr summary when --output is used")
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
    pva.set_defaults(fn=cmd_verify_attestation)

    pi = sub.add_parser("init", help="write a starter envcert.toml")
    pi.add_argument("path", nargs="?", default=".")
    pi.add_argument("--force", action="store_true")
    pi.set_defaults(fn=cmd_init)

    ps = sub.add_parser("schema", help="print the JSON Schema for EnvCert reports")
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
    except EnvCertError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return exc.exit_code
    except BrokenPipeError:
        return EXIT_OK
    except Exception as exc:  # noqa: BLE001
        print(f"error: internal error: {type(exc).__name__}: {exc}", file=sys.stderr)
        return EXIT_ERROR


# ensure checks are registered even when CLI imported without engine
import envcert.checks.dynamic_checks  # noqa: E402,F401
import envcert.checks.external_checks  # noqa: E402,F401
import envcert.checks.static_checks  # noqa: E402,F401

if __name__ == "__main__":
    sys.exit(main())
