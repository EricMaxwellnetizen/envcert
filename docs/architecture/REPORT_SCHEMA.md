# Report schema (version 1.0.0)

The canonical schema ships in the package at
`envcert/schemas/report.schema.json` and is printed by `envcert schema`.
Generated reports are validated against it in the test suite.

## Top-level fields

| Field | Meaning |
|---|---|
| `schema_version` | `"1.0.0"` — bump on breaking report changes |
| `envcert_version` | EnvCert release that produced the report |
| `generated_at` | UTC ISO-8601 timestamp |
| `assurance_context` | Who ran the tool (self-testing vs independent) — never conflated |
| `environment` | `task_name`, `task_path`, `adapter`, `bundle_digest_sha256`, `file_count`, `verifier_digest_sha256`, `solution_digest_sha256`, `image_digest` (null unless a built image digest is supplied by a future runner), `warnings` |
| `execution` | `mode` (none/docker/local-python), `profile`, `config_source`, `fail_on`, `repetitions`, `mutation_enabled`, `runner` (name/available/isolation) |
| `checks_executed` / `checks_not_executed` | Stable check IDs — a check that did not run is never represented as passed |
| `findings[]` | See below |
| `summary` | Counts by status and by failing severity |
| `errors[]` | Check-level errors (also surfaced as ERROR findings) |
| `policy` | `{passed, fail_on, rule}` |
| `limitations[]` | Standing limitations of this kind of evidence |

## Finding fields

`check_id` (stable, public), `title`, `description`, `category`, `severity`
(CRITICAL/HIGH/MEDIUM/LOW/INFO), `status` (PASS/FAIL/WARN/NOT_RUN/
NOT_APPLICABLE/ERROR), `artifact`, `path`, `line`, `evidence` (object),
`remediation`, `confidence` (high/medium/low), `limitations`.

FAIL vs WARN: FAIL = the checked property is violated on the evidence
available; WARN = heuristic/potential issue needing human confirmation, or a
lower-confidence violation. NOT_RUN (dynamic checks without opt-in) is
distinct from PASS — this distinction is a core product guarantee.

## Digest algorithm

`bundle_digest_sha256`: sha256 over, for each file (sorted relative POSIX
path, `.git` excluded, symlinks not followed): `relpath \0 sha256(content) \n`;
symlinks contribute `link:<target>` instead of a content hash. Any content
change changes the digest; `envcert verify report.json --task <dir>`
recomputes it. File-listing truncation and unreadable files are recorded in
`environment.warnings` / `limitations` rather than silently hashed as empty.

`envcert verify` also recomputes `policy.passed` and every `summary` counter
from the findings (using the recorded `fail_on` severities and
`baseline_suppressed` flags). A report whose asserted policy or counts
disagree with its own findings is rejected with exit code 2; `envcert attest`
refuses to build an attestation from such a report.

Three checks are opt-in because they need evidence the report does not carry:

- `--baseline <report.json>` recomputes which findings the baseline actually
  covers. A report that claims `baseline_suppressed` findings is rejected
  (exit 2) unless the baseline is supplied and matches.
- `--recheck --task <dir>` re-runs the report's static checks against the
  task and compares the findings; differences are reported as verification
  failures (exit 1). This is how a consumer detects findings that were
  dropped from a report.
- `--fail-on critical,high` evaluates the policy under the consumer's own
  severity threshold instead of the report's self-asserted `fail_on`.

Without `--recheck`, `verify` proves internal consistency only: it cannot
detect a report whose findings were removed wholesale.

## Attestation binding (in-toto Test Result)

`envcert attest report.json` emits an in-toto Statement v1:

- `predicateType`: `https://in-toto.io/attestation/test-result/v0.1`
- `subject[]`: task name → bundle digest; `verifier` → verifier digest;
  `reference-solution` → solution digest (when present). Mutable tags/labels
  are never used as subjects.
- `predicate.result`: PASSED/FAILED from the report policy;
  `configurationSource.uri = envcert://profile/<profile>` with
  `digest.sha256 = sha256(report bytes)`, binding the statement to the exact
  report.
- `predicate.x-envcert`: documented extension carrying EnvCert version,
  report schema version, adapter, executed/failing check IDs, assurance
  context, limitations, and `signed: false`. Rationale: the vetted Test
  Result predicate has no per-check field; the extension is additive,
  versioned with the report schema, and consumers may ignore it and rely on
  `result` + the report digest alone.

Signing: `--dsse` wraps the statement in a DSSE envelope; `--sign` invokes
`cosign sign-blob` and writes a detached `.sig`. If signing or OCI
attestation was explicitly requested but could not be performed (Cosign
missing, tlog/network failure, mutable image ref), `envcert attest` exits 3
and says the file is unsigned. `envcert verify-attestation` verifies a
detached `.sig` with `cosign verify-blob`; an unsigned statement/envelope
fails unless `--allow-unsigned` is passed for structural-only checking.
Without signing, output states plainly that it is unsigned and is not
cryptographic evidence.
