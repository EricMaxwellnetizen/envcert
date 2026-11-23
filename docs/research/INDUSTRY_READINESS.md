# Industry readiness

What "done enough to adopt" means for Envicert, and the evidence behind each
claim. This page is the operator-facing counterpart to the research pilots:
it states the deployment envelope, the guarantees, the limits, and the
checklist an organisation should follow before making Envicert a gate.

Envicert is an independent verification and evidence layer. It is **not** a
certification authority and never claims an environment is unhackable.

## 1. Deployment envelope

| Concern | Position |
|---|---|
| Runtime | Python 3.11+; **zero runtime dependencies**; no account, API key, LLM or network for static/dataset checks |
| Install | `pip install envicert` (PyPI), `pipx`, a pinned GitHub Action, or a checkout |
| Interfaces | CLI (`check`, `fix`, `new`, `verify`, `attest`, `verify-attestation`, `list-checks`, `explain`, `schema`), JSON/ SARIF/Markdown/HTML reports, pre-commit hooks, plugin checks via the `envicert.checks` entry point |
| Dynamic modes | `docker` (restricted container, shared host kernel), `local-python` (trusted tasks only, **no sandbox**), `external` (operator's disposable VM/remote runner) |
| Scale | 723 task bundles, the full 2,294-row SWE-bench test split and 131 Inspect evaluations in the 0.4.3/0.4.5 pilots; see `PILOT_SCALE.md` |
| Determinism | Same bundle + same settings produce the same static findings; dynamic findings depend on the selected runner and are labelled with it |
| Report contract | Schema `1.0.0`; `envicert verify` recomputes policy and summary counts and can re-run checks (`--recheck`); findings carry severity, confidence, evidence, remediation and limitations |
| Evidence | Optional in-toto Test Result attestation, DSSE/Cosign signing when installed; unsigned attestations are labelled unsigned |

## 2. What was proven at scale (not just unit-tested)

- **723 real task bundles**: Harbor Hub (algotune 154, gaia 165, cad-bench
  100, harbor-index 80, frontier-memory 15), Terminal-Bench 51 rendered
  tasks, Harbor repository 158 templates. Post-fix results: Hub 486/514,
  Terminal-Bench 47/51; remaining failures are documented review-level
  findings, not silent passes.
- **Full SWE-bench test split** (2,294 rows) plus Lite: streaming loader,
  no truncation; 19 hand-verified groups of distinct instances with
  identical problem statements and different gold patches were caught by
  EC081; EC080/EC085 clean across all rows.
- **131 inspect_evals packages**: 87 pass after sibling-scorer discovery;
  the rest are documented framework/pattern limits.
- **Performance corrections driven by scale**: the 2 MB read cap silently
  truncated SWE-bench to 57 of 2,294 rows (now streamed, full audit ~5 s);
  AST analysis was repeated 2–4× per task (now cached, cad-bench
  208 s → 51 s); `/testbed` vs `/tests` path confusion was made
  component-exact (harbor-index 52 → 67/80).  The 0.4.5 cross-module
  summary engine and the semantic near-duplicate pass each reintroduced a
  slowdown (AST re-walked 1.35M times; prompts re-normalised per
  candidate pair); both were fixed and re-measured on the same corpora
  (cad-bench 113 s → 67 s; full SWE-bench audit 19 s → ~5 s).  Verdict
  counts never changed during those fixes.
- **Dataset near-duplicate detection was validated, not assumed**: on
  40 real SWE-bench prompts, deterministically paraphrased and mixed
  with 40 untouched distractors, EC081 reported 44 near-duplicate pairs
  (all with conflicting labels) and 0 false positives.  An earlier
  TF-weighted metric produced 4 false positives on SWE-bench (unrelated
  issues sharing a template) and was replaced.
- **Executed false-pass proof**: EC066 is not a pattern check. The cheat
  battery plays deterministic cheats (stub solution, conftest outcome
  faking, forged reward file, verifier tampering) and reports a FAIL only
  when a cheat actually obtains a passing reward while gold passes.

## 3. Guarantees and honest limits

Guaranteed:

- Static and dataset checks never execute task code.
- Dynamic checks never run unless a mode is explicitly selected (a config
  boolean alone cannot silently enable unsandboxed execution).
- A missing Docker daemon, missing `pytest`/`node`, or failed gold run
  yields ERROR/NOT_APPLICABLE — never a fabricated PASS.
- Docker runs use `--cap-drop ALL`, `no-new-privileges`, resource/PID
  limits, a timeout, a read-only task mount and no `docker.sock`; built
  images are removed afterwards.
- Compose projects receive a generated hardening override; with network
  none the project's default network is `internal`.
- Reports are schema-versioned and independently verifiable; policy and
  counts cannot be edited without detection.

Not guaranteed:

- Semantic correctness of a verifier or unhackability of an environment.
- Detection of novel exploits beyond the fixed cheat battery and mutation
  operators (BenchJack-style adversarial audits own that).
- CVE scanning of base images (use Trivy/Grype).
- Full runtime visibility of mounts, secrets or platform configuration
  outside the bundle.
- Network isolation for compose definitions that override the default
  network or use `network_mode: host`; the report records the runner and
  the override used, but the compose file remains part of the trust base.
- Embedding-level paraphrase detection; EC081 uses a deterministic
  token-set cosine, not a model.

## 4. Adoption checklist

1. **Pin a version**: `envicert==0.4.5` or the Action at `@v0.4.5`
   (`@v0` tracks the latest 0.x). Pin in CI, not just locally.
2. **Gate pull requests on static checks** for every task/dataset change.
   Default policy fails on CRITICAL/HIGH; use `strict` to include MEDIUM
   once the backlog is clean.
3. **Upload SARIF** (`--format sarif`) to GitHub code scanning or your
   equivalent so findings live where reviewers already work.
4. **Adopt baselines deliberately**: `--baseline old.json` suppresses
   identical existing findings from policy while keeping them visible;
   ratchet the baseline down rather than regenerating it blindly.
5. **Run dynamic checks on trusted infrastructure**: nightly or on-demand,
   in Docker on a disposable host or through `--execution external` in
   your VM fleet. Never use `local-python` on untrusted bundles.
6. **Probe your real grader**: for NeMo Gym, run EC065 against the local
   `verify()` or the HTTP Resources Server (`--nemo-endpoint`).
7. **Review every WARN and every NOT_APPLICABLE**: they are the honest
   boundary of what was checked; a green report is not a claim of
   correctness.
8. **Keep evidence**: store the JSON report and optional attestation as
   release artifacts; `envicert verify report.json --task <task>` proves
   the report still matches the bundle.
9. **Re-run the pilots per release** (Hub/Terminal-Bench/SWE-bench) and
   hand-review new policy drivers before believing them.
10. **Treat compose and external runners as part of your threat model**:
    the task's compose file and your runner's isolation are inputs to the
    assurance argument, recorded in the report.

## 5. Operational expectations

| Operation | Typical cost | Notes |
|---|---|---|
| Static check, single task | sub-second to a few seconds | AST analysis cached per run; large repos benefit most |
| Dataset audit, 2,294 rows | ~5 s | Streamed; 20,000 rows/file analysed, cap recorded |
| Dynamic Docker gold/no-op/repeat | image build + 2–3 runs | Layer cache makes repeat builds cheap; compose projects tear down |
| Mutation testing | `max_mutants` × verifier runtime | Opt-in, bounded (1–200); equivalent mutants may survive |
| HTTP verifier probe | ≤ 10 rows × request latency | Bounded wall clock, response size and request count |

Exit codes are stable: `0` policy passed, `1` policy failed, `2` invalid
input/config, `3` internal/execution error. Reports always include the
runner and its isolation description, so evidence consumers can judge how
a dynamic result was produced.

## 6. Release integrity

Every release is expected to satisfy, from primary sources:

- full test suite green with the coverage gate (80%) and ruff/mypy clean;
- CI, Docs, Release and Security workflows green;
- the version tag points at the release commit (peeled tag verified);
- PyPI serves the version and a clean-venv install reports it;
- the installed wheel contains the release's code (spot-check new symbols);
- the GitHub Release body matches `docs/releases/vX.Y.Z.md`.

This checklist exists because a tag pushed at the wrong commit can make a
"successful" publish workflow re-upload the previous version. Verify the
artifact, not the workflow badge.

## 7. Versioning and support

- Check IDs (`ECxxx`) and the report schema (`1.0.0`) are stable public
  contracts; findings are additive within a minor series.
- 0.x minor releases may add checks and optional capabilities; patch
  releases fix behaviour without changing the report contract.
- Security reports: see `SECURITY.md`. The threat model, including what
  Docker isolation does and does not provide, is in
  `docs/architecture/THREAT_MODEL.md`.
