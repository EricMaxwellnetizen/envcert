# Scale pilot: humungous real-world campaign (0.4.3)

Date: 2026-11-23. Static analysis only for external corpora (plus the
Docker/live execution in PILOT_040). As before: a finding on a public
task is a methodology observation, not an accusation — every
policy-driving class below was hand-reviewed in source.

## Corpora (723 task bundles + 2 datasets + 131 eval packages)

| Corpus | Size | Policy pass | Time | Notes |
|---|---:|---:|---:|---|
| Harbor Hub: algotune | 154 tasks | 154 | 52s | clean |
| Harbor Hub: gaia | 165 | 165 | 39s | clean |
| Harbor Hub: cad-bench | 100 | 100 | 51s (was 208s) | perf fix below |
| Harbor Hub: harbor-index | 80 | 67 | 81s | drivers reviewed below |
| Harbor Hub: frontier-memory | 15 | 11 | 10s | EC054 review items |
| Terminal-Bench (rendered) | 51 | 47 | 96s | PILOT_040 |
| Harbor repo templates | 158 | 106 | 45s | templates, not tasks |
| SWE-bench full test split | 2,294 rows | — | 2s | EC081 true positive below |
| SWE-bench Lite (sample) | 30 rows | pass | <1s | PILOT_040 |
| inspect_evals (UK AISI) | 131 pkgs | 87 | 23s | EC053/EC056 review items |

## Rectifications this campaign forced (all regression-tested)

1. **Dataset files were silently truncated at 2MB.** The full SWE-bench
   audit initially inspected 57 of 2,294 rows. The dataset loader now
   streams from disk; the same file audits all 2,294 rows in 2s. A
   regression test audits a >2MB JSONL and asserts the full row count.
2. **AST analysis was run 2–4× per task.** EC052/EC053/EC054/EC056 now
   share one cached analysis per run: cad-bench 208s → 51s, algotune
   96s → 52s, with byte-identical findings (same pass counts/drivers).
3. **Inspect scorers in sibling modules were invisible**, producing
   assertion-free-verifier warnings for evals whose grading lives in
   `scorer.py`. The adapter now includes scorer modules (EC053 drivers
   on inspect_evals: 26 → 15; the rest are genuine review items).
4. **`/testbed` is not `/tests`.** EC023's substring match flagged SWE-
   style agent workspaces; targets are now matched component-exactly
   (harbor-index EC023 drivers 13 → 0).
5. **Version-pinned pipe-to-shell ≠ unversioned.** The uv installer
   (`…/uv/0.7.13/install.sh | sh`, 24 harbor-index tasks) is now EC032
   MEDIUM; unversioned installers stay HIGH (drivers 24 → 2).

## Verified true positives at scale

- **SWE-bench (full, 2,294 rows)**: EC081 finds 19 groups of distinct
  instances with identical normalized problem statements and different
  gold patches (e.g. `astropy__astropy-12842` vs `-12880`,
  `django__django-11555` vs `-11559`) — hand-verified against
  instance ids. EC085: all 2,294 grading specs consistent. EC080: no
  verbatim answer leakage.
- **harbor-index remaining drivers**: 9 EC054 review items (harness
  score files read back by test.sh — gated designs, WARN is the right
  output), 2 unversioned installers, 1 vendored `pytest.ini`, 1 real
  `exec()` in a USACO judge (its job; sandboxed externally).

## Method limits

Hub datasets were audited at their published `@latest`. Times are
wall-clock on the maintainer's Windows host, static profile, and will
differ elsewhere; the honest claim is the before/after on the same
host. inspect_evals numbers aggregate per-eval-directory runs with the
Inspect adapter (static-only, per its recorded limitations).
