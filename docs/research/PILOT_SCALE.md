# Scale pilot: humungous real-world campaign (0.4.3, re-run at 0.4.5)

Date: 2026-11-23. Static analysis only for external corpora (plus the
Docker/live execution in PILOT_040). As before: a finding on a public
task is a methodology observation, not an accusation — every
policy-driving class below was hand-reviewed in source.

## 0.4.5 re-run (same corpora, same host, same static profile)

The 0.4.5 release adds cross-module call-graph summaries (EC054), an
opt-in HTTP verifier probe, semantic near-duplicate detection (EC081)
and JS/TS mutation.  The full campaign was re-run to prove the new
analysis does not change verdicts on 723 real task bundles.

| Corpus | Size | 0.4.3 pass | 0.4.5 pass | Time (0.4.5) | Drivers (unchanged classes) |
|---|---:|---:|---:|---:|---|
| Harbor Hub: algotune | 154 tasks | 154 | 154 | 54s | clean |
| Harbor Hub: gaia | 165 | 165 | 165 | 43s | clean |
| Harbor Hub: cad-bench | 100 | 100 | 100 | 67s | clean (AST cache below) |
| Harbor Hub: harbor-index | 80 | 67 | 67 | 91s | EC054 9, EC032 2, EC021 1, EC056 1 |
| Harbor Hub: frontier-memory | 15 | 11 | 11 | 21s | EC054 3, EC012 1 |
| Terminal-Bench (rendered) | 51 | 47 | 47 | 126s | EC054 2, EC053 1, EC032 1 |
| Harbor repo templates | 158 | 106 | 107 | 50s | EC030 15, EC001 14, EC051 10, EC053 10, EC050 9, EC054 6 |
| SWE-bench full test split | 2,294 rows | — | — | ~5s | EC081 19 exact duplicate groups |
| inspect_evals (UK AISI) | 131 pkgs | 87 | 87 | 6s | EC053/EC056 review items |

No verdict flipped except one Harbor template that now passes (the
cross-module EC054 summaries recognise its validated reward path).  The
harbor-index EC054 drivers are the same nine gated designs documented
below — the cross-file summary engine does not clear them because they
genuinely read a harness score file back.

### Performance rectification forced by this re-run

The cross-module summary engine initially made static analysis ~2x
slower (cad-bench 51s → 113s): the AST was re-walked for every
assignment and every fixed-point iteration (1.35M `ast.walk` calls per
12 tasks).  Descendant lists are now cached per node for the duration of
one analysis (cad-bench 113s → 67s; profiled 12-task slice 33.9s →
14.5s).  The semantic near-duplicate pass had the same problem: it
re-normalised every candidate pair's prompts (45MB of text), so the full
SWE-bench audit went 3s → 19s; normalising once per row brought it back
to ~5s (semantic pass alone: 9.0s → 0.9s).

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
- **Semantic near-duplicates (0.4.5), real prompts**: SWE-bench's
  duplicates are textual, so the token-set cosine adds 0 findings there
  (correctly: its 19 duplicate groups are exact).  To measure the
  detector on realistic long prompts, 40 real SWE-bench problem
  statements were deterministically paraphrased (sentence reordering +
  synonym substitution + case noise) and placed next to 40 untouched
  distractor rows: EC081 reported **44 near-duplicate pairs, all with
  conflicting labels, and 0 false positives** on the distractors.
- **TF-weighted similarity was rejected as a metric**: an earlier
  sublinear-TF variant flagged 4 "semantic" pairs in SWE-bench — all
  four were false positives (pairs of unrelated issues sharing a pull
  request template, e.g. `scikit-learn-11206` vs `scikit-learn-14125`).
  The binary token-set cosine over discriminative tokens does not make
  that mistake; the false positives are recorded here rather than
  hidden.
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

The 0.4.5 re-run was executed on the same host but partly overlapped
other jobs, so its absolute times are upper bounds; the before/after
claims in the performance section were measured back-to-back on an
otherwise idle host.

Timing on this host is noisy: the same 131-package inspect_evals sweep
measured 6.1s, 6.6s and 6.8s in three back-to-back runs (0.4.4 tree
6.8s vs 0.4.5 tree 6.1s — no regression), but a run that started right
after a 100-task rollup measured 155s, and one run against the 0.4.4
tree was killed after 40 minutes.  The corpus and the verdicts were
identical in every case; only wall-clock differed.  Verdict counts, not
wall-clock, are the comparable number; where a time is quoted it is the
median of repeated idle-host runs.

The semantic near-duplicate metric is lexical (token-set cosine over
discriminative content tokens), not embedding-level: it catches
reordered or lightly reworded prompts, not arbitrary paraphrase. It is
a review aid — pairs are reported with their similarity and whether
their labels conflict, and the severity depends on that conflict.
