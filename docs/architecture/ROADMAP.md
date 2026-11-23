# Roadmap

Public roadmap. Detail and discussion live in the linked GitHub issues;
this page is the stable summary. Nothing here is promised functionality —
the README and check catalog describe what exists today.

## Now (0.4.x hardening)

- Keep the real-world pass rates in `docs/research/PILOT_SCALE.md`
  honest: re-run the Hub/Terminal-Bench/SWE-bench pilots per release
  and hand-review every new policy driver before believing it.
- Coverage ratchet: hold the 80% gate; raise as runner/attestation
  coverage improves.
- Keep the industry-readiness checklist in
  `docs/research/INDUSTRY_READINESS.md` current for every release.

## Shipped in 0.4.5

- [#1 EC054 full call-graph reward provenance](https://github.com/EricMaxwellnetizen/envcert/issues/1):
  function summaries (validates / returns-agent-data) propagate through
  helper chains **and across module imports**, so `A -> B -> compare`
  pipelines stop producing review WARNs while unvalidated chains stay
  flagged.
- [#2 Semantic near-duplicate detection](https://github.com/EricMaxwellnetizen/envcert/issues/2):
  deterministic token-cosine detection (>= 0.82) alongside 5-gram
  Jaccard, stdlib-only, bounded sample; conflicting-label pairs escalate
  to HIGH.
- [#3 NeMo Gym Resources-Server (HTTP) probing](https://github.com/EricMaxwellnetizen/envcert/issues/3):
  opt-in `--nemo-endpoint` gold/mutant/swap probing with bounded rows,
  response size and wall-clock budget; headers configurable and never
  echoed into evidence.
- [#4 Dynamic execution for docker-compose and prebuilt-image tasks](https://github.com/EricMaxwellnetizen/envcert/issues/4):
  prebuilt `docker_image` tasks and compose projects execute EC060/EC061/
  EC062/EC066 under a generated hardening override (cap-drop ALL,
  no-new-privileges, 2g/2cpu/256pid, internal default network).
- [#5 JS/TS solution mutation](https://github.com/EricMaxwellnetizen/envcert/issues/5):
  comment/string-aware lexer mutates JS/TS solutions; node (or
  tsx/ts-node) runs the task tests; rejection rate feeds EC063.

## Next

- Deterministic SWE-bench instance strengthening floor: mutant *patches*
  against FAIL_TO_PASS sets without LLM test generation (the offline
  complement to SWE-ABS, see `docs/research/RESEARCH_FINDINGS.md`).
- [#6 Framework listings and external adoption](https://github.com/EricMaxwellnetizen/envcert/issues/6):
  maintainer listings and independent users; this is outreach work, not
  a code gap.

## Later / evidence-gated

- Embedding-level semantic dedup beyond the deterministic token cosine
  (only if the offline core stays dependency-free; would be an optional
  extra).
- Hosted evidence retention, trend dashboards and org policies: only
  if the assessment-pilot demand in `docs/research/PRODUCT_REVIEW.md`
  materialises. The open-source core remains local and offline.

## Explicit non-goals

- LLM exploit discovery (BenchJack owns it), LLM test generation
  (SWE-ABS owns it for SWE-bench), generic CVE/SAST (Trivy/Semgrep own
  it), a single quality score, and any "certified unhackable" claim.
