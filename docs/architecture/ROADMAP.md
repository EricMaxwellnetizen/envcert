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

## Next

- [#1 EC054 full call-graph reward provenance](https://github.com/EricMaxwellnetizen/envcert/issues/1):
  function summaries (sources/sinks/validates) across helper chains and
  files, so validated grading pipelines stop producing review WARNs.
- [#3 NeMo Gym Resources-Server (HTTP) probing](https://github.com/EricMaxwellnetizen/envcert/issues/3):
  opt-in gold/mutant/swap probing against a user-supplied endpoint.
- [#4 Dynamic execution for docker-compose and prebuilt-image tasks](https://github.com/EricMaxwellnetizen/envcert/issues/4):
  prebuilt-image execution shipped in 0.4.4 (incl. EC066); compose
  services remain.
- Deterministic SWE-bench instance strengthening floor: mutant *patches*
  against FAIL_TO_PASS sets without LLM test generation (the offline
  complement to SWE-ABS, see `docs/research/RESEARCH_FINDINGS.md`).

## Later / evidence-gated

- [#2 Semantic near-duplicate detection](https://github.com/EricMaxwellnetizen/envcert/issues/2)
  (opt-in embeddings; core stays stdlib-only).
- [#5 JS/TS solution mutation](https://github.com/EricMaxwellnetizen/envcert/issues/5).
- Hosted evidence retention, trend dashboards and org policies: only
  if the assessment-pilot demand in `docs/research/PRODUCT_REVIEW.md`
  materialises. The open-source core remains local and offline.

## Explicit non-goals

- LLM exploit discovery (BenchJack owns it), LLM test generation
  (SWE-ABS owns it for SWE-bench), generic CVE/SAST (Trivy/Semgrep own
  it), a single quality score, and any "certified unhackable" claim.
