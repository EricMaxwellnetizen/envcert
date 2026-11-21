# Research findings

Date: 2026-11-22. Method: web research of primary sources (project repos,
official docs, papers) listed below. Claims are separated into *verified*
(read in a primary source), and *unknown/not verified*.

## Sources

| Project | Source | What was verified |
|---|---|---|
| Harbor | https://docs.harborframework.com/tasks/configuration , /tasks/verifier , github.com/harbor-framework/harbor | task.toml schema_version 1.4; `[task]/[metadata]/[verifier]/[agent]/[solution]/[environment]`; task dir = task.toml + instruction.md + environment/ + tests/test.sh + solution/solve.sh; verifier writes `/logs/verifier/reward.txt\|json`; `verifier.environment_mode = "separate"` + `[verifier.environment]` for separate verifier sandbox; network_mode `no-network\|public\|allowlist` (defaults to public); multi-step `steps/` layout; `tests/verifier.py` alternative (NeMo Gym convention) |
| NeMo Gym | https://docs.nvidia.com/nemo/gym/ (Harbor Environment Server, Task Folder Verifiers, Author Task Folders) | Runs Harbor task folders; `gym dataset validate` runs the reference solution through the verifier and requires reward 1 — explicitly noted there that this "does not prove a verifier rejects a wrong result"; shared vs separate verification semantics; reward-file failure kinds (`harbor:missing_reward`, etc.); verifier env/secret handling |
| BenchJack | https://github.com/benchjack/benchjack , https://sky.cs.berkeley.edu/project/benchjack/ , arXiv:2605.12673 | AI-agent benchmark hackability scanner (Berkeley Sky Lab, created 2026-04-15, Apache-2.0 at research time); multi-phase audit: static tools + AI-powered (Claude Code/Codex) deep inspection + PoC exploit generation, live web dashboard; taxonomy of 8 flaw patterns / Agent-Eval Checklist; found near-perfect hack rates on most of 10 audited benchmarks |
| trustworthy-env (Benchmark Audit Tool) | https://github.com/moogician/trustworthy-env , https://rdi.berkeley.edu/blog/trustworthy-benchmarks/ | Dual-engine audit: LLM semantic analysis (requires API key) + formal/static verification with Z3, AST/data-flow; 8-stage pipeline incl. runtime verification (strace + mutation testing) and adversarial PoC generation; 15 vulnerability classes; 50-issue regression catalog; Python 3.10+ |
| Inspect AI | https://github.com/UKGovernmentBEIS/inspect_ai , https://inspect.aisi.org.uk/sandboxing.html | Evaluation framework (UK AISI): tasks = dataset + solver(s) + scorer(s); sandbox integrations (Docker built in, k8s/VM extensions); reproducibility via structured JSON logs; not a task-bundle integrity checker |
| in-toto attestation | https://github.com/in-toto/attestation/blob/main/spec/predicates/test-result.md , spec/v1 | Statement v1 (`https://in-toto.io/Statement/v1`), vetted **Test Result** predicate (`https://in-toto.io/attestation/test-result/v0.1`, result PASSED/FAILED + configurationSource) and Simple Verification Result; DSSE envelope is the recommended signing layer |
| Cosign / Sigstore | https://docs.sigstore.dev/cosign/verifying/attestation/ , github.com/sigstore/cosign | `cosign attest --predicate --type`, `verify-attestation` with CUE/Rego policies; attestations bind to OCI image digests; sign-blob for arbitrary files |
| SWE-ABS | No primary repo was verified during the initial research | Treated as *unknown*: understood only as "test-strengthening for SWE-bench-style suites". No EnvCert feature depends on unverified SWE-ABS claims. |

## Key discoveries

1. **Gold-passing is the industry baseline, and it is insufficient.** NeMo Gym's
   own docs state that oracle validation "does not prove a verifier rejects a
   wrong result". Negative controls and mutation testing are the natural,
   differentiated complement — and are implementable deterministically.
2. **The two closest tools are AI-agent-driven and non-deterministic.**
   BenchJack and trustworthy-env use LLM agents (+ optional Z3) to *find and
   exploit* flaws, produce PoC exploits, and require API keys for their
   strongest modes. Neither is positioned as a deterministic, offline,
   CI-native checker producing a signed, schema-versioned evidence report.
   That gap is EnvCert's position (see PRODUCT_DECISIONS.md).
3. **Harbor already solved separate verification** (`environment_mode =
   "separate"`, fresh verifier sandbox, artifacts transfer). EnvCert must
   *check that tasks use it* (or justify shared mode) rather than reimplement
   Harbor's runtime. Harbor also re-uploads `/tests` at verification time,
   which mitigates some — not all — shared-filesystem attacks; findings must
   not overclaim.
4. **Network defaults are permissive**: Harbor `network_mode` defaults to
   `public`. A declared-policy check is high-value and trivially deterministic.
5. **Reward contract is precise**: `/logs/verifier/reward.txt|json`, reward.json
   wins, missing/invalid = 0/masked. A static "does the verifier ever write a
   reward" check catches a real, common breakage class.
6. **Attestation standards already exist.** The in-toto Test Result predicate
   expresses pass/fail + configuration source; DSSE + Cosign provide signing.
   Inventing a new predicate would be unjustified. EnvCert binds subjects by
   sha256 (bundle, verifier, solution) and carries tool detail in a documented
   extension field.
7. **Established scanners are complementary, not core.** Hadolint (Dockerfile
   lint), Semgrep (taint/AST rules), Trivy/Grype/Syft (CVE/SBOM) solve adjacent
   problems. Bundling them would add heavyweight, platform-specific binaries
   to a stdlib-only core; EnvCert instead documents them as recommended
   companions (SECURITY.md / guides) and keeps its own checks focused on
   evaluation integrity, which none of them cover.

## Overlap / differentiation summary

Overlap with BenchJack/trustworthy-env: leakage, weak-verifier, isolation and
shadowing *categories*. Differentiation: deterministic offline static checks
with stable IDs, explicit PASS/FAIL/WARN/NOT_RUN semantics, JSON Schema +
SARIF, policy exit codes for CI, digest-bound in-toto attestations, no LLM/API
key, no exploit generation. EnvCert does **not** generate exploits, does not
use an LLM, and does not claim formal (Z3) proof.

## Unresolved questions

- Real-world digest for the example base image (examples use a placeholder
  digest that must be replaced before actually building; documented inline).
- Whether Harbor's registry will standardise a task "integrity" metadata
  block that EnvCert should emit into; no such block was found in schema 1.4.
- SWE-ABS internals (not verified; deferred — tracked in GitHub Issues).
