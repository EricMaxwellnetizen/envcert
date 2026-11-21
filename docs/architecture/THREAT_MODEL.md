# Threat model

## Assets

- Integrity of benchmark scores/rewards (the thing EnvCert protects).
- The developer/CI host running EnvCert (EnvCert itself must not become the
  attack vector).
- Credentials on the host (env vars, cloud keys, Docker socket).
- Trust in EnvCert reports/attestations.

## Adversaries

1. **Malicious or careless task author** shipping a task bundle with leaked
   answers, weak verifiers, or hostile Dockerfiles.
2. **Benchmark-gaming agent** (the evaluated model/system) exploiting leaked
   material, shared verifier state, import/PATH shadowing, self-reported
   rewards, or unrestricted network.
3. **Compromised dependency / base image** silently changing the environment.
4. **Malicious input to EnvCert itself**: crafted task bundles, malformed
   TOML/reports/attestations aimed at path traversal, symlink escape, command
   injection, or resource exhaustion in the checker.

## Trust boundaries

```
[host: EnvCert process] ──reads──► [untrusted task bundle: files only]
        │  (static: never executed, never shell-interpreted)
        └──opt-in dynamic──► [runner: restricted docker container | local temp copy]
[verifier] ◄── must be independent of ── [agent-controlled files/processes]
[report/attestation consumer] ──verifies──► [report integrity: schema + bundle digest (+ optional signature)]
```

## Threats and EnvCert's response

| Threat | EnvCert response | Residual risk |
|---|---|---|
| Solution/gold material readable by agent | EC011/EC012/EC014 build-context + COPY analysis, EC010 git exposure | Runtime mounts outside the bundle are invisible statically (stated in findings) |
| Agent tampers with verifier (shared FS/process) | EC020 separation check, EC023 writable paths, EC021/EC022 shadowing | Harbor re-uploads /tests; runtime perms only fully proven dynamically |
| Verifier accepts anything | EC050–EC054 structure/AST checks, EC061 no-op control, EC063 mutation rate | Semantic correctness cannot be proven statically; mutation is a signal |
| Agent reports its own grade | EC054 self-reported-reward heuristic | Legit output-file reading needs human review (WARN, low confidence) |
| Answer retrieval via network | EC033 declared-policy check | EnvCert checks the *declared* policy; enforcement is the runner's job |
| Non-reproducible environment | EC030/EC031/EC040/EC041 pinning & lockfile signals | Digest pinning of a malicious image is still malicious — integrity ≠ safety of content |
| Host compromise via untrusted bundle (EnvCert's own safety) | Static mode only reads files (size-capped, binary-skipping, no symlink following, no shell construction from paths); dynamic docker mode: no privileged, cap-drop ALL, no-new-privileges, no docker.sock mount, resource/time limits, bounded logs, cleanup | Docker shares the host kernel — not a VM. Local-python mode has **no** sandbox and is labelled as such everywhere |
| Fake/tampered evidence | Report binds bundle/verifier/solution sha256; `verify` recomputes; attestation subjects are those digests; signing optional via Cosign | Unsigned reports are *not* cryptographic evidence and EnvCert says so in every relevant output |
| Resource exhaustion by huge bundles | File-count cap (5000), 2 MB text-read cap, bounded subprocess output, execution timeouts | Extremely large binary files still cost hashing time |

## Out of scope

- Proving a verifier semantically correct, or an environment "unhackable".
- CVE scanning of images (use Trivy/Grype), generic SAST (Semgrep),
  Dockerfile lint beyond integrity-relevant rules (Hadolint).
- LLM/agent-driven exploit discovery (BenchJack, trustworthy-env).
- Sandbox escapes in Docker itself; high-risk untrusted workloads should use
  a disposable VM / remote sandbox, which EnvCert's runner interface can be
  extended to target (see guides/WRITING_A_RUNNER.md).

## Assurance contexts (never conflated)

A report states who ran EnvCert (`assurance_context`): supplier self-testing,
consumer-side independent testing, and third-party auditing are different
assurance levels. EnvCert generates evidence; it does not decide which level
a given run represents beyond recording the invocation context.
