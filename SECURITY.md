# Security policy

## Reporting a vulnerability

Do **not** open a public issue for a security vulnerability in EnvCert
itself. Use GitHub's private vulnerability reporting ("Security →
Advisories → Report a vulnerability") on this repository, or contact the
maintainers via the address in the repository profile. Expect an
acknowledgement within 7 days. EnvCert follows coordinated disclosure:
a fix or a documented mitigation will be prepared before public details,
except where a vulnerability is already public.

For vulnerabilities you find *in third-party benchmarks/tasks* using
EnvCert: do not publish accusations without reproducible evidence; follow
that project's disclosure process. EnvCert findings marked WARN / low
confidence are heuristics, not confirmed vulnerabilities.

## Security model (summary — full version: docs/architecture/THREAT_MODEL.md)

- Static analysis treats task bundles as untrusted *data*: files are read
  with size caps, directory symlinks are never followed, and no task path is
  ever interpolated into a shell command.
- Dynamic execution is opt-in. Docker mode applies cap-drop ALL,
  no-new-privileges, CPU/memory/PID limits, timeouts, bounded logs, cleanup,
  and never mounts the host Docker socket or runs privileged. Docker is a
  shared-kernel boundary, not a VM.
- `local-python` mode has **no sandbox** and must only be used on trusted
  tasks; every report records the runner's isolation honestly.
- EnvCert itself has zero runtime dependencies, requires no account, no
  network and no telemetry.

## Supported versions

Only the latest 0.x release receives security fixes until 1.0.
