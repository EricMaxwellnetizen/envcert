# Writing an adapter or a runner

## Adapter

An adapter turns a framework's on-disk layout into a `TaskContext`
(`envicert/adapters/base.py`): file inventory, parsed config, Dockerfile,
build-context directory, tests/solution/environment locations, and honest
`warnings` for anything the adapter could not map.

1. Study the framework's *current* documented format; cite it in the module
   docstring (as `adapters/harbor.py` does).
2. Implement `load(root) -> TaskContext` and a cheap `is_<framework>_task`
   detector; wire detection into `core/engine.load_task` only when the
   detector is unambiguous.
3. Never execute framework code during loading.
4. Add fixtures: a minimal real task, a variant layout, and a malformed one.
   Do not claim support in the README until those fixtures pass.

## Runner

A runner executes tasks for dynamic checks (`envicert/runners/base.py`):
implement `info()` (availability + an honest one-line isolation description —
this string lands in every report) and the run methods you support,
returning `RunResult` with bounded output, timeouts and cleanup.

Non-negotiables: no privileged mode, no host Docker-socket mounts, no
credential passthrough by default, argument arrays instead of shell strings,
resource limits, and fail-safe behaviour (unavailable ⇒ ERROR/NOT_RUN
findings, never PASS).
