"""Task scaffolding (``envicert new``): a Harbor task that passes Envicert.

New benchmark tasks usually start by copying an old task -- and its flaws.
The scaffold starts from the safe shape instead: separate verifier,
declared no-network policy, digest-pinned base image, non-root agent user,
.dockerignore, a verifier that only writes reward 1 after real assertions,
and a reference solution.  ``envicert check`` on the result passes policy,
which the test-suite asserts.
"""
from __future__ import annotations

from pathlib import Path

PINNED_IMAGE = "python:3.12-slim@sha256:5e2bdb1b0d542d5039cffb8181c65930093949194a65c365dfb1b0fe13a4fa5b"

FILES: dict[str, str] = {
    "task.toml": '''schema_version = "1.4"
[task]
name = "{name}"
authors = [{{name="TODO your name"}}]
[metadata]
category = "programming"
difficulty_explanation = "Describe what makes this task hard."
[verifier]
timeout_sec = 120.0
environment_mode = "separate"
[agent]
timeout_sec = 120.0
[environment]
network_mode = "no-network"
cpus = 1
memory_mb = 1024
''',
    "instruction.md": """# Describe the task, not the answer

State exactly what the agent must produce (files, formats, locations),
without including solution code or expected outputs.

This scaffold's example task: create `/app/output.txt` containing exactly
the line `done` followed by a newline.
""",
    "environment/Dockerfile": f"""# Digest-pinned base image (EC030). Refresh deliberately, never float.
FROM {PINNED_IMAGE}
WORKDIR /app
COPY app/ /app/
RUN pip install --no-cache-dir pytest==8.3.5
RUN useradd --create-home agent
USER agent
""",
    "environment/.dockerignore": ".git\n__pycache__/\n",
    "environment/app/README.md": "# Agent workspace\n\nTask input files live here. Never put solutions, gold outputs or tests in this directory.\n",
    "tests/test.sh": """#!/bin/bash
set -euo pipefail
mkdir -p /logs/verifier
if python3 -m pytest -q /tests/test_outputs.py; then
  echo 1 > /logs/verifier/reward.txt
else
  echo 0 > /logs/verifier/reward.txt
fi
""",
    "tests/test_outputs.py": '''from pathlib import Path


def test_output_content():
    p = Path("/app/output.txt")
    assert p.is_file(), "output.txt missing"
    assert p.read_text(encoding="utf-8") == "done\\n"


def test_output_is_not_a_placeholder():
    text = Path("/app/output.txt").read_text(encoding="utf-8").strip().lower()
    assert text not in ("", "todo", "done?", "hello world")
    assert len(text) == len("done")
''',
    "solution/solve.sh": """#!/bin/bash
set -euo pipefail
printf 'done\\n' > /app/output.txt
""",
    "envicert.toml": """# Envicert configuration -- see docs/guides/CONFIGURATION.md
[envicert]
profile = "harbor"

[checks.dynamic]
enabled = false
repetitions = 3

[policy]
fail_on = ["critical", "high"]
""",
    "README.md": """# {name}

A Harbor task scaffolded by `envicert new`. It is shaped to pass
`envicert check .` (separate verifier, no-network, pinned image, real
assertions, reference solution).

Replace the example instruction/tests/solution with your task, then run:

```bash
envicert check .
envicert check . --execution docker   # gold + negative control + cheat battery
```
""",
}


def scaffold_task(dest: Path, name: str) -> list[str]:
    """Create the scaffold under ``dest``; return written relative paths."""
    dest = Path(dest)
    written: list[str] = []
    for rel, content in FILES.items():
        path = dest / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content.replace("{name}", name), encoding="utf-8")
        written.append(rel)
    return written
