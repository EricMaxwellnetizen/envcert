# External runner examples

`inspect_runner.py` implements Envicert's external runner protocol for Inspect AI evaluations (gold runs via `inspect eval`, accuracy from the Inspect log). Use it with:

```bash
pip install inspect_ai
envicert check ./my-inspect-eval --execution external --runner-command "python examples/external-runners/inspect_runner.py"
```

The same protocol is how a disposable-VM provider plugs in: the command receives `--task <dir> --variant gold|noop --timeout <s>` and prints one JSON line `{"reward": ..., "exit_code": ...}`. Envicert records the provider command and the provider's isolation claim in the report — it does not vouch for isolation it cannot see.
