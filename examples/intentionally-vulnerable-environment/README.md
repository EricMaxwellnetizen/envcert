# Intentionally vulnerable example — do not copy

This fixture deliberately contains weaknesses Envicert should detect
(EC010–EC014, EC020–EC023, EC030, EC032, EC040, EC052, EC053). Expected
results are locked in `tests/fixtures/expected-intentionally-vulnerable-environment.json`.

Note on EC010: the exposed VCS fixture lives in `environment/.git/`
(`HEAD`, `config`) in a local checkout. Git cannot track files under a
nested `.git/` directory, so after a fresh clone those two small files may
be absent; recreate them with:

```bash
mkdir -p environment/.git
printf 'ref: refs/heads/main\n' > environment/.git/HEAD
printf '[core]\n' > environment/.git/config
```

All other expected findings are present in tracked files.
