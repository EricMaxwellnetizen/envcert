# CI integration

## GitHub Actions (composite action in this repo)

```yaml
name: envcert
on: [pull_request]
permissions:
  contents: read
  security-events: write   # only if uploading SARIF
jobs:
  envcert:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: ./            # this repository's action.yml; or envcert/envcert@v0.1.0 once published
        with:
          path: ./my-task
          fail-on: critical,high
          sarif: envcert.sarif
```

The action installs EnvCert from PyPI (or from the checked-out repo when used
locally), runs **static checks only by default**, uploads JSON/SARIF
artifacts when requested, and fails the job per the configured policy.
Dynamic execution in CI is deliberately not the default: only enable
`execution: docker` on runners you control, understanding that task
Dockerfiles are untrusted code (see DYNAMIC_EXECUTION.md).

Copy-paste examples live in `examples/github-actions/`.

## Any other CI

```bash
pip install envcert
envcert check ./my-task --format json --output report.json   # exit 1 = policy failed
envcert verify report.json --task ./my-task
```

Exit codes: 0 policy passed · 1 policy failed · 2 invalid input/config ·
3 internal/execution error.
