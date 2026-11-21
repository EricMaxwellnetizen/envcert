#!/bin/bash
set -euo pipefail
mkdir -p /logs/verifier
printf "step-one\nstep-two\n" > /tmp/expected.txt
if diff -q /tmp/expected.txt /app/data.txt >/dev/null; then echo 1 > /logs/verifier/reward.txt; else echo 0 > /logs/verifier/reward.txt; fi
