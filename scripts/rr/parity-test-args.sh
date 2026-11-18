#!/usr/bin/env bash
# Prints Gradle --tests filters for scripts/rr/parity-tests.txt
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"
grep -v '^\s*#' scripts/rr/parity-tests.txt | sed '/^\s*$/d' | while read -r t; do printf -- '--tests *.%s ' "$t"; done
