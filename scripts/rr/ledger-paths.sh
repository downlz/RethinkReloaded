#!/usr/bin/env bash
# Prints the upstream files the fork is allowed to modify, as listed in FORK_CHANGES.md
# between the "ledger:begin" and "ledger:end" markers (one `path` per line).
set -euo pipefail
root=$(git rev-parse --show-toplevel)
sed -n '/<!-- ledger:begin -->/,/<!-- ledger:end -->/p' "$root/FORK_CHANGES.md" \
  | grep -o '^- `[^`]*`' | sed 's/^- `//; s/`$//' | sort -u
