#!/usr/bin/env bash
# Fails if the fork modifies an upstream file that is not listed in FORK_CHANGES.md.
# Base = the upstream tag recorded in .fork/UPSTREAM. Requires full history (fetch-depth: 0).
set -euo pipefail
root=$(git rev-parse --show-toplevel); cd "$root"
base=$(cat .fork/UPSTREAM)
git rev-parse -q --verify "refs/tags/$base" >/dev/null || { echo "missing tag $base (git fetch upstream --tags)"; exit 2; }

# Fork-owned paths are excluded: upstream never has them.
changed=$(git diff --name-only "$base" -- . \
  ':(exclude)engine/' ':(exclude)docs/fork/' ':(exclude)app/fork/' ':(exclude)scripts/rr/' \
  ':(exclude).fork/' ':(exclude).github/workflows/rr-*' ':(exclude).github/README.md' \
  ':(exclude)NOTICE' ':(exclude)FORK_CHANGES.md' | sort -u)
ledger=$(scripts/rr/ledger-paths.sh)

unlisted=$(comm -23 <(printf '%s\n' "$changed" | sed '/^$/d') <(printf '%s\n' "$ledger" | sed '/^$/d'))
stale=$(comm -13 <(printf '%s\n' "$changed" | sed '/^$/d') <(printf '%s\n' "$ledger" | sed '/^$/d'))

[ -n "$stale" ] && { echo "note: ledger entries with no diff vs $base (remove if upstream absorbed them):"; echo "$stale" | sed 's/^/  /'; }
if [ -n "$unlisted" ]; then
  echo "ERROR: upstream files modified but not listed in FORK_CHANGES.md:"; echo "$unlisted" | sed 's/^/  /'; exit 1
fi
# Every ledger file that differs must carry an [rr] marker (Apache-2.0 4(b) change notice).
missing=""
for f in $changed; do
  case "$f" in *.png|*.jar|*.webp) continue;; esac
  [ -f "$f" ] && ! grep -q '\[rr\]' "$f" && missing="$missing $f"
done
[ -z "$missing" ] || { echo "ERROR: modified upstream files without an [rr] marker:$missing"; exit 1; }
echo "ledger OK: $(printf '%s\n' "$changed" | sed '/^$/d' | wc -l | tr -d ' ') upstream file(s) modified vs $base, all listed."
