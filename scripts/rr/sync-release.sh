#!/usr/bin/env bash
# Merge an upstream celzero/rethink-app release tag into a sync/<tag> branch and print the review report.
# See docs/fork/UPSTREAM_SYNC.md.
#
# Usage: scripts/rr/sync-release.sh [--dry-run] <upstream-tag>
#   --dry-run   report only: shows commits, ledger-file changes, firestack drift and a trial-merge conflict list,
#               without creating branches, pushing tags or committing anything.
set -euo pipefail
dry=0; [ "${1:-}" = "--dry-run" ] && { dry=1; shift; }
NEW=${1:?usage: $0 [--dry-run] <upstream-tag>}
cd "$(git rev-parse --show-toplevel)"
OLD=$(cat .fork/UPSTREAM)

git remote get-url upstream >/dev/null 2>&1 || { echo "add the upstream remote first (docs/fork/UPSTREAM_SYNC.md §2)"; exit 2; }
git fetch -q upstream --tags
git rev-parse -q --verify "refs/tags/$NEW" >/dev/null || { echo "unknown upstream tag: $NEW"; exit 2; }
git merge-base --is-ancestor "$OLD" "$NEW" || echo "WARNING: $OLD is not an ancestor of $NEW (upstream history rewritten?)"
[ -z "$(git status --porcelain)" ] || { echo "working tree not clean"; exit 2; }

section() { printf '\n=== %s ===\n' "$*"; }
section "Upstream $OLD -> $NEW"
echo "commits: $(git rev-list --count --no-merges "$OLD..$NEW")"
git diff --shortstat "$OLD" "$NEW"

section "Upstream changes to files the fork patches (FORK_CHANGES.md)"
ledger=$(scripts/rr/ledger-paths.sh)
if [ -n "$ledger" ]; then
  # shellcheck disable=SC2086
  git diff --stat "$OLD" "$NEW" -- $ledger || true
fi

section "Build / CI / engine-adapter changes"
git diff --stat "$OLD" "$NEW" -- gradle.properties settings.gradle.kts build.gradle.kts app/build.gradle.kts \
  gradle/lib.toml .github/ app/src/main/java/com/celzero/bravedns/net/go/ \
  app/src/main/java/com/celzero/bravedns/service/BraveVPNService.kt app/src/main/res/menu/bottom_nav_menu.xml || true
new_wf=$(comm -13 <(git ls-tree --name-only "$OLD" .github/workflows/ | sort) <(git ls-tree --name-only "$NEW" .github/workflows/ | sort))
[ -n "$new_wf" ] && { echo "NEW upstream workflows (review; disable if they need celzero secrets):"; echo "$new_wf" | sed 's/^/  /'; }

section "firestack pin"
fo=$(git show "$OLD:gradle.properties" | sed -n 's/^firestackCommit=//p')
fn=$(git show "$NEW:gradle.properties" | sed -n 's/^firestackCommit=//p')
echo "$fo -> $fn"
if [ "$fo" != "$fn" ]; then
  echo "compare: https://github.com/celzero/firestack/compare/$fo...$fn"
  echo "--- Java API delta (port into engine/, see UPSTREAM_SYNC.md §5) ---"
  scripts/rr/firestack-api-diff.sh "$fo" "$fn" || true
fi

if [ $dry -eq 1 ]; then
  section "Trial merge (dry run)"
  tmp=$(mktemp -d "${TMPDIR:-/tmp}/rrsync.XXXXXX")
  git worktree add -q --detach "$tmp" HEAD
  if (cd "$tmp" && git merge -q --no-commit --no-ff "$NEW" >/dev/null 2>&1); then
    echo "merges cleanly"
  else
    echo "conflicts:"; (cd "$tmp" && git diff --name-only --diff-filter=U | sed 's/^/  /')
  fi
  (cd "$tmp" && git merge --abort >/dev/null 2>&1 || true)
  git worktree remove --force "$tmp"
  exit 0
fi

section "Merging"
git push -q origin "refs/tags/$NEW" || echo "(could not push tag $NEW to origin; push it manually)"
git switch -c "sync/$NEW"
if git merge --no-ff --log=200 -m "sync: merge upstream $NEW" "$NEW"; then
  echo "$NEW" > .fork/UPSTREAM
  git commit -q -am "sync: record upstream $NEW in .fork/UPSTREAM"
  scripts/rr/check-ledger.sh || true
  scripts/rr/rpn-tripwire.sh || true
  echo; echo "Next: port firestack drift (if any), push sync/$NEW, open PR → main (merge commit)."
else
  echo; echo "Resolve conflicts (see UPSTREAM_SYNC.md §6), then:"
  echo "  git commit && echo $NEW > .fork/UPSTREAM && git commit -am 'sync: record upstream $NEW'"
  exit 1
fi
