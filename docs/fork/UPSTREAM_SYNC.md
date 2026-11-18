# Upstream synchronization workflow

How RethinkReloaded absorbs each new release of [celzero/rethink-app](https://github.com/celzero/rethink-app)
without losing fork changes, and without rewriting upstream history or authorship.

## 1. Principles

1. **Release tags only.** The fork's `main` is always *one upstream release tag plus the fork patches*.
   We merge release tags (`v0.5.9`), never upstream `main` between releases.
2. **Merge, never rebase.** Upstream commits keep their SHAs, authors and dates. That preserves attribution and
   keeps `git describe` working, and the next merge only sees the new upstream commits.
   Squash and rebase merges are disabled at the repo level.
3. **Minimal footprint.** Fork code lives in fork-owned paths (`engine/`, `app/fork/`, `docs/fork/`, `scripts/rr/`,
   `.github/workflows/rr-*`, `.github/README.md`, `NOTICE`, `FORK_CHANGES.md`, `.fork/`), which upstream never touches.
   Every edit to an upstream file is listed in [`FORK_CHANGES.md`](../../FORK_CHANGES.md) and marked `[rr]` in the file.
   CI (`scripts/rr/check-ledger.sh`) fails if an unlisted upstream file is modified.
4. **Disable, don't delete.** Unwanted upstream workflows are disabled via `gh workflow disable`, not deleted.
   Deleting would cause modify/delete conflicts on every sync.
5. **Two upstreams.** rethink-app pins the Go engine in `gradle.properties` (`firestackCommit=<sha10>`), and every
   release bumps it. Each sync is therefore also a [firestack](https://github.com/celzero/firestack) API-drift review
   for the Rust engine (§5).

## 2. One-time local setup

```bash
git clone https://github.com/downlz/RethinkReloaded.git && cd RethinkReloaded
git remote add upstream https://github.com/celzero/rethink-app.git
git remote set-url --push upstream DISABLE       # accidental pushes to celzero fail
git config remote.upstream.tagOpt --tags
git config remote.pushDefault origin
git config rerere.enabled true                   # remember conflict resolutions across syncs
git config rerere.autoUpdate true
git config merge.conflictStyle zdiff3
gh repo set-default downlz/RethinkReloaded       # so `gh pr create` targets the fork
git fetch upstream --tags
```

## 3. Branches and tags

| Ref | Purpose | Rules |
|---|---|---|
| `main` | Default branch: upstream release + fork patches | Protected; PR + merge commit only; never force-pushed or rebased |
| `upstream/main` | Remote-tracking mirror of celzero | Fetch only; no local branch is committed to |
| `sync/vX.Y.Z` | Integration branch for one upstream release | Created from `main`, merged back with a merge commit |
| `engine/*` | Rust engine work | May rebase onto `main` before its PR |
| `fork/*` | Branding / attribution / tooling | May rebase onto `main` before its PR |
| `upstreamable/*` | Fixes to offer celzero | Branched from `upstream/main` so the PR is clean |

**Tags**
* Upstream tags (`v0.5.8`, `v0.5.5z`, …) are mirrored into the fork unchanged: `git push origin refs/tags/vX.Y.Z`.
* Fork releases use **annotated** tags `vX.Y.Z-rr.N`, for example `v0.5.8-rr.1` (the first fork release on top of upstream v0.5.8).
  Upstream never uses `-rr`, so the tag sets cannot collide.
* `versionName` comes from `git describe --tags --always` (upstream `app/build.gradle.kts`). It yields `v0.5.8-rr.1` on a
  release commit and `v0.5.8-rr.1-12-gabc1234` between releases. CI must check out with `fetch-depth: 0`.
* `.fork/UPSTREAM` records the upstream tag currently merged into `main`.

## 4. Per-release procedure

`scripts/rr/sync-release.sh vX.Y.Z` automates steps 2–4. Run it with `--dry-run` to preview.

### 4.1 Detect
`.github/workflows/rr-upstream-watch.yml` runs daily (and on demand). When `releases/latest` differs from
`.fork/UPSTREAM`, it opens an `upstream-sync` issue with:
* the commit count;
* upstream changes to ledger files;
* the old→new firestack pin and a compare link;
* the conflict list from a trial merge.

Manual check: `gh release view -R celzero/rethink-app --json tagName,publishedAt`.

### 4.2 Merge
```bash
NEW=v0.5.9; OLD=$(cat .fork/UPSTREAM)
git fetch upstream --tags && git push origin "refs/tags/$NEW"
git switch -c "sync/$NEW" origin/main
git merge --no-ff --log=200 -m "sync: merge upstream $NEW" "$NEW"   # rerere replays known resolutions
```

### 4.3 Review the incoming diff
```bash
git log --oneline --no-merges "$OLD..$NEW" | wc -l                   # size of the release
git diff --stat "$OLD" "$NEW"                                        # what upstream changed
git diff "$OLD" "$NEW" -- $(scripts/rr/ledger-paths.sh)              # upstream edits to files we patch
git diff "$OLD" "$NEW" -- gradle.properties settings.gradle.kts app/build.gradle.kts .github/ \
  app/src/main/java/com/celzero/bravedns/net/go/GoVpnAdapter.kt \
  app/src/main/java/com/celzero/bravedns/service/BraveVPNService.kt
git grep -l 'import com.celzero.firestack' "$NEW" -- app/src | wc -l  # engine API consumers
```
Look for:
* new firestack calls in Kotlin;
* new workflows;
* new RPN/billing entry points;
* changes to `bottom_nav_menu.xml`;
* changes around the `[rr]` hunks.

### 4.4 Post-merge checks
```bash
scripts/rr/check-ledger.sh        # no unlisted upstream edits
scripts/rr/rpn-tripwire.sh        # RPN still hidden in the fdroid flavor
gh workflow list --all            # disable any NEW upstream workflow that needs celzero secrets
```

### 4.5 Engine drift (§5), CI, ship
1. Port the firestack API drift (§5) on `engine/*` branches until the contract diff is empty.
2. Push `sync/$NEW`. CI (`rr-ci.yml`) builds with the **Go** engine (`ossrh`) and the **Rust** engine (`rust`) and runs unit tests.
3. Write `$NEW` to `.fork/UPSTREAM`, then open a PR `sync/$NEW → main` and merge with **Create a merge commit**.
4. Tag and release:
   ```bash
   git tag -a "$NEW-rr.1" -m "RethinkReloaded based on celzero/rethink-app $NEW"
   git push origin "$NEW-rr.1"
   ```
   `rr-release.yml` builds and attaches the signed fdroid APKs. The release notes link upstream's release notes.

## 5. Firestack API drift (Rust engine)

The Kotlin app calls firestack through gomobile-generated Java (`com.celzero.firestack.{intra,backend,settings}`).
The Rust engine vendors that Java from Maven Central's `firestack-<sha>-sources.jar` and implements the natives.
When the pin moves:

```bash
O=$(git show "$OLD:gradle.properties" | sed -n 's/^firestackCommit=//p')
N=$(git show "$NEW:gradle.properties" | sed -n 's/^firestackCommit=//p')
scripts/rr/firestack-api-diff.sh "$O" "$N"        # exact Java API delta (added/removed/changed methods)
gh api "repos/celzero/firestack/compare/$O...$N" \
  --jq '.files[] | select(.filename|test("^intra/")) | .status+" "+.filename'   # Go files changed
```
Then:
1. Re-vendor the facade at `$N` (`engine/tools/facade-sync.sh $N`) and regenerate the JNI stubs.
   New natives get default "unimplemented" bodies, so the build stays green.
2. For each changed Go file, find the Rust files whose `Derived-From:` header names it and port the semantic change.
   Use commit trailers `Ported-from: celzero/firestack@<sha>:<path>`.
3. Done when the contract test (javap diff of upstream AAR vs. ours) is empty and both-engine CI is green.

## 6. Conflict resolution guide

| Situation | Resolution |
|---|---|
| Upstream changed a file carrying an `[rr]` patch | Take upstream's version (`git checkout --theirs`), re-apply the `[rr]`-marked lines, and confirm the ledger entry is still accurate |
| `gradle.properties` | Always take upstream's version. The fork never edits it; the engine is chosen with `-PfirestackRepo=rust` |
| `strings.xml` / new Weblate locales | Cannot conflict. The fork never edits them; `app_name` is overridden by a generated overlay (see BRANDING.md) |
| `engine/`, `app/fork/`, `docs/fork/`, `scripts/rr/`, `rr-*` workflows, `.github/README.md`, `NOTICE` | Fork-owned; never conflict |
| `app/build.gradle.kts` / `settings.gradle.kts` | Take upstream's version and re-add the `[rr]` block (the `rust` repo option and the `apply(from = "fork/…")` line) |
| Upstream edits `bottom_nav_menu.xml` | No textual conflict, but the overlay would hide the change. `rpn-tripwire.sh` fails; regenerate `app/fork/res/menu/bottom_nav_menu.xml` from the new upstream file minus the RPN item |
| Upstream adds RPN/billing to the fdroid flavor | Tripwire fails; gate the new entry points with `BuildConfig.RR_RPN_ENABLED` and add them to the ledger |
| Upstream fixes something the fork patched (e.g. our upstreamed package-name fix) | Take upstream's version and remove the ledger entry |
| The same conflict comes up again | rerere replays it. Check with `git rerere diff` before committing |
| A bad sync was merged | `git revert -m 1 <merge-sha>` on a branch + PR. Never force-push `main` |

After resolving, always run `git diff "$NEW" -- . ':!engine' ':!docs/fork' ':!app/fork' ':!scripts/rr' ':!.fork'`.
The only differences from the upstream tag should be the ledger entries.

## 7. Contributing back

Fixes that are not fork-specific go to celzero first: branch `upstreamable/<topic>` from `upstream/main` and open a PR on
celzero/rethink-app. Once upstream merges and releases a fix, the next sync removes the fork's copy and its ledger entry.
