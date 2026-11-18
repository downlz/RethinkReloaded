# Branding and identity

RethinkReloaded renames the app in what users see and in package metadata. It never removes or hides credit to
Celzero and the RethinkDNS contributors. All branding lives in fork-owned files, so upstream merges stay clean.

## Identity

| Item | Upstream | RethinkReloaded | Where |
|---|---|---|---|
| applicationId | `com.celzero.bravedns` | `io.github.downlz.rethinkreloaded` (TV: `.tv` suffix, as upstream) | `app/fork/rethinkreloaded.gradle` |
| Kotlin namespace / packages | `com.celzero.bravedns` | **unchanged** (no files moved; keeps merges clean) | — |
| Launcher / app name | `Rethink`, `RethinkDNS` (25 locales), `Rethink TV` | `RethinkReloaded`, `RethinkReloaded TV` | generated overlay (below) |
| About header | `rethink` | `rethinkreloaded` + fork credit line under it | `app/fork/res/values/rr_strings.xml`, `[rr]` line in `AboutFragment.kt` |
| versionName | `git describe --tags` | same; fork tags are `vX.Y.Z-rr.N` | upstream build script |
| versionCode | `abi*10M + VERSION_CODE` | `abi*10M + VERSION_CODE*100 + rrRevision` | `app/fork/rethinkreloaded.gradle` |

Because the applicationId differs, RethinkReloaded installs **alongside** the original Rethink app. The two do not share
data. Users can move settings with upstream's backup/restore, which does not check the package name.

## How the name overlay works

Upstream defines `app_name` in `values/strings.xml` and overrides it in 25 locale files (Weblate keeps those in sync).
Editing them would conflict on every sync. Instead, the `rrNameOverlay<Variant>` task scans
`src/{main,full,tv}/res/values*/strings.xml` for every qualifier that defines `app_name`. It writes a matching
`values-<q>/rr_branding.xml` (for `app_name` and `app_name_small_case`) and registers it with `variant.sources.res.addGeneratedSourceDirectory(...)`.
Sources added through the variant API take precedence over the main, flavor and build-type source sets.
New locales from Weblate are picked up automatically.

`app/fork/res` is added as a static resource source directory in the same way. It holds:
* `values/rr_strings.xml`: fork-only strings (`rr_fork_credit`)
* `menu/bottom_nav_menu.xml`: upstream's bottom navigation without the Rethink Plus (RPN) tab

Verify after a build:
```bash
aapt2 dump badging app/build/outputs/apk/fdroidFull/debug/<apk> | grep -E "^package|application-label"
```
Every `application-label-<locale>` line should read `RethinkReloaded`.

## Package-name fixes (upstreamable)

Four places hardcoded `com.celzero.bravedns`. They break whenever the applicationId differs from the namespace, which
also happens in upstream's own `.alpha` and `.izzy` builds. They now use `BuildConfig.APPLICATION_ID`:

| File | Effect of the bug |
|---|---|
| `util/Constants.kt` `RETHINK_PACKAGE` | own app not skipped in the app list; own data usage lost; wrong App-info adapters |
| `database/AppInfoDAO.kt` `exemptRethinkApp` | with the original app installed, the fork exempted **the original app** from its firewall |
| `database/ConnectionTrackerDAO.kt` `RLOG_COLUMNS` | the fork's own log rows had the wrong package (missing icon) |
| `ui/HomeScreenActivity.kt` legacy prefs migration | read a non-existent prefs file and reset "LAN traffic" on every update |

These fixes should be offered upstream (`upstreamable/self-package`). Once celzero merges them, the ledger entries go away.

## RPN / Rethink Plus

RPN is Celzero's paid proxy network, tied to Celzero's billing account. The fork does not offer it:
* Only the **fdroid** flavor is shipped. Upstream already stubs billing there (`app/src/fdroid/.../iab`,
  `com/android/billingclient` stubs), and the RPN rows in proxy settings are hidden.
* The bottom-nav "Rethink Plus" tab is removed by the menu overlay (no Kotlin change; `HomeScreenActivity` uses `?.`).
* `BuildConfig.RR_RPN_ENABLED = false` is available if upstream adds new RPN entry points that need gating.
* The Rust engine implements RPN APIs only as permanent `unsupported` stubs.
* `scripts/rr/rpn-tripwire.sh` fails a sync if upstream changes the menu or the fdroid stubs.

## What is deliberately *not* rebranded

* Upstream source headers, `LICENSE`, `README.md`, in-app contributor and translator credits, and `FUNDING.yml` / `funding.json`.
  These are attribution and stay as they are.
* Strings that name Celzero's services ("Rethink DNS" resolver, blocklists, sponsor link). The fork still uses those
  services, so the names are accurate.
* Fastlane metadata (`fastlane/metadata/android/*/title.txt`). If the fork is ever listed on F-Droid or IzzyOnDroid,
  set the name in that listing's own metadata instead of editing these files.
