# Fork change ledger

This file lists every **upstream** file (from [celzero/rethink-app](https://github.com/celzero/rethink-app)) that
RethinkReloaded modifies. It keeps the fork's diff against each upstream release small and reviewable, and it is the
"prominent notice" of modified files required by Apache-2.0 §4(b). Each modified line or block is also tagged `[rr]`
in the file itself.

`scripts/rr/check-ledger.sh` (run in CI) fails when an upstream file differs from the tag in `.fork/UPSTREAM` but is
not listed below, or when a listed file lacks an `[rr]` marker.

Fork-owned paths need no ledger entry because upstream never has them:
`engine/`, `app/fork/`, `docs/fork/`, `scripts/rr/`, `.fork/`, `.github/workflows/rr-*`, `.github/README.md`, `NOTICE`,
`FORK_CHANGES.md`.

## Modified upstream files

| File | Change | Why | Upstreamable |
|---|---|---|---|
| `.gitignore` | ignore `keystore.properties`, `*.jks`, `*.keystore` | never commit signing material | yes |
| `app/build.gradle.kts` | one `apply(from = "fork/rethinkreloaded.gradle")` line at the end; `"rust"` case in `firestackDependency()` | branding layer; Rust engine selection | no |
| `settings.gradle.kts` | `includeBuild("engine/android")` when `-PfirestackRepo=rust` | Rust engine selection | no |
| `app/src/main/java/com/celzero/bravedns/util/Constants.kt` | `RETHINK_PACKAGE = BuildConfig.APPLICATION_ID` | self-detection breaks when applicationId ≠ namespace | yes (also fixes upstream .alpha/.izzy) |
| `app/src/main/java/com/celzero/bravedns/database/AppInfoDAO.kt` | `exemptRethinkApp` uses `$RETHINK_PACKAGE` | fork would exempt the *original* app from its firewall | yes |
| `app/src/main/java/com/celzero/bravedns/database/ConnectionTrackerDAO.kt` | `RLOG_COLUMNS` uses `$RETHINK_PACKAGE` | own log rows had wrong package | yes |
| `app/src/main/java/com/celzero/bravedns/ui/HomeScreenActivity.kt` | legacy prefs file name from `BuildConfig.APPLICATION_ID` | "LAN traffic" setting reset on every update | yes |
| `benchmark/src/main/java/com/celzero/bravedns/benchmark/VpnStartupBenchmark.kt` | target package `io.github.downlz.rethinkreloaded` | upstream's package would benchmark the original Rethink app installed next to the fork | no |
| `app/src/main/java/com/celzero/bravedns/ui/fragment/AboutFragment.kt` | append fork credit (`R.string.rr_fork_credit`) under the About header | attribution to Celzero in-app | no |

<!-- ledger:begin -->
- `.gitignore`
- `app/build.gradle.kts`
- `settings.gradle.kts`
- `app/src/main/java/com/celzero/bravedns/util/Constants.kt`
- `app/src/main/java/com/celzero/bravedns/database/AppInfoDAO.kt`
- `app/src/main/java/com/celzero/bravedns/database/ConnectionTrackerDAO.kt`
- `app/src/main/java/com/celzero/bravedns/ui/HomeScreenActivity.kt`
- `app/src/main/java/com/celzero/bravedns/ui/fragment/AboutFragment.kt`
- `benchmark/src/main/java/com/celzero/bravedns/benchmark/VpnStartupBenchmark.kt`
<!-- ledger:end -->

## Disabled upstream workflows (via `gh workflow disable`, files untouched)

| Workflow | Reason |
|---|---|
| `nightly.yml` | needs celzero's alpha keystore, Play dev-id and Telegram secrets |
| `izzyondroid.yml` | triggers on every `v*` tag (including fork tags) and needs celzero's IzzyOnDroid keystore |
| `telegram-notify.yml` | posts to celzero's Telegram channel |
| `ocr.yml` | needs celzero's LLM review credentials |
