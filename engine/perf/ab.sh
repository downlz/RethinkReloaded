#!/usr/bin/env bash
# Alternating A/B runs of the two engines on one device in one session (idle PSS, context switches, cached DNS).
# Single runs are noisy (background traffic of other apps flows through the VPN), so engines alternate per round.
#
#   engine/perf/ab.sh <go.apk> <rust.apk> [rounds=3] > engine/perf/ab-<label>.json
#
# Both APKs must be the same build type and signing key (installed over each other with -r; app data is kept).
# Requires engine/e2e/fs-probe on the device (see device-baseline.sh) and VPN consent (appops ACTIVATE_VPN allow).
set -euo pipefail
go_apk=${1:?go.apk}; rust_apk=${2:?rust.apk}; rounds=${3:-3}
pkg=io.github.downlz.rethinkreloaded
probe=/data/local/tmp/fs-probe
sh() { adb shell "$@" | tr -d '\r'; }
# taps the app's START button (found by resource id) when the app shows it
tap_start() {
  adb shell uiautomator dump /sdcard/rr-ui.xml >/dev/null 2>&1 || return 0
  adb shell cat /sdcard/rr-ui.xml | python3 -I -c '
import re, sys
x = sys.stdin.read()
m = re.search(r"<node [^>]*text=\"START\"[^>]*resource-id=\"[^\"]*fhs_dns_on_off_btn\"[^>]*bounds=\"\[(\d+),(\d+)\]\[(\d+),(\d+)\]\"", x)
if m:
    a = list(map(int, m.groups())); print((a[0] + a[2]) // 2, (a[1] + a[3]) // 2)
' | while read -r x y; do adb shell input tap "$x" "$y"; done
}
ctx() { sh "cat /proc/$1/task/*/status 2>/dev/null" | awk '/ctxt_switches/ {s += $2} END {print s+0}'; }
runs=""
for r in $(seq 1 "$rounds"); do
  for engine in go rust; do
    apk=$go_apk; [ $engine = rust ] && apk=$rust_apk
    adb install -r "$apk" >/dev/null
    sh appops set $pkg ACTIVATE_VPN allow
    owner=""
    # the app sometimes stops its own VPN right after a post-install launch (two starts race in Kotlin); relaunch once
    for attempt in 1 2; do
      sh am start -n $pkg/com.celzero.bravedns.ui.activity.LauncherAliasAppLock >/dev/null
      [ $attempt = 2 ] && { echo "round $r $engine: VPN not up; tapping START" >&2; sleep 3; tap_start; }
      for _ in $(seq 1 30); do
        owner=$(sh dumpsys vpn_management | awk '/Active package name:/ {p=$4} /Active vpn type:/ {if (!d && $4 != "-1") {print p}; d=1}')
        [ "$owner" = $pkg ] && break; sleep 1
      done
      [ "$owner" = $pkg ] && break
    done
    [ "$owner" = $pkg ] || { echo "round $r $engine: VPN not up (owner '$owner')" >&2; exit 1; }
    pid=$(sh pidof $pkg)
    sleep 60 # settle
    pss=(); nat=(); dal=(); gfx=()
    for _ in $(seq 1 6); do
      m=$(sh dumpsys meminfo "$pid")
      # App Summary rows (PSS, KB): "Native Heap:", "Java Heap:", "Graphics:", and the total
      pss+=("$(echo "$m" | awk '/TOTAL PSS:/ && !d {print $3; d=1}')")
      nat+=("$(echo "$m" | awk '/^ *Native Heap:/ && !d {print $3; d=1}')")
      dal+=("$(echo "$m" | awk '/^ *Java Heap:/ && !d {print $3; d=1}')")
      gfx+=("$(echo "$m" | awk '/^ *Graphics:/ && !d {print $2; d=1}')")
      sleep 5
    done
    c0=$(ctx "$pid"); sleep 60; c1=$(ctx "$pid")
    thr=$(sh "ls /proc/$pid/task | wc -l")
    dns=$(sh $probe dns 10.111.222.3:53 40 cached)
    runs="$runs{\"round\":$r,\"engine\":\"$engine\",\"pss_kb\":[$(IFS=,; echo "${pss[*]}")],\"native_heap_kb\":[$(IFS=,; echo "${nat[*]}")],\"java_heap_kb\":[$(IFS=,; echo "${dal[*]}")],\"graphics_kb\":[$(IFS=,; echo "${gfx[*]}")],\"ctx_per_min\":$((c1 - c0)),\"threads\":$thr,\"dns_cached\":$dns},"
    echo "round $r $engine: pss ${pss[5]} native ${nat[5]} java ${dal[5]} graphics ${gfx[5]} ctx/min $((c1 - c0))" >&2
  done
done
cat <<JSON
{
  "captured": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "device": "$(sh getprop ro.product.manufacturer) $(sh getprop ro.product.model) / Android $(sh getprop ro.build.version.release) / $(sh getprop ro.product.cpu.abi)",
  "screen": "on (charging), app in foreground, no user traffic",
  "runs": [${runs%,}]
}
JSON
