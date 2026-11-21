#!/usr/bin/env bash
# Alternating rounds of several builds of the app on one device (e.g. engine opt-levels): idle PSS and its parts,
# including ".so mmap" (code pages of native libraries, where the engine's own code shows), threads, and the app's
# CPU seconds while downloading a file through the VPN.
#
#   engine/perf/variants.sh <rounds> <url-host> <url-port> <url-path> <label>=<apk> [<label>=<apk> ...] > out.json
#
# Serve a large file from the host (emulator: python3 -m http.server 8000 --bind 127.0.0.1, url-host 10.0.2.2).
# APKs must share a signing key (installed over each other with -r; app data is kept). Needs engine/e2e/fs-probe
# on the device and VPN consent (appops ACTIVATE_VPN allow). Emulator numbers are relative only (TESTING.md §7).
# RR_WARM_DNS=<n>: send n uncached DNS queries through the VPN before sampling (touches the on-device blocklist).
set -euo pipefail
rounds=${1:?rounds}; host=${2:?url host}; port=${3:?url port}; path=${4:?url path}; shift 4
pkg=io.github.downlz.rethinkreloaded
probe=/data/local/tmp/fs-probe
sh() { adb shell "$@" | tr -d '\r'; }
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
# utime + stime of the process, in clock ticks (1/100 s)
cpu() { sh "cat /proc/$1/stat" | awk '{sub(/^.*\) /, ""); print $12 + $13}'; }
runs=""
for r in $(seq 1 "$rounds"); do
  for spec in "$@"; do
    label=${spec%%=*}; apk=${spec#*=}
    adb install -r "$apk" >/dev/null
    sh appops set $pkg ACTIVATE_VPN allow
    owner=""
    for attempt in 1 2; do
      sh am start -n $pkg/com.celzero.bravedns.ui.activity.LauncherAliasAppLock >/dev/null
      [ $attempt = 2 ] && { echo "round $r $label: VPN not up; tapping START" >&2; sleep 3; tap_start; }
      for _ in $(seq 1 30); do
        owner=$(sh dumpsys vpn_management | awk '/Active package name:/ {p=$4} /Active vpn type:/ {if (!d && $4 != "-1") {print p}; d=1}')
        [ "$owner" = $pkg ] && break; sleep 1
      done
      [ "$owner" = $pkg ] && break
    done
    [ "$owner" = $pkg ] || { echo "round $r $label: VPN not up (owner '$owner')" >&2; exit 1; }
    pid=$(sh pidof $pkg)
    [ -n "${RR_WARM_DNS:-}" ] && sh $probe dns 10.111.222.3:53 "$RR_WARM_DNS" uncached >/dev/null
    sleep 60 # settle
    pss=(); nat=(); so=(); gfx=(); oth=()
    for _ in $(seq 1 6); do
      m=$(sh dumpsys meminfo "$pid")
      pss+=("$(echo "$m" | awk '/TOTAL PSS:/ && !d {print $3; d=1}')")
      nat+=("$(echo "$m" | awk '/^ *Native Heap:/ && !d {print $3; d=1}')")
      so+=("$(echo "$m" | awk '/^ *\.so mmap/ && !d {print $3; d=1}')")
      gfx+=("$(echo "$m" | awk '/^ *Graphics:/ && !d {print $2; d=1}')")
      oth+=("$(echo "$m" | awk '/^ *Other mmap/ && !d {print $3; d=1}')")
      sleep 5
    done
    thr=$(sh "ls /proc/$pid/task | wc -l")
    c0=$(cpu "$pid")
    dl=$(sh $probe get "$host" "$port" "$path" 60)
    c1=$(cpu "$pid")
    bytes=$(echo "$dl" | sed -n 's/.*"bytes":\([0-9]*\).*/\1/p')
    mbit=$(echo "$dl" | sed -n 's/.*"mbit_s":\([0-9.]*\).*/\1/p')
    runs="$runs{\"round\":$r,\"variant\":\"$label\",\"pss_kb\":[$(IFS=,; echo "${pss[*]}")],\"native_heap_kb\":[$(IFS=,; echo "${nat[*]}")],\"so_mmap_kb\":[$(IFS=,; echo "${so[*]}")],\"graphics_kb\":[$(IFS=,; echo "${gfx[*]}")],\"other_mmap_kb\":[$(IFS=,; echo "${oth[*]}")],\"threads\":$thr,\"download_bytes\":${bytes:-0},\"download_mbit_s\":${mbit:-0},\"cpu_ticks\":$((c1 - c0))},"
    echo "round $r $label: pss ${pss[5]} native ${nat[5]} so ${so[5]} other-mmap ${oth[5]} gfx ${gfx[5]} thr $thr dl ${mbit:-?}Mbit/s cpu $((c1 - c0)) ticks" >&2
  done
done
cat <<JSON
{
  "captured": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "device": "$(sh getprop ro.product.model) / Android $(sh getprop ro.build.version.release) / $(sh getprop ro.product.cpu.abi)",
  "emulator": $( [ "$(sh getprop ro.kernel.qemu)" = "1" ] && echo true || echo false ),
  "firestack_pin": "$(cat "$(dirname "$0")/../api/PIN")",
  "runs": [${runs%,}]
}
JSON
