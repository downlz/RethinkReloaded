#!/usr/bin/env bash
# Captures engine resource metrics from a connected device/emulator while RethinkReloaded runs (VPN on).
#
#   engine/perf/capture.sh <label> [samples=10] [interval_s=6] > engine/perf/<label>.json
#
# Records: device, engine identity (Intra.build via bug-report-free means: libgojni size + logcat tag), VPN state,
# and per-sample PSS / native heap / RSS / thread count of the app process. Idle measurements: keep the screen on,
# no traffic. Compare Go vs Rust only on the same device + build type (see docs/fork/TESTING.md §7).
set -euo pipefail
label=${1:?usage: $0 <label> [samples] [interval_s]}; n=${2:-10}; iv=${3:-6}
pkg=io.github.downlz.rethinkreloaded
pid=$(adb shell pidof "$pkg" | tr -d '\r')
[ -n "$pid" ] || { echo "app not running" >&2; exit 1; }
apk_dir=$(adb shell pm path "$pkg" | head -1 | sed 's/^package://; s/base.apk$//' | tr -d '\r')
abi=$(adb shell getprop ro.product.cpu.abi | tr -d '\r')
lib_size=$(adb shell "unzip -l ${apk_dir}base.apk lib/$abi/libgojni.so 2>/dev/null" | awk '/libgojni/ {print $1}' | tr -d '\r')
# RR_ENGINE=rust|go overrides detection (the log line is lost if logcat was cleared after the app started)
engine=${RR_ENGINE:-$(adb logcat -d -s GoLog:I | grep -q "rust engine loaded" && echo rust || echo go)}
vpn=$(adb shell dumpsys connectivity | grep -c "VPN CONNECTED\|type: VPN\[" || true)
samples=""
for i in $(seq 1 "$n"); do
  mem=$(adb shell dumpsys meminfo "$pid" | tr -d '\r')
  pss=$(echo "$mem" | awk '/TOTAL PSS:/ {print $3; exit} /^ *TOTAL / {print $2; exit}')
  native=$(echo "$mem" | awk '/Native Heap:/ {print $3; exit}')
  st=$(adb shell cat /proc/"$pid"/status | tr -d '\r')
  rss=$(echo "$st" | awk '/^VmRSS:/ {print $2}')
  thr=$(echo "$st" | awk '/^Threads:/ {print $2}')
  samples="$samples{\"pss_kb\":${pss:-0},\"native_heap_kb\":${native:-0},\"rss_kb\":${rss:-0},\"threads\":${thr:-0}},"
  [ "$i" -lt "$n" ] && sleep "$iv"
done
cat <<JSON
{
  "label": "$label",
  "captured": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "device": "$(adb shell getprop ro.product.model | tr -d '\r') / Android $(adb shell getprop ro.build.version.release | tr -d '\r') / $abi",
  "emulator": $( [ "$(adb shell getprop ro.kernel.qemu | tr -d '\r')" = "1" ] && echo true || echo false ),
  "engine": "$engine",
  "firestack_pin": "$(cat "$(dirname "$0")/../api/PIN")",
  "libgojni_bytes": ${lib_size:-0},
  "vpn_connected": $( [ "${vpn:-0}" -gt 0 ] && echo true || echo false ),
  "samples": [${samples%,}]
}
JSON
