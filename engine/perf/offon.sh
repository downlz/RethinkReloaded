#!/usr/bin/env bash
# Tunnel cost of one engine build: PSS / native heap / graphics of a fresh app process with the VPN off, then after
# tapping START (same process). The difference between the two is what running the tunnel costs; the VPN-off figure
# includes what merely loading the engine costs (Go starts its runtime on load).
#
#   engine/perf/offon.sh <apk>      (prints two lines: off, on; leaves the VPN off)
#
# The app's saved VPN state must be off (the script stops an auto-started VPN and restarts the process).
set -euo pipefail
apk=${1:?apk}
pkg=io.github.downlz.rethinkreloaded
act=$pkg/com.celzero.bravedns.ui.activity.LauncherAliasAppLock
toggle() { # taps the app's START/STOP button, found by resource id
  adb shell uiautomator dump /sdcard/rr-ui.xml >/dev/null 2>&1
  adb shell cat /sdcard/rr-ui.xml | python3 -I -c '
import re, sys
m = re.search(r"fhs_dns_on_off_btn\"[^>]*bounds=\"\[(\d+),(\d+)\]\[(\d+),(\d+)\]\"", sys.stdin.read())
if m:
    a = list(map(int, m.groups())); print((a[0] + a[2]) // 2, (a[1] + a[3]) // 2)
' | while read -r x y; do adb shell input tap "$x" "$y"; done
}
vpn_on() { adb shell dumpsys vpn_management | grep -m1 -q "Active vpn type: 1"; }
sample() {
  pid=$(adb shell pidof $pkg | tr -d '\r')
  for _ in 1 2 3 4 5 6; do
    adb shell dumpsys meminfo "$pid" | tr -d '\r' | awk '/TOTAL PSS:/ && !a {p=$3; a=1} /^ *Native Heap:/ && !b {n=$3; b=1}
      /^ *Graphics:/ && !c {g=$2; c=1} END {printf "%d/%d/%d ", p/1024, n/1024, g/1024}'
    sleep 5
  done
  echo
}
adb install -r "$apk" >/dev/null
adb shell appops set $pkg ACTIVATE_VPN allow
adb shell input keyevent WAKEUP
adb shell am start -n $act >/dev/null; sleep 8
if vpn_on; then toggle; sleep 3; adb shell am force-stop $pkg; adb shell am start -n $act >/dev/null; sleep 8; fi
[ -n "$(adb shell pidof $pkg | tr -d '\r')" ] || { echo "app not running" >&2; exit 1; }
sleep 52
echo -n "off (pss/native/graphics MB): "; sample
toggle; sleep 60
vpn_on || { echo "VPN did not start" >&2; exit 1; }
echo -n "on  (pss/native/graphics MB): "; sample
toggle; sleep 3
