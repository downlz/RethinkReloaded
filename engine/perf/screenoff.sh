#!/usr/bin/env bash
# Screen-off cost of the installed engine build: voluntary context switches (thread wakeups), CPU time and the
# battery estimate of the app while the screen is off, the charger is reported unplugged and no one uses the phone.
#
#   engine/perf/screenoff.sh <label> [minutes=15] > engine/perf/screenoff-<label>.json
#
# The VPN must be up. batterystats is reset at the start and the charger state is restored at the end. Doze is not
# forced: this is the first, non-dozing stretch of screen-off time, the most sensitive one for wakeups.
set -euo pipefail
label=${1:?usage: $0 <label> [minutes]}; mins=${2:-15}
pkg=io.github.downlz.rethinkreloaded
sh() { adb shell "$@" | tr -d '\r'; }
pid=$(sh pidof $pkg); [ -n "$pid" ] || { echo "app not running" >&2; exit 1; }
uid=$(sh dumpsys package $pkg | awk -F= '/^ *appId=/ && !d {print $2+0; d=1}')
vol() { sh "cat /proc/$pid/task/*/status 2>/dev/null" | awk '/^voluntary_ctxt_switches/ {s += $2} END {print s+0}'; }
inv() { sh "cat /proc/$pid/task/*/status 2>/dev/null" | awk '/^nonvoluntary_ctxt_switches/ {s += $2} END {print s+0}'; }
ticks() { sh cat /proc/"$pid"/stat | awk '{print $14 + $15}'; }
restore() { adb shell dumpsys battery reset >/dev/null 2>&1 || true; }
trap restore EXIT

sh dumpsys battery unplug >/dev/null
sh dumpsys batterystats --reset >/dev/null
sh input keyevent SLEEP
sleep 10
v0=$(vol); n0=$(inv); t0=$(ticks)
sleep $((mins * 60))
v1=$(vol); n1=$(inv); t1=$(ticks)
[ "$(sh pidof $pkg)" = "$pid" ] || { echo "app restarted during the window" >&2; exit 1; }
# per-uid estimate, e.g. "UID u0a123: 1.23 ( cpu=1.10 ... )"; app uid printed as u0aNNN
appid=$(python3 -I -c "u=$uid; print(f'u0a{u-10000}' if u >= 10000 else str(u))")
est=$(sh dumpsys batterystats | awk -v a="UID $appid:" 'index($0, a) && !d {print $3; d=1}')
sh input keyevent WAKEUP
cat <<JSON
{
  "label": "$label",
  "captured": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "device": "$(sh getprop ro.product.model) / Android $(sh getprop ro.build.version.release)",
  "minutes": $mins,
  "voluntary_switches_per_min": $(( (v1 - v0) / mins )),
  "involuntary_switches_per_min": $(( (n1 - n0) / mins )),
  "cpu_seconds": $(python3 -I -c "print(($t1 - $t0) / 100)"),
  "battery_estimate_mah": ${est:-null}
}
JSON
