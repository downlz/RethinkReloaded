#!/usr/bin/env bash
# Cold start and VPN-ready time of the installed engine build (run once per engine; the app must have the VPN on).
#
#   engine/perf/startup.sh <label> [iterations=5] > engine/perf/startup-<label>.json
#
# Per iteration: force-stop, then `am start -W` (TotalTime: launch to first frame, as Macrobenchmark's
# StartupTimingMetric) while timing on the device, from the launch, until a tun interface exists and until a DNS query
# to the VPN's DNS address is answered. The app restarts its VPN on launch.
set -euo pipefail
label=${1:?usage: $0 <label> [iterations]}; n=${2:-5}
pkg=io.github.downlz.rethinkreloaded
act=$pkg/com.celzero.bravedns.ui.activity.LauncherAliasAppLock
runs=""
for i in $(seq 1 "$n"); do
  adb shell am force-stop $pkg
  sleep 3
  out=$(adb shell "
    t0=\$(date +%s%N)
    am start -W -n $act > /data/local/tmp/am.out &
    tun=''; dns=''
    while [ -z \"\$dns\" ]; do
      now=\$(date +%s%N); el=\$(( (now - t0) / 1000000 ))
      [ \$el -gt 30000 ] && break
      if [ -z \"\$tun\" ] && ls /sys/class/net | grep -q '^tun'; then tun=\$el; fi
      if [ -n \"\$tun\" ] && /data/local/tmp/fs-probe lookup 10.111.222.3:53 example.com 2>/dev/null | grep -q '\"rcode\":0'; then
        dns=\$(( (\$(date +%s%N) - t0) / 1000000 ))
      fi
      sleep 0.02
    done
    wait
    echo \"\$(grep TotalTime /data/local/tmp/am.out | tr -dc 0-9) \${tun:-null} \${dns:-null}\"
  " | tr -d '\r')
  read -r total tun dns <<<"$out"
  echo "iteration $i: total ${total}ms tun ${tun}ms dns ${dns}ms" >&2
  runs="$runs{\"total_time_ms\":${total:-null},\"tun_up_ms\":$tun,\"dns_ready_ms\":$dns},"
  sleep 5
done
cat <<JSON
{
  "label": "$label",
  "captured": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "device": "$(adb shell getprop ro.product.model | tr -d '\r') / Android $(adb shell getprop ro.build.version.release | tr -d '\r')",
  "runs": [${runs%,}]
}
JSON
