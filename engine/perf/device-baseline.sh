#!/usr/bin/env bash
# Engine baseline on a connected device (set ANDROID_SERIAL). Run once with RethinkReloaded's VPN connected, and once
# with --no-vpn (no VPN at all) as the network reference. Requires engine/e2e/fs-probe built for the device ABI:
#   cargo ndk -t arm64-v8a build --release -p fs-probe   (in engine/)
#
#   engine/perf/device-baseline.sh <label> [--no-vpn] > engine/perf/<label>.json
#
# Optional: RR_HTTP_TARGET="<host> <port> <path>" for the download test (recommended: a LAN HTTP server).
# Sections: meta, idle (PSS/RSS/threads samples + context switches/min as a wakeup proxy), dns (via the VPN's DNS
# address: uncached + cached), tcp connect latency, download throughput + app CPU seconds per GB.
set -euo pipefail
label=${1:?usage: $0 <label> [--no-vpn]}; novpn=0; [ "${2:-}" = "--no-vpn" ] && novpn=1
here=$(cd "$(dirname "$0")" && pwd); engine=$(cd "$here/.." && pwd)
pkg=io.github.downlz.rethinkreloaded
probe=/data/local/tmp/fs-probe
sh() { adb shell "$@" | tr -d '\r'; }

abi=$(sh getprop ro.product.cpu.abi)
adb push "$engine/target/$( [ "$abi" = arm64-v8a ] && echo aarch64-linux-android || echo armv7-linux-androideabi )/release/fs-probe" $probe >/dev/null
sh chmod 755 $probe
transport=$(sh dumpsys connectivity | grep -m1 -oE 'Active default network: [0-9]+' || true)
# only non-identifying link properties (no SSID / BSSID / MAC / IP)
wifi=$(sh dumpsys wifi | grep -m1 'mWifiInfo SSID' | grep -oE 'Wi-Fi standard: [^,]+|RSSI: -?[0-9]+|Link speed: [0-9]+Mbps|Rx Link speed: [0-9]+Mbps' | paste -sd ';' - || true)
# "Active package name" is the last *prepared* VPN app; it is connected only when "Active vpn type" is not -1
vpn_owner=$(sh dumpsys vpn_management 2>/dev/null | awk '/Active package name:/ {p=$4} /Active vpn type:/ {if ($4 != "-1") print p; exit}' || true)

if [ $novpn -eq 0 ]; then
  [ "$vpn_owner" = "$pkg" ] || { echo "VPN owner is '$vpn_owner', expected $pkg" >&2; exit 1; }
  dns_server=$(sh dumpsys connectivity | grep -m1 -A3 'VpnTransportInfo' | grep -oE 'DnsAddresses: \[ /[0-9.]+' | grep -oE '[0-9.]+$' || true)
  dns_server=${dns_server:-10.111.222.3}
  pid=$(sh pidof $pkg)
else
  [ -z "$vpn_owner" ] || { echo "a VPN ($vpn_owner) is active; --no-vpn needs none" >&2; exit 1; }
  dns_server=1.1.1.1
fi

cpu_ticks() { sh cat /proc/"$1"/stat | awk '{print $14 + $15}'; }
ctx() { sh "cat /proc/$1/task/*/status 2>/dev/null" | awk '/ctxt_switches/ {s += $2} END {print s+0}'; }

idle="null"; wake="null"
if [ $novpn -eq 0 ]; then
  sleep 20 # settle after start
  idle=$("$here/capture.sh" "$label" 10 6 | python3 -I -c 'import json,sys; print(json.dumps(json.load(sys.stdin)))')
  c0=$(ctx "$pid"); sleep 60; c1=$(ctx "$pid")
  wake="{\"ctx_switches_per_min\":$((c1 - c0)),\"threads\":$(sh "ls /proc/$pid/task | wc -l")}"
fi

dns_unc=$(sh $probe dns "$dns_server:53" 40 uncached)
dns_cac=$(sh $probe dns "$dns_server:53" 40 cached)
tcp=$(sh $probe tcp 1.1.1.1:443 20)
# RR_HTTP_TARGET="<host> <port> <path>" (e.g. a LAN box: python3 -m http.server) avoids internet variance;
# otherwise public plain-HTTP test files are tried in order.
targets=("${RR_HTTP_TARGET:-}" "cachefly.cachefly.net 80 /100mb.test" "speedtest.tele2.net 80 /100MB.zip")
for target in "${targets[@]}"; do
  [ -n "$target" ] || continue
  t0=0; [ $novpn -eq 0 ] && t0=$(cpu_ticks "$pid")
  get=$(sh $probe get $target 20)
  t1=0; [ $novpn -eq 0 ] && t1=$(cpu_ticks "$pid")
  bytes=$(echo "$get" | grep -oE '"bytes":[0-9]+' | cut -d: -f2 || true)
  [ "${bytes:-0}" -gt 1000000 ] && break
done
cpu_per_gb="null"
if [ $novpn -eq 0 ] && [ "${bytes:-0}" -gt 0 ]; then
  cpu_per_gb=$(python3 -I -c "print(round(($t1-$t0)/100/($bytes/1e9), 2))")
fi

cat <<JSON
{
  "label": "$label",
  "captured": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "device": "$(sh getprop ro.product.manufacturer) $(sh getprop ro.product.model) / Android $(sh getprop ro.build.version.release) (API $(sh getprop ro.build.version.sdk)) / $abi",
  "vpn": $( [ $novpn -eq 0 ] && echo "\"$vpn_owner\"" || echo null ),
  "network": "$transport${wifi:+; $wifi}",
  "http_target": "${target:-}",
  "firestack_pin": "$(cat "$engine/api/PIN")",
  "screen": "on (charging), idle = no user traffic",
  "idle": $idle,
  "wakeups": $wake,
  "dns_uncached": $dns_unc,
  "dns_cached": $dns_cac,
  "tcp_connect": $tcp,
  "download": $get,
  "app_cpu_seconds_per_gb": $cpu_per_gb
}
JSON
