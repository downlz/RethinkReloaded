#!/usr/bin/env bash
# Soak: keeps traffic flowing through RethinkReloaded's VPN for hours and samples the app process, to catch leaks
# (memory, file descriptors, threads) and crashes. Each cycle: uncached DNS queries, TCP connects, a short download,
# then a sample. The report fits a line through each metric and prints growth per hour.
#
#   engine/perf/soak.sh <hours> <cycle_minutes> <url-host> <url-port> <url-path> > engine/perf/soak-<label>.json
#
# The VPN must be up (the script does not start it) and engine/e2e/fs-probe pushed to /data/local/tmp. The fd
# count needs a debuggable build (run-as); a restart of the app process (new pid) is reported and ends the run.
set -euo pipefail
hours=${1:?hours}; cycle=${2:?cycle minutes}; host=${3:?url host}; port=${4:?url port}; path=${5:?url path}
pkg=io.github.downlz.rethinkreloaded
probe=/data/local/tmp/fs-probe
sh() { adb shell "$@" | tr -d '\r'; }
pid0=$(sh pidof $pkg); [ -n "$pid0" ] || { echo "app not running" >&2; exit 1; }
end=$(( $(date +%s) + hours * 3600 ))
t0=$(date +%s)
samples=""; restarted=false
while [ "$(date +%s)" -lt "$end" ]; do
  sh $probe dns 10.111.222.3:53 100 uncached >/dev/null || true
  sh $probe tcp "$host:$port" 20 >/dev/null || true
  sh $probe get "$host" "$port" "$path" 10 >/dev/null || true
  pid=$(sh pidof $pkg)
  if [ "$pid" != "$pid0" ]; then restarted=true; echo "app restarted ($pid0 -> ${pid:-none})" >&2; break; fi
  m=$(sh dumpsys meminfo "$pid")
  pss=$(echo "$m" | awk '/TOTAL PSS:/ && !d {print $3; d=1}')
  nat=$(echo "$m" | awk '/^ *Native Heap:/ && !d {print $3; d=1}')
  fds=$(sh "run-as $pkg ls /proc/$pid/fd 2>/dev/null | wc -l")
  thr=$(sh "ls /proc/$pid/task | wc -l")
  vpn=$(sh dumpsys vpn_management | awk '/Active vpn type:/ {print ($4 != "-1") ? 1 : 0; exit}')
  el=$(( $(date +%s) - t0 ))
  samples="$samples{\"s\":$el,\"pss_kb\":${pss:-0},\"native_heap_kb\":${nat:-0},\"fds\":${fds:-0},\"threads\":${thr:-0},\"vpn\":${vpn:-0}},"
  echo "t=${el}s pss $pss native $nat fds $fds threads $thr vpn $vpn" >&2
  sleep $(( cycle * 60 ))
done
json="{\"captured\":\"$(date -u +%Y-%m-%dT%H:%M:%SZ)\",\"device\":\"$(sh getprop ro.product.model) / Android $(sh getprop ro.build.version.release)\",\"emulator\":$( [ "$(sh getprop ro.kernel.qemu)" = "1" ] && echo true || echo false ),\"hours\":$hours,\"restarted\":$restarted,\"samples\":[${samples%,}]}"
echo "$json" | python3 -I -c '
import json, sys
d = json.load(sys.stdin)
s = d["samples"]
def slope(k):
    # least squares, per hour
    if len(s) < 2: return None
    xs = [p["s"] / 3600 for p in s]; ys = [p[k] for p in s]
    mx, my = sum(xs) / len(xs), sum(ys) / len(ys)
    den = sum((x - mx) ** 2 for x in xs)
    return round(sum((x - mx) * (y - my) for x, y in zip(xs, ys)) / den, 1) if den else None
d["per_hour"] = {k: slope(k) for k in ("pss_kb", "native_heap_kb", "fds", "threads")}
print(json.dumps(d, indent=1))
print("growth per hour:", d["per_hour"], file=sys.stderr)
'
