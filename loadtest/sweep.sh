#!/usr/bin/env bash
#
# Sweep the gateway's vCPU budget against arrival rate, and record what each
# combination costs in CPU and memory — the input to "how many RPS does one
# gateway carry, and how big does its CVM need to be".
#
# The docker rig next door (docker-compose.yml) measures ONE gateway size at a
# time, and answers the capacity question by walking a ramp into overload. That
# needs a host with enough spare cores that the fixture and the driver are
# demonstrably not the thing saturating — otherwise the knee is theirs, not the
# gateway's. This script is the form that survives a small host, because it does
# not rely on a knee at all:
#
#   * It runs every process under `taskset`, a CPU-SET, so the gateway, the
#     fixture and the driver own disjoint cores and cannot steal from each other.
#     (The docker rig uses `cpus:`, a CFS bandwidth quota: the container still
#     competes for every core, it just gets throttled. A quota is the right model
#     for a CVM; a cpuset is the right instrument for attributing a measurement.)
#   * The headline number it collects is the gateway's own CPU-SECONDS PER
#     REQUEST, read from its `process_cpu_seconds_total`. That is a property of
#     the code and the hardware — it does not move when the host is busy — so
#     capacity per core follows by division, and it is measurable at a
#     comfortable rate instead of at the edge of collapse.
#   * It reads `/proc` for all three processes, so every row states what the
#     FIXTURE and the DRIVER were using too. A row where either is near its own
#     core budget is a void row, and the CSV says so rather than leaving it to be
#     noticed.
#
# What it deliberately does NOT do: §8 response verification. That needs
# direct-broker mode and a matched fixture (README "Pricing §8 response
# verification"), so it stays with the compose rig — this script always runs
# -verify-responses=false, and every capacity figure it produces therefore omits
# the one extra upstream fetch per response that production pays.
#
# Read RESULTS.md for what a run of this produced and how to interpret a row.
#
# Usage:
#   loadtest/sweep.sh                       # default matrix, writes ./sweep-out
#   RATES="10 20 40" GATEWAY_CPU_LIST="1 2" loadtest/sweep.sh
#   MOCK_CHUNKS=256 EXPECTED_SECONDS=11 loadtest/sweep.sh   # longer completions
#
# Needs: go, and a k6 binary (K6_BIN, or on PATH). No docker, no root.

set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
out_dir=${OUT_DIR:-$PWD/sweep-out}
k6_bin=${K6_BIN:-$(command -v k6 || true)}

die() {
  echo "sweep: $*" >&2
  exit 1
}

# ---------------------------------------------------------------------------
# The matrix.
# ---------------------------------------------------------------------------

# Gateway vCPU budgets to sweep. Each value must fit in GATEWAY_CORE_POOL below.
GATEWAY_CPU_LIST=${GATEWAY_CPU_LIST:-"1 2"}
# Arrival rates (requests/s) to hold at each budget. Sub-saturation rates are the
# useful ones for the CPU-per-request figure; the ladder should still climb far
# enough to show latency turning up, which is what pins the knee.
RATES=${RATES:-"5 10 20 40 80"}
DURATION=${DURATION:-60s}

# Core assignment. The gateway takes the first GATEWAY_CPUS cores of its pool;
# the fixture and driver get their own, so a saturated gateway cannot starve the
# two processes whose health decides whether the row is valid.
GATEWAY_CORE_POOL=${GATEWAY_CORE_POOL:-"0,1"}
MOCK_CORES=${MOCK_CORES:-"2"}
K6_CORES=${K6_CORES:-"3"}

# Completion shape (the fixture's schedule) and prompt size. These set how much
# per-frame work one request implies, which is the main reason an RPS number is
# only meaningful next to them — see RESULTS.md "RPS is the wrong unit".
MOCK_TTFT=${MOCK_TTFT:-200ms}
MOCK_CHUNK_INTERVAL=${MOCK_CHUNK_INTERVAL:-40ms}
MOCK_CHUNKS=${MOCK_CHUNKS:-64}
MOCK_CHUNK_BYTES=${MOCK_CHUNK_BYTES:-16}
PROMPT_BYTES=${PROMPT_BYTES:-512}
STREAM=${STREAM:-true}
# Must track the fixture's schedule or k6 mis-sizes its VU pool and silently
# offers less load than the row claims (dropped_iterations). Derived here so the
# common case of changing MOCK_CHUNKS does not need a second edit; the ceiling is
# the fixture's own schedule rounded up, plus a second of slack.
#
# secs parses the Go duration forms the fixture accepts for these two knobs. It is
# not a general duration parser and does not need to be — but it must not silently
# read "1s" as 1ms, which is the failure that would under-size the pool by 1000×
# and quietly turn every row into a lighter test than it claims.
secs() {
  awk -v d="$1" 'BEGIN {
    if (match(d, /^[0-9.]+ms$/))     { printf "%f", substr(d, 1, length(d) - 2) / 1000 }
    else if (match(d, /^[0-9.]+s$/)) { printf "%f", substr(d, 1, length(d) - 1) }
    else if (match(d, /^[0-9.]+m$/)) { printf "%f", substr(d, 1, length(d) - 1) * 60 }
    else                             { print "ERR" }
  }'
}
ttft_s=$(secs "$MOCK_TTFT")
gap_s=$(secs "$MOCK_CHUNK_INTERVAL")
[[ $ttft_s != ERR && $gap_s != ERR ]] ||
  die "MOCK_TTFT / MOCK_CHUNK_INTERVAL must look like 200ms, 1.5s or 2m (got '$MOCK_TTFT' / '$MOCK_CHUNK_INTERVAL')"
# Round UP, then add a second: the pool may be generous, never short.
default_expected=$(awk -v t="$ttft_s" -v n="$MOCK_CHUNKS" -v g="$gap_s" \
  'BEGIN { printf "%d", int(t + (n - 1) * g) + 2 }')
EXPECTED_SECONDS=${EXPECTED_SECONDS:-$default_expected}

GATEWAY_PORT=${GATEWAY_PORT:-18443}
GATEWAY_METRICS_PORT=${GATEWAY_METRICS_PORT:-19999}
MOCK_PORT=${MOCK_PORT:-18080}

# ---------------------------------------------------------------------------

gw_pid=""
mock_pid=""

cleanup() {
  [[ -n $gw_pid ]] && kill "$gw_pid" 2>/dev/null || true
  [[ -n $mock_pid ]] && kill "$mock_pid" 2>/dev/null || true
  wait 2>/dev/null || true
}
trap cleanup EXIT

[[ -n $k6_bin ]] || die "no k6 binary: set K6_BIN or put k6 on PATH"
command -v taskset >/dev/null || die "taskset not found (util-linux)"

mkdir -p "$out_dir"
csv="$out_dir/sweep.csv"

# metric reads one gauge/counter out of a Prometheus exposition.
metric() {
  awk -v name="$2" '$1 == name { print $2; exit }' "$1"
}

# proc_cpu_seconds is a process's total CPU time (user+system) from /proc, in
# seconds. Used for the fixture and the driver, which expose no metrics of their
# own — without it, "was the fixture the bottleneck?" is a guess.
proc_cpu_seconds() {
  local pid=$1
  [[ -r /proc/$pid/stat ]] || {
    echo 0
    return
  }
  awk -v ticks="$(getconf CLK_TCK)" '{ print ($14 + $15) / ticks }' "/proc/$pid/stat"
}

start_fixture() {
  local cores
  cores=$(echo "$MOCK_CORES" | tr ',' '\n' | grep -c .)
  taskset -c "$MOCK_CORES" env "GOMAXPROCS=$cores" \
    "$out_dir/mockupstream" \
    -listen "127.0.0.1:$MOCK_PORT" \
    -ttft "$MOCK_TTFT" \
    -chunk-interval "$MOCK_CHUNK_INTERVAL" \
    -chunks "$MOCK_CHUNKS" \
    -chunk-bytes "$MOCK_CHUNK_BYTES" \
    -sign=false \
    >"$out_dir/mockupstream.log" 2>&1 &
  mock_pid=$!
}

# start_gateway brings the gateway up pinned to the first $1 cores of the pool.
# Attestation is off because the fixture serves no TDX quote (see README "Why a
# fixture upstream"); -onchain and -warm require it, so they follow.
start_gateway() {
  local cpus=$1 cores
  cores=$(echo "$GATEWAY_CORE_POOL" | tr ',' '\n' | head -n "$cpus" | paste -sd,)
  [[ $(echo "$cores" | tr ',' '\n' | grep -c .) -eq $cpus ]] ||
    die "GATEWAY_CORE_POOL=$GATEWAY_CORE_POOL has fewer than $cpus cores"

  taskset -c "$cores" env \
    "GOMAXPROCS=$cpus" \
    "ZG_GATEWAY_LISTEN=127.0.0.1:$GATEWAY_PORT" \
    "ZG_GATEWAY_METRICS_LISTEN=127.0.0.1:$GATEWAY_METRICS_PORT" \
    "ZG_GATEWAY_ROUTER_URL=http://127.0.0.1:$MOCK_PORT" \
    ZG_GATEWAY_ATTEST=false \
    ZG_GATEWAY_ONCHAIN=false \
    ZG_GATEWAY_WARM=false \
    ZG_GATEWAY_VERIFY_RESPONSES=false \
    ZG_GATEWAY_PPROF=true \
    ZG_GATEWAY_ALLOWED_ORIGINS= \
    ZG_GATEWAY_DSTACK_SOCKET= \
    "$out_dir/gateway" >"$out_dir/gateway-${cpus}cpu.log" 2>&1 &
  gw_pid=$!

  for _ in $(seq 1 60); do
    if curl -fsS "http://127.0.0.1:$GATEWAY_PORT/healthz" >/dev/null 2>&1; then
      echo "sweep: gateway up on cores $cores (GOMAXPROCS=$cpus)"
      return
    fi
    sleep 0.5
  done
  die "gateway did not become healthy; see $out_dir/gateway-${cpus}cpu.log"
}

# sample_peaks polls the gateway's metrics for the life of a run and keeps the
# high-water marks. Concurrency and RSS are peaks, not averages: the CVM has to
# survive the peak, and an average would size it for a load it never actually
# carries. Streaming makes the gap large — every stream is held open for its
# whole token schedule, so in-flight sits far above the arrival rate.
sample_peaks() {
  local url=$1 out=$2
  local peak_inflight=0 peak_rss=0 peak_goroutines=0
  while :; do
    local body inflight rss goroutines
    body=$(curl -fsS "$url" 2>/dev/null) || { sleep 1; continue; }
    inflight=$(awk '$1 == "zg_gateway_http_requests_in_flight" { print $2; exit }' <<<"$body")
    rss=$(awk '$1 == "process_resident_memory_bytes" { print $2; exit }' <<<"$body")
    goroutines=$(awk '$1 == "go_goroutines" { print $2; exit }' <<<"$body")
    # printf "%.0f" normalises Prometheus's exponential notation (1.39e+07).
    [[ -n $inflight ]] && inflight=$(printf "%.0f" "$inflight") &&
      ((inflight > peak_inflight)) && peak_inflight=$inflight
    [[ -n $rss ]] && rss=$(printf "%.0f" "$rss") &&
      ((rss > peak_rss)) && peak_rss=$rss
    [[ -n $goroutines ]] && goroutines=$(printf "%.0f" "$goroutines") &&
      ((goroutines > peak_goroutines)) && peak_goroutines=$goroutines
    printf '%s %s %s\n' "$peak_inflight" "$peak_rss" "$peak_goroutines" >"$out"
    sleep 1
  done
}

# calibrate reports ns/op for one L1 microbenchmark, pinned to the driver's cores
# and single-threaded. It is a deterministic, CPU-bound unit of exactly the work
# this measurement is about (per-frame JCS + AEAD), so it is a yardstick for the
# host itself.
#
# It is run as BOOKENDS, and that is not ceremony. A shared or burstable host can
# change speed under you between ladders — measured here at 8.6 us/op during one
# session and 13.3 us/op hours later on the same box, a 55% swing that silently
# inflates every utilisation figure taken after it and makes two ladders
# uncomparable. Without a yardstick the drift is invisible and reads as a real
# effect of whatever was changed between the runs. With one, capacity numbers also
# become PORTABLE: a host whose calibration is k times this one's carries roughly
# 1/k the rate, so a result can be moved to other hardware instead of being
# quoted as an absolute.
calibrate() {
  (cd "$repo_root/protocol" && taskset -c "$K6_CORES" env GOMAXPROCS=1 \
    go test -run '^$' -bench BenchmarkResponseSealFrame -benchtime 2s ./wire/ 2>/dev/null) |
    awk '/^BenchmarkResponseSealFrame/ { print $3; exit }'
}

echo "sweep: building gateway + fixture"
(cd "$repo_root/client" && go build -o "$out_dir/gateway" ./cmd/gateway &&
  go build -o "$out_dir/mockupstream" ./cmd/mockupstream)

echo "sweep: calibrating host (BenchmarkResponseSealFrame, 1 core)"
calib_before=$(calibrate)
echo "sweep: calibration before = ${calib_before:-?} ns/op"

echo "sweep: fixture on cores $MOCK_CORES, driver on cores $K6_CORES"
start_fixture
sleep 2

# CSV columns. Two of them are read wrong easily enough to be worth stating here:
#
# achieved_rps is k6's http_reqs.rate, which divides the request count by the
#   WHOLE elapsed test — including the drain after the load window, while the last
#   streams finish. So it sits below target_rate by roughly
#   completion_length/duration even on a perfectly healthy run (at the default
#   shape: 6001 requests offered in a 60s window, 62.8s elapsed, 95.6 reported for
#   a true 100/s). With dropped == 0, TARGET_RATE is the rate the gateway was
#   offered; achieved_rps is not a shortfall and must not be quoted as capacity.
#
# cpu_seconds_per_req is a total, not a marginal cost: it carries the process's
#   fixed idle overhead divided by however many requests the row served, so it
#   falls as the rate rises. The per-request cost is the SLOPE of
#   gateway_cpu_util against target_rate across rows — see RESULTS.md.
printf 'gateway_cpus,target_rate,achieved_rps,ttft_p50_ms,ttft_p95_ms,ttft_p99_ms,failed_rate,dropped,cpu_seconds_per_req,gateway_cpu_util,peak_inflight,peak_rss_bytes,peak_goroutines,mock_cpu_util,k6_cpu_util,verdict\n' >"$csv"

for cpus in $GATEWAY_CPU_LIST; do
  [[ -n $gw_pid ]] && kill "$gw_pid" 2>/dev/null && wait "$gw_pid" 2>/dev/null || true
  gw_pid=""
  start_gateway "$cpus"

  mock_cores_n=$(echo "$MOCK_CORES" | tr ',' '\n' | grep -c .)
  k6_cores_n=$(echo "$K6_CORES" | tr ',' '\n' | grep -c .)

  for rate in $RATES; do
    tag="cpu${cpus}-rate${rate}"
    echo "sweep: === gateway_cpus=$cpus rate=$rate duration=$DURATION ==="

    metrics_url="http://127.0.0.1:$GATEWAY_METRICS_PORT/metrics"
    before="$out_dir/$tag.before"
    after="$out_dir/$tag.after"
    curl -fsS "$metrics_url" >"$before"

    peaks="$out_dir/$tag.peaks"
    : >"$peaks"
    sample_peaks "$metrics_url" "$peaks" &
    sampler_pid=$!

    mock_cpu_before=$(proc_cpu_seconds "$mock_pid")
    start_ns=$(date +%s%N)

    summary="$out_dir/$tag.summary.json"
    # k6's own CPU comes from bash's `time`, whose output goes to the enclosing
    # redirect while k6's own streams go to the log. Sampling /proc for it instead
    # would race the process's exit, and this total is exactly what is wanted.
    k6_times="$out_dir/$tag.k6time"
    set +e
    {
      TIMEFORMAT='%U %S'
      time GATEWAY_URL="http://127.0.0.1:$GATEWAY_PORT" \
        MODE=steady RATE="$rate" DURATION="$DURATION" \
        STREAM="$STREAM" PROMPT_BYTES="$PROMPT_BYTES" \
        EXPECTED_SECONDS="$EXPECTED_SECONDS" \
        taskset -c "$K6_CORES" "$k6_bin" run \
        --summary-export="$summary" --no-color --quiet \
        "$repo_root/loadtest/k6/chat.js" >"$out_dir/$tag.k6.log" 2>&1
    } 2>"$k6_times"
    k6_status=$?
    set -e

    end_ns=$(date +%s%N)
    mock_cpu_after=$(proc_cpu_seconds "$mock_pid")
    kill "$sampler_pid" 2>/dev/null || true
    wait "$sampler_pid" 2>/dev/null || true
    curl -fsS "$metrics_url" >"$after"

    wall=$(awk -v a="$start_ns" -v b="$end_ns" 'BEGIN { printf "%.3f", (b - a) / 1e9 }')
    cpu_before=$(metric "$before" process_cpu_seconds_total)
    cpu_after=$(metric "$after" process_cpu_seconds_total)
    # Both files are written by something that could have died early, so neither
    # read may be allowed to abort the sweep — a missing sample is a zero in one
    # column, not a lost run.
    peak_inflight=0 peak_rss=0 peak_goroutines=0
    read -r peak_inflight peak_rss peak_goroutines <"$peaks" 2>/dev/null || true
    k6_user=0 k6_sys=0
    read -r k6_user k6_sys <"$k6_times" 2>/dev/null || true

    # k6 exits non-zero when a threshold fails — which is the run TELLING us
    # something (an abort on gateway_failed, or dropped iterations). The row is
    # still worth recording; the verdict column is what flags it.
    if [[ ! -s $summary ]]; then
      echo "sweep: no summary for $tag (k6 exit $k6_status); see $tag.k6.log" >&2
      continue
    fi

    row=$(jq -r \
      --arg cpus "$cpus" --arg rate "$rate" \
      --arg wall "$wall" \
      --arg cpu_before "${cpu_before:-0}" --arg cpu_after "${cpu_after:-0}" \
      --arg inflight "${peak_inflight:-0}" --arg rss "${peak_rss:-0}" \
      --arg goroutines "${peak_goroutines:-0}" \
      --arg mock_before "$mock_cpu_before" --arg mock_after "$mock_cpu_after" \
      --arg mock_cores "$mock_cores_n" --arg k6_cores "$k6_cores_n" \
      --arg k6_user "$k6_user" --arg k6_sys "$k6_sys" '
      def n(x): (x // 0);
      ($cpus | tonumber) as $c
      | ($wall | tonumber) as $w
      | (($cpu_after | tonumber) - ($cpu_before | tonumber)) as $cpu
      | n(.metrics.http_reqs.count) as $reqs
      | n(.metrics.http_reqs.rate) as $rps
      | n(.metrics.gateway_failed.value) as $failed
      | n(.metrics.dropped_iterations.count) as $dropped
      | (if $reqs > 0 then $cpu / $reqs else 0 end) as $cpu_per_req
      | (if $w > 0 then $cpu / ($w * $c) else 0 end) as $util
      | ((($mock_after | tonumber) - ($mock_before | tonumber))
          / (if $w > 0 then $w * ($mock_cores | tonumber) else 1 end)) as $mock_util
      | ((($k6_user | tonumber) + ($k6_sys | tonumber))
          / (if $w > 0 then $w * ($k6_cores | tonumber) else 1 end)) as $k6_util
      # A row is only about the gateway if the two supporting processes had
      # headroom and the driver actually offered the configured load. 0.85 is a
      # deliberately low bar: a process above it is close enough to its own
      # ceiling that its queueing is already in the latency numbers.
      #
      # Dropped iterations are read against gateway utilisation, because the same
      # symptom has two opposite causes. With the gateway saturated, the
      # completions it is still serving take far longer, each VU is held far
      # longer, and the pool runs dry BECAUSE of the overload — the row is a real
      # overload observation (quote its latency, not its rate). With the gateway
      # idle, nothing upstream explains it and the pool was simply too small: a
      # driver fault, and the row describes a lighter test than it claims.
      | (if $dropped > 0 and $util > 0.9 then "overload:saturated"
         elif $dropped > 0 then "void:dropped_iterations"
         elif $mock_util > 0.85 then "void:fixture_saturated"
         elif $k6_util > 0.85 then "void:driver_saturated"
         elif $failed > 0.01 then "overload"
         else "ok" end) as $verdict
      | [ $cpus, $rate,
          ($rps | .*100 | round / 100),
          (n(.metrics.http_req_waiting["med"]) | .*100 | round / 100),
          (n(.metrics.http_req_waiting["p(95)"]) | .*100 | round / 100),
          (n(.metrics.http_req_waiting["p(99)"]) | .*100 | round / 100),
          ($failed | .*10000 | round / 10000),
          $dropped,
          ($cpu_per_req | .*1000000 | round / 1000000),
          ($util | .*1000 | round / 1000),
          $inflight, $rss, $goroutines,
          ($mock_util | .*1000 | round / 1000),
          ($k6_util | .*1000 | round / 1000),
          $verdict ]
      | @csv' "$summary")

    echo "$row" >>"$csv"
    echo "sweep: $row"
  done
done

calib_after=$(calibrate)
{
  echo "before_ns_per_op=${calib_before:-unknown}"
  echo "after_ns_per_op=${calib_after:-unknown}"
} >"$out_dir/calibration.txt"

echo
echo "sweep: wrote $csv"
if command -v column >/dev/null; then
  column -s, -t "$csv"
else
  cat "$csv"
fi

echo
echo "sweep: host calibration ${calib_before:-?} -> ${calib_after:-?} ns/op (BenchmarkResponseSealFrame)"
# 10% is well outside this benchmark's own run-to-run spread on a quiet host, so
# past it the rows above were not all taken against the same machine speed and
# should not be compared with each other — rerun on a quiet host.
if [[ -n ${calib_before:-} && -n ${calib_after:-} ]]; then
  awk -v a="$calib_before" -v b="$calib_after" 'BEGIN {
    if (a <= 0) exit
    d = (b - a) / a; if (d < 0) d = -d
    printf "sweep: %s (drift %.1f%%)\n",
      (d > 0.10 ? "WARNING: the host changed speed mid-sweep — rows are NOT comparable" \
                : "host speed was stable across the sweep"), d * 100
  }'
fi
