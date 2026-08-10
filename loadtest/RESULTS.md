# How much can one gateway carry: a measured answer

A run of [`sweep.sh`](./sweep.sh) at layer 2 — the real gateway against the
fixture upstream, with inference capacity taken out of the picture. Read
[README.md](./README.md) first for what the layers are and why L2 is the one that
answers the capacity question.

**The short answer, and then the reason it needs a qualifier:**

| | per gateway vCPU |
|---|---|
| Sustainable operating rate | **~140 req/s** (72% CPU, p99 TTFT +71 ms) |
| Knee — highest rate still serving | **~220 req/s** (94% CPU, p99 TTFT +204 ms) |
| Above the knee | no shedding, latency collapses to seconds |
| Memory | **~17 MiB + 270 KiB per concurrent stream** |

Those numbers are for **64-token streamed completions**. That qualifier is not a
footnote — it moves the answer by more than 8×, and the section below explains
why an RPS figure quoted without a completion length is close to meaningless for
this service. The one-line generalisation, fitted across completion lengths from
16 to 256 tokens and accurate to within 3%:

> **CPU per request ≈ 0.88 ms + 51 µs per output token**
>
> so per vCPU: **knee ≈ 900 / (0.88 + 0.051 × tokens) req/s**

## What was measured

| | |
|---|---|
| Host | 4 vCPU Intel Xeon @ 2.10 GHz, 15 GiB RAM |
| Gateway | pinned to 1 or 2 cores (`taskset` cpuset + matching `GOMAXPROCS`) |
| Fixture | 2 cores, driver (k6 0.54.0) 1 core, disjoint from the gateway's |
| Shape | 200 ms TTFT, then a 16-byte frame every 40 ms; 512-byte prompt; streaming |
| Per point | 60 s at a constant arrival rate, open-loop |
| Build | Go 1.24.7, `-attest=false -onchain=false -warm=false -verify-responses=false` |

Every row was checked for whether it is about the gateway at all: the fixture and
the driver never exceeded 0.69 and 0.44 of their own core budgets respectively, so
no reported point is one of theirs. That check is the `verdict` column, and it is
the reason a 4-core host can produce a usable answer here — see `sweep.sh`'s
header for why it uses cpusets and CPU-per-request rather than the docker rig's
CFS quotas and a ramp.

**Not measured** (all of it makes production strictly slower than these numbers):
in-enclave TLS termination and HAProxy on the same vCPU budget, DCAP verification
on a cold quote cache, §8 response verification (one extra upstream fetch per
response), and real provider behaviour. Those are L3/L4.

## CPU against RPS

One gateway vCPU, 64-frame completions. `cpu` is the fraction of that vCPU the
gateway itself burned; TTFT percentiles are `http_req_waiting`, against the
fixture's 200 ms floor — so the gateway's own contribution is the excess over 200.

| offered req/s | cpu | TTFT p50 | p95 | p99 | in-flight | RSS | verdict |
|---|---|---|---|---|---|---|---|
| 5 | 0.06 | 202 | 203 | 204 | 14 | 19 MiB | ok |
| 10 | 0.09 | 202 | 203 | 204 | 28 | 24 MiB | ok |
| 20 | 0.15 | 202 | 203 | 205 | 56 | 31 MiB | ok |
| 40 | 0.24 | 202 | 203 | 206 | 112 | 47 MiB | ok |
| 60 | 0.33 | 202 | 205 | 210 | 167 | 62 MiB | ok |
| 80 | 0.43 | 202 | 209 | 216 | 224 | 76 MiB | ok |
| 100 | 0.52 | 203 | 215 | 224 | 278 | 91 MiB | ok |
| 140 | 0.72 | 205 | 240 | 271 | 407 | 124 MiB | ok |
| 180 | 0.83 | 216 | 263 | 290 | 509 | 150 MiB | ok |
| **220** | **0.94** | 281 | 369 | **406** | 649 | 183 MiB | ok |
| 260 | 0.97 | 3762 | 6683 | **7671** | 1479 | 416 MiB | overload |

Read the last two rows together, because that transition is the whole finding.
At 220 req/s the gateway is at 94% of its core and still serving every request —
p99 TTFT 406 ms, degraded but alive. At 260 it is out of CPU, and **it does not
shed load: it queues**. TTFT p99 goes to 7.7 s, in-flight concurrency more than
doubles to 1479 (each of those a stalled user), and RSS more than doubles with it.
Not one request returned an error, so a monitor watching status codes would call
this healthy while every user waits eight seconds for a first token. This is
exactly the missing-admission-control gap (issue #20) showing up as a measurement:
there is no rate limit and no max-in-flight, so past saturation everything
degrades together instead of some requests getting a fast 503.

That is why the operating figure above is **140 req/s per vCPU and not 220**. 220
is where the cliff starts, and the cliff is unusually sharp because nothing
between the gateway and the user applies back-pressure.

### Two cores: scaling is sub-linear

| offered req/s | cores used, 1-vCPU gateway | cores used, 2-vCPU gateway | penalty |
|---|---|---|---|
| 40 | 0.24 | 0.29 | +19% |
| 100 | 0.52 | 0.59 | +14% |
| 180 | 0.83 | 0.98 | +18% |

The same work costs ~15–19% more CPU spread over two cores than packed into one —
ordinary multi-core cost (scheduler, cache coherency, GC across more Ps). So a
2-vCPU gateway is worth about **1.75×** a 1-vCPU one, not 2×: extrapolating the
2-core ladder to 94% utilisation puts its knee near **380 req/s**. Latency at a
given rate is better with two cores (260 req/s: p99 282 ms on two cores vs 406 ms
at 220 req/s on one), so the second core buys headroom as well as throughput.

The 2-core knee is **extrapolated, not observed** — with the gateway on two cores,
this host has one core left for the fixture, which would have saturated first and
voided the row. Confirming it needs a bigger host; the CPU-per-request figure it
rests on is a hardware property and does not move with contention, which is why
the extrapolation is worth making at all.

## RPS is the wrong unit — cost scales with output tokens

Per-request CPU is dominated by per-token work, so the same gateway serves wildly
different request rates depending on how long the completions are. Three
completion lengths, one vCPU each, showing the last healthy rate and the first
that collapsed:

| completion | last healthy rate | cpu there | p99 TTFT | first collapsed rate | p99 there |
|---|---|---|---|---|---|
| 16 tokens | **500 req/s** | 0.85 | 265 ms | 700 | 3,530 ms |
| 64 tokens | **220 req/s** | 0.94 | 406 ms | 260 | 7,671 ms |
| 256 tokens | **60 req/s** | 0.84 | 405 ms | 75 | 3,956 ms |

An 8.3× spread in RPS from the completion length alone. Dividing utilisation by
rate gives the per-request cost at each knee — 1.70 ms, 4.26 ms and 14.02 ms — and
those three points fit a straight line in token count:

> **CPU per request ≈ 0.88 ms + 51 µs per output token**

Fitted on the 16- and 256-token rows, it predicts the 64-token row at 4.16 ms
against 4.26 ms measured — within 2.4%, across a 16× range of completion length.

The fixed 0.88 ms is the route-preview round trip, the HPKE seal of the request,
and HTTP handling. The 51 µs per token is opening the sealed frame, re-framing it
as SSE and writing it. The L1 microbenchmarks on this host agree that this is
where the time goes: an HPKE setup is ~64 µs and is paid once per request, while
`ResponseSealFrame` is 8.6 µs of pure JCS+AEAD, and the measured 51 µs is that plus
the JSON, base64, SSE and syscall work around it.

So capacity for a real workload follows from its average completion length:

| average completion | CPU/req | req/s per vCPU, knee | req/s per vCPU, operating (~65% cpu) |
|---|---|---|---|
| 16 tokens | 1.7 ms | ~530 | ~380 |
| 64 tokens | 4.2 ms | ~220 | ~155 |
| 256 tokens | 14 ms | ~64 | ~46 |
| 512 tokens | 27 ms | ~33 | ~24 |
| 1024 tokens | 53 ms | ~17 | ~12 |

**Tokens/s is the more stable unit, but it is not constant either.** At the knee a
vCPU pushes ~8,000 output tokens/s at 16-token completions, ~14,100 at 64 and
~15,400 at 256: a 1.9× spread against RPS's 8.3×. Short completions are *less*
efficient per token, because the fixed 0.88 ms is a larger share of their cost.
Quote a rate together with the completion length it assumes, or quote tokens/s and
name the range.

### Long completions collapse at lower CPU utilisation

Worth noting for anything above a few hundred tokens: the 256-token shape broke at
**89%** CPU, while the 64-token shape survived 94% and only broke at 97%. The
difference is concurrency, not CPU — at 75 req/s with 10.4 s completions the
gateway was holding 947 streams open, and the scheduling, GC and connection
bookkeeping over that many in-flight requests is itself the cost that tips it.
So the safe utilisation target should come down as completions get longer: ~65% is
comfortable at 64 tokens, and long-completion workloads want more headroom than
that rather than less.

## Memory against concurrency

Memory tracks **concurrent streams**, not request rate, and one line fits all 21
healthy points across every configuration measured — 1 and 2 vCPU, 16/64/256-token
completions, 14 to 947 streams in flight:

> **RSS ≈ 17 MiB + 270 KiB per in-flight stream** (~5.0 goroutines each)

Concurrency follows from Little's law — `rate × completion seconds` — which is why
streaming makes it so much larger than the arrival rate: at 100 req/s with 2.7 s
completions the gateway holds ~278 streams open, not 100.

The practical consequence is that **CPU is the binding constraint, not memory**,
by a wide margin. A 2-vCPU gateway at its 380 req/s knee holds ~1,030 streams —
about 290 MiB. Even a 1 GiB CVM has room to spare.

The exception is worth stating, because it is the one way memory becomes the
ceiling first: `core.providerTimeout` is 10m30s, and with no admission control a
provider that accepts requests and then stops sending tokens lets streams
accumulate for that whole window. At a modest 25 req/s that is ~15,700 held
streams before the first one times out — **~4 GiB**, on a gateway whose CPU is
nearly idle because no frames are arriving. Sizing RAM purely from the healthy
steady state under-provisions exactly this failure.

## Sizing a CVM

Combining the above, for the default 64-token shape:

| CVM | operating rate (~70% CPU) | knee | RSS at the knee |
|---|---|---|---|
| 1 vCPU | ~140 req/s *(measured)* | ~220 req/s *(measured)* | ~183 MiB *(measured)* |
| 2 vCPU | ~245 req/s | ~380 req/s | ~290 MiB |
| 4 vCPU | ~430 req/s | ~670 req/s | ~500 MiB |

Only the 1-vCPU row is measured end to end. The others apply the 1.75×-per-doubling
factor from the two-core comparison, so the 2-vCPU row is a short extrapolation
from real data and the 4-vCPU row assumes the same penalty repeats — plausible, but
untested, and the direction of any error is optimistic.

Then **derate for what L2 does not include** — TLS termination and HAProxy share
the same vCPU budget, and production additionally runs `-attest`, `-onchain` and
`-verify-responses`, the last of which adds an upstream fetch per response. Treat
these as an upper bound and confirm at L3 before promising a number.

Two recommendations fall out of the shape of the data rather than from any single
figure:

- **2 vCPU / 2 GiB is the sensible floor** for a production CVM. The RAM is not
  for the steady state, which needs a few hundred MiB; it is for the stalled-stream
  case above, and it is cheap insurance against the one scenario that OOMs a CVM
  whose CPU looks fine.
- **Scale out, not up.** The second core returns 1.75×, and a third and fourth
  will return less. The blue/green tooling already runs several CVMs behind one
  `app_id` (`deploy/phala/blue-green.md`, "Scaling one side"), so replicas are the
  cheaper axis once one CVM is at 2 vCPU.

## What the cloud deployment is actually configured with

**This repo does not pin it.** `deploy/phala/docker-compose.yml` sets no
`cpus:`/`mem_limit:` for the gateway service, and `deploy/phala/README.md` deploys
with a bare `phala cvm create --compose deploy/phala/docker-compose.yml` — no
resource flags — so the CVM's vCPU, RAM and disk are whatever was chosen in the
Phala Cloud dashboard at deploy time. Read the live values there; they cannot be
recovered from the tree.

That is a genuine gap, and worth being precise about why it is one. `app_id`
commits to the compose file byte-for-byte, which is what makes the deployment
verifiable — but the CVM's resource allocation is *not* in that file. So two CVMs
with identical, correctly-attested `app_id`s can differ by 4× in capacity, and
nothing in the attestation or the repo records which is which. The measurement
above only becomes actionable once the deployed size is written down next to it;
recording the intended vCPU/RAM in `deploy/phala/README.md` (and in the release
notes the workflow generates) would close it without touching `app_id`.

## Reproducing

```sh
# 1 vCPU gateway, fixture on 2 cores, driver on the 4th — the ladder above.
K6_BIN=/path/to/k6 GATEWAY_CPU_LIST=1 GATEWAY_CORE_POOL=0 \
  MOCK_CORES=1,2 K6_CORES=3 RATES="40 100 140 180 220 260" \
  loadtest/sweep.sh

# Completion-length sensitivity: the reason RPS alone does not answer the question.
MOCK_CHUNKS=16  RATES="100 300 500 700" loadtest/sweep.sh
MOCK_CHUNKS=256 RATES="20 40 60 75"     loadtest/sweep.sh
```

Two traps when reading `sweep.csv`, both documented at the CSV header in
`sweep.sh`: `achieved_rps` is diluted by the post-window drain and is *not* a
shortfall (`target_rate` is the offered rate whenever `dropped` is 0), and
`cpu_seconds_per_req` is a total that carries idle overhead — the per-request cost
is the slope of `gateway_cpu_util` against `target_rate` across rows.

## Appendix: the other ladders

The 64-token/1-vCPU ladder is in the table above. These are the three that the
fits also rest on. Across all 21 healthy rows the fixture never passed 0.69 of its
own two cores and the driver never passed 0.44 of its one, so none of these rows
is a measurement of the supporting cast.

**16-token completions, 1 vCPU** (0.8 s per completion):

| offered req/s | cpu | TTFT p50 | p99 | in-flight | RSS | verdict |
|---|---|---|---|---|---|---|
| 100 | 0.24 | 202 | 204 | 82 | 40 MiB | ok |
| 300 | 0.60 | 202 | 278 | 261 | 90 MiB | ok |
| **500** | 0.85 | 211 | 265 | 447 | 139 MiB | ok |
| 700 | 0.97 | 2165 | 3530 | 1693 | 361 MiB | overload |
| 850 | 0.97 | 2554 | 3219 | 1896 | 366 MiB | overload |

**256-token completions, 1 vCPU** (10.4 s per completion):

| offered req/s | cpu | TTFT p50 | p99 | in-flight | RSS | verdict |
|---|---|---|---|---|---|---|
| 20 | 0.34 | 203 | 215 | 214 | 72 MiB | ok |
| 40 | 0.65 | 207 | 259 | 427 | 128 MiB | ok |
| **60** | 0.84 | 258 | 405 | 648 | 185 MiB | ok |
| 75 | 0.89 | 2319 | 3956 | 947 | 275 MiB | overload |

**64-token completions, 2 vCPU** — the linearity check. `cpu` here is per-core, so
cores used is twice it; the fixture had only one core in this layout, which is why
the ladder stops at 260 rather than climbing to this gateway's knee.

| offered req/s | cpu (per core) | cores used | TTFT p50 | p99 | in-flight | RSS | verdict |
|---|---|---|---|---|---|---|---|
| 40 | 0.14 | 0.29 | 202 | 204 | 111 | 47 MiB | ok |
| 100 | 0.30 | 0.59 | 202 | 211 | 279 | 93 MiB | ok |
| 180 | 0.49 | 0.98 | 203 | 236 | 516 | 152 MiB | ok |
| 260 | 0.63 | 1.27 | 213 | 282 | 766 | 215 MiB | ok |

**L1 single-core reference** (same host, `go test -bench`, `GOMAXPROCS=1`) — what
the per-request and per-token costs above are made of:

| benchmark | ns/op |
|---|---|
| `crypto.SetupSender` (HPKE, per request) | 63,830 |
| `crypto.SetupReceiver` (HPKE, per response) | 62,755 |
| `wire.SealRequest` 1 KiB | 96,311 |
| `wire.OpenResponse` 1 KiB | 112,984 |
| `wire.ResponseSealFrame` (per token, no re-handshake) | 8,622 |
| `crypto.SealAEAD` 1 KiB | 858 |
