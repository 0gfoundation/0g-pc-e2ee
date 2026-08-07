# Measuring the gateway's concurrency capacity

The question this directory answers is "how much concurrent load can one gateway
instance carry" — not "how fast is 0G inference". Those are different numbers, and
a load test pointed at the production router answers only the second one: provider
inference dominates every other cost on the path, so the result tracks provider
capacity and moves whenever the fleet does, while costing real inference spend.

So the measurement is layered, each layer adding exactly one variable back.

| Layer | What runs | What it isolates | Where |
|-------|-----------|------------------|-------|
| **L1** | `go test -bench` on `protocol/crypto`, `protocol/wire` | Single-core seal/open throughput — the CPU ceiling every later number is judged against | `protocol/README.md` |
| **L2** | Real gateway → **fixture upstream** | The gateway itself: sealing, per-request control-plane round trips, connection pooling, HTTP handling | **this directory** |
| **L3** | L2, deployed to a CVM behind dstack-ingress | What the TEE packaging costs: in-enclave TLS termination, HAProxy, the CVM's vCPU budget | `deploy/phala/` |
| **L4** | Gateway → real router → real providers | End-to-end capacity as users experience it (now provider-bound) | production/staging |

L2 is the one that actually answers the question, and it is what this directory
runs. Do L1 first anyway — it takes a minute and it tells you whether an L2 result
is CPU-bound or I/O-bound.

## Why a fixture upstream

`client/cmd/mockupstream` impersonates every upstream the gateway talks to — the
router's route-preview and chat-completions endpoints, a provider broker's e2ee
pubkey endpoint, the sealed inference, and the §8 signature endpoint — in one
process, with a configurable time-to-first-token, inter-token gap and token count.

It is protocol-exact, not a stub: it opens every sealed request with a real HPKE
key and fails closed if the seal is wrong, seals every response frame the same way
a provider enclave does, and produces a genuine EIP-191 secp256k1 §8 signature that
the gateway verifies fail-closed. `client/cmd/mockupstream/upstream_test.go` drives
it with the real client core to keep that true. A load run against it therefore
exercises the real gateway path — if it did not, the numbers would describe a
lookalike.

**Blind spot:** the fixture cannot forge a TDX quote, so the gateway runs with
`-attest=false` against it (and therefore `-onchain=false`, `-warm=false`). A real
deployment additionally pays a DCAP verify whenever the quote cache is cold; the
warmer exists to keep that off the request path, so at steady state the difference
is small — but a cold-start or warmer-failure scenario is not covered here. Measure
that at L3.

That constraint also reaches §8 response verification, which production runs: in
router mode the gateway refuses `-verify-responses` without `-attest`, because the
signer it anchors on must come from a verified quote and the router is untrusted.
So the default rig runs with verification off — see below for how to price it
separately.

## Run it

```sh
cd loadtest
docker compose up --build -d

# Bracket the ceiling: a staircase of arrival rates that aborts past 1% errors.
docker compose --profile load run --rm k6

# Then pin a number at a rate just under the knee.
docker compose --profile load run --rm -e MODE=steady -e RATE=40 -e DURATION=5m k6
```

The gateway is CPU-limited to `GATEWAY_CPUS` (default 2) so the result maps onto a
CVM size rather than onto the test host. The fixture gets `MOCK_CPUS` (default 4)
because it does real HPKE work on both halves of every request — **watch its CPU,
and if it is pegged, the run measured the fixture and the numbers are void.**

Without Docker, the same rig is two processes and a local k6 — handy for a quick
check that the path works before committing a host to a real run:

```sh
cd ../client
go run ./cmd/mockupstream -listen 127.0.0.1:18080 -ttft 200ms -chunk-interval 40ms -chunks 64 &
ZG_GATEWAY_LISTEN=127.0.0.1:18443 ZG_GATEWAY_METRICS_LISTEN=127.0.0.1:19999 \
ZG_GATEWAY_ROUTER_URL=http://127.0.0.1:18080 \
ZG_GATEWAY_ATTEST=false ZG_GATEWAY_ONCHAIN=false ZG_GATEWAY_WARM=false \
ZG_GATEWAY_VERIFY_RESPONSES=false ZG_GATEWAY_PPROF=true ZG_GATEWAY_ALLOWED_ORIGINS= \
ZG_GATEWAY_DSTACK_SOCKET= \
go run ./cmd/gateway &

curl -N -X POST http://127.0.0.1:18443/v1/chat/completions \
  -H 'Authorization: Bearer sk-loadtest' -H 'Content-Type: application/json' \
  -d '{"model":"mock-model","messages":[{"role":"user","content":"hi"}],"stream":true}'

GATEWAY_URL=http://127.0.0.1:18443 k6 run ../loadtest/k6/chat.js
```

Note this shares one machine between driver, gateway and fixture, so it is good for
a smoke test and bad for a capacity number — they compete for the same cores.

Useful knobs (all via env on `docker compose`):

| Variable | Default | What it changes |
|---|---|---|
| `GATEWAY_CPUS` | `2` | Gateway CPU budget — the main capacity-per-core input |
| `ZG_GATEWAY_MAX_IDLE_CONNS_PER_HOST` | `128` | Idle connection pool; see the A/B below |
| `ZG_GATEWAY_VERIFY_RESPONSES` | `false` | §8 verification — see the section below; needs direct-broker mode here |
| `MOCK_TTFT` / `MOCK_CHUNK_INTERVAL` / `MOCK_CHUNKS` | `200ms` / `40ms` / `64` | The simulated completion shape |
| `STREAM` | `true` | Streaming vs buffered completions |
| `PROMPT_BYTES` | `512` | Prompt size, which drives per-request seal cost |
| `MODE` / `RATE` / `START_RATE` / `PEAK_RATE` / `STEPS` | `ramp` / … | Load shape (see `k6/chat.js`) |

## Read the results

**Open-loop, always.** The k6 driver uses arrival-rate executors, never a fixed VU
pool. A fixed-VU test throttles itself as the server slows, so the server never
really overloads and the latency numbers understate the problem (coordinated
omission). If the k6 summary reports `dropped_iterations`, the *driver* ran out of
VUs — raise `MAX_VUS` and rerun; that is not a gateway result.

**The three numbers that matter:**

- `http_req_waiting` — time to response headers. The gateway writes headers when
  the first sealed frame arrives (`openaiproxy.serveStream`), so on a streaming run
  this *is* end-to-end time-to-first-token. This is the user-visible number.
- `gateway_failed` — non-2xx **plus** 200s whose body is not a complete response. A
  mid-stream failure arrives as an error event inside a 200, so status alone
  over-reports success.
- `http_req_duration` — the whole exchange. On a streaming run it is dominated by
  the fixture's token schedule, so it only becomes informative once the gateway
  itself is the slow part.

The capacity figure is **the highest step whose p99 `http_req_waiting` has not yet
turned up and whose error rate is still under 1%** — not the peak RPS reached.

**Watch the gateway's own metrics next to the client's.** On `:9464`:

- `zg_gateway_http_requests_in_flight` — concurrency actually carried. For streaming
  this is far above the arrival rate (every stream is held open for its whole
  schedule), and it is the number that describes the load, not RPS.
- `zg_gateway_completions_total{result,source,stage}` — attributes each failure to
  the gateway or to its upstream. The client can only see "it broke".
- `zg_gateway_http_request_duration_seconds` — server-side latency, so the gap
  against the client's view is queueing and network.

`deploy/grafana/0g-pc-gateway.json` already plots these.

**When you want to know *why*, profile.** The compose sets `ZG_GATEWAY_PPROF=true`,
which mounts the Go profiler on the metrics listener (never published in a real
deployment). During a steady run:

```sh
go tool pprof -http=:8000 http://localhost:9464/debug/pprof/profile?seconds=30
go tool pprof -http=:8001 http://localhost:9464/debug/pprof/heap
curl -s 'http://localhost:9464/debug/pprof/goroutine?debug=1' | head -40
```

## The connection-pool A/B

Go's `http.DefaultTransport` keeps **2** idle connections per host. The gateway
sends every request to the *same* router host — route preview, the sealed
completion, and (with verification on) a §8 signature fetch per response — so at a
pool of 2, every concurrent request past the second dials and TLS-handshakes a
fresh connection and then throws it away, paying it again next time.

The shipped default is now 128 (`core.DefaultMaxIdleConnsPerHost`), tunable via
`-max-idle-conns-per-host` / `ZG_GATEWAY_MAX_IDLE_CONNS_PER_HOST`. The old
behaviour is one env var away, which makes it a clean experiment — run the same
steady load twice:

```sh
ZG_GATEWAY_MAX_IDLE_CONNS_PER_HOST=2   docker compose up -d gateway
docker compose --profile load run --rm -e MODE=steady -e RATE=40 k6

ZG_GATEWAY_MAX_IDLE_CONNS_PER_HOST=128 docker compose up -d gateway
docker compose --profile load run --rm -e MODE=steady -e RATE=40 k6
```

Note this rig speaks **plaintext HTTP** to the fixture, so it shows the dial and
socket churn but not the TLS handshake cost that dominates the same effect against
a real HTTPS router. Expect the gap to be wider in production than it looks here.

## Pricing §8 response verification

Verification costs one extra upstream GET per response, and production has it on.
Router mode here cannot: the gateway requires `-attest` for it, and the fixture
serves no quote. Direct-broker mode can — with no router in the path the signer
comes from the broker the operator pointed at directly, so the gateway permits it
without attestation. That mode **drops the route-preview call**, so it is not a
substitute for the main measurement; run it as a matched pair and take the
difference:

```sh
export ZG_GATEWAY_PROVIDER_URL=http://mockupstream:8080

ZG_GATEWAY_VERIFY_RESPONSES=false docker compose up -d --build gateway mockupstream
docker compose --profile load run --rm -e MODE=steady -e RATE=40 k6

ZG_GATEWAY_VERIFY_RESPONSES=true  docker compose up -d --build gateway mockupstream
docker compose --profile load run --rm -e MODE=steady -e RATE=40 k6
```

The fixture's signing follows `ZG_GATEWAY_VERIFY_RESPONSES` automatically, so both
sides stay consistent. Add `MOCK_SIGNATURE_DELAY` to model a slow broker: the fetch
is on the critical path, after the final frame, so it lands directly on
end-to-end latency (not on TTFT).

One invariant if you touch `MOCK_SIGNATURE_CACHE`: keep it well above peak
concurrency. The fixture retains signatures in a fixed ring, and one evicted before
the gateway fetches it surfaces as a fail-closed verification error that reads like
a gateway fault. The 65536 default is far above anything a single gateway carries.

## Known gaps worth testing next

- **No admission control.** The gateway has no concurrency limit or rate limit
  (issue #20), so past saturation it does not shed load — everything slows together
  until requests time out. The ramp will show this as a latency cliff rather than a
  rising 503 rate. Whether to add a max-in-flight limit that returns 503 is a
  decision this measurement should inform.
- **Long-lived streams.** `core.providerTimeout` is 10m30s, and each in-flight
  stream holds a goroutine, a connection to the router, and buffers. Memory, not
  CPU, may be the real ceiling for high-`MOCK_CHUNKS` shapes — watch the heap
  profile and `go_goroutines`.
- **Cold quote cache** (L3) — the one significant path this layer cannot cover.
- **The ingress hop** (L3) — TLS terminates inside the CVM, and handshakes are
  CPU-expensive on the same vCPU budget the gateway is using.
