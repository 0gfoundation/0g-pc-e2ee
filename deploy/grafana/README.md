# Grafana dashboard — 0G-PC Gateway

[`0g-pc-gateway.json`](./0g-pc-gateway.json) is a ready-to-import Grafana
dashboard for the gateway's Prometheus metrics (see
[`client/metrics`](../../client/metrics) for the metric set, and
[`deploy/phala`](../phala) for how the `prometheus-agent` sidecar ships the
samples to your store).

## Import

Grafana → **Dashboards → New → Import** → upload the JSON (or paste it). On
import you pick two variables:

- **Data source** — any Prometheus-compatible source that holds the gateway's
  `remote_write` data.
- **Service** — filters by the `service` label. The `prometheus-agent` sets
  `external_labels: { service: 0g-pc-gateway }`, so pick that; the default (`All`)
  matches everything, including data that carries no `service` label.

It can also be provisioned as a file-based dashboard (drop it in a folder your
Grafana `dashboards` provider watches). The `uid` is `0g-pc-gateway`.

## Layout

One dashboard, five collapsible rows — one service, so cross-metric correlation
(latency vs quote-cache misses, open failures vs a bad provider) stays on one
screen:

1. **Overview — traffic & health**: request rate, 5xx/4xx ratio, in-flight,
   completion success ratio, E2EE open-failure rate; rate by route/status; HTTP
   latency p50/p90/p99 by route.
2. **Completions**: outcome by result, and errors broken down by
   `source`/`stage` (gateway fault vs router/provider).
3. **Attestation & E2EE**: quote-cache hit ratio, verifications by result, verify
   latency, untrusted-measurement rate, open failures.
4. **Warmer & DCAP collateral**: warmer last-success age (with alert-colored
   thresholds), sweep/provider outcomes, collateral cache + fetch latency.
5. **Process runtime**: goroutines, resident memory, CPU.

## Suggested alerts

The dashboard is for eyeballs; wire the actual alerts in your alerting stack. The
highest-signal ones:

- `rate(zg_gateway_response_open_failures_total[5m]) > 0` — sustained E2EE open
  failures (key/enc/AAD mismatch or frame tampering).
- `time() - max(zg_gateway_warmer_last_success_timestamp_seconds) > 900` — the
  warmer has stalled (only meaningful when `-warm` is enabled).
- quote-cache hit ratio falling toward 0, or `quote_verification` errors rising —
  providers failing verification, or the warmer not keeping the cache hot.
