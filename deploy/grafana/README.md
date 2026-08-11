# Grafana dashboard — 0G-PC Gateway

[`0g-pc-gateway.json`](./0g-pc-gateway.json) is a ready-to-import Grafana
dashboard for the gateway's Prometheus metrics (see
[`client/metrics`](../../client/metrics) for the metric set, and
[`deploy/phala`](../phala) for how the `prometheus-agent` sidecar ships the
samples to your store).

## Import

Grafana → **Dashboards → New → Import** → upload the JSON (or paste it). On
import you pick the dashboard variables:

- **Data source** — any Prometheus-compatible source that holds the gateway's
  `remote_write` data.
- **Service** — filters by the `service` label. The `prometheus-agent` sets
  `external_labels: { service: 0g-pc-gateway }`, so pick that; the default (`All`)
  matches everything, including data that carries no `service` label.
- **Environment** — filters by the `env` label (`staging` / `mainnet`), which the
  agent stamps from `ZG_PROM_ENV`. When both environments remote_write into the
  same store this is how you scope the board to one; `All` shows both.
- **Instance** — filters by the `instance_id` label: which CVM produced the
  series. `service` and `env` are external labels and so are byte-identical
  across the replicas of one `app_id`; `instance_id` is the only label that
  separates them. It is a *target* label, written per CVM by the `cvm-identity`
  init container into the file_sd documents both scrape jobs discover from (see
  [`client/cmd/cvmid`](../../client/cmd/cvmid)), which is what puts it on `up`
  and the other synthesised per-scrape series too — not just on the exposition.
  Default `All` sums the replicas together, which is what you want for the RED
  panels; pick one when you are chasing a single replica. The option list comes
  from `up`, not from request traffic, so a replica that has served nothing still
  appears.

  `All` expands to `.*`, which also matches series carrying no `instance_id` at
  all — the shape you get when the guest-agent lookup failed at boot and
  `cvm-identity` wrote its file_sd documents unlabelled. Those series are visible
  under `All` and under no specific instance.

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
   latency, response-signature verification failures by reason (fetch vs
   signature), untrusted-measurement rate, E2EE open failures.
4. **Warmer & DCAP collateral**: warmer last-success age (with alert-colored
   thresholds), sweep/provider outcomes, collateral cache + fetch latency.
5. **Process runtime**: goroutines, resident memory, CPU. These are the panels
   that are not summed, so they draw one line per replica; the legend is
   `{{instance_id}}` rather than Prometheus' own `instance`, which is the scrape
   address (`gateway:9464`) and therefore the same string in every replica.

## Suggested alerts

The dashboard is for eyeballs; wire the actual alerts in your alerting stack. The
highest-signal ones:

- `rate(zg_gateway_response_open_failures_total[5m]) > 0` — sustained E2EE open
  failures (key/enc/AAD mismatch or frame tampering).
- `rate(zg_gateway_response_verification_failures_total{reason="signature"}[5m]) > 0`
  — a response failed §8 signature verification against the grounded signer: an
  integrity/authenticity failure of a provider (the `reason="fetch"` bucket is
  the softer, operational proof-retrieval failure).
- `time() - max(zg_gateway_warmer_last_success_timestamp_seconds) > 900` — the
  warmer has stalled (only meaningful when `-warm` is enabled).
- quote-cache hit ratio falling toward 0, or `quote_verification` errors rising —
  providers failing verification, or the warmer not keeping the cache hot.
