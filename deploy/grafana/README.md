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

One dashboard, eight collapsible rows — one service, so cross-metric correlation
(latency vs quote-cache misses, open failures vs a bad provider) stays on one
screen:

1. **Overview — traffic & health**: request rate, 5xx/4xx ratio, in-flight,
   completion success ratio, E2EE open-failure rate; rate by route/status; HTTP
   latency p50/p90/p99 by route; in-flight against its configured limit, with the
   shed rate on the same axes. That last panel is where saturation and its
   consequence are visible together: a shed is a 503, so it is already in the
   "5xx ratio" and "rate by status" panels above, where it reads as a fault the
   gateway committed rather than as the limiter doing its job — subtract this
   series to get faults alone. It is also the panel that confirms or refutes the
   premise behind `route.retryGate` (row 3): that a router outage becomes
   gateway-wide shedding, because each retrying request holds its concurrency
   slot for the whole retry ceiling.
2. **Completions**: outcome by result, and errors broken down by
   `source`/`stage` (gateway fault vs router/provider).
3. **Route preview — the uncached control plane**: retried-preview ratio, failure
   rate, calls by outcome, preview latency p50/p99, attempts by result, and
   suppressed retries. This row exists because preview is the only outbound
   dependency on the request path with no cache in
   front of it — deliberately, since the ranking must reflect the live fleet — so
   its latency is a floor on every sealed request's latency, and its health is
   request health. Read **"Retried previews"** first: it is where a degrading
   router shows up while the error rate is still flat, because the retries are
   absorbing it. A ratio that climbs and stays up is the signal to go look at the
   router, not at this gateway. Two outcomes are broken out of `failed` on purpose,
   and neither belongs in a router alert: `canceled` is a caller that gave up
   mid-flight, and `rejected` is the router *answering* — a 4xx/429 for a caller's
   own bad credential or unknown model, or a well-formed reply with no candidates
   for the model asked for. Fold either in and one misconfigured tenant can hold
   the panel red forever. `failed` is what is left: we could not get a usable answer
   out of the router. The retried-ratio denominator is an allowlist of exactly those
   three retry-relevant outcomes (`ok`, `ok_retried`, `failed`) rather than "all but
   canceled": anything else in the denominator dilutes the ratio and hides the
   degradation it exists to show, and a denylist stops being right the moment an
   outcome is added.
   - **Calls and attempts answer different questions.** "Calls by outcome" is one
     series per chat request; "attempts by result" is one per HTTP attempt, and it
     is the triage view the calls series cannot give — whether the router is *flaky*
     (`retryable` climbing, the retries absorbing it) or *refusing us* (`rejected`
     climbing, nothing to absorb).
   - **The retry ceiling is budget + one attempt, not one attempt.** The budget
     (`route.previewRetryBudget`) only gates whether another attempt may *start*;
     an attempt already in flight is bounded by `previewAttemptTimeout` instead. So
     a router that fails slowly — say a proxy that 502s after 20s — gets one more
     attempt, and the end-to-end worst case is about twice the header timeout. Both
     bounds are real: without the per-attempt one, the shared client caps only the
     wait for headers and a dribbled body would leave a preview unbounded.
   - **`retries suppressed` rising means the router is fully down, not flaky.**
     Retrying an uncached dependency multiplies load on it exactly when it can
     least take it, and each retrying request holds its gateway concurrency slot
     for the ceiling above rather than for one attempt — so a router outage would
     turn into gateway-wide shedding, which the in-flight/limit/shed panel in row 1
     is what confirms. After a few consecutive answerless calls the
     retries switch themselves off (`route.retryGate`) until an answer comes back.
     The first attempt of every request is still made, so callers still get their
     real error; what stops is the amplification. Read it next to `failed`: both
     up together is an outage, `ok_retried` up with this flat is a degradation.
     The panel counts the retry ATTEMPTS not made, not the calls affected, so it
     reads as load shed — an upper bound, since the budget might independently have
     declined some of them.
4. **Data plane — the sealed request to the provider**: upstream failure ratio and
   candidate-fallback rate; attempts by outcome; buffered completion latency;
   stream time-to-first-frame and open duration; the §8 signature fetch and its
   latency. Rows 1–2 measure what this gateway *served*, which is preview +
   materialization + this; only this row isolates the hop that dominates it.
   Eight things to know when reading it:
   - **Why this ratio uses a denylist when the preview one uses an allowlist.** The
     rule is which way an omission fails. A *failure* ratio built as a denylist
     fails LOUD: a new outcome nobody classified lands in the numerator, the number
     goes up, and somebody looks. Built as an allowlist it would fail SILENT — a new
     failure mode simply would not count — and it would need every current failure
     outcome enumerated correctly. The retried-preview ratio is the mirror
     image: there a denylist fails silent (a new outcome dilutes the fraction), so it
     is an allowlist. Allowlist when omission causes silence, denylist when omission
     causes noise.
   - **`canceled`, `internal` and `http_4xx` are not provider failures** and are
     excluded from the failure ratio on both sides of the fraction. `canceled` means
     the caller went away mid-attempt — a closed tab, not a bad provider; `internal`
     is a fault in this gateway, which deserves its own attention and not a
     provider's blame; `http_4xx` is what `completeOnce` calls a client fault (auth,
     bad request, unknown model), and leaving it in was the §4 rule "a caller's own
     fault is never a router alert" applied to preview via `rejected` and then not to
     the data plane — a tenant spraying malformed requests moved a provider-health
     number. Excluded from BOTH sides, not just the numerator: kept in the
     denominator it would instead *dilute* a real provider failure rate, which is the
     same failure the preview ratio's allowlist exists to prevent. What is left is
     the honest base for this number — attempts where the provider had a chance to
     succeed. A 4xx spike is still visible in "attempts by outcome" next door; it
     just does not accuse anybody. The residual judgement call: a provider's own
     404 or 401 can be infrastructure rather than the caller, and those go
     uncounted here.
     `timeout` is the neighbouring case that *is* the provider: our own deadline
     fired because it went quiet.
   - **`unverified` and `unverifiable` are very different findings.** `unverified`
     means a §8 signature *was* retrieved and did not verify against the grounded
     signer — an integrity claim about a provider, and what the alert below pages
     on. `unverifiable` means it could not be retrieved at all, so nothing was
     proven either way; that is the broker having a bad minute, or us, and it is
     deliberately outside the integrity alert. The §8 fetch panel draws the same
     line for itself: `timeout` is OUR attempt deadline expiring mid-fetch,
     `canceled` is the caller leaving, and `internal` is a fetch that never
     happened (no endpoint to fetch from, or an endpoint/chatKey that would not
     form a URL). Only `failed` means the broker was asked and did not deliver,
     which is the one an operator can act on. All three used to be `failed` or
     `canceled`, which put our own deadline and our own gaps in the broker's
     number.
   - **`budget cut` is our ceiling firing, not anything upstream.** It counts
     requests where `core.resolveBudget` running out actually truncated the walk —
     it cut a candidate's materialization short, or it denied a fallback the walk
     would otherwise have made — and it is the only way to tell whether that
     ceiling is set anywhere near right, so read it against the buffered-latency
     p99. It is deliberately NOT on the failure ratio: the request failed, but the
     thing that failed it was us. Two cases are deliberately absent, both because
     the number is worthless if it also counts requests the ceiling did not change.
     A caller disconnecting mid-walk ends the walk silently — and is not a fallback
     either, since filing a closed tab as bad routing is what the fallback series
     exists not to do. And a failed attempt on the *last* candidate: a running
     attempt is never cut by the budget, so there the budget only decides whether
     to move on, and there was nothing to move on to. Counting it would book every
     request whose upstream is slower than the budget (90s, against a 630s provider
     timeout) as a ceiling cut — manufacturing exactly the correlation with the
     latency p99 this bullet asks you to read, and on a single-provider deployment
     turning the panel into a slow-failure counter.
   - **A failing chain is bounded, in both factors.** `core.resolveBudget` charges
     materialization AND failed attempts, so the walk stops instead of paying
     `providerTimeout` once per candidate; `route.maxPreviewCandidates` bounds how
     many candidates the router can put in front of us in the first place. The
     ceiling is the budget plus the one attempt already running when it ran out —
     a running attempt is never cut, because that would cut a completion mid-stream.
     Watch `fallbacks` next to the completion-latency p99: if the p99 sits near the
     budget while fallbacks climb, requests are spending their whole allowance
     walking a bad chain.
   - **Candidate fallbacks are the only signal that the router's ranking is putting
     bad providers first.** The requests they cover *succeed*, so nothing else
     records them — not the error rate, not the completion outcome. A rate that
     climbs while everything looks green is a routing problem, not a gateway one.
     Failures on the *last* candidate are deliberately not counted: nothing was
     fallen back to, and counting them would light this panel up on any
     single-provider deployment.
   - **Stream TTFF and stream open duration answer different questions.** Open
     duration is set by how much the model has to say, so it is not a latency SLI;
     TTFF is what a streaming caller experiences. They are separate panels, and
     buffered latency is a third series again — mixing a 10-minute stream into the
     completion histogram is what makes such a panel unreadable.
   - **Both duration panels filter `result="ok"`.** `kind` alone was not enough:
     a 4xx rejected in 20ms and a caller who left after 200ms are attempts, but
     they are not completion latency, and while they were in the histogram they
     pulled down the same p99 the budget-cut bullet above tells you to read the
     resolve ceiling against. `upstream_attempt_duration_seconds` is therefore
     labelled `kind` × `result` (`ok|failed|canceled`) — coarser than the counter
     next door, which keeps the full outcome, because every outcome here would
     multiply the bucket series by it. `canceled` is its own value rather than part
     of `failed` for the same reason it is its own bucket on the counter, plus one
     specific to a histogram: its duration says when the caller left, not how long
     anything took. To ask "how long do doomed attempts take to give up", chart
     `result="failed"`; the panels here deliberately do not.
5. **Attestation & E2EE**: quote-cache hit ratio, verifications by result, verify
   latency, response-signature verification failures by reason (fetch vs
   signature), untrusted-measurement rate, E2EE open failures. Read the
   untrusted-measurement rate against the mode: with `ZG_GATEWAY_ATTEST_ENFORCE` on
   (as deployed) it is zero **by construction** — an unlisted boot chain fails the
   verification instead of taking the warn path, so it lands in "verifications by
   result" as an `error`. It is a signal only in warn mode, where it is the baseline
   that says whether enforce can be turned on.
6. **On-chain grounding (hop 5)**: ready-provider count, chain-RPC lookup-failure
   and signer-mismatch rates, all grounding outcomes, and revalidations. This row
   is what said whether `ZG_GATEWAY_ONCHAIN_ENFORCE` could be turned on — the criterion
   was `lookup_failed` and `mismatch` sitting at zero in warn mode, since every other
   outcome is one enforce would also have allowed — and now that it is on, the row is
   what says whether the gate is costing anything. Read the two failure classes
   separately — `mismatch`/`not_acknowledged` are verdicts about a provider,
   `lookup_failed` is our own chain RPC, and under enforce both are refused candidates —
   and note "Ready providers" uses `min` across the selected replicas, not a sum: one
   replica that can ground nothing is the number that matters, since it is the one
   failing every request.
7. **Warmer & DCAP collateral**: warmer last-success age (with alert-colored
   thresholds), sweep/provider outcomes, collateral cache + fetch latency.
8. **Process runtime**: goroutines, resident memory, CPU. These are the panels
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
- `sum(rate(zg_gateway_candidate_fallbacks_total[5m])) > 0.1` — the client keeps
  having to move off the provider the router ranked first. Every request this covers
  *succeeded*, so no other series shows it: the fallback repaired the outcome and
  charged the caller a second attempt for it. Sustained, it means the ranking is
  wrong, which is a router-side fix, not a gateway one. Split by `reason` before
  escalating — `upstream` is providers failing under load, `materialize` is
  candidates we cannot even prepare (quote, key or on-chain grounding).
- `sum(rate(zg_gateway_upstream_attempts_total{outcome=~"undecodable|unverified"}[5m])) > 0`
  — a provider answered 2xx with a body that would not open, or one whose §8
  signature was retrieved and did not verify. Both are integrity signals, not
  capacity ones, and they pair with the two E2EE alerts above; keep them out of any
  ratio built on `http_*`/`transport`, which are ordinary operational failures. Note
  what is deliberately absent: `unverifiable` (the signature could not be fetched at
  all) proves nothing about the provider, so it belongs to whoever owns the broker,
  not to a provider-integrity page. Same for `internal`, which is ours.
- `sum(rate(zg_gateway_preview_calls_total{outcome="ok_retried"}[5m])) /
  clamp_min(sum(rate(zg_gateway_preview_calls_total{outcome=~"ok|ok_retried|failed"}[5m])), 1e-9) > 0.05`
  — more than 5% of chat requests needed a route-preview retry to succeed. Nothing is
  failing yet, which is exactly why this is worth an alert: the retries are paying for
  a degrading router out of every caller's latency budget, and the request error rate
  will not show it until they stop being enough. Pair it with
  `sum(rate(zg_gateway_preview_calls_total{outcome="failed"}[5m])) > 0`, which is
  when they have. The denominator is an allowlist — `ok|ok_retried|failed`, the three
  outcomes where retry logic was actually in play — rather than "everything except
  canceled". That is deliberate: a denylist has to be revisited every time an outcome
  is added, and when `rejected` and `internal` arrived it was not, so a tenant
  spraying 401s could dilute a real 20% retry rate down to 0.2% and keep the alert
  quiet. `canceled` is a caller that disconnected, `rejected` is the router answering
  that caller's own 401/404/429 or reporting an empty fleet, and `internal` is a
  request this gateway could not even build; none of the three says anything about
  whether the router is degrading, so none belongs on either side of the fraction.
- `rate(zg_gateway_onchain_grounding_total{outcome="mismatch"}[5m]) > 0` — a
  provider's quote-bound signer disagreed with the chain, and still disagreed after
  a live re-read. Not an operational blip: it means the enclave that answered is not
  the one the registry says it should be. Alert on any of it.
- `rate(zg_gateway_onchain_grounding_total{outcome="lookup_failed"}[5m]) > 0` — our
  chain RPC could not be read, past the retry AND the cache's grace window. With
  `ZG_GATEWAY_ONCHAIN_ENFORCE` on (as deployed) these are refused requests, so this is
  an availability alert on our own dependency, not a finding about a provider.
- `min by(instance)(zg_gateway_warmer_ready_providers) == 0 and on(instance)
  sum by(instance)(zg_gateway_warmer_sweeps_total) > 0` — a replica is up but has no
  usable provider at all, so it can serve nothing. This is the shape of a cold start
  during an upstream outage; it is also what the blue/green standby probe (`/readyz`)
  gates the cutover on, so a firing alert here explains a refused switch. The gauge is
  registered unconditionally but only ever set by a warmer sweep, so **without `-warm`
  it reads a constant 0** and a bare `== 0` would page forever on a healthy replica;
  the `and on(instance)` clause restricts it to replicas that have actually swept.
  Gated on sweep *attempts* rather than on `warmer_last_success_timestamp_seconds`
  deliberately: a replica whose every sweep fails outright never stamps a success, and
  that is the case most worth paging on, not one to suppress. Shipped compose sets
  `ZG_GATEWAY_WARM=true`, so the clause is a no-op there.
- `rate(zg_gateway_warmer_signer_refreshes_total{result="mismatch"}[5m]) > 0` — the
  warmer found a provider whose on-chain signer does not vouch for its quote-bound
  one. Under enforce that provider is unusable, and enough of them turn `/readyz`
  red and hold back a blue/green cutover; it is the same condition as a grounding
  `mismatch`, seen from the sweep rather than from a request.
- `rate(zg_gateway_onchain_revalidations_total{result="ok"}[5m]) > 0` — informational
  rather than a page: a stale or cached reading disagreed but a live re-read agreed,
  which is the signature of a benign broker-signer rotation. Worth noticing during a
  provider upgrade, worth investigating if it happens with no upgrade under way.
- quote-cache hit ratio falling toward 0, or `quote_verification` errors rising —
  providers failing verification, or the warmer not keeping the cache hot.
