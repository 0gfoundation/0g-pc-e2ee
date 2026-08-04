# Blue/green deployment for the cloud-TEE gateway

How to run two gateway CVMs side by side and cut traffic between them with zero
downtime and instant rollback. Read [`README.md`](./README.md) first — this
document assumes its record model, the `app_id`-from-compose binding, and the
Let's Encrypt notes.

## Why blue/green here is a DNS pointer flip, not a load-balancer weight

The gateway's `app_id` is `SHA-256(app-compose)`, and the compose embeds the
gateway image **by digest**. So a new gateway build is a **different `app_id`** —
a separate, separately-attested CVM (README "Pin the image digest"). That single
fact shapes everything:

- **dstack only load-balances *within one `app_id`*.** Deploy N CVMs from the
  *same* compose and dstack's gateway spreads traffic across them automatically
  ("when using the app ID, the load balancer selects one of the available
  instances"). That is horizontal scaling / HA, and it is **orthogonal** to
  releases — see [Scaling one side](#scaling-one-side-replicas).
- **Two different images are two unrelated apps.** dstack will not blend traffic
  across them, so a release cannot be a weighted canary at this layer. It is an
  **all-or-nothing flip** of one record: `_dstack-app-address.<DOMAIN>`, the TXT
  the dstack gateway reads to learn which `app_id` owns the domain.

So "blue" and "green" are two CVMs with two `app_id`s, both serving `<DOMAIN>`,
and releasing = repointing `_dstack-app-address.<DOMAIN>` from one to the other.
[`switch.sh`](./switch.sh) does that flip safely.

> **No percentage canary.** If you need gradual rollout, it has to be a *replica*
> story (same `app_id`, more instances) or a second layer you build yourself.
> The mechanism here gives fast atomic cutover + fast rollback, not 5%/50%/100%.

## The record architecture

The served zone (`0g.ai`) is operator-delegated and we hold no token for it, so
**nothing in this scheme edits `0g.ai`** — its three CNAMEs already point into
the delegation zone and never move again. Everything happens in the delegation
zone (`integratenetwork.work`), which the deploy token controls. Each side runs
in its own delegation **sub-zone** so the records each CVM auto-manages never
collide with the other side's:

```
① served zone 0g.ai — static, set once, NEVER touched again:
     router-api-tee.0g.ai                      CNAME → router-api-tee.0g.ai.integratenetwork.work
     _dstack-app-address.router-api-tee.0g.ai  CNAME → _dstack-app-address.router-api-tee.0g.ai.integratenetwork.work
     _acme-challenge.router-api-tee.0g.ai      CNAME → _acme-challenge.router-api-tee.0g.ai.integratenetwork.work

② delegation zone integratenetwork.work — the SWITCH LAYER (switch.sh owns these):
     router-api-tee.0g.ai.integratenetwork.work                     CNAME → <GATEWAY_DOMAIN>     (static; set once)
     _dstack-app-address.router-api-tee.0g.ai.integratenetwork.work CNAME → …a… | …b…            ← ★ traffic switch
     _acme-challenge.router-api-tee.0g.ai.integratenetwork.work     CNAME → …a… | …b…            ← issuance switch

③ delegation zone — PER-SIDE, each CVM's dstack-ingress writes ITS OWN:
     side a (DELEGATION_ZONE=a.integratenetwork.work):
       _dstack-app-address.router-api-tee.0g.ai.a.integratenetwork.work  TXT = <app_id_a>:443
       _acme-challenge.router-api-tee.0g.ai.a.integratenetwork.work      TXT = <acme token, during issuance>
     side b (DELEGATION_ZONE=b.integratenetwork.work):
       _dstack-app-address.router-api-tee.0g.ai.b.integratenetwork.work  TXT = <app_id_b>:443
       _acme-challenge.router-api-tee.0g.ai.b.integratenetwork.work      TXT = <acme token, during issuance>
```

A client connecting to `router-api-tee.0g.ai` resolves ① → ② → ③, so the dstack
gateway reads whichever `app_id` the **traffic switch** (②) currently points at,
and routes L4 to that CVM, where its dstack-ingress terminates TLS with its own
Let's Encrypt cert for `router-api-tee.0g.ai`.

**Why sub-zones need no extra token.** dstack-ingress's Cloudflare provider
resolves the **longest parent zone** the token can see, so
`DELEGATION_ZONE=a.integratenetwork.work` is written into the real
`integratenetwork.work` zone — `a.` / `b.` are just record-name prefixes, not
Cloudflare zones. One token scoped to `integratenetwork.work` covers both sides
*and* the switch layer.

**What actually moves on a release.** Only the **traffic switch** (② line 2).
The **issuance switch** moves only when a side needs to obtain/renew its cert;
the **serving alias** (② line 1) is set once to `GATEWAY_DOMAIN` and never moves.

## One-time setup

You need a Cloudflare API token that can **edit DNS in `integratenetwork.work`**
(the same one the CVMs use for delegation is fine). Export it for the script:

```sh
export CF_API_TOKEN=...          # Cloudflare token for integratenetwork.work
# defaults already match production; override if your names differ:
# export DOMAIN=router-api-tee.0g.ai
# export CF_ZONE=integratenetwork.work
```

1. **Serving alias (once).** Create
   `router-api-tee.0g.ai.integratenetwork.work` CNAME → your `GATEWAY_DOMAIN`
   (the `_.<cluster>.phala.network` value from the compose). It never changes,
   and both sides route through the same cluster, so one static value serves
   both. `switch.sh` does not manage this record.

2. **Deploy side a and side b.** Two CVMs from [`docker-compose.yml`](./docker-compose.yml),
   identical **except** `DELEGATION_ZONE`, each pinned to the gateway image you
   want on that side:

   | | side a (blue) | side b (green) |
   |---|---|---|
   | `DOMAIN` | `router-api-tee.0g.ai` | `router-api-tee.0g.ai` |
   | `DELEGATION_ZONE` | `a.integratenetwork.work` | `b.integratenetwork.work` |
   | gateway image | current digest | new digest |

   Everything else (the `GATEWAY_DOMAIN`, `CLOUDFLARE_API_TOKEN`, gateway env)
   stays as in the shared compose. Each side, on boot, publishes its own
   `_dstack-app-address.…a/b…` and tries to issue a cert for `router-api-tee.0g.ai`
   — for which it needs the issuance switch (next section).

3. **Confirm the switch layer.** `./switch.sh status` prints where the traffic
   and issuance switches point and each side's published `app_id`.

## Certificates: the issuance switch and rate limits

For an **instant** flip, both sides must already hold a valid cert for
`router-api-tee.0g.ai` at the moment you cut over. ACME dns-01 validates the
single record `_acme-challenge.router-api-tee.0g.ai`, which can only resolve to
one side at a time — that is the **issuance switch**.

To let side b obtain its first cert (blue keeps serving throughout):

```sh
./switch.sh acme b        # point _acme-challenge at side b; wait for it to issue
# …watch side b's logs / status until it has a cert…
./switch.sh acme a        # point it back at the live side so the live side can renew
```

The issuance switch is only borrowed for the minutes it takes to issue; the live
side's cert has weeks of validity left, so it is unaffected. `switch.sh switch`
also moves the issuance switch to the new side, so after a cutover the new live
side renews itself automatically.

**Let's Encrypt limits (README repeats these).** The binding limit is **5
duplicate certificates per exact hostname per rolling week**. Each fresh CVM
issues once from an empty `cert-data` volume, so you can stand up ~5 fresh CVMs
for `router-api-tee.0g.ai` per week. A real cutover costs ~1 issuance and is well
within budget; what burns it is **re-building a side repeatedly against the
production hostname while iterating**. When iterating, test on the staging CA
(`ACME_STAGING=true` in that side's compose — untrusted certs, high limits) and
switch to the production compose only once it works.

## Cutover

```sh
./switch.sh status                        # confirm current live side + target health
./switch.sh switch b                      # flip traffic (and issuance) to side b
```

`switch.sh switch b`:

1. refuses if b is already live;
2. **gate 1** — reads side b's published `app_id` from the delegation zone;
   aborts if b has not published one (its CVM is not up);
3. **gate 2** — if `--probe-url` is given, health-checks side b **directly**
   before sending it traffic (see [Health-checking the standby](#health-checking-the-standby-side));
4. records the outgoing side for `rollback`, then repoints the traffic + issuance
   switches at b;
5. polls `https://router-api-tee.0g.ai/healthz` until it succeeds; **if it never
   recovers, it auto-rolls-back** to the previous side and exits non-zero.

Useful flags: `--dry-run` (print the Cloudflare changes, apply nothing),
`--yes` (no prompt, for automation), `--probe-url URL`, `--no-verify` (skip the
post-switch check + auto-rollback).

## Rollback

```sh
./switch.sh rollback        # back to the side you switched away from
# or explicitly:
./switch.sh switch a
```

Rollback is the same pointer flip in reverse. Because the old side is still
running and still holds a valid cert, it is effectively instant (bounded by the
`TTL`, default 60 s, plus any gateway-side resolver cache). **Keep the old side
running until you are confident in the new one** — a destroyed side is no longer
a rollback target.

## Health-checking the standby side

The one genuinely environment-specific piece. `https://<DOMAIN>/healthz` always
hits the **live** side, so to verify the *standby* before cutover you need a way
to reach it directly. Options, roughly in order of preference:

- **A direct probe URL** you pass as `--probe-url`. If your dstack cluster
  exposes per-app hostnames (e.g. an `<app_id>-<port>` form that routes to a
  specific app), point `--probe-url` at the standby's health path there. This is
  the clean path when available; confirm the exact form with your cluster.
- **A temporary probe hostname** for the standby (e.g. add a second name to that
  side via the ingress `DOMAINS`/`ROUTING_MAP` support). Costs an extra cert and
  DNS you control; only worth it if you cut over often.
- **Cut over during a low-traffic window and rely on the post-switch check.**
  `switch.sh` verifies `/healthz` after the flip and auto-rolls-back on failure.
  Since both sides serve the same domain with valid certs, a failed green that
  gets rolled back is a brief blip, not a broken TLS state. Acceptable for
  infrequent releases; not a substitute for a real pre-flip probe.

Whichever you use, `switch.sh` always does **gate 1** (the standby must be
publishing an `app_id`) and the **post-switch `/healthz` + auto-rollback**, so a
completely dead standby can never silently take traffic.

## Migrating the current single instance into this scheme

The instance running today uses `DELEGATION_ZONE=integratenetwork.work`, so it
writes the **switch-layer names themselves** (the base-zone
`_dstack-app-address.router-api-tee.0g.ai.integratenetwork.work` etc.) and
**keeps reasserting** the routing one. You cannot relabel it in place — changing
`DELEGATION_ZONE` changes the compose, hence the `app_id`, hence it is a new CVM
anyway. So migrate by standing the first managed side up beside it:

1. **Deploy side a** with `DELEGATION_ZONE=a.integratenetwork.work` (same image
   the live instance runs, to start). It publishes `…a…` records the live
   instance never touches.
2. **Issue side a's cert:** `./switch.sh acme a`. The base-zone `_acme-challenge`
   name is only written transiently during the live instance's own renewals, so
   converting it to a CNAME → side a is safe between renewals; side a completes
   ACME and now holds a valid `router-api-tee.0g.ai` cert.
3. **Verify side a** directly (a probe, per above). It is healthy but takes no
   traffic yet — routing still points at the live instance's TXT.
4. **Cut over and retire the legacy instance promptly, in that order:**
   ```sh
   ./switch.sh switch a          # converts the routing name to a CNAME → side a
   # …then destroy the legacy CVM so it stops reasserting the routing TXT…
   ```
   The legacy instance reasserts the base-zone routing record on its reconcile
   loop, so until it is gone routing can briefly flap between it and side a.
   **This is not an outage:** both serve `router-api-tee.0g.ai` with valid certs,
   so every request succeeds either way. Once the legacy CVM is destroyed, the
   CNAME → side a is stable.
5. You now have side a as the sole managed side. The next release brings up
   **side b** under `b.integratenetwork.work` and uses `switch.sh` normally.

## Scaling one side (replicas)

Independent of releases: to scale or add HA **within** a side, deploy more CVMs
from that side's *exact* compose (same `app_id`). dstack load-balances across
them by `app_id`, and each publishes the same `_dstack-app-address` value, so no
switch-layer change is needed. Releases (this document) change `app_id` and flip
the pointer; scaling keeps `app_id` and adds instances. They compose cleanly —
`switch.sh` neither knows nor cares how many CVMs back the side it points at.

> **[verify] on the custom-domain path.** dstack's app-id load balancing is
> documented for the platform-hostname path. Our deployment adds dstack-ingress
> + L4 passthrough on our own domain; the routing key is still the `app_id` in
> `_dstack-app-address`, so replicas *should* balance the same way, but confirm
> empirically (bring up two same-compose CVMs, watch both receive traffic)
> before relying on it for HA.

## Limitations & things to confirm in your environment

- **No weighted/percentage canary** — atomic flip only (see the top section).
- **Standby probe is cluster-specific** — see [Health-checking the standby](#health-checking-the-standby-side).
- **Cutover latency** is the switch-layer `TTL` (default 60 s) plus whatever the
  dstack gateway caches for `_dstack-app-address`. The flip is not sub-second;
  size the `TTL` and expectations accordingly.
- **Two CNAME hops** (① → ② → ③ for a TXT lookup) — standard and resolver-safe,
  but if you debug resolution by hand, follow the full chain.
- **`app_id` LB across replicas on the custom-domain path is [verify]** — see
  [Scaling one side](#scaling-one-side-replicas).
- **Every managed side is a separate attestation.** A verifier must re-audit each
  side's `app_id` against [`docker-compose.yml`](./docker-compose.yml) per
  README "Verify"; blue and green are audited independently.
