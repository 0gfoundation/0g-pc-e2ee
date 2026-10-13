# E2EE for async images and video — plan (draft)

> Status: **discussion draft**, not reviewed. Touches three repos: `0g-pc-e2ee`
> (SPEC + cloud gateway), `0g-serving-broker` (enclave side), `0g-router`
> (forwarding + billing). Synchronous E2EE (chat / image / anthropic / speech /
> embedding) is live; this covers `/v1/async/images/*` and `/v1/videos` only.
>
> The only E2EE client is the **cloud gateway** (TEE, TLS terminated in the
> enclave, zero client code). Everything below assumes it is the party that
> seals requests and opens results on the user's behalf.

## 1. Where things stand

| | Async image | Video |
|---|---|---|
| Who generates | Broker worker calls upstream (`wait=true`, holds the connection); native TEE model or forwarder | **Centralized vendor** (Seedance / MiniMax / DashScope) via the in-CVM `videotranslator` |
| Where the result lives | **Broker DB**: `AsyncJob.ResponseBody`, plaintext b64, `ResultTTL` 30m | **Vendor CDN**; the broker never stores it, `/content` relays it (today via `io.ReadAll` of the whole mp4) |
| What the user polls | `GET /v1/async/jobs/:id`, returns the full result every time | `GET /v1/videos/:id` (status, broker relays the vendor live) + `/content` (download) |
| Signature | Signed at completion, **kept only in a 20m in-process cache** (shorter than the 30m TTL, lost on restart) | Signed over the queued body at create, re-signed over the terminal poll JSON; **never covers the mp4 bytes** |
| A sealed request today | Router 400 (no `prompt`); broker `RefuseAsync` 400 | Router 400 (no `prompt`, incidental rather than deliberate); **broker has no explicit refusal** |
| Through the gateway | Falls into `mux.Handle("/")`, cleartext passthrough, marked `X-0G-E2EE: none` | Same |

Router billing runs when the user polls or downloads (`processAsyncBilling`);
`AsyncReconcileWorker` bills jobs whose clients never came back. Both paths share
that one function.

## 2. Goals and non-goals

**Goals**
- The router (and its operator), network intermediaries, and the provider's host
  operator cannot read the async-image prompt/result or the video prompt/clip.
- Billing does not regress: the router bills on image count / duration /
  resolution / tokens without decrypting, fail-closed.
- Users keep nothing beyond the job id they already keep.

**Non-goals**
- **The video vendor sees plaintext.** It generates the clip, so it necessarily
  sees the prompt and the output. Video E2EE is the same trust level as
  forwarder chat (`verified`), **not** `private`, and must be described that way.
- No general `response_format: url`, sync or async.
- Broker restarts already drop queued jobs; sealing does not make that worse and
  this plan does not fix it.
- **Deferred:** a user-held secret (e.g. an `X-0G-E2EE-Secret` header) that would
  keep a leaked job id useless even to the router operator (§3.2).

## 3. Shared design

### 3.1 Keys: two independent HPKE setups, split in time

Same as sync (SPEC §6/§7):
- **Request**: `SetupBaseS(enc_pub, "0g-pc/v1/seal")`; the envelope carries
  `client_eph_pub`, bound in the AAD.
- **Result**: a fresh `SetupBaseS(client_eph_pub, "0g-pc/v1/resp")` inside the
  enclave **when the job completes**. It needs only the public key, not the
  request's HPKE context.
- **The poll request is not sealed** (it carries only a job id). The response is
  the sealed frame stored at completion.
- **Seal once.** Every poll returns the same sealed frame. Re-sealing per poll
  would require keeping plaintext in the DB.

New MUSTs:
- **A fresh eph keypair per job**, so the router cannot swap one job's result for
  another job of the same user (a swapped frame fails to open).
- The result frame's AAD binds `job_id`; the §8 signature binds `reqH`, so the
  gateway can confirm the result answers the request it submitted.

### 3.2 Who holds `eph_priv`: carried in the job id

```
user_job_id = router_job_id + "." + b64url(eph_priv)      // 32-byte X25519 scalar, 43 chars
```

The gateway stays stateless and needs **no key of its own**: any replica, on
either blue-green side, can serve any poll.

1. The gateway **strips** the key segment before forwarding to the router, so the
   router never sees it. **The design rests on this.**
2. The gateway **never logs a full `user_job_id`**: not in access logs, error
   logs, or metric labels. On polls it sits in the URL path, so the log paths need
   an explicit check.
3. No transplant protection is needed. Each job's result is sealed to its own
   `client_eph_pub` (§3.1), so a key attached to the wrong job just fails to open.
   The gateway rejects a malformed segment.
4. User-facing docs: **under E2EE the job id is a credential.**
   - A third party holding it still cannot get the sealed frame, because the
     router's ownership check stops them.
   - The router operator can. It relays every sealed frame, so a leaked
     `user_job_id` lets it decrypt that one job. The key opens exactly one job.
   - In normal flow the router never sees the key segment; the risk is the user
     leaking it.

**Considered: wrapping the key under a gateway key** (`AEAD_{K_wrap}(eph_priv)`).
It does not stop the router either. An operator holding a leaked id can replay
it through the gateway, since the user's `sk-` key passes through to the router
and the router enforces auth itself, and the gateway would unwrap and decrypt for
it. What wrapping buys is marginal:
- a gateway-enforced expiry, which the broker's result TTL already approximates;
- a decryption that needs the live gateway, so it can be rate-limited or audited.

Its cost is a new long-lived key that must be identical on every replica and
across blue-green sides, whose `app_id`s differ, so app-scoped KMS derivation
alone yields different keys. That would make every gateway deploy strand
in-flight jobs unless solved. **Not worth it.**

**Rejected: a TEE-side cache of (user, job) → `eph_priv`.** Its lookup keys are a
job id (in the router's `async_jobs` table) and a credential (seen by the router
on every request). So the router could fetch any job's plaintext through the
gateway without any leak at all. Defending against that needs a user-held secret
the router never sees, and the key in the job id already is one.

### 3.3 Key lifecycle

| Key | Needed when | Lifecycle | Async impact |
|---|---|---|---|
| Client `eph_priv` | Submit → last download | Fresh per job, carried in the job id (§3.2) | Survives gateway restarts, replica changes and blue-green switches: no gateway key involved |
| Broker `enc_priv` (`/e2ee-enc`, KMS-derived) | Async image: submit → worker dispatch. Video: at create only (unsealed synchronously) | Deterministic, stable across restarts; rotates only when the measurement changes (broker upgrade); single current key | An upgrade lands with a restart, which already drops queued jobs. **No new loss.** A completed result needs only `client_eph_pub`, not this key |
| Video content key `K` | Every `/content` download | Fresh per clip (§5) | The broker stores only `H(K)`, so broker upgrades do not strand clips |

No key in this design must survive a deploy of the gateway or the broker beyond
what already does today.

### 3.4 Router-side constraints (both profiles)

- **Billing fields cleartext and bound.** `status`, `usage.output_images`, video
  duration, `size`, and `completion_tokens` stay cleartext and inside the AAD and
  the signature. The router reads them as today.
  - Missing or invalid means **fail-closed**, as with sync `writeSealedImageCountError`; no "default to 1".
  - The user poll and the reconcile worker share `processAsyncBilling`, so one change covers both.
- **Do not rewrite sealed responses.** Today the router re-serializes poll
  responses (`UseNumber`), and the video path adds fields (`fillVideoRequestEcho`).
  On a sealed response it may inject only where the SPEC declares
  `unbound_fields` (e.g. `x_0g_trace`). Everything else passes through byte-for-byte.
- **No fallback after acceptance.** The gateway's candidate walk ends at the 202.
  A job accepted by one enclave that later fails must be resubmitted.
- Auth and ownership checks are unchanged: the router still verifies the job
  belongs to the account.

## 4. Async image (`/v1/async/images/generations`)

### 4.1 Flow

```
① POST /v1/async/images/generations
   gateway: fresh eph keypair; seal prompt to enc_pub; cleartext model / n / size / response_format="b64_json"
   router: admits sealed (no prompt) → broker: stores the sealed envelope as-is, enqueues, 202
   gateway: returns user_job_id = router_job_id + "." + b64url(eph_priv)
② broker worker (in enclave): unseal → call upstream → images
   SetupBaseS(client_eph_pub) seals data[]; cleartext usage.output_images
   §8 signature; sealed frame + signature written to the DB (no plaintext)
③ GET /v1/async/jobs/:user_job_id
   gateway: split off eph_priv, forward GET /v1/async/jobs/:router_job_id
   router: bills on cleartext fields, passes the sealed frame through
   gateway: verify + open → plaintext to the user, X-0G-E2EE: sealed
```

### 4.2 Changes

**SPEC (0g-pc-e2ee)**
- New profile `async-image`.
  - Request: as `image` (pin `response_format=b64_json`).
  - Result frame: as §7.1, AAD adds `job_id`.
  - The poll frame is immutable for the TTL.
- The MUSTs in §3.1.

**Broker (0g-serving-broker)**
- `RefuseAsync`: admit the `async-image` profile (flag-gated); keep refusing everything else.
- Submit: `AsyncJob.RequestBody` stores the sealed envelope.
  - **Do not run `forceB64ResponseFormat` on a sealed body**: it rewrites cleartext and breaks the AAD. Rely on the pin instead.
- Worker: unseal at dispatch, reusing the sync unseal path (`MaybeUnsealRequest`); seal and sign at completion.
- **Persist the signature.** Add a column on `AsyncJob`; the signature endpoint reads the DB first and the cache only accelerates.
- Poll: return the sealed frame plus cleartext billing fields.

**Router (0g-router)**
- `AsyncGenerateImage`:
  - Sealed with no `prompt`: admit.
  - Sealed with a `prompt`: 400, as sync.
- `processAsyncBilling`: bill sealed results on `usage.output_images`, fail-closed.
- Poll response: no re-serialization of sealed bodies (inject only into `unbound_fields`).
- Everything behind `features.e2ee_async` (default off), with an Internal Changelog entry.
- `router_image_request_options_total{sealed}` already covers the async endpoints.

**Gateway (0g-pc-e2ee)**
- Register `POST /v1/async/images/generations` and `GET /v1/async/jobs/{id}` as
  sealed surfaces instead of the `/` cleartext passthrough.
- Build / split `user_job_id` (§3.2); log redaction.

## 5. Video (`/v1/videos`, text-to-video first)

### 5.1 How it differs from images

The result is not in the broker. The problem is **encrypt-on-download**, not
encryption at rest.

```
① POST /v1/videos: as 4.1① (sealed prompt; cleartext model / seconds / size)
   broker: unseal → videotranslator → vendor; VideoPollJob stores the sealed envelope
② broker's background poll sees completion:
   generate a fresh content key K
   seal K to client_eph_pub inside the status frame
   store only H(K) (a commitment, not a secret); sign the status frame
③ GET /v1/videos/:id → status frame (cleartext status / duration / size / tokens + sealed part)
④ GET /v1/videos/:id/content
   gateway: open K from the status frame; send K sealed to the broker's CURRENT enc_pub with the request
   broker: unseal K, check H(K) == stored commitment (else refuse)
           pull the mp4 from the vendor CDN, STREAM-encrypt with chunked AEAD under K
           (64KB chunks, nonce = chunk counter, final-chunk flag), stream out
   router: io.Copy as today; gateway: stream-decrypt
```

Why the gateway returns K instead of the broker storing it:
- The broker holds no long-lived secret per clip, so a broker upgrade (new
  measurement → new KMS-derived keys) does not make in-flight clips undownloadable.
- The router only ever sees K sealed to the enclave.
- **The `H(K)` check is essential.** Without it the router could send *its own*
  key and receive the clip encrypted to itself.

Integrity chain: §8 signature → status frame → sealed K → per-chunk AEAD. No hash
of the mp4 is needed.

### 5.2 Changes

**SPEC**
- New profile `video`.
  - Request seals `prompt`.
  - Status frame sealed/cleartext field table.
  - The **content-key return** (sealed K on `/content`, commitment check).
  - The **content stream format**: chunk size, nonce, final flag, header version.
  - States vendor visibility.

**Broker**
- `/v1/proxy/videos` create: unseal, forward to the sidecar; `VideoPollJob.RequestBody` stores the sealed envelope.
- At completion: generate K, store `H(K)`, seal K into the status frame, sign.
- Status for sealed jobs: the broker **assembles** the frame. It does not relay the
  vendor JSON verbatim, which may echo the prompt; that belongs in the sealed part.
- `/content`: accept the sealed K, check the commitment, replace `io.ReadAll` with streaming encryption.
- **Now:** explicitly 400 sealed video requests until this ships (today only the
  router's `prompt` check stops them, incidentally).

**Router**
- `AsyncGenerateVideo`: admit sealed with no `prompt`.
  - `model`, `seconds`, `size` stay required.
  - Slot reservation and quoting are unchanged.
- Billing reads duration / size / tokens from the status frame's cleartext, fail-closed.
- Stop rewriting sealed status frames (`fillVideoRequestEcho`), or confine it to `unbound_fields`.
- `/content`:
  - Forward the sealed-K request header to the broker (the router forwards only an allowlist of headers today).
  - Account for AEAD overhead (~16B per 64KB) in `maxVideoContentSize`.

**Gateway**
- Register the three video paths.
- Return sealed K on `/content`; stream-decrypt.
- `user_job_id` as for images.

## 6. Phases

| Phase | Scope | Repos |
|---|---|---|
| **P0** (small, now) | Broker explicitly refuses sealed video; user docs state that async/video are **not** E2EE today (the gateway already marks `X-0G-E2EE: none`) | broker, docs |
| **P1** async image (text-to-image) | §4 end to end, `features.e2ee_async` default off, staging first | all three |
| **P2** video (text-to-video) | §5 end to end, incl. streaming encryption and K return | all three |
| **P3** inputs with images | image-to-video, async image edits (and sync `/v1/images/edits`): JSON-ify the input image into a sealed field, as speech §5.3 | SPEC + all three |

P1 builds what P2 reuses: the key-carrying job id, the persisted signature, and the router
not rewriting sealed responses.

## 7. Risks and open questions

1. **Video positioning.** Is "E2EE, vendor-visible" (`verified` tier) acceptable externally?
2. **Broker status caching.** Video status is relayed live today; for sealed jobs
   the broker assembles it. Should it cache, to spare the vendor?
3. **Storage growth.** A sealed frame is about 1/3 larger than raw bytes (b64)
   plus small overhead. `AsyncJob` uses `mediumblob` (16MB cap); confirm large
   `n` × high resolution fits.

## 8. Acceptance

- **End to end:** submit → poll → open through the gateway for images; for video,
  a full download that passes every chunk's AEAD.
- **Tamper tests** (each must fail to open or verify, or be refused):
  - router swaps a result frame;
  - attaches one job's key segment to another job;
  - edits a cleartext billing field;
  - sends its own K on `/content` (must be refused by the commitment check).
- **Billing:** user poll and reconcile worker charge identically; missing billing
  fields fail closed and charge nothing.
- **Log audit:** no full `user_job_id`, `eph_priv`, `K`, plaintext prompt or result
  in gateway or router logs.
- **Gateway deploy drill:** a blue-green switch with in-flight image and video
  jobs, all still retrievable afterwards.
- **Metrics:** `router_image_request_options_total{sealed="true"}` on async
  endpoints; gateway `X-0G-E2EE: sealed` share.
