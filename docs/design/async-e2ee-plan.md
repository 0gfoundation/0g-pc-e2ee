# E2EE for async text-to-image — plan (draft)

> Status: **discussion draft**. Touches three repos: `0g-pc-e2ee` (SPEC + cloud
> gateway), `0g-serving-broker` (enclave side), `0g-router` (forwarding + billing).
> Synchronous E2EE (chat / image / anthropic / speech / embedding) is live.
>
> **Scope: `POST /v1/async/images/generations` + `GET /v1/async/jobs/{id}` only.**
> Async image edits and video are out of scope. Video requirements already raised
> in review are recorded in [Appendix A](#appendix-a-video--deferred) so they are
> not lost.
>
> The only E2EE client is the **cloud gateway** (TEE, TLS terminated in the
> enclave, zero client code). It seals requests and opens results on the user's
> behalf.

## 1. Where things stand

| | Async text-to-image |
|---|---|
| Who generates | The broker worker calls the upstream (`wait=true`, holds the connection). The upstream is a native TEE model or a forwarder |
| Where the result lives | **Broker DB**: `AsyncJob.ResponseBody` (`mediumblob`), provider JSON with plaintext b64, `ResultTTL` 30m |
| Submit response | `202 {jobId, status, provider_address}` |
| Poll | `GET /v1/async/jobs/:jobId?provider_address=0x…` (the router requires `provider_address`). Every poll returns the full result |
| Signature | Signed at completion, **kept only in a 20m in-process cache** (shorter than the 30m TTL, lost on restart) |
| A sealed request today | Refused on both sides, deliberately. Router: `AsyncGenerateImage` documents the decision not to give async the e2ee exception (`internal/handler/async_inference.go:408-420`); what actually rejects the body is the `prompt`-required check. Broker: `RefuseAsync` 400 |
| Through the gateway | Falls into `mux.Handle("/")`, cleartext passthrough, marked `X-0G-E2EE: none` |

Router billing runs when the user polls (`processAsyncBilling`).
`AsyncReconcileWorker` bills jobs whose clients never came back. Both paths share
that one function.

## 2. Goals and non-goals

**Goals**
- The router (and its operator), network intermediaries, and the provider's host
  operator can neither read the prompt or the images, nor substitute a result of
  their choosing.
- Billing does not regress: the router bills on the image count without
  decrypting, fail-closed.
- Users keep nothing beyond the job id they already keep.

**Non-goals**
- Async image edits, video (Appendix A), `response_format: url`.
- Broker restarts already drop queued jobs; sealing does not make that worse and
  this plan does not fix it.
- **Deferred:** a user-held secret (e.g. an `X-0G-E2EE-Secret` header) that would
  keep a leaked job id useless even to the router operator (§3.2).

## 3. Design

### 3.1 Keys: two independent HPKE setups, split in time

As in sync (SPEC §6/§7):
- **Request**: `SetupBaseS(enc_pub, "0g-pc/v1/seal")`. The envelope carries
  `client_eph_pub`, bound in the AAD.
- **Result**: a fresh `SetupBaseS(client_eph_pub, "0g-pc/v1/resp")` inside the
  enclave **when the job completes**. It needs only the public key, not the
  request's HPKE context.
- **The poll request is not sealed** (it carries only a job id). The response is
  the sealed frame stored at completion.
- **Seal once.** Every poll returns the same sealed frame. Re-sealing per poll
  would require keeping plaintext in the DB.
- **A fresh eph keypair per job.**

### 3.2 Who holds `eph_priv`: carried in the job id

```
user_job_id = router_job_id + "." + b64url(eph_priv)      // 32-byte X25519 scalar, 43 chars
```

The gateway stays stateless and needs **no key of its own**: any replica, on
either blue-green side, can serve any poll.

1. The gateway **splits off** the key segment before forwarding to the router,
   so the router never sees it. **The design rests on this.**
2. The gateway **never logs a full `user_job_id`**: not in access logs, error
   logs, or metric labels. On polls it sits in the URL path, so the log paths need
   an explicit check.
3. User-facing docs: **under E2EE the job id is a credential.**
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

Its cost is a long-lived key that must be identical on every replica and across
blue-green sides, whose `app_id`s differ, so app-scoped KMS derivation alone
yields different keys. That would make every gateway deploy strand in-flight
jobs. **Not worth it.**

**Rejected: a TEE-side cache of (user, job) → `eph_priv`.** Its lookup keys are a
job id (in the router's `async_jobs` table) and a credential (seen by the router
on every request). So the router could fetch any job's plaintext through the
gateway without any leak at all.

### 3.3 Binding the result to the request (stateless)

**The attack.** `client_eph_pub` is cleartext in the request envelope, so the
router can read it, and HPKE base mode does not authenticate the sender.

1. The router submits **its own** request, with a prompt of its choosing, carrying
   the victim's `client_eph_pub`.
2. A genuine enclave serves it, seals the result to the victim's eph key, and
   signs. The signature is over the *router's* `reqH`.
3. When the victim polls, the router returns that frame. The gateway can open it
   and the signature is valid, but the content is the router's.

A fresh eph key per job stops swaps between two jobs of the same user. It does not
stop this. Checking `reqH` would, but a stateless gateway has no `reqH` at poll
time.

**The fix: a bind value derived from `eph_priv`, sealed in the request and echoed
sealed in the result.**

```
bind = HKDF-SHA256(ikm = eph_priv, salt = "", info = "0g-pc/v1/async-bind", L = 32)

request sealed object:  { "prompt": …, "_bind": b64url(bind) }   // "_bind" listed in sealed_fields
result  sealed object:  { "data": […], "_bind": <echoed verbatim> }
```

- **Enclave**
  - On open, it takes `_bind` out of the sealed object and **strips it before
    calling the upstream**; it is not a model parameter.
  - At completion, it puts `_bind` back into the sealed result.
- **Gateway**
  - On poll, it recomputes `bind` from the `eph_priv` in the job id.
  - It opens the frame and requires `_bind` to be present and equal (constant-time).
  - Missing or unequal → refuse; never return content.

Why this holds:
- **Only the victim's request carries the right `bind`.** The value is derived
  from `eph_priv`, which the router never sees, and it sits inside the request's
  sealed part.
- **Only the enclave the request was sealed to can learn it**, since only that
  enclave holds the matching `enc_priv`. The gateway chose that enclave at submit
  time from an attested `enc_pub` (preview + quote verification).
- So a frame that opens under `eph_priv` **and** carries the right `bind` was
  produced by that attested enclave for this request:
  - The router cannot forge one: it would need `bind`.
  - It cannot substitute its own job's result: wrong `bind`.
  - It cannot edit any cleartext field: they are in the frame's AAD, and the
    router cannot re-seal without `bind`.
- **Content authenticity therefore does not depend on the §8 signature.** The
  signature stays for auditors and for billing evidence, but the gateway does not
  need to fetch or verify it on the poll path.

Residual case, accepted: the router replays the victim's *exact* sealed request
(same `bind`). The enclave produces a second result for the victim's own prompt.
The content is not router-chosen, and the router pays for the replay on its own
account.

### 3.4 Which provider — and why a wrong answer is safe

The gateway is stateless, so the provider for a poll comes from the client's
`provider_address` query parameter. The client got it from the 202 the gateway
relayed, and it passes through the router unchanged.

- **Opening and authenticating the result needs nothing provider-specific**:
  `eph_priv` plus the bind check of §3.3. The gateway does not look up the
  provider's keys on the poll path.
- **If the router or the client names the wrong provider**, whatever frame comes
  back fails the bind check. Only the enclave the request was sealed to can have
  produced a valid one. A wrong `provider_address` gives at worst a refusal,
  never wrong content.

### 3.5 Gateway surface rules

- Register `POST /v1/async/images/generations` and `GET /v1/async/jobs/{id}` as
  sealed surfaces, no longer the `/` passthrough (only for models in
  `-seal-models`, as on sync surfaces).
- **Rewrite outward ids.** In the 202 and in every poll response, replace
  `jobId` with `user_job_id`. Leave `provider_address` as is.
- **Poll matrix** (no silent downgrade):

| Request carries key segment | Response carries `_e2ee` | Gateway answers |
|---|---|---|
| yes | yes | Open + bind check → plaintext, `X-0G-E2EE: sealed` (refuse if either fails) |
| yes | **no** | **Refuse** (`e2ee_downgrade`): a sealed job must come back sealed; a cleartext body here is either a fault or a router-fabricated result |
| **no** | yes | **Refuse** (`e2ee_key_missing`): never pass a sealed frame through, never pretend it is cleartext |
| no | no | Cleartext passthrough, `X-0G-E2EE: none` (a job submitted without E2EE) |

- Malformed key segment → 400, before anything is forwarded.

### 3.6 Router-side constraints

- **Billing field.** `usage.output_images` stays cleartext, inside the frame's
  AAD and the §8 signature.
  - Missing or invalid means **fail-closed** (as sync `writeSealedImageCountError`),
    not today's "default to 1".
  - The user poll and the reconcile worker share `processAsyncBilling`, so one
    change covers both.
- **Bound top-level fields.** `unbound_fields` names top-level fields only, so the
  profile lists the top-level fields that must stay bound: `usage` (and with it
  `usage.output_images`), `created`, `model`. Anything the router injects
  (`x_0g_trace`) must be a declared top-level unbound field.
- **Do not rewrite sealed responses.** Today the router re-serializes poll
  responses (`UseNumber`). On a sealed response it may only add declared unbound
  top-level fields; everything else passes through unchanged.
- **No fallback after acceptance.** The gateway's candidate walk ends at the 202.
  A job accepted by one enclave that later fails must be resubmitted.
- Auth and the ownership check are unchanged.

### 3.7 Key lifecycle

| Key | Needed when | Lifecycle | Impact |
|---|---|---|---|
| Client `eph_priv` | Submit → last poll | Fresh per job, carried in the job id (§3.2) | Survives gateway restarts, replica changes and blue-green switches: no gateway key involved |
| Broker `enc_priv` (`/e2ee-enc`, KMS-derived) | Submit → worker dispatch | Deterministic, stable across restarts; rotates only when the measurement changes (broker upgrade); single current key | An upgrade lands with a restart, which already drops queued jobs. **No new loss.** A completed result needs only `client_eph_pub` |

No key must survive a deploy of the gateway or the broker beyond what already does
today.

### 3.8 Storage and size limits

Encoding stacks up:
- The provider returns images as b64 (≈ 4/3 × raw).
- That JSON is the sealed plaintext, and the HPKE ciphertext is base64url-encoded
  into `_e2ee.ciphertext`, another ≈ 4/3.

| | Stored size | Max raw image bytes in a 16 MiB `mediumblob` |
|---|---|---|
| Today (plaintext JSON) | ≈ 1.33 × raw | ≈ 12.6 MB |
| Sealed frame stored as JSON | ≈ 1.78 × raw | ≈ 9.4 MB |

Worked example (assumption: a 1024×1024 PNG is roughly 1.5–3 MB; real sizes
depend on model and content):

| | Raw | Today | Sealed as JSON |
|---|---|---|---|
| `n=4` at ~2.5 MB each | ~10 MB | ~13.3 MB, fits | **~17.8 MB, does not fit** |

So sealing breaks a case that works today. Fix:
- Store the ciphertext as **raw bytes** in a new nullable `LONGBLOB` column
  (`sealed_result`), so storage stays ≈ 1.33 × raw, as today.
- Assemble the JSON frame at poll time.
- Sealed rows leave `ResponseBody` empty.

This is an additive migration: nullable column, idempotent, old binaries
unaffected. Changing `ResponseBody` to `LONGBLOB` on a hot table would not be.

The wire is still ≈ 1.78 × raw. The router reads async poll bodies, on both the
user poll and the reconcile worker, through
`readCappedBody(…, maxImageResponseSize)`, which is 32 MB. That allows ≈ 18 MB of
raw images per job. This is above today's effective ceiling (≈ 12.6 MB, the
`mediumblob`), so the router cap is not what binds once storage moves to `LONGBLOB`.
A body over the cap is truncated (metered by `router_response_truncated_total`),
and for a sealed frame that means it fails to open. Gateway and router caps should
be stated together in the SPEC.

## 4. Flow

```
① POST /v1/async/images/generations        (gateway ← user, plaintext over TLS into the TEE)
   gateway: preview → pick provider, verify quote, get enc_pub
            fresh eph keypair; bind = HKDF(eph_priv, "0g-pc/v1/async-bind")
            seal {prompt, _bind} to enc_pub
            cleartext: model / n / size / response_format="b64_json"
   router:  admits sealed (no prompt) → broker: stores the sealed envelope as-is, enqueues → 202 {jobId, …}
   gateway: rewrites jobId → user_job_id = jobId + "." + b64url(eph_priv)

② broker worker (in enclave)
   open → strip _bind → call upstream → images
   seal {data, _bind} to client_eph_pub; cleartext usage.output_images
   §8 signature; sealed ciphertext + signature persisted (no plaintext)

③ GET /v1/async/jobs/:user_job_id?provider_address=0x…
   gateway: split off eph_priv; forward GET /v1/async/jobs/:jobId?provider_address=…
   router:  bills on usage.output_images (fail-closed), passes the frame through
   gateway: §3.5 matrix → open + bind check → plaintext, jobId rewritten, X-0G-E2EE: sealed
```

## 5. Changes by repo

**SPEC (0g-pc-e2ee)**
- New profile `async-image`.
  - Request: as `image` (pin `response_format=b64_json`), plus the reserved
    sealed field `_bind` (§3.3).
  - Result: as §7.1, plus `_bind` echoed in the sealed object. The bound
    top-level field list is in §3.6. The poll frame is immutable for the TTL.
  - MUSTs:
    - fresh eph per job;
    - the enclave strips `_bind` before the upstream;
    - the receiver refuses a missing or unequal `_bind`;
    - the §3.5 poll matrix.

**Broker (0g-serving-broker)**
- `RefuseAsync`: admit the `async-image` profile (flag-gated); keep refusing
  everything else, async edits included.
- Submit: store the sealed envelope in `AsyncJob.RequestBody`.
  - **Do not run `forceB64ResponseFormat` on a sealed body**: it rewrites
    cleartext and breaks the AAD. Rely on the pin instead.
- Worker:
  - Unseal at dispatch, reusing the sync unseal path (`MaybeUnsealRequest`).
  - Strip `_bind`.
  - At completion, seal `{data, _bind}`, sign, and write ciphertext to
    `sealed_result` (§3.8).
- **Persist the signature.** Add a column on `AsyncJob`; the signature endpoint
  reads the DB first and the cache only accelerates.
- Poll: assemble the frame from `sealed_result` plus cleartext billing fields.
- Explicitly 400 sealed `/v1/videos` requests now (P0; today only the router's
  `prompt` check stops them, incidentally).

**Router (0g-router)**
- `AsyncGenerateImage`:
  - Sealed with no `prompt`: admit.
  - Sealed with a `prompt`: 400, as sync.
- `processAsyncBilling`: bill sealed results on `usage.output_images`, fail-closed.
- Poll response: no re-serialization of sealed bodies (§3.6). The 32 MB read cap (§3.8) is sufficient; no change.
- Everything behind `features.e2ee_async` (default off), with an Internal
  Changelog entry.
- `router_image_request_options_total{sealed}` already covers the async endpoints.

**Gateway (0g-pc-e2ee)**
- §3.5 in full: surfaces, id rewriting, the poll matrix, key-segment parsing.
- `bind` derivation and the constant-time check.
- Log redaction for `user_job_id`.

## 6. Phases

| Phase | Scope | Repos |
|---|---|---|
| **P0** (small, now) | Broker explicitly refuses sealed `/v1/videos`; user docs state async and video are **not** E2EE today (the gateway already marks `X-0G-E2EE: none`) | broker, docs |
| **P1** async text-to-image | §3–§5, `features.e2ee_async` default off, staging first | all three |
| later | Async image edits (needs the JSON-ified image-editing profile, which sync edits also lack); video (Appendix A) | — |

## 7. Risks and open questions

1. **Typical output sizes per image model.** The §3.8 estimate assumes 1.5–3 MB
   PNGs; measure the models actually served before fixing caps.

## 8. Acceptance

- **End to end:** submit → poll → open through the gateway; `jobId` rewritten in
  both the 202 and poll responses.
- **Tamper tests** (each must be refused, with no content returned):
  - **The router submits its own request with the victim's `client_eph_pub` and
    returns that result on the victim's poll** (bind mismatch).
  - The router returns another job's frame for the same user (open fails).
  - The router edits `usage.output_images` (open fails).
  - The router returns a cleartext body for a sealed job (`e2ee_downgrade`).
  - A poll without the key segment for a sealed job (`e2ee_key_missing`).
  - A wrong `provider_address` (refused, never wrong content).
- **Billing:** the user poll and the reconcile worker charge identically; a
  missing `usage.output_images` fails closed and charges nothing.
- **Size:** `n=4` at the largest supported size round-trips (storage, router
  read cap, gateway).
- **Log audit:** no full `user_job_id`, `eph_priv`, `bind`, or plaintext prompt or
  images in gateway or router logs.
- **Gateway deploy drill:** a blue-green switch with in-flight jobs, all still
  retrievable afterwards.

---

## Appendix A: video — deferred

Video is out of scope for this plan. The sketch from the first draft is not
carried forward. These requirements came out of review and any future video
design must meet them:

1. **The vendor sees plaintext.** The vendor generates the clip. Video E2EE is
   the `verified` trust level (forwarder), not `private`, and must be described
   that way.
2. **Result binding.** Same attack and same fix as §3.3 (`bind` echoed in the
   sealed status frame).
3. **No nonce reuse on `/content`.** If a content key `K` is reused across
   downloads and every stream starts its chunk counter at 0, any difference
   between two downloads is nonce reuse under GCM: it leaks the XOR of the
   plaintexts and allows forgery. Differences include the vendor CDN re-encoding,
   a Range or resumed download, or a retry from the middle.
   - Derive a per-download key `K_dl = HKDF(K, salt)` with a random `salt` in the
     stream header.
   - The SPEC must state whether Range requests are refused or how they are served.
4. **Billing fields vs today's fallbacks.** `processAsyncBilling` falls back to
   the router's own `reqRef.Size`; the code notes the broker's translator does not
   return `size`. `seconds` falls back to `requestedSeconds` when the provider
   omits it.
   - The broker-assembled sealed status frame must carry `seconds` and `size`.
   - The design must say whether those router-side fallbacks stay for sealed
     jobs. Keeping them is legitimate, since they are router-owned data, but it
     must be explicit. A blanket "fail-closed" would break cases that rely on
     them today.
   - The profile must list which top-level fields stay bound.
5. **Provider identity for `/content`.** If the gateway returns `K` sealed to the
   provider's current `enc_pub`, it must know the provider and obtain its attested
   key. The design must state where that comes from and why a wrong answer is
   safe (it is, given item 2).
6. **Outward ids.** As §3.5. Video's create and status responses use `id` (and the
   router composes an outward video id).
7. **Other routes.**
   - `GET /v1/videos` (list) can show only router ids, which cannot retrieve a
     sealed result. Document this.
   - `/v1/videos/:id/artifacts` and `/v1/videos/:id/artifacts/:key/content`
     (supply line only today) must refuse sealed jobs.
8. **Size check on `/content`.** The router checks the upstream `Content-Length`
   against `maxVideoContentSize` (1 GiB), then truncates with `io.LimitReader`.
   - The SPEC must make ciphertext length deterministic (header + 16-byte tag per
     chunk), or the stream must use chunked transfer.
   - The router's check must count ciphertext length. Otherwise a clip near 1 GiB
     is truncated and its last chunk fails to open.
