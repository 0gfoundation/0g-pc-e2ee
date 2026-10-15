# E2EE for async text-to-image — plan

> Status: **implemented** (P1, async text-to-image), not yet enabled anywhere.
> Where the code departs from this plan is listed in [As built](#as-built) at the
> end; read that first. Touches three repos: `0g-pc-e2ee` (SPEC + cloud
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
| Poll | `GET /v1/async/jobs/:jobId?provider_address=0x…`. **`provider_address` is required**: `PollAsyncJob` returns 400 without it (`internal/handler/async_inference.go:1144-1147`), so the client must keep the one from the 202 and send it back. (The "pass provider_address to disambiguate" fallback is the video route's, not this one.) Response `{jobId, status, createdAt, updatedAt, errorMessage?, data?}`, with status `pending` / `processing` / `completed` / `failed`; `data` is the provider JSON, present only when `completed` |
| Failure text | On a non-200 upstream, the upstream error **body** becomes the client-visible `errorMessage` (`ctrl/async.go:394-406`, sanitized only of forwarder identity fields) |
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

Parsing (normative):
- Split on the **last** `.`.
- The router part must match the router's job-id charset `[A-Za-z0-9_-]`
  (`ValidateJobID`).
- The key part must base64url-decode to **exactly 32 bytes**.
- Anything else is a 400 that **does not echo the input** (it may hold a key).

Neither charset contains `.` today, so the split is unambiguous. The rules make a
future job-id format change fail loudly instead of splitting wrongly.

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

**Replay of the victim's exact sealed request.** The router resubmits the
victim's own envelope (same `bind`). The enclave produces a second result for
the victim's own prompt.

- Neither the prompt nor either result is readable by the router: the request
  is sealed to `enc_pub`, and both results are sealed to the victim's
  `client_eph_pub`.
- **Swapping at poll time is blocked by the `jobId` check (§3.6).** The replay
  gets a new broker-assigned `jobId`, and `jobId` is bound in the frame's AAD. A
  replay frame returned on the original job's poll does not match the router part
  of `user_job_id`.
- **What remains is at submit time.** The router can answer the victim's submit
  with the replay's 202. The gateway builds `user_job_id` from that `jobId`, and
  the victim then follows the replay job. Its content is still a sample of the
  victim's own prompt, never router-chosen. The effect is one extra generation,
  i.e. an extra charge.
- Billing is out of scope. The router sees the user's `sk-` key and is the
  billing authority, so it can mis-bill with or without a replay. E2EE neither
  protects against this nor makes it worse.

**The `jobId` check compares the broker-assigned id.** Today an image job's
outward `jobId` is the broker's id verbatim. Video already composes an outward
id (`zg_<provider>_<id>`). If image ids ever change the same way, the gateway must
compare the frame's `jobId` against the broker id it derives explicitly from
`user_job_id`. The profile states which id is compared, so a format change
breaks loudly rather than silently disabling the check.

### 3.4 Which provider — and why a wrong answer is safe

The gateway is stateless, so on a poll the provider comes from the client's
**required** `provider_address` query parameter. The client got it from the 202
the gateway relayed, and the router uses it as given. There is no router-side
lookup on this route.

- **Opening and authenticating the result needs nothing provider-specific**:
  `eph_priv` plus the bind check of §3.3. The gateway does not look up the
  provider's keys on the poll path.
- **If the router or the client names the wrong provider**, whatever frame comes
  back fails the bind check. Only the enclave the request was sealed to can have
  produced a valid one. A wrong `provider_address` gives at worst a refusal,
  never wrong content.

### 3.5 Poll response format

The **whole terminal poll response is the sealed frame**, so `jobId`, `status`
and `usage` are all inside the AAD. A completed sealed job polls as:

```json
{
  "jobId": "<router/broker job id>",
  "status": "completed",
  "createdAt": "…", "updatedAt": "…",
  "model": "…",
  "usage": { "output_images": 2 },
  "_e2ee": { "v": 1, "enc": "…", "sealed_fields": ["data", "_bind"],
             "unbound_fields": ["model", "x_0g_trace"], "final": true, "ciphertext": "…" }
}
```

- The sealed `data` is the provider JSON exactly as today's cleartext poll embeds
  it. After opening, the gateway restores today's shape: `{jobId, status,
  createdAt, updatedAt, data: {…}}`.
- **Bound top-level fields:** `jobId`, `status`, `createdAt`, `updatedAt`,
  `usage` (and with it `usage.output_images`). `unbound_fields` names
  top-level fields only, so nothing nested can be unbound.
- **Declared unbound top-level fields: exactly `["model", "x_0g_trace"]`.** The
  router injects `x_0g_trace` on completed polls (`pkg/inference/async.go:3556-3578`).
  `model` is unbound as on every sync sealed response (the broker's
  `e2eeResponseUnboundFields`), so the router may restore the client's alias.
  - The AAD is `JCS(frame minus ciphertext minus the unbound_fields-listed
    fields)`, and `unbound_fields` itself sits inside `_e2ee` and is bound. So the
    **broker must declare it in the frame at completion**. It cannot be added
    later. A frame without it fails to open on the first poll that carries a trace.
  - Any further router injection on this route needs a SPEC change and a broker
    release first.
- The broker builds this frame **once, at completion**: it knows `jobId` and
  `status=completed` then. It stores the cleartext part next to the raw
  ciphertext (§3.9) and returns it verbatim on every poll. Fields it would add
  per poll must be unbound or omitted.
- **Non-terminal and failed responses are not frames.** They carry no `_e2ee`,
  and their content is restricted:

| Status | Shape for a sealed job |
|---|---|
| `pending` / `processing` | `{jobId, status, createdAt, updatedAt}` only. Cleartext, unauthenticated, carries no content |
| `failed` | `{jobId, status, createdAt, updatedAt, errorMessage}`, where `errorMessage` is **a fixed error code only**, e.g. `upstream_error:422`, `timeout`, `broker_error`. **The upstream error body is never stored or returned** for a sealed job; moderation errors can echo the prompt. Sealing the error text is a possible later refinement |
| `completed` | The frame above |

### 3.6 Gateway surface rules

- Register `POST /v1/async/images/generations` and `GET /v1/async/jobs/{id}` as
  sealed surfaces, no longer the `/` passthrough (only for models in
  `-seal-models`, as on sync surfaces). `-seal-models` is the rollout switch;
  there is no separate flag.
- **`response_format: "url"` on the submit is forwarded in the clear**
  (`X-0G-E2EE: none`), not refused as on the sync image surface. Interim; the
  product decision is open, and it lives in one place (`openaiproxy.WithCleartext`).
- **Submit pinning.** The gateway picked one enclave (preview + quote
  verification) and sealed to its `enc_pub`. The submit must therefore carry
  `X-0G-Provider-Address` (+ `X-0G-Provider-Identity` when the candidate has one)
  and `X-0G-Provider-Allow-Fallbacks: false`. Otherwise the router may route to
  another provider, whose enclave cannot open the request, and the job is wasted.
  The gateway also checks that the 202's `provider_address` equals the pin.
- **Rewrite outward ids.** In the 202 and in every poll response, after opening,
  replace `jobId` with `user_job_id`. Leave `provider_address` as is.
- **Poll matrix.** Keyed on the request's key segment and the response's
  `status`; no silent downgrade.

| Key segment | Response | Gateway answers |
|---|---|---|
| yes | `pending` / `processing`, no `_e2ee` | Relay `{jobId→user_job_id, status, createdAt, updatedAt}`; drop any other field. `X-0G-E2EE: sealed` |
| yes | `failed`, no `_e2ee` | Relay with `errorMessage` only if it is a known error code; otherwise replace it with a generic code |
| yes | `completed` **with** `_e2ee` | Open, then check `_bind` and that the frame's `jobId` equals the broker-assigned id carried in `user_job_id` (today: its router part, verbatim; §3.3) → plaintext in today's shape, `jobId→user_job_id`. Refuse if any check fails |
| yes | `completed` **without** `_e2ee` | **Refuse** (`e2ee_downgrade`): a fault or a router-fabricated result |
| yes | anything carrying `_e2ee` with a non-`completed` status | **Refuse** (malformed) |
| **no** | carries `_e2ee` | **Refuse** (`e2ee_key_missing`): never pass a sealed frame through, never pretend it is cleartext |
| no | no `_e2ee` | Cleartext passthrough, `X-0G-E2EE: none` (a job submitted without E2EE) |

**Non-2xx responses** to a request carrying a key segment:
- Relay the HTTP status and the router's error `code` when it is a known code,
  e.g. `async_job_not_found`, `invalid_request`, `invalid_sealed_response`,
  `upstream_error`.
- Replace the message with a fixed text for that code.
- **Never relay the body verbatim.** The router forwards a broker non-2xx as-is
  (`pkg/inference/async.go:3394-3407`), which may carry upstream text.
- Never include `user_job_id` in an error.
- `X-0G-E2EE: sealed` is still set, since the request was on the sealed path.

Non-terminal and failed responses are cleartext and unauthenticated, so a router
can lie about status: hold a job at `processing`, or claim `failed`. That is
denial of service. It does not expose content and cannot inject content, the same
as a router simply dropping the request.

#### Gateway implementation constraints (from the current code)

- **Logging.** "Never log a full `user_job_id`" means code changes, not a review.
  The key segment must be redacted wherever the gateway prints a path:
  - the access log reads the original `r.URL.Path` after the handler returns
    (`cmd/gateway/main.go:877-883`), so redaction belongs in that middleware;
  - the router-passthrough error log prints the path (`cmd/gateway/routerproxy.go:104`);
  - the refusal response at `cmd/gateway/main.go:1196` **echoes the path in the
    response body**.
- **Routing.**
  - `sealModels.dispatch` matches surfaces by exact `r.URL.Path`
    (`cmd/gateway/sealmodels.go:218`). The poll is a dynamic path and needs a
    pattern route (`GET /v1/async/jobs/{id}`).
  - **Model gating does not apply to polls.** A poll carries no model, so
    `-seal-models` cannot be evaluated. The poll handler is always registered and
    decides only by the presence of a key segment: present → sealed handling;
    absent → cleartext passthrough. Model gating applies to the submit only.
- **`-unsealed-subtree=refuse` must not cover `/v1/async/jobs/`.** Async edits
  and the legacy video poll use the same path; refusing it would break them.
  Keyless polls take the cleartext passthrough whatever that flag says.

### 3.7 Router-side constraints

- **A persisted sealed marker.** Add `async_jobs.sealed` (`BOOLEAN NOT NULL
  DEFAULT false`, additive migration), set at submit when the request carries
  `_e2ee`. As in sync (`requestSealed || IsE2EESealed(response)`,
  `image_handler.go:142-143`), the request side and the response side are judged
  independently: **a job is sealed if its row is sealed *or* the poll body
  carries `_e2ee`.** Otherwise a broker that drops `_e2ee` would push billing back
  onto `len(data.data)` with its default of 1. Billing, TEE verdicts, and the
  failure handling below all key off this.
- **Billing field.** For a sealed job, the image count is the frame's top-level
  `usage.output_images`, not `len(data.data)`, which is ciphertext now. A sealed
  row whose poll body has no `_e2ee` is a downgrade and fails closed. It never
  falls back to counting `data`.
  - Reuse the sync `extractSealedImageCount(body, requested)`
    (`image_handler.go`) on the whole poll body: it already reads top-level
    `usage.output_images` and fails closed on missing, negative, or above-request
    counts.
  - It needs the requested `n` as its ceiling, and `async_jobs` does not store it
    today. Add a nullable `requested_n` column (additive migration), written at
    submit **for every image job** from the cleartext `n` (default 1). It is a
    ceiling, not the sealed marker.
  - Missing or invalid means **fail-closed** (as sync `writeSealedImageCountError`),
    not today's "default to 1".
  - The user poll and the reconcile worker share `processAsyncBilling`, so one
    change covers both.
- **After a fail-closed billing error.** A sealed result with no usable count is
  non-conforming: the broker refuses to seal without one. It must not loop.
  Today the poll path keeps answering 502, and the reconcile worker logs "reconcile
  billing failed" and retries next cycle, re-fetching up to ~32 MB each time until
  the expiry sweep. For sealed jobs:
  - **mark the job `failed`** (no charge) on the first such error, on either path;
  - count it on a new `router_async_sealed_unbillable_total{provider}`;
  - count it against the provider's health as the sync path does (`executor.go`,
    "a provider returning unbillable sealed responses");
  - later polls then see `failed` and stop.
- **TEE verdict.** With `verify_tee=true`, the sync path gives no verdict for a
  sealed request (`handler.go:510`). `asyncTEEVerdict` (`async.go:1669`) does
  not know the job is sealed and would verify a different signing scheme,
  reporting `tee_verified: false` against an honest provider and counting it as
  unverified. For sealed jobs, skip the verdict: omit `tee_verified`, and count it
  on neither `router_async_tee_unverified_total` nor
  `router_async_tee_unavailable_total`. The gateway's bind check (§3.3) is what
  authenticates the content.
- **Do not change any value; inject only declared unbound fields.** The AAD is
  computed over `JCS(...)` (SPEC §5.2), so re-serialization itself is harmless:
  key order, HTML escaping, and whitespace from `json.Marshal(respMap)` do not
  break `Open`, and the router already decodes with `UseNumber`, so numbers keep
  their literals. The actual rules:
  - no bound field's value changes;
  - only the declared unbound top-level fields (§3.5) are added.
  
  No byte-for-byte passthrough is needed.
- **No fallback after acceptance.** The gateway's candidate walk ends at the 202.
  A job accepted by one enclave that later fails must be resubmitted.
- Auth and the ownership check are unchanged.

### 3.8 Key lifecycle

| Key | Needed when | Lifecycle | Impact |
|---|---|---|---|
| Client `eph_priv` | Submit → last poll | Fresh per job, carried in the job id (§3.2) | Survives gateway restarts, replica changes and blue-green switches: no gateway key involved |
| Broker `enc_priv` (`/e2ee-enc`, KMS-derived) | Submit → worker dispatch | Deterministic, stable across restarts; rotates only when the measurement changes (broker upgrade); single current key | An upgrade lands with a restart, which already drops queued jobs. **No new loss.** A completed result needs only `client_eph_pub` |

No key must survive a deploy of the gateway or the broker beyond what already does
today.

### 3.9 Storage and size limits

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
- Store the frame's cleartext part (§3.5) separately, fixed at completion.
- At poll, base64url the ciphertext into `_e2ee.ciphertext`. The frame's bytes
  are deterministic across polls.
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
            pin: X-0G-Provider-Address (+ -Identity), X-0G-Provider-Allow-Fallbacks: false
   router:  admits sealed (no prompt), records sealed=true and requested_n
            → broker: stores the sealed envelope as-is, enqueues → 202 {jobId, provider_address, …}
   gateway: checks provider_address == pin
            rewrites jobId → user_job_id = jobId + "." + b64url(eph_priv)

② broker worker (in enclave)
   open → strip _bind → call upstream → images
   build the frame {jobId, status:"completed", …, usage.output_images, _e2ee}:
   seal {data, _bind} to client_eph_pub with the frame's cleartext in the AAD
   §8 signature; ciphertext + cleartext part + signature persisted (no plaintext)
   on failure: status "failed", errorMessage = fixed code only (§3.5)

③ GET /v1/async/jobs/:user_job_id?provider_address=0x…   (required; repeated until terminal)
   gateway: parse per §3.2; forward GET /v1/async/jobs/:jobId?provider_address=…
   router:  sealed (row or body) + completed → bills via extractSealedImageCount(body, requested_n);
            no usable count → mark failed, no charge, no content;
            passes the frame through (no value changes, unbound fields only)
   gateway: §3.6 matrix
            pending / processing → status only
            completed → open + bind + jobId check → today's shape, jobId rewritten
            X-0G-E2EE: sealed
```

## 5. Changes by repo

**SPEC (0g-pc-e2ee)**
- New profile `async-image`.
  - Request: as `image` (pin `response_format=b64_json`), plus the reserved
    sealed field `_bind` (§3.3).
  - Poll response: the JSON shapes per status in §3.5 (terminal response = the
    frame; sealed `data` + `_bind`; bound and unbound top-level field lists;
    `failed` carries a fixed error code only). The frame is immutable for the TTL.
  - `user_job_id` format and parsing rules (§3.2).
  - MUSTs:
    - fresh eph per job;
    - the enclave strips `_bind` before the upstream;
    - the receiver refuses a missing or unequal `_bind`, or a frame `jobId` that
      does not match;
    - the §3.6 poll matrix;
    - the submit pins the sealed-to provider with fallbacks off.

**Broker (0g-serving-broker)**
- `RefuseAsync`: admit the `async-image` profile (flag-gated); keep refusing
  everything else, async edits included.
- Submit: store the sealed envelope in `AsyncJob.RequestBody`.
  - **Do not run `forceB64ResponseFormat` on a sealed body**: it rewrites
    cleartext and breaks the AAD. Rely on the pin instead.
- Worker:
  - Unseal at dispatch, reusing the sync unseal path (`MaybeUnsealRequest`).
  - Strip `_bind`.
  - At completion, build the frame (§3.5), declaring
    `unbound_fields: ["model", "x_0g_trace"]`; seal `{data, _bind}`, sign, and write
    ciphertext plus the cleartext part (§3.9).
  - On failure of a sealed job, store a fixed error code. **Never store the
    upstream error body.**
- **Persist the signature.** Add a column on `AsyncJob`; the signature endpoint
  reads the DB first and the cache only accelerates.
- Poll: return the stored frame for `completed`; status-only bodies otherwise (§3.5).
- Explicitly 400 sealed `/v1/videos` requests now (P0; today only the router's
  `prompt` check stops them, incidentally).

**Router (0g-router)**
- `AsyncGenerateImage`:
  - Sealed with no `prompt`: admit.
  - Sealed with a `prompt`: 400, as sync.
- New `async_jobs` columns, both additive: `sealed` (bool, default false) and
  `requested_n` (nullable, all image jobs).
- `processAsyncBilling`: sealed = row or body. For a sealed job, call
  `extractSealedImageCount(body, requested_n)`. Any failure marks the job failed
  with no charge, increments `router_async_sealed_unbillable_total`, and counts
  against provider health (§3.7).
- `asyncTEEVerdict`: skip for sealed jobs; no metric (§3.7).
- Poll response: change no bound value, inject only declared unbound fields
  (§3.7). The 32 MB read cap (§3.9) is sufficient; no change.
- Everything behind `features.e2ee_async` (default off), with an Internal
  Changelog entry.
- `router_image_request_options_total{sealed}` already covers the async endpoints.

**Gateway (0g-pc-e2ee)**
- §3.6 in full: surfaces, submit pinning, id rewriting, the poll matrix, non-2xx
  handling, and the implementation constraints (log redaction in the access-log
  middleware, routerproxy, and the refusal body; a pattern route for polls; no
  model gating on polls; `-unsealed-subtree` scope); §3.2 parsing.
- `bind` derivation and the constant-time check.
- Log redaction for `user_job_id`.

## 6. Phases

| Phase | Scope | Repos |
|---|---|---|
| **P0** (small, now) | Broker explicitly refuses sealed `/v1/videos`; user docs state async and video are **not** E2EE today (the gateway already marks `X-0G-E2EE: none`) | broker, docs |
| **P1** async text-to-image | §3–§5, `features.e2ee_async` default off, staging first | all three |
| later | Async image edits (needs the JSON-ified image-editing profile, which sync edits also lack); video (Appendix A) | — |

## 7. Risks and open questions

1. **Typical output sizes per image model.** The §3.9 estimate assumes 1.5–3 MB
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
  - The router changes the frame's `jobId` or `status` (open fails).
  - A `pending` / `processing` body carrying extra fields (dropped, not relayed).
  - A malformed key segment (400, input not echoed).
  - The router answers the submit with the 202 of a replay of the victim's
    request (accepted residual: content is the victim's own prompt; documented,
    not refused).
- **Non-terminal polls:** `pending` and `processing` responses pass through the
  gateway as status-only bodies with `jobId` rewritten; repeated polls through to
  `completed` succeed.
- **Failure:** a sealed job whose upstream returns an error that echoes the
  prompt yields `failed` with a fixed code; the prompt text appears in no
  response, broker row, or log.
- **Submit pinning:** with the pinned provider unavailable, the submit fails
  rather than landing on another provider.
- **Trace:** a completed sealed poll with `x_0g_trace` injected opens (the
  broker-declared `unbound_fields` covers it).
- **Errors:** router 404 / 400 / 502 and a broker non-2xx with upstream text,
  each on a keyed poll, relay status and code only, with no body text and no
  `user_job_id`.
- **Unbillable sealed result:** a frame without `usage.output_images` is marked
  `failed` once with no charge; the reconcile worker does not re-fetch it;
  `router_async_sealed_unbillable_total` increments.
- **Downgrade billing:** a sealed row whose poll body lacks `_e2ee` fails closed
  and is never billed by counting `data`.
- **`verify_tee=true`** on a sealed job: `tee_verified` omitted; no unverified or
  unavailable metric.
- **Log audit (gateway):** access log, routerproxy error log and the refusal body
  show the poll path with the key segment redacted.
- **Billing:** the user poll and the reconcile worker charge identically; a
  missing `usage.output_images` fails closed and charges nothing.
- **Size:** `n=4` at the largest supported size round-trips (storage, router
  read cap, gateway).
- **Log audit:** no full `user_job_id`, `eph_priv`, `bind`, or plaintext prompt or
  images in gateway or router logs.
- **Gateway deploy drill:** a blue-green switch with in-flight jobs, all still
  retrievable afterwards.


## As built

What shipped, and every place it differs from the plan above.

- **Where it landed:** SPEC §7.5 and the `async-image` profile (#142), router
  0gfoundation/0g-router#1028, broker 0gfoundation/0g-serving-broker#762,
  gateway #144.
- **No feature flags anywhere.** The router flag (`features.e2ee_async`) and the
  broker switch from §5 were dropped. The gateway is the only sealer, so
  **`ZG_GATEWAY_SEAL_MODELS` is the rollout switch**: async submits are sealed
  only for models listed there, exactly as on the sync surfaces. Production
  lists no image model, so nothing is sealed until one is added.
- **Broker opens the request at submit, not at dispatch.** A stale enc key
  (409 `e2ee_key_mismatch`) or a bad envelope (400) is answered on the submit,
  before any job row or billing record exists. The plaintext rides only the
  in-memory queue; the row stores the envelope.
- **The §8 signature is not persisted** (plan §5 said it would be). It stays in
  the broker's in-process cache, as for plaintext async jobs. The gateway does
  not need it: a sealed result is authenticated by `_bind`. Persisting it is a
  separate change covering sealed and plaintext jobs alike.
- **Storage** is as §3.9: two nullable columns, `sealed_frame` (BLOB, the frame
  with its ciphertext emptied) and `sealed_result` (LONGBLOB, raw ciphertext).
  The broker bills on the images actually delivered, which is the
  `usage.output_images` the frame publishes.
- **Failure codes** a sealed job stores: `upstream_error:<status>`,
  `upstream_error`, `timeout`, `broker_error`. The gateway relays those and maps
  the broker's restart message to `broker_error`; anything else becomes
  `job_failed`.
- **Router**, beyond §3.7:
  - a reported count of `0` is unbillable (the enclave never seals an image-less
    result);
  - an unbillable result on a job already `billed` is relayed, not 502'd, so a
    client that lost the billing poll's response still gets what it paid for;
  - a sealed submit whose `async_jobs` row cannot be written is refused, since
    without `requested_n` it could never be billed or failed;
  - the async submit validates `size` and `n` like the sync one. `n` still has
    no upper bound on either; that is open.
- **Gateway**, beyond §3.6:
  - `response_format: "url"` on an async submit is **forwarded in the clear**,
    marked `X-0G-E2EE: none`, instead of refused as on sync image. Interim; the
    product decision is open, and it lives in `openaiproxy.WithCleartext`.
  - Keyed polls go through the sealed credential gate and in-flight cap. Keyless
    polls go through the cleartext passthrough, which refuses an answer carrying
    `_e2ee`, does not forward the caller's `Accept-Encoding`, and refuses an
    answer in an encoding it did not ask for.
  - The poll namespace is folded by `sealedNamespaceGuard` (case and `%2F`
    spellings land on the keyed route), and any other path under
    `/v1/async/jobs/` that contains a `.` is refused rather than forwarded, so no
    spelling hands the key to the router. A legacy job id that itself contains a
    `.` gets a 400 instead of passing through; that is deliberate.
  - The key segment is redacted from the access log (case-insensitively, from
    the first `.`) and from the passthrough error log.
- **Not done:** the P0 broker refusal of sealed `/v1/videos` (dropped for now), and
  the public docs outside this repository. `deploy/phala/README.md` describes
  async image for gateway users, including that the job id is a credential and
  that edits and video are not sealed.

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
6. **Outward ids.** As §3.6. Video's create and status responses use `id` (and the
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
