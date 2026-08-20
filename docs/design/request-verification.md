# Request verification — what a user is shown, and what it is worth

The hosted gateway verifies the provider on the user's behalf: it checks the TDX
quote before sealing, and checks the §8 response signature before returning a
body. Both are fail-closed. That is the whole convenience of the hosted form —
and it is also the problem this document is about, because **a verdict the
gateway reaches about itself is not evidence to the person reading it.**

So: what do we put in front of a user, and what is each thing actually worth?

This doc fixes the vocabulary and the information architecture. It does not
specify wire formats — where a mechanism needs one, it points at the issue.

> Scope: the **hosted gateway** path. A local sidecar or in-process SDK user holds
> the keys and runs the checks themselves; none of this applies to them. This
> machinery is precisely the price of the hosted form.

## 1. Three questions, not one

"Can I verify my request?" runs together three claims with very different
footing.

| | The question | Provable per request? | Rests on |
|---|---|---|---|
| **A. Identity** | Who ran this? Which broker, which image? | Yes | TDX quote, measurement, on-chain `teeSignerAddress` |
| **B. Authenticity** | Is this answer really that enclave's output for *my* prompt? | Partly — see §5 | §8 signature (`scheme:reqH:respH`) |
| **C. Confidentiality** | Did the gateway read or leak my prompt? | **No. Never.** | Only the gateway's own code identity |

**C is the one to be careful about.** No per-request receipt can establish it —
not ours, not anyone's. The only thing that speaks to it is "the gateway runs the
code you can read", i.e. `pcverify` plus the published manifest. A verification
panel that leaves a user feeling their privacy was *verified* has misled them,
however accurate its individual fields are.

The consequence for the UI is concrete: the sentence "the gateway sees your
plaintext" belongs **on the gateway hop itself**, where the claim is made — not in
a disclaimer block at the bottom, which is where text goes to be skipped.

## 2. Two trust chains — pick one, and say which

There are two coherent stances a user can take, and they are mutually exclusive
in what they count as evidence.

| | **Chain A — attestation-rooted** | **Chain B — per-request, gateway untrusted** |
|---|---|---|
| What the user does | Verifies gateway code identity once; reads the source; sees verification is on and fail-closed | Checks each request themselves |
| Gateway's own verdicts | **Count** — transitively, via attestation | Count for nothing |
| Needs a caller nonce | No | Yes, and much more |
| chatKey existence check | Redundant | Necessary but insufficient |

**We currently ship chain A**, and that is the right call for now: the
architecture is built around an attested gateway, and `-verify-responses` is on
and fail-closed.

The failure mode to avoid is **mixing them**. Handing a user a chatKey and saying
"go check it yourself" invites chain B; but the check on offer only carries weight
under chain A (see §4). A user who believes B and performs that check thinks they
verified something they did not.

So the rule for copy: anything presented as a user-performable check must state
which chain it belongs to. In practice that means the panel's own hierarchy puts
**"verify the gateway" first**, because everything else hangs off it.

## 3. The honesty ladder — three states, not two

A row of green checkmarks is the wrong default, because at least one claim we
display cannot honestly carry one. The panel encodes three states, and the glyph
(filled / half / hollow) carries the ladder so colour is only reinforcement:

| | State | Meaning |
|---|---|---|
| ● | **Proven** | Traces to a root — hardware, code, or on-chain — and the user can re-derive it |
| ◐ | **Observed** | We read the value; there is no baseline to compare it against |
| ○ | **Not trusted** | Somebody's assertion. Not evidence, by construction |

Concrete assignments today:

- Gateway OS image → **●**. `identity.go` only emits a name when the allowlist was
  configured *and* an entry matched, so a non-null value cannot mean "unchecked".
  Null is ambiguous (no match / no allowlist) and both cases render the same way:
  *not established* — never "failed".
- Provider measurement → **◐**. Hop 3's allowlist has a fillable shape (#72) and no
  entries. See §6.
- Everything the router says → **○**. Per SPEC §8.2 a router-injected
  `x_0g_trace` is in `unbound_fields` and therefore outside the signature *by
  construction*. `tee_verified` and the billing figures are in that class. They
  are hints; the panel must not render them as conclusions.

## 4. What the router can actually see

Worth stating precisely, because it is easy to understate and the understatement
shows up in user-facing copy.

The router sees **exact** token usage, not an estimate: SPEC §7 leaves `usage`
cleartext specifically so the router can bill on it. It also sees the **exact byte
length** of the sealed content — ChaCha20-Poly1305 adds a 16-byte tag and no
padding, so ciphertext length is plaintext length plus a constant. Add the
per-frame timing of a stream, and `sealed_fields` (which discloses *that* you sent
tools, not what they are).

What it cannot do is change any of it: `usage` is in the AAD and covered by the
signature, so the router reads and bills but cannot lie.

> Two design docs still describe this as a "coarse token count"
> (`trust-chain.md`, `router-e2e.md`). That predates `usage` being cleartext for
> billing and should be corrected — an auditor reading both gets two different
> answers.

## 5. The gap in B: plaintext versus ciphertext

The §8 signature binds `reqH = H(sha256(aad), sha256(ct))`. The user holds
plaintext and has never seen a byte of `aad`/`ct`. Publishing the transcript alone
does not close this: a dishonest gateway could seal a *different* prompt, obtain a
perfectly valid signature, and display fabricated plaintext — every published
artifact verifies.

Three ways to close it, in increasing order of correctness:

1. **Reveal the sealing randomness.** Derive the HPKE sender key from a recorded
   seed; publish the seed and the response ephemeral private key after the
   exchange. The user re-seals their own plaintext and compares bytes, and opens
   the response frames directly. Costs that request's confidentiality against
   anyone who recorded the wire — so it is an explicit per-request audit mode, off
   by default.
2. **Commit–reveal, enforced in the enclave.** A bound cleartext
   `_e2ee.pt_commit = H(salt ‖ plaintext)` with `salt` inside the sealed object;
   the enclave rejects the request unless the commitment matches what it decrypted.
   Reveal only `salt`. Zero key disclosure, and the binding is enforced by the
   enclave rather than asserted by the gateway. **This is the target design**; it
   needs a broker-side change.
3. **Ciphertext half only** (publish `aad`/`ct`, verify `reqH`/`respH`). Proves a
   legitimate enclave signed *some* exchange with this `usage`. Fine for billing
   disputes, useless against prompt substitution. Do not call it "request
   verification".

None of this ships under chain A. It is the content of chain B, and the pieces
(caller nonce, transcript endpoint, plaintext binding) go together or not at all —
a nonce alone is half a gesture.

## 6. Hop 3 — establishing the provider's code identity

Hop 3 is the one trust root not yet doing its job. What follows is the route, based
on a real provider `/v1/quote` reply.

### What the quote already gives us

Two things confirmed against a live staging broker:

- **`mr_config_id` uses the V1 layout** — `0x01 ‖ compose_hash(32) ‖ zeros`, and the
  hash matches the compose hash reported elsewhere in the reply. So the compose
  hash sits in the **signed** TD report and is readable with the existing
  `attest.ComposeHashFromMRConfigID`. **No event-log replay is required** — which
  matters, because the event log is unsigned and replaying it is both more work and
  a weaker link.
- The reply also carries the full `app_compose` text. It is unsigned convenience
  data, but it is *self-authenticating*: hash it and compare to the compose hash
  from the verified quote. A provider cannot substitute it.

That makes the following viable, and it mirrors what `pcverify` already does for
the gateway:

```
verified quote
  └─ mr_config_id → compose_hash            (signed; no replay)
        └─ sha256(app_compose) must equal it (self-authenticating)
              └─ docker_compose_file → image references
                    └─ each must be an allowlisted 0G-published digest
```

The allowlist is then **a list of image digests we publish**, not a list of expected
measurement registers — much cheaper, because we already know our own digests and
would otherwise need reproducible builds to predict an RTMR.

### The OS-image half is still required

It is tempting to read "allowlist images instead of measurements" as replacing the
measurement check. It does not: what makes `mr_config_id` trustworthy in the first
place is that the guest OS enforces the binding between the attestation and the
manifest, and that is established by MRTD/RTMR1/RTMR2 matching an audited OS image.
Drop it and everything downstream is self-asserted. The two are complementary
halves:

| Registers | Establishes |
|---|---|
| MRTD / RTMR1 / RTMR2 | which guest OS — and thus that the manifest binding is enforced |
| `mr_config_id` → compose → digests | which application code |

Providers run the same platform as the gateway, so this reuses the existing
machinery: `evidence.CheckOSImage` is exported precisely so two callers reach one
verdict from one allowlist. Three details:

- **Keep provider and gateway entries separate** (two lists, or a role tag).
  Sharing one list means adding an entry for a provider silently widens what is
  acceptable for the gateway. Free now, annoying later.
- **Expect version drift.** The gateway runs `dstack-nvidia-0.5.4.1`; the staging
  broker runs `dstack-nvidia-dev-0.5.7-…`. Even once both are release images they
  will not upgrade in lockstep — the allowlist is a list for exactly this reason. A
  **dev** image should not be an entry for production.
- **Fail closed on a non-dstack quote.** The broker has GCP and AliCloud TEE
  backends besides Phala. Those carry no compose hash in `mr_config_id` and this
  whole route does not apply; an unrecognized layout must be rejected, not waved
  through.

### What byte-matching would have covered, and what replaces it

For the gateway we match the compose text byte-for-byte against a published
manifest. That single check pins everything at once: image digests, `allowed_envs`,
the pre-launch script, and any deploy-time interpolation.

We do **not** publish per-provider manifests — providers differ from one another,
and pinning each one would mean a release for every config change. That is a
deliberate trade, and the cost is precise: **everything the byte-match used to pin
now needs saying out loud.** The list below is not extra hardening piled on top; it
is the byte-match, itemized.

The organizing question is not "are there extra containers" — an init container that
writes a volume and exits is ordinary infrastructure, the same shape as the
gateway's own `cvm-identity`. It is:

> **Does anything in this compose let unmeasured content influence what the enclave
> does?**

Three channels:

| Channel | What it looks like |
|---|---|
| Interactive access | `DSTACK_AUTHORIZED_KEYS` in `allowed_envs`; a pre-launch script that writes `authorized_keys` or sets a root password |
| Unpinned code | a tag-only image reference — the app image, and equally `alpine:3.18` in a helper |
| **Unmeasured configuration** | `${VAR}` interpolation landing in a file the app reads |

The third is the subtle one, because it looks like plumbing. A real example:

```yaml
config-init:
  image: alpine:3.18
  environment: [ CONFIG_B64_1=${CONFIG_B64_1} ]
  command: [ sh, -c, 'echo "$$CONFIG_B64_1" | base64 -d > /config/config-1.yaml' ]
```

`compose_hash` commits to the literal text `${CONFIG_B64_1}` — that a variable is
here, not what it holds. The value arrives at deploy time. So the broker's runtime
configuration sits outside the attestation, and an operator can change it without
moving `compose_hash`. Note this evades both other checks: the image is correct, and
the variable name looks nothing like credential injection.

The fix keeps the pattern and makes the content measured — a literal hash in the
compose text, verified by the init container:

```yaml
  environment:
    - CONFIG_B64_1=${CONFIG_B64_1}
    - CONFIG_SHA256=9f2a…c41e            # literal — committed by compose_hash
  command:
    - sh
    - -c
    - |
      echo "$$CONFIG_B64_1" | base64 -d > /config/config-1.yaml
      echo "$$CONFIG_SHA256  /config/config-1.yaml" | sha256sum -c - || exit 1
```

The value is still supplied at deploy time; substituting it is now detectable. And
the per-provider difference collapses to that one hash literal, so the *shape* stays
uniform and a policy check can be mechanical: every interpolation that lands in a
file has a paired `_SHA256` literal, and the script actually checks it.

### Decision: enforce digest pinning, defer the rest

**Only condition one is enforced in code for now: an image reference without a
digest fails.** It earns that place because without it nothing downstream means
anything — a floating tag keeps `compose_hash` stable while the code behind it
changes, so every other check is defeated by it alone. It is also deployment
discipline rather than a policy engine, which is the cheapest kind of rule to hold.

The rest — `allowed_envs`, `pre_launch_script`, the interpolation-hash rule,
`public_logs`/`public_sysinfo` — becomes a **provider launch checklist**, reviewed by
a person, not code.

The reason that is proportionate today: every provider is 0G-operated, so "the
operator can reach inside" describes our own team. Those are internal-controls
questions, and a checklist is the right instrument for internal controls.

**Revisit when third-party providers join.** At that point the same items stop being
internal controls and become admission criteria, and a checklist is no longer the
right instrument — they have to be mechanical. That is also when hop 3 genuinely
needs to stop being warn-only. Until then the panel reports the provider's
measurement as **observed (◐)**, which is the honest state.

### The rollout window, and what the panel does during it

The SPEC §4.2 `report_data` layout (`enc_pub ‖ signer_addr ‖ version`) is
implemented but not fully deployed. The staging broker sampled above still
publishes the old form — the signer address as ASCII hex, zero-padded, with no
`enc_pub` — so sealing against *that* instance is not possible until it rolls.

Two consequences that outlive the rollout itself, both worth building for rather
than discovering:

**Both layouts coexist while it rolls.** That is what the `version` field is for
and the client must branch on it, not assume the new one. A provider on the old
layout is a provider that cannot be sealed to — a routing fact, not an error.

**A provider upgrade transiently breaks the on-chain signer check.** The registry
holds exactly one `teeSignerAddress` per provider and cannot express "old and new
are both valid for the next few minutes", while a broker upgrade rotates `enc_pub`
and `signer_addr` **together** — they come out of one `report_data`, so they never
split. So during any provider rollout the chain and the quote name different
signers for a while, in whichever order the operator sequences it. The resolver
narrows the window by re-reading live instead of ruling on a cached value, but it
cannot close it (`trust-chain.md`, "What is *not* in the trust chain").

For the panel this shows up as `verdicts.onchain_signer` failing on a provider that
is merely mid-deploy. **Do not render that as a compromised broker.** It is
indistinguishable at the endpoint from a real mismatch, so the honest treatment is
the ◐ state, not ✗ — and the deployment runbook, not the UI, is where the window
gets shortened. Frontend should expect this before it appears, or the first
occurrence gets reported as a bug.

## 7. Where each panel field comes from

| Field | Source | Status |
|---|---|---|
| Model, token usage | response body (`usage` is cleartext by design) | available |
| Gateway domain | the caller's own base URL | available |
| Serving replica | `X-0G-Gateway-Instance` | available, CORS-exposed |
| chatKey | `ZG-Res-Key` | available, CORS-exposed |
| Provider address | `X-Provider`, gateway-originated (#76) | available, CORS-exposed |
| app_id, compose hash, OS image, containers, release | `GET /v1/gateway/identity` (#79) | available |
| Evidence bundle | `GET /evidences/` from the gateway, `ACAO: *` (#75) | available |
| Provider endpoint, quote verdicts, measurement | `GET /v1/providers/{address}/identity` (#82) | available |

Two notes on the shape of that data:

- **Compute it server-side.** In-browser DCAP verification has no maintained
  implementation and the collateral it needs is itself cross-origin. More
  fundamentally, `pcverify`'s endpoint-binding step is **impossible in a browser**:
  JavaScript cannot see its own connection's peer certificate. A browser package
  that returns PASS while structurally unable to perform that step is worse than
  none — it reassures exactly where impersonation lives. If we ship one, its result
  must be split per-claim, and endpoint identity must read "use `pcverify`".
- **`/v1/gateway/identity` is a self-description, not evidence.** It exists so the
  panel has something to render; what makes its values trustworthy is that
  `pcverify` reaches the same ones independently. It must never grow a
  `"verified": true`.

### The replica caveat

`pcverify` establishes endpoint identity **for the connection it made**. Blue/green
keeps two CVMs live and the platform picks one per TCP connection, so the replica a
user verified is not necessarily the one that served them; a redeploy also changes
`app_id`/`compose_hash` legitimately.

Surfacing the instance id is what makes that legible, and it is why the field is in
the panel rather than being treated as an operator-only detail. Pair it with a
published mapping from the current `app_id` to its release, so a value changing
reads as a deploy rather than as a substitution.

## 8. Deliberately not doing

| Candidate | Why not, for now |
|---|---|
| "Verify your request" as a chatKey existence check | Replayable without a caller nonce: a real-but-unrelated chatKey passes. Fine as a transparency action; misleading as a verification entry point |
| Caller nonce, transcript endpoint, plaintext binding | These are chain B. They ship together or not at all (§5) |
| Router image digest in the panel | The router is untrusted by design; displaying its digest implies it is part of the chain |
| Self-reported version strings | A dishonest backend prints anything. The only meaningful digest is `compose_hash` out of a verified quote |
| Proxying app-compose for the browser | Only needed for the in-browser route, which §7 rules out for now |
| An app-layer challenge endpoint | Would let a browser close endpoint identity by having the enclave sign a caller nonce with the quote-bound certificate key. Genuinely closes the §7 gap, but turns that key into a signing oracle — needs its own design pass on domain separation before anyone builds it |

## 9. Order of work

Done: `/evidences/` served with CORS (#75), the provider address reported from our
own pin rather than the router's claim (#76), `GET /v1/gateway/identity` (#79),
`GET /v1/providers/{address}/identity` (#82), and the §4 correction (#83). Every
row in §7 now has a source.

That makes the panel the bottleneck rather than the backend: **four endpoints are
live with nothing consuming them.**

1. **Build the panel.** §7 for the fields, §3 for the ladder, §2 for labelling which
   chain each check belongs to. Three rules that are easy to lose in
   implementation: `os_image` null renders as *not established*, never as *failed*;
   the router hop carries no verdict mark at all; "verify the gateway" sits first,
   because every "we checked this for you" hangs off it. Also expect
   `onchain_signer` to fail on a provider mid-deploy — see §6's rollout window.
2. `report_data` rollout completed across providers. Implemented; until a given
   provider carries the §4.2 layout it cannot be sealed to, and both layouts have to
   be handled meanwhile.
3. Hop 3, enforced half (§6): digest pinning, provider OS-image entries kept
   separate from the gateway's, non-dstack quotes rejected.
4. Hop 3, checklist half (§6): written down as a provider launch review, not code.
5. Chain B, if and when we choose to sell it: nonce + transcript + commit–reveal,
   together.
