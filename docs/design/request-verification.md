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

### Three conditions, all load-bearing

**1. Digests, not tags — a tag-only reference must fail.** The staging sample pins
`image: …:latest`. A floating tag keeps `compose_hash` stable while the code behind
it changes, so an allowlist keyed on names proves nothing. This is the same caveat
`pcverify` already prints for the gateway, and why `containerRef.Digest` keeps an
empty value visible instead of hiding it. Under this scheme it has to be an
outright failure, not a note.

**2. The OS-image allowlist is still required.** It is tempting to read
"allowlist images instead of measurements" as replacing the measurement check. It
does not: what makes `mr_config_id` trustworthy in the first place is that the
guest OS enforces the binding between the attestation and the manifest. That is
established by MRTD/RTMR1/RTMR2 matching an audited OS image. Drop it and the rest
of the chain is self-asserted. The two checks are **complementary halves**:

| Registers | Establishes |
|---|---|
| MRTD / RTMR1 / RTMR2 | which guest OS — and thus that the manifest binding is enforced |
| `mr_config_id` → compose → digests | which application code |

Note the staging broker runs `dstack-nvidia-dev-0.5.7-…`, a **dev** image, and a
different one from the gateway's. Provider OS images need their own allowlist
entries, and a dev image should not be among them for production.

**3. The policy must cover the whole app-compose, not just images.** The staging
sample carries `DSTACK_AUTHORIZED_KEYS` in `allowed_envs`, plus a pre-launch script
that writes `authorized_keys` and sets a root password. An enclave someone can SSH
into does not keep a prompt confidential, regardless of which image it runs. It also
sets `public_logs` / `public_sysinfo` true.

That sample is a template deployment, not the real broker — but it shows the review
surface. At minimum the policy should cover `allowed_envs`, `pre_launch_script`,
`key_provider`, and the log/sysinfo exposure flags. For 0G-operated providers the
cleanest rule is what we use for the gateway: **byte-for-byte match against a
published manifest**, falling back to digest-plus-policy only for providers whose
manifest we do not publish.

### Separately: report_data has not migrated

The observed `report_data` is the signer address as **ASCII hex**, zero-padded —
the pre-SPEC layout that §4.2 flags as a breaking change. It does not carry
`enc_pub`, so the spec'd binding between the quote and the HPKE recipient key is
not in place on this broker yet. Sealing against it requires that migration first;
it is a prerequisite for hop 3 mattering in production, and is tracked with the
protocol work rather than here.

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
| Provider endpoint, quote verdicts, measurement | — | **missing**; needs a provider identity endpoint |

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

1. Panel renders what already exists (§7 rows marked available), with the §3 ladder
   and the §2 rule about which chain each check belongs to.
2. Correct the two "coarse token count" lines (§4).
3. Provider identity endpoint — unblocks the broker hop.
4. Hop 3 policy (§6): digest pinning enforced, provider OS entries, app-compose
   policy beyond images.
5. Chain B, if and when we choose to sell it: nonce + transcript + commit–reveal,
   together.
