// Package route resolves, per request, which provider enclave the gateway
// should seal to — the "route" trust shape from docs/design/cloud-gateway.md
// (§ open question 3): the gateway centralizes provider selection for a 0-code
// client instead of pinning one provider up front.
//
// A Router implements core.Resolver in two hops:
//
//  1. Control plane — POST the routing-relevant fields to the 0G router's
//     route-preview API (POST /v1/routing/preview). The router ranks its live
//     fleet and returns an ordered candidate list (its provider-retry budget) —
//     the fallback chain core walks. The sealed fields (the prompt) are stripped
//     before this call, so the router still never sees plaintext.
//  2. Provider identity — GET a candidate's HPKE recipient key from the broker's
//     e2ee pubkey API (…/v1/e2ee/pubkey), yielding the enc key to seal to and the
//     signer address sealed into _e2ee.signer_addr (SPEC §4). This is deferred
//     per candidate (core.Candidates.Provider): the happy path fetches only the
//     head's key, and a fallback fetches the next candidate's key on demand.
//
// The resulting core.Provider seals to the chosen provider's enc key, but its
// URL is the *router's* chat-completions endpoint, not the provider's: the
// sealed request goes through the router (centralized auth/billing), which
// forwards to the pinned provider (SPEC §4.4). Two distinct pins, which may
// differ: the signer address is the crypto pin in the envelope, while the
// preview's provider address is the routing pin core sends as
// X-0G-Provider-Address (with fallback off) so the router forwards to exactly
// the provider whose key the request is sealed to.
//
// The enc key is trusted as delivered here; verifying it out of an attestation
// quote (protocol/attest, issue #7) is a later step.
package route

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/0gfoundation/0g-pc-e2ee/client/chain"
	"github.com/0gfoundation/0g-pc-e2ee/client/compose"
	"github.com/0gfoundation/0g-pc-e2ee/client/core"
	"github.com/0gfoundation/0g-pc-e2ee/client/endpoint"
	"github.com/0gfoundation/0g-pc-e2ee/client/evidence"
	"github.com/0gfoundation/0g-pc-e2ee/client/metrics"
	"github.com/0gfoundation/0g-pc-e2ee/protocol/attest"
	"github.com/0gfoundation/0g-pc-e2ee/protocol/crypto"
	"github.com/0gfoundation/0g-pc-e2ee/protocol/wire"
	"golang.org/x/sync/singleflight"
)

// The service types this package speaks, taken from client/endpoint rather than
// spelled again here.
//
// They are vars, not consts, because a row's field is not a constant expression
// — and that is the point. Held as their own literals they were a second
// spelling of "chatbot" and "text-to-image" with nothing tying it to the first:
// editing either side compiled, passed every test, and took the surface down at
// runtime with "no sealed upstream path for service type". Deriving them removes
// the second spelling instead of documenting it.
//
// Exported for WithWarmServiceTypes, whose argument really is a service type: it
// says which slice of the FLEET to keep hot, and the provider catalog is indexed
// by service type. Resolve no longer takes one — it takes the row, because a
// service type cannot name a surface.
var (
	// DefaultServiceType is the service type of the chat fleet. It is the router's
	// internal service-type vocabulary — the same strings GET /v1/service-types
	// returns and GET /v1/providers?service_type= accepts — not the model modality
	// on /v1/models.
	//
	// It covers BOTH chat surfaces: /v1/chat/completions and /v1/messages are one
	// pool of providers answering two request shapes, so warming this one value
	// keeps the Anthropic surface's providers hot too, and there is deliberately no
	// second constant for it.
	DefaultServiceType = endpoint.Chat.ServiceType
	// ServiceTypeTextToImage is the service type of the image fleet.
	ServiceTypeTextToImage = endpoint.Image.ServiceType
)

// b64 is base64url without padding — the enc_pub encoding on the wire (SPEC §3),
// matching how the broker publishes it.
var b64 = base64.RawURLEncoding

const (
	// DefaultRouterURL is the 0G router's base URL. The route-preview and
	// chat-completions paths are appended to it; callers configure the router
	// domain, not the full endpoint.
	DefaultRouterURL = "https://router-api.0g.ai"
	// previewPath is the router's route-preview endpoint, appended to the router
	// base URL. It is owned here because this package owns that API contract.
	previewPath = "/v1/routing/preview"
	// providersPath is the router's provider-catalog endpoint. The warmer GETs it
	// (with ?service_type=) to enumerate provider on-chain addresses; the serving
	// endpoint itself is resolved from chain, not from this list.
	providersPath = "/v1/providers"
	// defaultPubkeyTTL bounds how long a fetched provider enc key is reused
	// before re-fetching, amortizing the extra round trip the route path adds
	// (docs/design/router-e2e.md "extra round trip"). Providers rotate keys
	// rarely, so a few minutes is safe; a bad guess only costs a re-seal.
	defaultPubkeyTTL = 5 * time.Minute
	// defaultQuoteTTL bounds how long a DCAP-verified result is reused. Kept short
	// (not permanent) so a TCB downgrade, collateral expiry, revocation, or enc-key
	// rotation is re-checked promptly; the warmer refreshes ahead of it.
	defaultQuoteTTL = 5 * time.Minute
	// controlPlaneHeaderTimeout bounds the wait for response headers on a
	// control-plane call (preview, pubkey, quote) — short, unlike the data plane's,
	// because none of these streams.
	controlPlaneHeaderTimeout = 30 * time.Second
	// Route-preview attempt policy. Preview is the one outbound dependency on the
	// request path with nothing in front of it: every other hop is served from a
	// cache the warmer keeps hot (quote, collateral, on-chain signer), while the
	// ranking has to reflect the live fleet and so is fetched per request. That
	// makes a single blip on this call a failed chat completion, which is what these
	// retries are for. Replaying it is safe: it ranks providers and starts no
	// inference, so an attempt that failed in transit costs at most a duplicate
	// read.
	//
	// previewAttempts is the total number of attempts, previewRetryBackoff the pause
	// before the second (doubling for each after it).
	previewAttempts     = 3
	previewRetryBackoff = 200 * time.Millisecond
	// previewAttemptTimeout bounds ONE attempt, end to end.
	//
	// Without it an attempt has no bound at all: r.http sets only
	// ResponseHeaderTimeout, which covers the wait for response HEADERS and not the
	// body read, so a router that dribbles a reply keeps a caller waiting for as
	// long as it likes. Preview is a small control-plane call that never streams and
	// whose body is already capped at maxControlBodyBytes, so bounding the whole
	// attempt costs nothing real — and it is what makes the ceiling below a fact
	// rather than an assumption.
	previewAttemptTimeout = controlPlaneHeaderTimeout
	// previewRetryBudget gates whether ANOTHER attempt may start. It is checked
	// before each backoff and never imposed on an attempt already in flight, so it
	// can never cut short a preview that is about to succeed.
	//
	// Because it only gates entry, the end-to-end ceiling is this budget PLUS one
	// full attempt — about 2× controlPlaneHeaderTimeout, NOT 1×. An earlier version
	// of this comment claimed that retrying inside the budget added no worst case a
	// caller did not already have. That was wrong: a probe failing each attempt
	// after 20s measured 40s against a 30s "budget", because the budget check had
	// already passed when the second attempt began. State the real bound.
	//
	// What the budget does buy is self-selection for the cases retrying helps: a
	// fast failure (refused connection, reset, a proxy's 502) leaves nearly the
	// whole budget and gets its retries, while a router that hangs until its
	// attempt timeout consumes the budget in one attempt and gets none — which is
	// right, because there retrying only makes the user wait longer for the same
	// error. The middle case (a proxy that 502s after 20s) does get one more
	// attempt, and previewAttemptTimeout is what bounds what that costs.
	previewRetryBudget = controlPlaneHeaderTimeout
	// quoteVerifyTimeout bounds a single (de-duplicated) quote verification, which
	// runs under a context detached from any one caller (so no caller's
	// cancellation kills the shared work); this caps a hung upstream instead.
	quoteVerifyTimeout = 60 * time.Second
	// x25519PubLen is the byte length of the HPKE (X25519) recipient key.
	x25519PubLen = 32
	// maxPreviewCandidates caps how many candidates one preview reply may contribute
	// to the fallback chain. The router chooses the list and nothing else bounds its
	// length — maxControlBodyBytes leaves room for thousands — and core walks it
	// SERIALLY, so N is one of the two factors in what a failing chain costs a
	// caller (core.resolveBudget bounds the other). Truncating is cheap and safe
	// here: the list arrives ranked best-first, so what is dropped is the tail the
	// client would reach only after everything better had already failed.
	maxPreviewCandidates = 8
	// maxControlBodyBytes caps a control-plane response body read (preview /
	// pubkey), guarding against an unbounded response.
	maxControlBodyBytes = 1 << 20 // 1 MiB
	// reverifyFailureBackoff is how soon a recovery re-verification may be retried
	// after one that FAILED (as opposed to one that concluded the provider really
	// does mismatch). Short, because such a failure says nothing about the provider.
	reverifyFailureBackoff = 30 * time.Second
	// signerRevalidateWindow bounds how often a disagreement may force a live
	// signer re-read for one provider. A rotation is picked up within it; a provider
	// that keeps disagreeing costs one chain RPC per window instead of one per
	// request.
	signerRevalidateWindow = time.Minute
)

// Router resolves the provider for each request via the route-preview + pubkey
// APIs. It is safe for concurrent use.
type Router struct {
	previewURL   string
	base         string
	providersURL string
	// warmServiceTypes is the only service-type state left on the Router, and it
	// is genuinely the router's: which slice of the fleet the background warmer
	// keeps hot. The service type of a REQUEST arrives with Resolve instead — it
	// describes the request, not this connection. One 0G Router serves every
	// endpoint at one URL, so a per-endpoint Router would have duplicated this
	// object's caches, transport and verifier against one host while still
	// getting the upstream path wrong, which is exactly what it did.
	warmServiceTypes []string
	// extraSensitiveFields are fields the operator adds to the withheld set, on
	// top of whatever the request's service type already withholds. See
	// WithSensitiveFields for why it adds rather than replaces.
	extraSensitiveFields map[string]struct{}
	http                 *http.Client
	cache                *pubkeyCache
	// verifier, when non-nil, switches candidate materialization from trusting
	// the router-supplied pubkey endpoint to fetching and DCAP-verifying the
	// provider's attestation quote, sourcing enc_pub/signer from the verified
	// report_data. Nil keeps the legacy pubkey-endpoint behavior.
	verifier *attest.Verifier
	logger   *slog.Logger
	// registry, when non-nil, grounds the quote-bound signer in the on-chain
	// InferenceServing registry (SPEC §4.4 step 3 / trust-chain hop 5): the signer
	// must equal the provider's acknowledged teeSignerAddress. onchainEnforce
	// makes a negative result fail-closed (skip the candidate) instead of a warn.
	registry       chain.SignerRegistry
	onchainEnforce bool
	// quoteCache memoizes DCAP-verified results (enc_pub/signer + the facts the same
	// verification established) per endpoint, and quoteSF collapses concurrent misses
	// for the same endpoint into a single verification so a cold/expired key can't
	// stampede the expensive quote+collateral path. Used only on the
	// quote-verification path (verifier != nil).
	quoteCache *quoteCache
	quoteSF    singleflight.Group
	// identities keeps, per provider address, the outcome of the checks this process
	// ran before sealing to that provider — read by the gateway's provider-identity
	// endpoint (see provideridentity.go). Written only from the path that materializes
	// a candidate; nothing reads it on the request path.
	identities *identityStore
	// The two recovery paths are rate-limited per subject: re-verifying a quote
	// (keyed by quote URL) and re-reading a signer (keyed by provider address).
	// Both exist to avoid rejecting a provider on cached evidence, and both would
	// otherwise let a provider that keeps disagreeing turn that generosity into a
	// per-request cost.
	quoteReverify    rateLimiter
	signerRevalidate rateLimiter
	// The preview pacing pair, defaulted from previewAttemptTimeout and
	// previewRetryBudget. Fields rather than bare constants so a test can scale both
	// down and exercise the real end-to-end ceiling (budget + one attempt) in
	// milliseconds instead of a minute — per Router, not mutable globals, so such
	// tests stay parallel-safe.
	//
	// Read through attemptTimeout()/retryBudget(), which default a zero the way
	// candidateWalk.limit() does. Without that, a Router not built by New — and the
	// tests already construct &Router{} directly — gave every preview an
	// already-expired context and failed every request, silently and totally.
	previewAttemptTO time.Duration
	previewBudgetTO  time.Duration
	// previewRetries switches preview retries off while the router looks down, so a
	// router outage does not become a load multiplier against it and a slot-holding
	// multiplier against us. See retryGate.
	previewRetries retryGate
	// warmState is the outcome of the most recent completed warmer sweep — how many
	// providers it prepared end to end — read by a caller that needs to know whether
	// this process can serve anything at all (see WarmState).
	warmMu    sync.Mutex
	warmState WarmState
}

// Option customizes a Router.
type Option func(*Router)

// WithWarmServiceTypes sets which service types the background quote warmer
// enumerates providers for (default DefaultServiceType alone). Unlike the
// service type of a REQUEST — which travels with Resolve, because it describes
// the request, not this router — this is a property of the router: it says which
// slice of the fleet to keep hot.
//
// A caller serving several surfaces passes each one's service type, so their
// providers' quotes are verified ahead of the first request rather than on it.
// Empty values are ignored; passing none leaves the default.
//
// DUPLICATES are collapsed, because a caller that derives this from the rows it
// serves now legitimately produces them: /v1/chat/completions and /v1/messages
// are both "chatbot", so a gateway serving both hands us that value twice. The
// sweep already de-duplicates by provider ADDRESS, so the waste was one extra
// fleet ENUMERATION per sweep — a GET the router answers identically — rather
// than repeated verification. Collapsing here keeps every caller from having to
// know that two rows can share a service type.
func WithWarmServiceTypes(types ...string) Option {
	return func(r *Router) {
		var out []string
		seen := make(map[string]struct{}, len(types))
		for _, t := range types {
			if t == "" {
				continue
			}
			if _, dup := seen[t]; dup {
				continue
			}
			seen[t] = struct{}{}
			out = append(out, t)
		}
		if len(out) > 0 {
			r.warmServiceTypes = out
		}
	}
}

// WithHTTPClient overrides the HTTP client used for the control-plane calls.
// The default bounds the response-header wait; callers rarely need this.
func WithHTTPClient(h *http.Client) Option {
	return func(r *Router) {
		if h != nil {
			r.http = h
		}
	}
}

// WithSensitiveFields adds request fields to those stripped before the preview
// call, so they never reach the (untrusted) router in cleartext.
//
// ADDITIVE, not a replacement. Its documented purpose has always been "withhold
// MORE than the profile's sealed set" — an operator who also seals "user" or
// "metadata" — but it used to REPLACE the derived set, which made the two
// readings differ exactly where it mattered. With the request's service type now
// arriving per call, replacing would be worse than untidy: one router serves
// both endpoints, so a chat-shaped override would become the withheld set for
// image requests too, and since the preview body is everything NOT withheld, a
// wrong set does not fail — it uploads the prompt. Adding cannot do that.
//
// An empty or nil set is a no-op.
func WithSensitiveFields(fields []string) Option {
	return func(r *Router) {
		if len(fields) == 0 {
			return
		}
		if r.extraSensitiveFields == nil {
			r.extraSensitiveFields = make(map[string]struct{}, len(fields))
		}
		for _, f := range fields {
			r.extraSensitiveFields[f] = struct{}{}
		}
	}
}

// withheldFor is the set of fields kept out of the preview body for one request:
// the surface's own payload fields plus any the operator added. Computed per
// call because the surface is per call.
func (r *Router) withheldFor(ep endpoint.Endpoint) map[string]struct{} {
	base := sensitiveFieldsFor(ep)
	out := make(map[string]struct{}, len(base)+len(r.extraSensitiveFields))
	for _, f := range base {
		out[f] = struct{}{}
	}
	for f := range r.extraSensitiveFields {
		out[f] = struct{}{}
	}
	return out
}

// sensitiveFieldsFor returns the fields to withhold from the preview for one
// surface, derived from its wire profile — so an image request cannot be
// previewed with its `prompt` in the clear, nor an Anthropic one with its
// top-level `system`.
//
// The set used to be an independent option kept in sync with the surface by
// hand, with the chat set hardcoded as the default. That is a leak waiting to
// happen: the preview body is everything NOT in this set, so a stale set does not
// fail, it silently ships the payload to the router.
//
// A row whose profile WIRE does not know gets the union of every payload field
// any profile has. Over-stripping is the safe direction — it can only cost
// routing fidelity, since the router then ranks on fewer fields, while
// under-stripping leaks — and an unanalysed surface is exactly the case where
// guessing narrow would be wrong.
//
// Keying that fallback on "wire does not know this profile" rather than on "the
// endpoint table has no such row" is what makes the zero Endpoint safe HERE. The
// zero row fails closed for sealing all by itself (wire rejects its empty
// profile on every seal and open), but wire.DefaultSealedFieldsFor of an empty
// profile is the EMPTY SET — so a caller that trusted the row and asked only for
// its default sealed fields would withhold NOTHING and upload the entire payload,
// prompt included, to the untrusted router. The empty answer is the dangerous
// one, so it is the one that triggers the union.
//
// That union is taken over wire.Profiles(), the PROTOCOL's list, and NOT over
// endpoint.All, the surfaces this gateway mounts. The two can diverge, and a
// union over the mounted rows would silently shrink as rows are added or removed
// — the wrong direction for a complement.
func sensitiveFieldsFor(ep endpoint.Endpoint) []string {
	if fields := wire.DefaultSealedFieldsFor(ep.Profile); len(fields) > 0 {
		return fields
	}
	return everyProfilesPayloadFields()
}

// everyProfilesPayloadFields is the union of the default sealed set of every
// profile the protocol defines — what an unrecognised service type withholds.
// Recomputed per call rather than cached in a package var: it is off the hot
// path (only a service type outside the table reaches it) and a var would
// re-introduce, as initialisation order, the staleness this exists to remove.
func everyProfilesPayloadFields() []string {
	var out []string
	for _, p := range wire.Profiles() {
		for _, f := range wire.DefaultSealedFieldsFor(p) {
			if !slices.Contains(out, f) {
				out = append(out, f)
			}
		}
	}
	return out
}

// WithPubkeyTTL sets how long a fetched provider enc key is cached and reused.
// A non-positive TTL disables caching (fetch every request).
func WithPubkeyTTL(d time.Duration) Option {
	return func(r *Router) { r.cache = newPubkeyCache(d) }
}

// WithQuoteTTL sets how long a DCAP-verified result (enc_pub/signer) is cached
// and reused on the quote-verification path. A non-positive TTL disables
// caching (verify every request). Keep it short — it bounds how long a TCB
// downgrade / revocation / key rotation goes unnoticed.
func WithQuoteTTL(d time.Duration) Option {
	return func(r *Router) { r.quoteCache = newQuoteCache(d) }
}

// WithQuoteVerification makes the Router obtain each candidate's enc_pub and
// signer from a DCAP-verified attestation quote instead of the router-supplied
// pubkey endpoint: it GETs the provider's /v1/quote, runs v.Verify (genuine TDX
// + measurement policy + report_data binding), and seals only to the verified
// enc_pub. This is what stops a compromised router from pointing the client at a
// key it controls. Without this option the Router keeps the legacy behavior of
// trusting the pubkey endpoint.
//
// logger receives a warning whenever a genuine quote's measurement is not in the
// verifier's allowlist (only reachable when v uses attest.ModeWarn); nil uses
// slog.Default().
func WithQuoteVerification(v *attest.Verifier, logger *slog.Logger) Option {
	return func(r *Router) {
		if v == nil {
			return
		}
		if logger == nil {
			logger = slog.Default()
		}
		r.verifier = v
		r.logger = logger
	}
}

// WithOnChainVerification makes the Router cross-check each candidate's
// quote-bound signer against the provider's acknowledged teeSignerAddress in the
// on-chain InferenceServing registry (SPEC §4.4 step 3 / trust-chain hop 5). DCAP
// quote verification (WithQuoteVerification) proves the signer belongs to a
// genuine, audited enclave, but not that it is the *expected* provider — a
// look-alike enclave running the same image passes the quote check. Grounding the
// signer in the chain — a source the untrusted router cannot forge — closes that
// gap. This option is meaningful only alongside WithQuoteVerification (otherwise
// the signer comes from the router-supplied pubkey endpoint, not a quote).
//
// enforce=false is observe-only: a missing/unacknowledged/mismatched on-chain
// signer (or an RPC failure) is logged and the candidate is still used, mirroring
// attest warn mode for staged rollout.
//
// enforce=true is fail-closed on every negative — an unacknowledged or mismatched
// signer, and equally a lookup that could not be performed at all — so enforce
// means the chain was actually READ, never merely consulted. There is deliberately
// no knob to relax the second case: a check that can lapse whenever an adversary
// degrades one RPC endpoint is not a check anything may call proven, and since the
// deployment's env block is measured into the CVM attestation, such a knob could
// not be flipped mid-incident any faster than enforce itself can be turned off.
// The two negatives are still COUNTED apart, because they call for different
// responses — a mismatch is a signal about a provider, a lookup failure a signal
// about our own chain RPC.
//
// logger nil uses slog.Default() (or the logger a prior WithQuoteVerification
// set).
func WithOnChainVerification(reg chain.SignerRegistry, enforce bool, logger *slog.Logger) Option {
	return func(r *Router) {
		if reg == nil {
			return
		}
		r.registry = reg
		r.onchainEnforce = enforce
		if r.logger == nil {
			if logger == nil {
				logger = slog.Default()
			}
			r.logger = logger
		}
	}
}

// New returns a Router that talks to the given router base URL (empty uses
// DefaultRouterURL). The route-preview and chat-completions paths are appended
// to it, so callers configure only the router domain — a trailing slash and a
// base path prefix are both respected (e.g. "https://host/api" →
// "https://host/api/v1/routing/preview").
func New(routerURL string, opts ...Option) *Router {
	if routerURL == "" {
		routerURL = DefaultRouterURL
	}
	base := strings.TrimRight(routerURL, "/")
	// A dedicated transport with a server-sized idle-connection pool and a bounded
	// header wait, mirroring core.NewWithResolver; the control-plane calls are
	// short, so no long-stream concern applies. The pool matters most here: preview
	// runs on EVERY request against the one router host, so an undersized pool
	// (Go's default is 2) turns each concurrent request past the second into a
	// fresh dial + TLS handshake (see core.NewPooledTransport).
	tr := core.NewPooledTransport()
	tr.ResponseHeaderTimeout = controlPlaneHeaderTimeout
	r := &Router{
		previewURL:       base + previewPath,
		base:             base,
		providersURL:     base + providersPath,
		warmServiceTypes: []string{DefaultServiceType},
		http:             &http.Client{Transport: tr},
		previewAttemptTO: previewAttemptTimeout,
		previewBudgetTO:  previewRetryBudget,
		cache:            newPubkeyCache(defaultPubkeyTTL),
		quoteCache:       newQuoteCache(defaultQuoteTTL),
		identities:       newIdentityStore(providerIdentityTTL, maxProviderIdentities),
	}
	for _, o := range opts {
		o(r)
	}
	// No post-loop derivation of the withheld set any more: it depends on the
	// request's service type, which arrives at Resolve. Option order therefore
	// cannot decide it, which is the failure the old sensitiveFieldsSet flag
	// existed to prevent.
	return r
}

// Resolve implements core.Resolver: it runs the route-preview once and returns
// the ranked candidate list as core.Candidates. Materializing a candidate (its
// pubkey fetch) is deferred to Candidates.Provider, so the happy path fetches
// only the head's key; core walks the rest only on fallback.
// Resolve previews the fleet for one request. ep describes the REQUEST — its
// surface, its profile, its upstream path — and so travels with it rather than
// being fixed on the Router: one 0G Router serves every endpoint at one URL, and
// everything that differs between endpoints (which providers to rank, which
// fields to withhold from the preview body, which upstream path to POST to) is a
// property of the request shape.
//
// It takes the row rather than the service-type string it used to, because the
// string cannot name a surface: /v1/chat/completions and /v1/messages are both
// "chatbot", and re-deriving the row from it here returned whichever came first
// in the table — previewing and POSTing the Anthropic surface as OpenAI chat,
// which withholds the wrong payload fields (uploading the top-level `system` the
// chat profile has no opinion about) and reaches a handler expecting another
// request shape. The three questions below are now read off the row the caller
// already holds instead of looked up from a projection of it.
//
// A malformed row is still refused rather than defaulted — see upstreamURL and
// withheldFor, which fail closed in opposite directions because a wrong upstream
// and a wrong withheld set have different safe answers.
func (r *Router) Resolve(ctx context.Context, ep endpoint.Endpoint, req wire.Request) (core.Candidates, error) {
	upstream, err := r.upstreamURL(ep)
	if err != nil {
		return nil, err
	}
	providers, err := r.preview(ctx, ep, req)
	if err != nil {
		return nil, err
	}
	return &routeCandidates{router: r, providers: providers, upstreamURL: upstream}, nil
}

// upstreamURL is the router endpoint a sealed request of this service type is
// POSTed to — the ROUTER, not the provider directly, because the router is the
// centralized auth/billing point: it authenticates, then forwards to the pinned
// provider (SPEC §4.4). Derived from the service type rather than fixed at
// construction:
// fixing it is how every sealed image request came to be POSTed to
// /v1/chat/completions, where the router hands it to the chatbot handler and the
// pinned image provider is not in the pool.
//
// The path now travels with the rest of the surface's row instead of being
// re-derived here, which is the same fix one level up: that bug was possible
// because the upstream path was a property of this Router while the profile was
// a property of the Client, and nothing held the two together.
//
// A row without an upstream path is REFUSED rather than defaulted. There is no
// safe guess: left unchecked this would resolve to the bare router origin and
// POST the sealed request there, and falling back to chat would send it to the
// chat endpoint under the wrong pool. Note that the withheld set does NOT fail
// here — sensitiveFieldsFor still answers, over-strippingly, for the same row,
// because the two questions have opposite safe answers: refusing to send is safe,
// refusing to withhold is a leak.
func (r *Router) upstreamURL(ep endpoint.Endpoint) (string, error) {
	if ep.UpstreamPath == "" {
		return "", fmt.Errorf("endpoint row %q (service type %q) has no sealed upstream path",
			ep.Path, ep.ServiceType)
	}
	return r.base + ep.UpstreamPath, nil
}

// routeCandidates is the ranked preview list as a core.Candidates. It holds the
// router (for the per-candidate pubkey fetch and the completions URL) and the
// ordered candidates; Provider materializes one on demand.
type routeCandidates struct {
	router    *Router
	providers []previewProvider
	// upstreamURL is resolved once per Resolve from the request's service type,
	// so every candidate materialized from this list agrees on where the sealed
	// request goes.
	upstreamURL string
}

func (c *routeCandidates) Len() int { return len(c.providers) }

// Provider materializes the i-th candidate into a core.Provider, fetching its
// enc key from the broker (cached). It fails (so core skips to the next
// candidate) if the candidate lacks the endpoint/address the seal + pin need.
func (c *routeCandidates) Provider(ctx context.Context, i int) (core.Provider, error) {
	prov := c.providers[i]
	// Address is the routing pin core sends so the router forwards to exactly this
	// provider; without it the router could re-route to a provider whose key can't
	// open the sealed request. Skip such a candidate rather than pin to nothing.
	// Well-formed, not merely non-empty. This value is the routing pin AND the key
	// for the per-provider limiter below, and it is chosen by the untrusted router:
	// validating it here is what bounds that key space to real addresses instead of
	// letting an adversary grow the map with strings of its own invention.
	if !isAddress(prov.Address) {
		return core.Provider{}, upstream(0, fmt.Errorf(
			"route preview candidate has no usable address (got %q)", prov.Address))
	}
	if prov.Endpoint == "" {
		return core.Provider{}, upstream(0, fmt.Errorf("route preview candidate has no endpoint"))
	}
	// canonical_id is the cleartext model the sealed request must name (each
	// candidate serves its own — the list is heterogeneous when the caller omits
	// "model"). The router contract always provides it; an empty one is a contract
	// violation this client cannot seal a correct request for, so reject it.
	if prov.CanonicalID == "" {
		return core.Provider{}, upstream(0, fmt.Errorf("route preview candidate has no canonical_id"))
	}
	// Obtain the enc key + signer this candidate will be sealed to. With quote
	// verification configured, they come from a DCAP-verified attestation quote
	// (trustworthy even though the untrusted router chose the endpoint). Without
	// it, the legacy path trusts the router-supplied pubkey endpoint — a
	// compromised router could point that at a key it controls and MITM the
	// prompt (the reason quote verification exists).
	var (
		encPub crypto.PublicKey
		signer string
		// verified carries the keys AND the facts the same verification established
		// (measurement verdict, compose hash). It stays zero on the legacy pubkey path,
		// where nothing was verified — which is why that path records no provider
		// identity below.
		verified    quoteResult
		quoteCached bool
		err         error
	)
	if c.router.verifier != nil {
		verified, quoteCached, err = c.router.verifiedProviderCached(ctx, prov.Endpoint)
		encPub, signer = verified.encPub, verified.signer
	} else {
		var pubkeyURL string
		pubkeyURL, err = derivePubkeyURL(prov.Endpoint)
		if err == nil {
			encPub, signer, err = c.router.pubkey(ctx, pubkeyURL)
		} else {
			err = upstream(0, fmt.Errorf("provider endpoint: %w", err))
		}
	}
	if err != nil {
		return core.Provider{}, err
	}
	// Ground the quote-bound signer in the on-chain registry (SPEC §4.4 step 3 /
	// trust-chain hop 5): it must equal this provider's acknowledged
	// teeSignerAddress. This is what distinguishes the *expected* provider from a
	// look-alike enclave running the same audited image (both pass the quote
	// check). Keyed on prov.Address (the provider's on-chain account), whose
	// Address→teeSigner mapping the untrusted router cannot forge.
	onchain := VerdictNotChecked
	// grounded is the on-chain check's error, acted on AFTER the record below rather
	// than where it is produced. A candidate this check REJECTS is still one we
	// verified and reached a verdict about, and returning early would leave an earlier
	// "pass" record standing for up to its TTL while this gateway is actively refusing
	// the provider — the one way this endpoint could state something the gateway no
	// longer believes.
	var grounded error
	if c.router.registry != nil {
		g, err := c.router.groundSignerOnChain(ctx, prov.Address, signer)
		// A mismatch about to cost this candidate its place, decided against a CACHED
		// quote, is the other half of "never reject on stale evidence": a broker
		// upgrade rotates enc_pub and signer together, so our cached pair can name the
		// old enclave while the chain already names the new one. Re-read the quote and
		// ground once more before ruling. Only when the quote was cached — a freshly
		// verified one is already the best evidence available — and reverifiedKeys
		// additionally rate-limits itself, without which this would run a live DCAP
		// verify on EVERY request against a provider that keeps mismatching, since the
		// re-verification refills the very cache entry that gates it.
		//
		// Note this does NOT depend on err: the OUTCOME is what says a recovery is
		// owed, and the verdict mode only changes what the recovery is worth. Under
		// enforce — the shipped configuration — it is the whole difference between "the
		// provider routinely rotated its signer" and a candidate refused outright: err
		// is non-nil here, and re-grounding the fresh quote in the rotated arm below is
		// what clears it. Under warn, err is nil for a mismatch it merely logged and the
		// recovery still matters, because the verdict was never the only thing at stake:
		// the stale quote carries a stale enc_pub too, so without re-verifying, warn
		// mode would go on sealing to an enclave that has rotated and the request would
		// fail at the provider.
		if g.outcome == groundingMismatch && quoteCached {
			fresh, rerr := c.router.reverifiedProvider(ctx, prov.Endpoint)
			// All three arms say something, because a mismatch that survives to the
			// metric is `onchain_grounding_total{outcome="mismatch"}` — the counter the
			// runbook pages on as an accusation against a provider. Unlogged, "the
			// recovery could not run" and "the recovery ran and the accusation stood"
			// reach the operator as the same number, and only the second one is evidence.
			switch {
			case rerr != nil:
				// Throttled, or the quote fetch failed: our side of the call concluded
				// nothing. The mismatch below is the CACHED quote's, never re-checked.
				c.router.logger.Warn("could not re-verify the quote after an on-chain signer mismatch; the mismatch stands on the cached quote",
					"provider", prov.Address, "cached_signer", signer, "err", rerr)
			case fresh.signer != signer:
				c.router.logger.Info("re-verified quote after an on-chain signer mismatch; the cached quote had rotated",
					"provider", prov.Address, "cached_signer", signer, "fresh_signer", fresh.signer)
				// Take the fresh result WHOLE, facts included: they describe the enclave we
				// are now sealing to, and a record built from the rotated-away quote would
				// report the wrong compose hash for the request that actually happened.
				verified = fresh
				encPub, signer = fresh.encPub, fresh.signer
				g, err = c.router.groundSignerOnChain(ctx, prov.Address, signer)
				g.revalidated = true
			default:
				// Live quote, live chain read (groundSignerOnChain revalidates its own
				// cached readings), and they still disagree. This is the one shape of
				// mismatch that is actually an accusation.
				c.router.logger.Warn("re-verified quote after an on-chain signer mismatch; the quote signer had not rotated and the mismatch stands",
					"provider", prov.Address, "signer", signer)
			}
		}
		// Both counters are recorded once, HERE, on the conclusion that actually stood.
		// Recording them inside groundSignerOnChain counted superseded conclusions too:
		// a benign broker rotation would raise a `mismatch` — the metric documented as
		// an accusation worth paging on — and a `negative` revalidation, on its way to
		// resolving cleanly.
		if g.revalidated {
			metrics.OnChainRevalidation(revalidationResult(g.outcome))
		}
		metrics.OnChainGrounding(string(g.outcome))
		// The verdict reported to a panel is the same conclusion these counters record —
		// the one that stood after any recovery — so the two can never tell different
		// stories about one request. See onchainVerdictOf.
		onchain = onchainVerdictOf(g.outcome)
		grounded = err
	}
	// Keep what those checks established, so a verification panel can show this hop
	// instead of a blank (see provideridentity.go). Only on the verified path: with
	// quote verification off there is no verdict to report, and reporting the router's
	// word for it would be worse than reporting nothing.
	if c.router.verifier != nil {
		c.router.recordProviderIdentity(providerIdentityOf(prov.Address, prov.Endpoint, verified, onchain))
	}
	if grounded != nil {
		return core.Provider{}, grounded
	}
	// Two distinct pins, which may differ (so they are NOT cross-checked):
	//   - SignerAddr (broker's signer_address) → sealed into _e2ee.signer_addr,
	//     the crypto pin the provider enclave verifies and that signs responses.
	//   - Address (the router's provider address) → the routing pin core sends as
	//     X-0G-Provider-Address so the router forwards to exactly this provider.
	// Model is the candidate's canonical_id, written into the sealed request's
	// cleartext "model" so it names the model this provider serves (the preview
	// list is heterogeneous when the caller omits "model"). URL is the router's
	// completions endpoint, NOT the provider's: the sealed request goes through the
	// router for auth/billing.
	return core.Provider{
		URL:        c.upstreamURL,
		EncPubKey:  encPub,
		SignerAddr: signer,
		Address:    prov.Address,
		Model:      prov.CanonicalID,
		// The provider's own endpoint (where its enc key / quote were fetched) is
		// also where its §8 response signature is served — the router does not
		// proxy /v1/proxy/signature. Carry it so verification can fetch direct.
		Endpoint: prov.Endpoint,
	}, nil
}

// verifiedKeys is the keys-only form, for the callers that seal but report nothing:
// the direct-broker resolver (which pins no on-chain address, so it has no provider
// identity to record) and tests. It also discards the provenance flag — see
// verifiedProviderCached.
func (r *Router) verifiedKeys(ctx context.Context, endpoint string) (crypto.PublicKey, string, error) {
	res, _, err := r.verifiedProviderCached(ctx, endpoint)
	if err != nil {
		return nil, "", err
	}
	return res.encPub, res.signer, nil
}

// verifiedProviderCached returns the DCAP-verified enc_pub + signer for a candidate
// endpoint, plus the facts the same verification established (see quoteFacts), from
// the cache when fresh and otherwise by verifying its quote. It
// collapses concurrent misses for the same endpoint into ONE verification
// (quote fetch + go-tdx-guest + Intel PCS collateral is expensive and
// rate-limit-sensitive) via singleflight; the rest share the result. Errors are
// not cached, so a transient failure is retried on the next request.
//
// cached reports that the result came from the quote cache rather than a live
// verification, i.e. that it may lag the provider by up to the quote TTL. A
// caller about to REJECT a provider over these keys uses it to decide whether a
// re-verification could change the verdict (see reverifiedProvider).
func (r *Router) verifiedProviderCached(ctx context.Context, endpoint string) (_ quoteResult, cached bool, _ error) {
	// Key the cache + singleflight by the DERIVED quote URL, not the raw endpoint,
	// so different endpoint spellings for the same provider (bare origin, /v1, full
	// chat URL, trailing slash) — and, importantly, the warmer's chain-sourced URL
	// vs a request's router-supplied endpoint — coincide when they name the same
	// host. Deriving up front also fails a malformed endpoint before any lookup.
	quoteURL, err := deriveQuoteURL(endpoint)
	if err != nil {
		return quoteResult{}, false, upstream(0, fmt.Errorf("provider endpoint: %w", err))
	}
	if res, ok := r.quoteCache.get(quoteURL); ok {
		metrics.QuoteCacheLookup(true)
		return res, true, nil
	}
	metrics.QuoteCacheLookup(false)
	res, err := r.verifyAndCache(ctx, quoteURL)
	if err != nil {
		return quoteResult{}, false, err
	}
	return res, false, nil
}

// reverifiedProvider forces a live re-verification of endpoint's quote, for the case
// where a CACHED quote is about to cost a provider its candidacy and the cached
// copy may itself be the thing that is wrong (the rotation story in
// groundSignerOnChain, seen from the quote side).
//
// Quote verification is expensive and rate-limit-sensitive, so this runs only when
// the alternative is rejecting the provider outright, and at most once per quote
// TTL per provider. That limit is load-bearing rather than belt-and-braces: "the
// quote came from the cache" reads like a bound on its own, but re-verifying
// REFILLS that entry, so the next request is a cache hit again and a provider that
// keeps mismatching would force a live fetch plus DCAP verify on every request.
func (r *Router) reverifiedProvider(ctx context.Context, endpoint string) (quoteResult, error) {
	quoteURL, err := deriveQuoteURL(endpoint)
	if err != nil {
		return quoteResult{}, upstream(0, fmt.Errorf("provider endpoint: %w", err))
	}
	if !r.mayReverifyQuote(quoteURL) {
		return quoteResult{}, upstream(0, fmt.Errorf("quote re-verification for %s throttled", quoteURL))
	}
	res, err := r.verifyAndCache(ctx, quoteURL)
	if err != nil {
		// The attempt concluded nothing about the provider — the quote endpoint or the
		// collateral fetch failed, which is our side of the call. Holding the full TTL
		// would reject a possibly-rotated provider for minutes over a transient fault,
		// so allow another attempt shortly instead.
		r.quoteReverify.reschedule(quoteURL, reverifyFailureBackoff)
		return quoteResult{}, err
	}
	return res, nil
}

// mayReverifyQuote reports whether a recovery re-verification for quoteURL is due,
// and stamps it when it is. One per quote TTL: long enough that a mismatching
// provider cannot turn the recovery path into a per-request DCAP verify, short
// enough that a genuine rotation is picked up on the same schedule an ordinary
// cache refresh would have picked it up.
func (r *Router) mayReverifyQuote(quoteURL string) bool {
	window := r.quoteCache.ttl
	if window <= 0 {
		window = defaultQuoteTTL
	}
	return r.quoteReverify.allow(quoteURL, window)
}

// verifyAndCache runs (or joins, via singleflight) the verification for quoteURL
// and caches a success. It does NOT consult the cache first — that is the
// caller's choice (verifiedKeys reads cache-first; the warmer forces a refresh).
//
// The shared verification runs under a context DETACHED from the caller that
// happened to lead (context.WithoutCancel keeps its values, drops its
// cancellation), so one caller disconnecting or timing out cannot fail the
// verification for the others coalesced onto it; it is still bounded by
// quoteVerifyTimeout so a hung upstream can't leak the in-flight call. Each
// caller waits via DoChan and honors ITS OWN context — a caller whose request is
// canceled returns immediately without dooming the rest.
func (r *Router) verifyAndCache(ctx context.Context, quoteURL string) (quoteResult, error) {
	ch := r.quoteSF.DoChan(quoteURL, func() (any, error) {
		vctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), quoteVerifyTimeout)
		defer cancel()
		res, err := r.verifyQuoteAt(vctx, quoteURL)
		if err != nil {
			return nil, err
		}
		r.quoteCache.put(quoteURL, res)
		return res, nil
	})
	select {
	case <-ctx.Done():
		return quoteResult{}, upstream(0, fmt.Errorf("provider quote verification: %w", ctx.Err()))
	case res := <-ch:
		if res.Err != nil {
			return quoteResult{}, res.Err
		}
		return res.Val.(quoteResult), nil
	}
}

// verifyQuoteAt is the uncached work behind verifiedProvider: fetch the attestation
// quote from quoteURL and DCAP-verify it, returning the enc_pub + signer bound
// into the verified report_data, plus the facts the same verification established
// (see quoteFacts). Because the keys come out of a genuine, signed
// quote, it does not matter that the untrusted router chose the endpoint: a
// substituted endpoint serving an attacker key would fail verification. On a
// warn-mode measurement miss it logs but still returns the (genuine) keys.
func (r *Router) verifyQuoteAt(ctx context.Context, quoteURL string) (res quoteResult, err error) {
	// Meter the actually-performed verification (this runs only on a cache miss)
	// and its latency, so the histogram measures the expensive path — quote fetch
	// + go-tdx-guest signature/TCB checks + any collateral fetch — that the warmer
	// and the quote cache exist to keep off the request path.
	start := time.Now()
	defer func() { metrics.QuoteVerification(err == nil, time.Since(start)) }()

	raw, appCompose, err := r.fetchQuote(ctx, quoteURL)
	if err != nil {
		return quoteResult{}, err
	}
	verified, err := r.verifier.Verify(raw)
	if err != nil {
		return quoteResult{}, upstream(0, fmt.Errorf("provider quote: %w", err))
	}
	if !verified.MeasurementTrusted {
		metrics.MeasurementUntrusted()
		// All three registers the allowlist compares, not MRTD alone: an operator
		// reading this line is looking at the only place the observed boot chain
		// appears, so it should carry enough to record an entry rather than enough to
		// know one is missing. RTMR3/RTMR0 are deliberately absent — see
		// attest.BootChain.
		bc := attest.BootChainOf(verified.Measurement)
		r.logger.Warn("sealing to provider whose boot chain is not in the allowlist (attest warn mode)",
			"quote_url", quoteURL,
			"mrtd", fmt.Sprintf("%x", bc.MRTD[:]),
			"rtmr1", fmt.Sprintf("%x", bc.RTMR1[:]),
			"rtmr2", fmt.Sprintf("%x", bc.RTMR2[:]),
			"signer_addr", verified.SignerAddr)
	}
	composeHash, haveHash := composeHashOf(raw, verified, r.logger)
	facts := quoteFacts{
		measurement: r.measurementVerdict(verified),
		// The verifier reports which audited image matched, so the record can name it
		// instead of leaving a panel with a bare "pass". Empty unless the boot chain was
		// allowlisted AND the entry carried a label, which is exactly when there is an
		// image to name — see attest.Verified.MeasurementImage.
		osImage: verified.MeasurementImage,
	}
	if haveHash {
		facts.composeHash = hex.EncodeToString(composeHash[:])
		facts.containers = r.containersOf(appCompose, composeHash, quoteURL)
	}
	return quoteResult{
		encPub: verified.EncPub,
		signer: verified.SignerAddr,
		facts:  facts,
	}, nil
}

// containersOf turns the reply's unauthenticated app-compose into the container
// list behind it — but only after the hash gate.
//
// The whole security argument is one line of it: evidence.VerifyAppCompose accepts
// the bytes only when sha256 over them equals composeHash, which came out of the
// quote the verifier just authenticated. Before that the text is whatever the
// provider (or anyone on the path) chose to send; after it, it is the manifest the
// enclave actually booted. There is no partial credit — a mismatch returns nothing
// rather than a "probably right" list.
//
// Everything past the gate is re-reading pinned bytes, so nothing here can make a
// deployment more or less trustworthy — only its display right or wrong. Which is
// why every failure yields nil and a debug line instead of failing the request: a
// provider is not less usable because we could not draw its container list.
func (r *Router) containersOf(appCompose []byte, composeHash [attest.ComposeHashLen]byte, quoteURL string) []compose.Service {
	if len(appCompose) == 0 {
		// fetchQuote already logged why there is none; saying it twice per verification
		// would only make the real lines harder to find.
		return nil
	}
	ac, err := evidence.VerifyAppCompose(appCompose, composeHash)
	if err != nil {
		// VerifyAppCompose fails for three different reasons and only one of them is a
		// security signal, so they must not share a line. A digest mismatch means the
		// reply carried an app-compose that is not the one its own quote commits to —
		// benign explanations exist (a reply assembled from another instance), but so
		// does a substitution attempt, and this is the one place either would show.
		//
		// The other two — authenticated bytes that are not JSON, or that carry no
		// docker_compose_file — are past the gate. Logging those as a mismatch would be
		// false, and would hand an operator a standing security alert every cache miss
		// for a provider whose runner simply is not docker-compose.
		if sha256.Sum256(appCompose) != composeHash {
			r.logger.Warn("provider app-compose does not match the compose_hash its quote binds; reporting no containers",
				"quote_url", quoteURL, "err", err)
		} else {
			r.logger.Debug("provider app-compose is authenticated but carries no readable compose text; reporting no containers",
				"quote_url", quoteURL, "err", err)
		}
		return nil
	}
	services, err := compose.ParseServices([]byte(ac.DockerComposeFile))
	if err != nil {
		r.logger.Debug("provider compose text does not parse, reporting no containers",
			"quote_url", quoteURL, "err", err)
		return nil
	}
	return services
}

// measurementVerdict turns the boot-chain outcome into the three-state verdict a
// reader can act on. MeasurementTrusted alone cannot: it is false both for an
// enclave running an image we have not audited and for a deployment that has
// audited none, and those must never be shown as the same thing (see
// attest.Verifier.MeasurementBaselineConfigured).
//
// VerdictNoBaseline is reached only by a build whose embedded allowlist
// (client/evidence/brokerimages.json) has no entries, and saying exactly that is the
// point: the panel marks the hop "observed only" rather than implying either a pass or
// a finding.
func (r *Router) measurementVerdict(verified attest.Verified) Verdict {
	switch {
	case verified.MeasurementTrusted:
		return VerdictPass
	case r.verifier.MeasurementBaselineConfigured():
		return VerdictNoMatch
	default:
		return VerdictNoBaseline
	}
}

// composeHashOf reads the dstack compose hash — which application configuration the
// provider enclave booted — out of the quote's mr_config_id, or returns "" when the
// register's layout does not expose one (V2/V3 commit to it inside a digest).
//
// The register comes from a STRUCTURAL re-parse of the same bytes the verifier just
// authenticated, which is what makes the value trustworthy: mr_config_id sits inside
// the signed TD report, so the signature check that produced `verified` covers it.
// The measurement equality guard is what holds that argument together — it confirms
// the offsets this parse reads describe the same TD the verifier saw. If a future
// quote layout moved them, the mismatch reports nothing rather than a field lifted
// from bytes no one checked.
//
// With the wired parser the guard is trivially satisfied: client/dcap verifies the
// signature and then extracts through this same KAT-pinned function, so both sides
// read one parse of one buffer (the re-parse costs a 632-byte copy on a cache miss).
// It earns its place against a parser that derives the measurement some other way —
// a fake in a test, a future decoder — where "the bytes I read describe the TD you
// verified" stops being self-evident.
//
// This exists here, rather than on attest.Verified, because the quoteParser seam
// does not surface mr_config_id (see attest.Verify's step-2 note). Reading it from
// the verified bytes is the same thing the gateway does for its own quote, and it
// avoids widening a protocol-level interface that every participant depends on.
// It returns the hash itself rather than its hex spelling because two callers need
// different things from it: the identity record reports hex, and the container
// lookup compares raw bytes against sha256 of the app-compose. Hexing and re-parsing
// between the two would be a lossy round trip in the one place that must not have
// one.
func composeHashOf(raw []byte, verified attest.Verified, logger *slog.Logger) (hash [attest.ComposeHashLen]byte, ok bool) {
	body, err := attest.ParseTDXQuoteBody(raw)
	if err != nil {
		logger.Debug("provider quote: cannot structurally re-parse a verified quote, reporting no compose_hash", "err", err)
		return hash, false
	}
	if body.Measurement != verified.Measurement {
		logger.Warn("provider quote: structural re-parse disagrees with the verified measurement, reporting no compose_hash")
		return hash, false
	}
	hash, err = attest.ComposeHashFromMRConfigID(body.MRConfigID)
	if err != nil {
		// A V2/V3 (or absent) mr_config_id does not carry the hash in the clear. Nothing
		// is wrong with the quote; there is simply nothing to read.
		logger.Debug("provider quote: mr_config_id does not expose compose_hash", "err", err)
		return hash, false
	}
	return hash, true
}

// groundingOutcome classifies one grounding attempt. The split that matters is
// between the two negatives: a VERDICT is a statement about the provider (the
// chain and the quote disagree, or the chain acknowledges nobody) and is the
// reason enforce mode exists; a lookup failure is a statement about OUR OWN chain
// RPC, and rejecting a provider over it converts our infrastructure's bad day
// into the user's failed request.
type groundingOutcome string

// grounding is what one grounding attempt concluded, plus whether reaching that
// conclusion required a live re-read. The caller needs both: the outcome is what
// gets counted, and the re-read is what the revalidation metric describes — and
// only the caller knows whether a LATER recovery superseded this conclusion.
type grounding struct {
	outcome     groundingOutcome
	revalidated bool
}

const (
	groundingOK              groundingOutcome = "ok"
	groundingOKStale         groundingOutcome = "ok_stale"
	groundingMismatch        groundingOutcome = "mismatch"
	groundingNotAcknowledged groundingOutcome = "not_acknowledged"
	groundingLookupFailed    groundingOutcome = "lookup_failed"
)

// groundSignerOnChain enforces SPEC §4.4 step 3 / trust-chain hop 5: the signer
// bound into the (DCAP-verified) quote must equal the provider's acknowledged
// teeSignerAddress in the on-chain InferenceServing registry.
//
// Enforce mode is fail-closed on every negative: a VERDICT about the provider
// (mismatch or unacknowledged) and equally a failure of the lookup itself, so
// enforce means the chain was actually read rather than merely consulted. The two
// are still counted apart, because they call for different responses: a mismatch is
// a signal about a provider, a lookup failure is a signal about our own chain RPC.
//
// Warn mode is observe-only throughout (log and proceed), mirroring attest warn
// mode for staged rollout.
//
// A negative is never returned on stale evidence: see revalidate.
func (r *Router) groundSignerOnChain(ctx context.Context, providerAddr, signer string) (grounding, error) {
	got, err := r.registry.AcknowledgedSigner(ctx, providerAddr)
	if err != nil {
		return r.onchainLookupFailed(providerAddr, err)
	}
	// A negative computed from a CACHED reading is not a verdict — and "cached"
	// means any cache hit, not only a stale one. A within-TTL entry can still be
	// minutes old, and a broker upgrade rotates the signer, so an entry that
	// disagrees with a freshly quoted signer is the expected shape of a benign
	// rollout whether or not its TTL happens to have lapsed. Ruling on either would
	// reject a healthy provider for as long as the entry lives. Get fresh evidence
	// before saying no; the rate limit keeps a provider that keeps disagreeing from
	// turning that into a chain RPC per request.
	revalidated := false
	// chain.ProviderKey, not providerAddr: this address comes from the untrusted
	// router, and every comparison on it elsewhere is case-insensitive. Keying the
	// limiter on the raw spelling made "the same provider, differently capitalized" a
	// fresh key with a fresh allowance — so the rate limit, whose whole job is to stop
	// a disagreeing provider costing us a chain RPC per request, could be stepped
	// around by the party choosing the spelling. Bound to ONE variable used by both
	// the read and the write below: keying them differently is not a weaker limit but
	// a broken one, since the backoff would land where nothing reads it.
	key := chain.ProviderKey(providerAddr)
	if got.Cached && !signerAgrees(got, signer) &&
		r.signerRevalidate.allow(key, signerRevalidateWindow) {
		revalidated = true
		got, err = r.revalidate(ctx, providerAddr, signer)
		if err != nil {
			// Symmetric with the quote side: the re-read concluded nothing about the
			// provider, so holding the full window would spend it on our own RPC's bad
			// second. Without this, a rotation that coincides with one blip is judged a
			// mismatch for the rest of the window even after the chain recovers — the
			// cached entry still disagrees, and nothing is allowed to go look again.
			// That files our problem under the metric documented as an accusation.
			r.signerRevalidate.reschedule(key, reverifyFailureBackoff)
			res, ferr := r.onchainLookupFailed(providerAddr, err)
			res.revalidated = true
			return res, ferr
		}
	}
	switch {
	case !got.Acknowledged:
		return r.onchainVerdict(groundingNotAcknowledged, revalidated,
			fmt.Sprintf("provider %s has no acknowledged on-chain TEE signer", providerAddr))
	case !signerAgrees(got, signer):
		return r.onchainVerdict(groundingMismatch, revalidated, fmt.Sprintf(
			"quote signer %s does not match on-chain teeSignerAddress %s for provider %s",
			signer, got.Address, providerAddr))
	}
	outcome := groundingOK
	if got.Stale {
		// A match confirmed against a stale entry still stands — staleness is only
		// disqualifying for a negative — but it is worth counting separately, since a
		// sustained ok_stale rate means the chain RPC has been unreachable for longer
		// than the cache TTL and the grace window is carrying the deployment.
		outcome = groundingOKStale
	}
	return grounding{outcome: outcome, revalidated: revalidated}, nil
}

// revalidate re-reads the signer live, bypassing the cache and its grace window,
// and reports what the fresh evidence says. Only the freshly read value is
// returned: acting on the stale one after going to the trouble of refuting it
// would defeat the point.
func (r *Router) revalidate(ctx context.Context, providerAddr, signer string) (chain.Signer, error) {
	fresh, err := r.registry.RefreshSigner(ctx, providerAddr)
	if err != nil {
		// Not counted here either — the rule below is unconditional, and this branch
		// used to break it, double-counting every failed re-read. The caller reports
		// this as a lookup_failed revalidation like any other outcome.
		return chain.Signer{}, err
	}
	if signerAgrees(fresh, signer) {
		r.logger.Info("on-chain signer disagreed when cached but agrees when read live; treating as a rotation, not a mismatch",
			"provider", providerAddr, "signer", signer)
	}
	// Deliberately not counted here. This re-read may yet be superseded — when the
	// QUOTE was the stale side, the caller re-verifies it and grounds again, and a
	// count taken now would file that benign rotation as a surviving disagreement.
	// The caller records one revalidation, with the outcome that stood.
	return fresh, nil
}

// revalidationResult labels a revalidation by what the fresh evidence concluded,
// so the quote-side recovery and the chain-side one report in the same vocabulary.
// It keys off the OUTCOME, not the returned error: warn mode returns nil for a
// mismatch it merely logged, so an error-based reading would file a surviving
// disagreement as a clean recovery.
func revalidationResult(outcome groundingOutcome) string {
	switch outcome {
	case groundingOK, groundingOKStale:
		return "ok"
	case groundingLookupFailed:
		return "lookup_failed"
	default:
		return "negative"
	}
}

// signerAgrees reports whether an on-chain reading positively vouches for the
// quote-bound signer. Anything less — unacknowledged, or a different address — is
// a negative, so a caller can test "is this good?" without spelling out each way
// it could be bad.
func signerAgrees(onchain chain.Signer, signer string) bool {
	return onchain.Acknowledged &&
		strings.EqualFold(strings.TrimSpace(onchain.Address), strings.TrimSpace(signer))
}

// onchainVerdict handles a negative that IS about the provider: fail-closed under
// enforce, observe-only under warn.
func (r *Router) onchainVerdict(outcome groundingOutcome, revalidated bool, msg string) (grounding, error) {
	g := grounding{outcome: outcome, revalidated: revalidated}
	if r.onchainEnforce {
		return g, upstream(0, errors.New(msg))
	}
	r.logger.Warn("on-chain signer check failed; proceeding (onchain warn mode)", "detail", msg)
	return g, nil
}

// onchainLookupFailed handles a negative that is about our own chain RPC rather
// than the provider: fail-closed under enforce (an unread chain is not a pass),
// observe-only under warn like every other outcome.
//
// Either way the outcome is reported as lookup_failed rather than as a verdict, so
// a chain-RPC problem never shows up in the metrics as a provider accusation. That
// distinction is the whole point of keeping this separate from onchainVerdict — it
// buys attribution, not leniency, and the two need different alerts and different
// fixes.
func (r *Router) onchainLookupFailed(providerAddr string, cause error) (grounding, error) {
	g := grounding{outcome: groundingLookupFailed}
	msg := fmt.Sprintf("on-chain signer lookup for provider %s failed", providerAddr)
	if r.onchainEnforce {
		return g, upstream(0, fmt.Errorf("%s: %w", msg, cause))
	}
	r.logger.Warn("on-chain signer lookup failed; proceeding with the signer unchecked (onchain warn mode)",
		"detail", msg, "err", cause)
	return g, nil
}

// fetchQuote GETs and decodes a provider's /v1/quote reply.
//
// It returns two things with very different standing. `raw` is the TDX quote the
// caller is about to verify. `appCompose` is the app-compose text the same reply
// carries in its unsigned `tcb_info` — worth nothing until it is hashed against
// the verified quote's compose_hash (attest.AppComposeFromQuoteResponse says why),
// which containersOf does and nothing else may skip.
//
// A reply carrying no app-compose is not an error: `appCompose` comes back nil and
// the container list is simply absent. Only the quote is load-bearing here.
func (r *Router) fetchQuote(ctx context.Context, quoteURL string) (raw, appCompose []byte, err error) {
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, quoteURL, nil)
	if err != nil {
		return nil, nil, upstream(0, err)
	}
	resp, err := r.http.Do(httpReq)
	if err != nil {
		return nil, nil, upstream(0, fmt.Errorf("fetch provider quote: %w", err))
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxControlBodyBytes))
	if err != nil {
		return nil, nil, upstream(0, fmt.Errorf("read provider quote: %w", err))
	}
	if resp.StatusCode != http.StatusOK {
		return nil, nil, upstreamBody(resp.StatusCode, body, fmt.Errorf("provider quote returned %d", resp.StatusCode))
	}
	raw, err = attest.DecodeQuoteResponse(body)
	if err != nil {
		return nil, nil, upstream(0, err)
	}
	appCompose, acErr := attest.AppComposeFromQuoteResponse(body)
	if acErr != nil {
		// Never fatal: this half feeds a display, and the quote — the half that decides
		// whether we seal at all — parsed fine.
		//
		// Both branches log, at Debug, and the absent one is the reason why. A provider
		// serving `public_tcbinfo: false` legitimately omits it, and a container list
		// that is permanently null looks identical to a bug on our side; without a line
		// here an operator has no way to tell "that provider does not publish it" from
		// "we stopped reading it". The 0G broker does publish it — its app-compose sets
		// public_tcbinfo true and its /v1/quote carries app_compose today — so on this
		// fleet the absent branch firing is itself the signal.
		if errors.Is(acErr, attest.ErrNoAppCompose) {
			r.logger.Debug("provider quote reply carries no app_compose (public_tcbinfo off?); reporting no containers",
				"quote_url", quoteURL)
		} else {
			r.logger.Debug("provider quote reply: cannot read app_compose, reporting no containers",
				"quote_url", quoteURL, "err", acErr)
		}
		appCompose = nil
	}
	return raw, appCompose, nil
}

// attemptTimeout and retryBudget read the pacing pair with the constants as
// defaults, so a zero value means "unset" rather than "instantly expired" / "no
// retries". Mirrors candidateWalk.limit(); the asymmetry between them was one
// direct-construction away from being live.
func (r *Router) attemptTimeout() time.Duration {
	if r.previewAttemptTO > 0 {
		return r.previewAttemptTO
	}
	return previewAttemptTimeout
}

func (r *Router) retryBudget() time.Duration {
	if r.previewBudgetTO > 0 {
		return r.previewBudgetTO
	}
	return previewRetryBudget
}

// previewResult classifies one preview attempt, so the retry decision and the
// metric label come from ONE judgement rather than a bool and a string that can
// drift apart.
//
// The split that matters is rejected vs broken. Both are terminal, but only one is
// about the router being unwell: a 401 from a tenant with a misconfigured key, or
// an empty candidate list because the fleet has nobody for that model, is the
// router ANSWERING — correctly, from its point of view. Folding those into the
// same bucket as "we could not get a usable answer" makes any alert on preview
// health pinnable by a single misconfigured caller.
type previewResult string

const (
	// previewOK: a usable candidate list.
	previewOK previewResult = "ok"
	// previewRetryable: no answer yet — a transport failure, a body that dropped
	// mid-read, or a 5xx. Another attempt may get one.
	previewRetryable previewResult = "retryable"
	// previewRejected: the router answered definitively and negatively — a 4xx or
	// 429, or a well-formed reply with no candidates. Retrying cannot change it,
	// and it is usually about the caller or the fleet, not about the router.
	previewRejected previewResult = "rejected"
	// previewBroken: the router answered with something unusable (a body that will
	// not decode). Terminal like rejected, but this one IS the router misbehaving.
	previewBroken previewResult = "broken"
	// previewCanceled: the caller went away mid-attempt. Says nothing about the
	// router, so it is kept out of every failure bucket.
	previewCanceled previewResult = "canceled"
	// previewInternal: a fault in THIS process — a request we could not even build.
	// Its own bucket for the same reason the data plane has one: our bug must not
	// point a runbook at the router.
	previewInternal previewResult = "internal"
)

// callOutcome maps the attempt result that ENDED a preview onto the call-level
// outcome. Only "no usable answer" becomes failed; a definitive negative travels
// through as rejected so the two can be alerted on differently.
func (r previewResult) callOutcome() string {
	switch r {
	case previewRejected:
		return "rejected"
	case previewCanceled:
		return "canceled"
	case previewInternal:
		return "internal"
	default:
		return "failed"
	}
}

// previewProvider is one candidate in the route-preview reply.
type previewProvider struct {
	Address     string `json:"address"`
	CanonicalID string `json:"canonical_id"`
	Endpoint    string `json:"endpoint"`
	ModelID     string `json:"model_id"`
}

// previewResponse is the route-preview reply. ServiceType echoes the requested
// service_type; there is no top-level model because the candidate list is
// heterogeneous when the caller omits "model" (each candidate carries its own).
type previewResponse struct {
	Object      string            `json:"object"`
	ServiceType string            `json:"service_type"`
	Providers   []previewProvider `json:"providers"`
}

// preview asks the router to rank providers for req and returns the full ordered
// candidate list (the router's provider-retry budget — the fallback chain). It
// sends the routing-relevant fields (the request minus the sealed fields) plus
// the surface's service_type and api_format, forwarding the caller's credential
// and X-0G-* directives so the router authenticates/bills and steers exactly as
// it would for the sealed request. "model" is optional and passes through when
// present (it is not a sealed field): present → candidates are that model's
// providers; omitted → candidates are any provider of the service type.
//
// A transient failure is retried (see previewAttempts and previewRetryBudget for
// the policy and its sizing); a definitive one is returned on the first attempt,
// so a caller's 401 or 404 is never delayed by a retry that cannot change it.
func (r *Router) preview(ctx context.Context, ep endpoint.Endpoint, req wire.Request) ([]previewProvider, error) {
	withheld := r.withheldFor(ep)
	payload := make(map[string]json.RawMessage, len(req)+2)
	for k, v := range req {
		if _, sensitive := withheld[k]; sensitive {
			continue
		}
		payload[k] = v
	}
	// Force the service type of THIS request; a chat body carries no service_type
	// of its own, and the router needs it to route.
	serviceTypeJSON, _ := json.Marshal(ep.ServiceType)
	payload["service_type"] = serviceTypeJSON
	// api_format selects the SURFACE within that service type, for the one service
	// type that has two: `chatbot` answers /v1/chat/completions and /v1/messages,
	// and only this field tells the router which pool to rank. Without it an
	// Anthropic request previews as OpenAI chat and can be pinned to a provider
	// that does not serve /v1/messages at all.
	//
	// The ROW decides it, exactly as it decides service_type above, and a value in
	// the request body is DROPPED rather than forwarded. That deletion is the
	// load-bearing half: everything not withheld is copied into this payload, so
	// before it a caller could put `"api_format": "anthropic"` in an ordinary
	// /v1/chat/completions body and have it reach preview — narrowing the pool to
	// providers that serve only /v1/messages while the request was sealed under the
	// chat profile and POSTed to /v1/chat/completions. On an image request the same
	// field is worse: the router refuses a surface on a non-chat service type, so
	// the preview 400s and the request fails outright. Passing unknown body fields
	// through is fine — the router ignores them — but this one it now acts on, so
	// it is ours to state and not the caller's to influence.
	//
	// Sent only when the row names one. An omitted api_format and "openai" mean
	// the same thing upstream — neither narrows, because OpenAI is the default
	// surface every chat provider answers and many do not enumerate it in
	// `api_formats` — so sending it for chat would add a field that cannot change
	// the answer.
	if ep.APIFormat != "" {
		apiFormatJSON, _ := json.Marshal(ep.APIFormat)
		payload["api_format"] = apiFormatJSON
	} else {
		delete(payload, "api_format")
	}

	// One call-level observation on EVERY exit path, recorded by a defer rather than
	// at each return so the counter cannot drift from the control flow as this loop
	// grows. "failed" is the honest default: it is what falling out of the loop
	// means, and every better outcome overwrites it before returning.
	//
	// Installed before the marshal below, which used to return ahead of it — the one
	// exit that recorded nothing at all, and the one that most obviously belongs in
	// the internal bucket.
	start := time.Now()
	outcome := "failed"
	defer func() { metrics.PreviewCall(outcome, time.Since(start)) }()

	// Marshal once, outside the retry loop: the body is identical on every attempt
	// (each attempt wraps these bytes in its own reader), and a marshal failure is a
	// fault in the request we were handed, not something an attempt could clear.
	body, err := json.Marshal(payload)
	if err != nil {
		outcome = previewInternal.callOutcome()
		return nil, upstream(0, fmt.Errorf("marshal preview request: %w", err))
	}

	backoff := previewRetryBackoff
	var lastErr error
	for attempt := 0; attempt < previewAttempts; attempt++ {
		if attempt > 0 {
			// Stop when the next backoff would carry this preview past its budget, and
			// surface the failure we already have rather than a budget message: the
			// caller wants to know what the router did, not how we paced our retries.
			if time.Since(start)+backoff >= r.retryBudget() {
				break
			}
			// Retries are off while the router is failing everything: the first attempt
			// above already happened, so the caller loses nothing but the amplification.
			if !r.previewRetries.allow() {
				// Count the retries NOT made, not the calls that lost them: the whole
				// point of the number is how much amplification was shed, and one Inc()
				// per call under-reported that by up to previewAttempts-1.
				metrics.PreviewRetrySuppressed(previewAttempts - attempt)
				break
			}
			t := time.NewTimer(backoff)
			select {
			case <-ctx.Done():
				t.Stop()
				outcome = "canceled"
				return nil, upstream(0, fmt.Errorf("route preview: %w (last error: %v)", ctx.Err(), lastErr))
			case <-t.C:
			}
			backoff *= 2
		}
		providers, res, err := r.previewOnce(ctx, body, req)
		if err == nil {
			metrics.PreviewAttempt(string(res))
			r.previewRetries.answered()
			// A success that NEEDED a retry gets its own outcome. It is the series that
			// shows the retries earning their keep — and the one that stops a degrading
			// router from hiding behind a flat error rate, which is the whole failure
			// mode of adding retries to an uncached dependency.
			outcome = "ok"
			if attempt > 0 {
				outcome = "ok_retried"
			}
			return providers, nil
		}
		// Only a RETRYABLE failure may be re-attributed to the caller, and the test is
		// an allowlist for the same reason verifyOutcome's is: written as "anything
		// when ctx is done" it also relabelled previewBroken — the router answering
		// with a body that will not decode, which the constant defines as the router
		// misbehaving — and previewInternal, our own fault. Both would have landed in
		// canceled, the one bucket every alert deliberately ignores. Reachable, too:
		// the caller need only go away after the body was read.
		//
		// A caller that has given up is attributed to itself, not to the router — the
		// same distinction chain.noteFailure draws before stamping a cooldown.
		if res == previewRetryable && ctx.Err() != nil {
			res = previewCanceled
		}
		metrics.PreviewAttempt(string(res))
		lastErr = err
		if res != previewRetryable {
			// Does not touch the retry gate: only a preview that SUCCEEDED reopens it
			// (retryGate.answered explains why a definitive reply does not).
			outcome = res.callOutcome()
			return nil, err
		}
	}
	// Out of attempts (or out of budget, or out of retry allowance) with only
	// retryable failures behind us: we never got a usable answer, which is the one
	// shape that is squarely the router's — and the one the gate counts.
	r.previewRetries.noAnswer()
	return nil, lastErr
}

// previewOnce performs a single route-preview POST with the already-marshaled
// body, returning the ranked candidate list. req is used only to describe what was
// previewed in the "no provider available" error.
//
// The returned previewResult drives both the retry decision and the metric label.
// previewRetryable is worth another attempt: a transport failure (the request may
// never have arrived), a body that dropped mid-read (nothing was decoded yet), or
// a 5xx (the router faulted, and may not next time). Everything else is terminal:
//   - 429 is the router's own per-account rate limiter. Note this deliberately
//     differs from the data plane's retryableStatus, where a 429 means "try a
//     different provider" — here there is only the one router, so another attempt
//     spends more of the caller's allowance to be told the same thing, and the
//     caller is better served by seeing the status and its Retry-After.
//   - any other 4xx is a client fault (auth, bad request, unknown model) that
//     recurs identically. Both are previewRejected: the router answered.
//   - an empty candidate list is also the router answering — negatively, about
//     the fleet — so it is previewRejected too, not a failure to reach it.
//   - a body that will not decode is previewBroken: an answer, but an unusable
//     one, and unlike the others it is the router itself misbehaving.
//
// The attempt runs under its own previewAttemptTimeout, which is what bounds it:
// the shared client caps only the wait for headers, so without this a slow body
// would leave the attempt (and the retry ceiling built on it) unbounded.
func (r *Router) previewOnce(ctx context.Context, body []byte, req wire.Request) ([]previewProvider, previewResult, error) {
	ctx, cancel := context.WithTimeout(ctx, r.attemptTimeout())
	defer cancel()

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, r.previewURL, bytes.NewReader(body))
	if err != nil {
		// Reachable only for a previewURL this process built wrong — our own
		// configuration, not the router misbehaving. (The gateway parses -router-url at
		// startup and exits, so this is near-unreachable; label it honestly anyway,
		// because "broken" sends a runbook at the router.)
		return nil, previewInternal, upstream(0, err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	// Forward routing directives first, then the credential, so the credential
	// always wins over anything forwarded (mirrors core.doRequest).
	for k, vs := range core.ForwardedHeadersFrom(ctx) {
		for _, v := range vs {
			httpReq.Header.Add(k, v)
		}
	}
	if cred := core.CredentialFrom(ctx); cred != "" {
		httpReq.Header.Set("Authorization", cred)
	}

	resp, err := r.http.Do(httpReq)
	if err != nil {
		return nil, previewRetryable, upstream(0, fmt.Errorf("route preview request: %w", err))
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxControlBodyBytes))
	if err != nil {
		return nil, previewRetryable, upstream(0, fmt.Errorf("read route preview response: %w", err))
	}
	if resp.StatusCode != http.StatusOK {
		// Surface the router's status verbatim (401/404/503 are meaningful) and carry
		// its body as Error.Body; the proxy decides whether to pass the router's
		// client-facing error through (sidecar / structured passthrough) or withhold
		// it (see openaiproxy.errorEnvelope).
		return nil, previewStatusResult(resp.StatusCode),
			upstreamBody(resp.StatusCode, raw, fmt.Errorf("route preview returned %d", resp.StatusCode))
	}

	var pr previewResponse
	if err := json.Unmarshal(raw, &pr); err != nil {
		return nil, previewBroken, upstream(0, fmt.Errorf("decode route preview response: %w", err))
	}
	if len(pr.Providers) == 0 {
		return nil, previewRejected, upstream(http.StatusServiceUnavailable, fmt.Errorf("no provider available for %s", modelDesc(req)))
	}
	// The router returns candidates ranked best-first; core pins the head and
	// falls back down the rest (SPEC §4.4). Per-candidate validation is deferred
	// to routeCandidates.Provider so a single malformed candidate is skipped, not
	// fatal to the whole list. Trimmed to maxPreviewCandidates so the length of the
	// walk is ours rather than the router's.
	if len(pr.Providers) > maxPreviewCandidates {
		pr.Providers = pr.Providers[:maxPreviewCandidates]
	}
	return pr.Providers, previewOK, nil
}

// previewStatusResult classifies a non-200 route-preview status. Only a 5xx is
// worth another attempt; everything else is the router answering (see previewOnce
// for why 429 is not retried here even though the data plane retries it).
func previewStatusResult(status int) previewResult {
	if status >= 500 && status <= 599 {
		return previewRetryable
	}
	return previewRejected
}

// pubkeyResponse is the broker's /v1/e2ee/pubkey reply.
type pubkeyResponse struct {
	V             int    `json:"v"`
	KEMID         string `json:"kem_id"`
	EncPub        string `json:"enc_pub"`
	KeyID         string `json:"key_id"`
	SignerAddress string `json:"signer_address"`
}

// pubkey returns the provider's HPKE recipient key and signer address, from the
// cache when fresh or fetched from the broker's e2ee pubkey API.
func (r *Router) pubkey(ctx context.Context, pubkeyURL string) (crypto.PublicKey, string, error) {
	if encPub, signer, ok := r.cache.get(pubkeyURL); ok {
		return encPub, signer, nil
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, pubkeyURL, nil)
	if err != nil {
		return nil, "", upstream(0, err)
	}
	resp, err := r.http.Do(httpReq)
	if err != nil {
		return nil, "", upstream(0, fmt.Errorf("fetch provider pubkey: %w", err))
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxControlBodyBytes))
	if err != nil {
		return nil, "", upstream(0, fmt.Errorf("read provider pubkey: %w", err))
	}
	if resp.StatusCode != http.StatusOK {
		return nil, "", upstreamBody(resp.StatusCode, raw, fmt.Errorf("provider pubkey returned %d", resp.StatusCode))
	}

	var pk pubkeyResponse
	if err := json.Unmarshal(raw, &pk); err != nil {
		return nil, "", upstream(0, fmt.Errorf("decode provider pubkey: %w", err))
	}
	encPub, signer, err := validatePubkey(pk)
	if err != nil {
		return nil, "", upstream(0, err)
	}
	r.cache.put(pubkeyURL, encPub, signer)
	return encPub, signer, nil
}

// validatePubkey checks the broker's reply is one this client can seal to and
// returns the decoded enc key and signer address.
func validatePubkey(pk pubkeyResponse) (crypto.PublicKey, string, error) {
	// A mismatched version/KEM means the provider expects a different suite than
	// wire seals with, so a sealed request could never be opened — reject early.
	if pk.V != 0 && pk.V != wire.Version {
		return nil, "", fmt.Errorf("provider pubkey version %d unsupported (want %d)", pk.V, wire.Version)
	}
	if pk.KEMID != "" && pk.KEMID != wire.KEMID {
		return nil, "", fmt.Errorf("provider kem_id %q unsupported (want %q)", pk.KEMID, wire.KEMID)
	}
	encPub, err := b64.DecodeString(pk.EncPub)
	if err != nil {
		return nil, "", fmt.Errorf("bad enc_pub: %w", err)
	}
	if len(encPub) != x25519PubLen {
		return nil, "", fmt.Errorf("enc_pub must be %d bytes (X25519), got %d", x25519PubLen, len(encPub))
	}
	if !isAddress(pk.SignerAddress) {
		return nil, "", fmt.Errorf("bad signer_address %q (want 0x followed by 40 hex)", pk.SignerAddress)
	}
	return crypto.PublicKey(encPub), pk.SignerAddress, nil
}

// deriveV1Base resolves a provider endpoint to its "scheme://host/…/v1" base.
// The endpoint may be a bare origin (https://host[:port]), the /v1 base, or the
// full chat-completions URL (…/v1/chat/completions); all three resolve to the
// same /v1 base, so the pubkey and quote paths hang off it consistently.
func deriveV1Base(endpoint string) (string, error) {
	u, err := url.Parse(endpoint)
	if err != nil {
		return "", fmt.Errorf("%q is not a valid URL: %w", endpoint, err)
	}
	if u.Scheme == "" || u.Host == "" {
		return "", fmt.Errorf("%q is not an absolute URL", endpoint)
	}
	base := strings.TrimSuffix(u.Path, "/")
	switch {
	case strings.HasSuffix(base, "/chat/completions"):
		base = strings.TrimSuffix(base, "/chat/completions")
	case strings.HasSuffix(base, "/v1"):
		// already the /v1 base — leave as-is
	default:
		base += "/v1"
	}
	// Lower-case the scheme and host: both are case-insensitive per RFC 3986, and
	// this string is a CACHE AND LIMITER KEY. Carrying the router's capitalization
	// through would make one provider several keys — a fresh quote-cache miss and a
	// fresh re-verification allowance per spelling, each costing a DCAP verify.
	return strings.ToLower(u.Scheme) + "://" + strings.ToLower(u.Host) + base, nil
}

// deriveOrigin reduces a provider endpoint to its origin (scheme://host[:port]),
// dropping whatever path spelling the router used. It is the form a panel shows and
// a human recognises; the paths under it are this package's business.
func deriveOrigin(endpoint string) (string, error) {
	u, err := url.Parse(endpoint)
	if err != nil {
		return "", fmt.Errorf("%q is not a valid URL: %w", endpoint, err)
	}
	if u.Scheme == "" || u.Host == "" {
		return "", fmt.Errorf("%q is not an absolute URL", endpoint)
	}
	return u.Scheme + "://" + u.Host, nil
}

// derivePubkeyURL turns a provider endpoint into the broker's e2ee pubkey URL.
func derivePubkeyURL(endpoint string) (string, error) {
	base, err := deriveV1Base(endpoint)
	if err != nil {
		return "", err
	}
	return base + "/e2ee/pubkey", nil
}

// deriveQuoteURL turns a provider endpoint into its DCAP quote URL. legacy=false
// requests the SPEC §4.2 report_data layout (enc_pub‖signer_addr‖version‖reserved),
// the layout attest.ParseReportData decodes.
func deriveQuoteURL(endpoint string) (string, error) {
	base, err := deriveV1Base(endpoint)
	if err != nil {
		return "", err
	}
	return base + "/quote?legacy=false", nil
}

// modelDesc describes what was previewed for a "no provider available" error.
// "model" is optional on this path (matching the execute path): present → the
// message names it; omitted → the preview asked for any provider of the service
// type, so there is no model to name.
func modelDesc(req wire.Request) string {
	raw, ok := req["model"]
	if !ok {
		return "the requested service type"
	}
	var model string
	if err := json.Unmarshal(raw, &model); err != nil || model == "" {
		return "the requested service type"
	}
	return fmt.Sprintf("model %q", model)
}

// upstream wraps err as a StageUpstream *core.Error, carrying status so the
// proxy can surface a meaningful router/broker status (401/404/503) verbatim; a
// status of 0 lets the proxy default it (502).
func upstream(status int, err error) error {
	return &core.Error{Stage: core.StageUpstream, Status: status, Err: err}
}

// upstreamBody is upstream() carrying the raw upstream response body — used for a
// non-2xx control-plane reply (route-preview / pubkey / quote) so the router's or
// broker's own client-facing error travels as core.Error.Body. Like the data
// plane, the body is untrusted content held out of Error() (the proxy decides
// whether to surface it; see openaiproxy).
func upstreamBody(status int, body []byte, err error) error {
	return &core.Error{Stage: core.StageUpstream, Status: status, Err: err, Body: string(body)}
}

// isAddress reports whether s is a 0x-prefixed 20-byte hex address (the on-chain
// signer format, SPEC §4.2). Case-insensitive on the hex body; no EIP-55 check.
func isAddress(s string) bool {
	if len(s) != 42 || s[0] != '0' || s[1] != 'x' {
		return false
	}
	for i := 2; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= '0' && c <= '9', c >= 'a' && c <= 'f', c >= 'A' && c <= 'F':
		default:
			return false
		}
	}
	return true
}

func sliceToSet(ss []string) map[string]struct{} {
	m := make(map[string]struct{}, len(ss))
	for _, s := range ss {
		m[s] = struct{}{}
	}
	return m
}

// pubkeyCache is a small TTL cache of resolved provider keys, keyed by the
// broker's pubkey URL. Safe for concurrent use.
type pubkeyCache struct {
	ttl time.Duration
	mu  sync.Mutex
	m   map[string]pubkeyEntry
}

type pubkeyEntry struct {
	encPub crypto.PublicKey
	signer string
	exp    time.Time
}

func newPubkeyCache(ttl time.Duration) *pubkeyCache {
	return &pubkeyCache{ttl: ttl, m: make(map[string]pubkeyEntry)}
}

func (c *pubkeyCache) get(key string) (crypto.PublicKey, string, bool) {
	if c.ttl <= 0 {
		return nil, "", false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.m[key]
	if !ok || time.Now().After(e.exp) {
		return nil, "", false
	}
	return e.encPub, e.signer, true
}

func (c *pubkeyCache) put(key string, encPub crypto.PublicKey, signer string) {
	if c.ttl <= 0 {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.m[key] = pubkeyEntry{encPub: encPub, signer: signer, exp: time.Now().Add(c.ttl)}
}
