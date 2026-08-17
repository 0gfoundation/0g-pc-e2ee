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
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/0gfoundation/0g-pc-e2ee/client/chain"
	"github.com/0gfoundation/0g-pc-e2ee/client/core"
	"github.com/0gfoundation/0g-pc-e2ee/client/metrics"
	"github.com/0gfoundation/0g-pc-e2ee/protocol/attest"
	"github.com/0gfoundation/0g-pc-e2ee/protocol/crypto"
	"github.com/0gfoundation/0g-pc-e2ee/protocol/wire"
	"golang.org/x/sync/singleflight"
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
	// completionsPath is the router's OpenAI chat-completions endpoint. The sealed
	// request is POSTed here — to the router, not the provider directly — because
	// the router is the centralized auth/billing point; it authenticates, then
	// forwards to the pinned provider (SPEC §4.4).
	completionsPath = "/v1/chat/completions"
	// DefaultServiceType is the service type sent to the preview API for a chat
	// completion. It is the router's internal service-type vocabulary — the same
	// strings GET /v1/service-types returns and GET /v1/providers?service_type=
	// accepts — not the model modality on /v1/models. A chat-completions proxy
	// always previews "chatbot".
	DefaultServiceType = "chatbot"
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
	// quoteVerifyTimeout bounds a single (de-duplicated) quote verification, which
	// runs under a context detached from any one caller (so no caller's
	// cancellation kills the shared work); this caps a hung upstream instead.
	quoteVerifyTimeout = 60 * time.Second
	// x25519PubLen is the byte length of the HPKE (X25519) recipient key.
	x25519PubLen = 32
	// maxControlBodyBytes caps a control-plane response body read (preview /
	// pubkey), guarding against an unbounded response.
	maxControlBodyBytes = 1 << 20 // 1 MiB
)

// Router resolves the provider for each request via the route-preview + pubkey
// APIs. It is safe for concurrent use.
type Router struct {
	previewURL      string
	completionsURL  string
	providersURL    string
	serviceType     string
	sensitiveFields map[string]struct{}
	http            *http.Client
	cache           *pubkeyCache
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
	// onchainRequireLookup makes enforce mode fail-closed on a registry LOOKUP
	// failure too, not just on a verdict about the provider. Off by default: see
	// onchainLookupFailed for why an RPC outage should degrade rather than sever.
	onchainRequireLookup bool
	// quoteCache memoizes DCAP-verified results (enc_pub/signer) per endpoint, and
	// quoteSF collapses concurrent misses for the same endpoint into a single
	// verification so a cold/expired key can't stampede the expensive quote+
	// collateral path. Used only on the quote-verification path (verifier != nil).
	quoteCache *quoteCache
	quoteSF    singleflight.Group
}

// Option customizes a Router.
type Option func(*Router)

// WithServiceType sets the service type sent as the preview request's
// "service_type" (default DefaultServiceType, "chatbot"). It is bound to the
// endpoint the caller serves — a chat proxy previews "chatbot" — so callers set
// it once, not per request.
func WithServiceType(t string) Option {
	return func(r *Router) {
		if t != "" {
			r.serviceType = t
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

// WithSensitiveFields sets the request fields stripped before the preview call,
// so they never reach the (untrusted) router in cleartext. Default is
// wire.DefaultSealedFields; keep it in sync with the client's seal set so
// exactly the sealed fields are withheld from routing.
func WithSensitiveFields(fields []string) Option {
	return func(r *Router) {
		set := make(map[string]struct{}, len(fields))
		for _, f := range fields {
			set[f] = struct{}{}
		}
		r.sensitiveFields = set
	}
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
// attest warn mode for staged rollout. enforce=true is fail-closed on a VERDICT
// about the provider — an unacknowledged or mismatched signer skips the candidate
// so core falls back to the next.
//
// A failure of the lookup ITSELF is deliberately not in that class: it says
// nothing about the provider, and since every candidate of every request is
// grounded on the request path, treating it as fatal turns a chain-RPC outage
// into a total outage. It degrades to observe-only unless the operator opts in
// with WithOnChainRequireLookup. logger nil uses slog.Default() (or the logger a
// prior WithQuoteVerification set).
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

// WithOnChainRequireLookup extends enforce mode to registry LOOKUP failures: a
// candidate whose on-chain signer could not be read at all is skipped, rather
// than used ungrounded with a warning. It is off by default because the lookup is
// on the request path for every candidate, so an unreachable chain RPC would fail
// every request — an outage caused by our own dependency rather than by anything
// wrong with a provider. Turn it on for a deployment that would rather refuse
// service than serve a request whose provider identity it could not confirm.
//
// It has no effect without enforce: warn mode is observe-only by definition.
func WithOnChainRequireLookup(require bool) Option {
	return func(r *Router) { r.onchainRequireLookup = require }
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
		previewURL:      base + previewPath,
		completionsURL:  base + completionsPath,
		providersURL:    base + providersPath,
		serviceType:     DefaultServiceType,
		sensitiveFields: sliceToSet(wire.DefaultSealedFields()),
		http:            &http.Client{Transport: tr},
		cache:           newPubkeyCache(defaultPubkeyTTL),
		quoteCache:      newQuoteCache(defaultQuoteTTL),
	}
	for _, o := range opts {
		o(r)
	}
	return r
}

// Resolve implements core.Resolver: it runs the route-preview once and returns
// the ranked candidate list as core.Candidates. Materializing a candidate (its
// pubkey fetch) is deferred to Candidates.Provider, so the happy path fetches
// only the head's key; core walks the rest only on fallback.
func (r *Router) Resolve(ctx context.Context, req wire.Request) (core.Candidates, error) {
	providers, err := r.preview(ctx, req)
	if err != nil {
		return nil, err
	}
	return &routeCandidates{router: r, providers: providers}, nil
}

// routeCandidates is the ranked preview list as a core.Candidates. It holds the
// router (for the per-candidate pubkey fetch and the completions URL) and the
// ordered candidates; Provider materializes one on demand.
type routeCandidates struct {
	router    *Router
	providers []previewProvider
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
	if prov.Address == "" {
		return core.Provider{}, upstream(0, fmt.Errorf("route preview candidate has no address"))
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
		encPub      crypto.PublicKey
		signer      string
		quoteCached bool
		err         error
	)
	if c.router.verifier != nil {
		encPub, signer, quoteCached, err = c.router.verifiedKeysCached(ctx, prov.Endpoint)
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
	if c.router.registry != nil {
		outcome, err := c.router.groundSignerOnChain(ctx, prov.Address, signer)
		// A mismatch about to cost this candidate its place, decided against a CACHED
		// quote, is the other half of "never reject on stale evidence": a broker
		// upgrade rotates enc_pub and signer together, so our cached pair can name the
		// old enclave while the chain already names the new one. Re-read the quote and
		// ground once more before ruling. (Only worth doing when the quote was cached
		// — a freshly verified one is already the best evidence available — which also
		// stops a hostile provider from forcing a DCAP verification per request.)
		if err != nil && outcome == groundingMismatch && quoteCached {
			freshEnc, freshSigner, rerr := c.router.reverifiedKeys(ctx, prov.Endpoint)
			if rerr == nil && freshSigner != signer {
				c.router.logger.Info("re-verified quote after an on-chain signer mismatch; the cached quote had rotated",
					"provider", prov.Address, "cached_signer", signer, "fresh_signer", freshSigner)
				encPub, signer = freshEnc, freshSigner
				_, err = c.router.groundSignerOnChain(ctx, prov.Address, signer)
			}
		}
		if err != nil {
			return core.Provider{}, err
		}
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
		URL:        c.router.completionsURL,
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

// verifiedKeys returns the DCAP-verified enc_pub + signer for a candidate
// endpoint, discarding the provenance flag. See verifiedKeysCached.
func (r *Router) verifiedKeys(ctx context.Context, endpoint string) (crypto.PublicKey, string, error) {
	encPub, signer, _, err := r.verifiedKeysCached(ctx, endpoint)
	return encPub, signer, err
}

// verifiedKeysCached returns the DCAP-verified enc_pub + signer for a candidate
// endpoint, from the cache when fresh, otherwise by verifying its quote. It
// collapses concurrent misses for the same endpoint into ONE verification
// (quote fetch + go-tdx-guest + Intel PCS collateral is expensive and
// rate-limit-sensitive) via singleflight; the rest share the result. Errors are
// not cached, so a transient failure is retried on the next request.
//
// cached reports that the keys came from the quote cache rather than a live
// verification, i.e. that they may lag the provider by up to the quote TTL. A
// caller about to REJECT a provider over these keys uses it to decide whether a
// re-verification could change the verdict (see reverifiedKeys).
func (r *Router) verifiedKeysCached(ctx context.Context, endpoint string) (_ crypto.PublicKey, _ string, cached bool, _ error) {
	// Key the cache + singleflight by the DERIVED quote URL, not the raw endpoint,
	// so different endpoint spellings for the same provider (bare origin, /v1, full
	// chat URL, trailing slash) — and, importantly, the warmer's chain-sourced URL
	// vs a request's router-supplied endpoint — coincide when they name the same
	// host. Deriving up front also fails a malformed endpoint before any lookup.
	quoteURL, err := deriveQuoteURL(endpoint)
	if err != nil {
		return nil, "", false, upstream(0, fmt.Errorf("provider endpoint: %w", err))
	}
	if encPub, signer, ok := r.quoteCache.get(quoteURL); ok {
		metrics.QuoteCacheLookup(true)
		return encPub, signer, true, nil
	}
	metrics.QuoteCacheLookup(false)
	res, err := r.verifyAndCache(ctx, quoteURL)
	if err != nil {
		return nil, "", false, err
	}
	return res.encPub, res.signer, false, nil
}

// reverifiedKeys forces a live re-verification of endpoint's quote, bypassing the
// cache, and returns the keys the fresh quote binds. It exists for one situation:
// a cached quote is about to cost a provider its candidacy, and the cached copy
// may itself be the thing that is wrong. A broker upgrade rotates enc_pub and
// signer together, so for up to the quote TTL our cached pair names the OLD
// enclave while the chain already names the new one — a benign rollout that
// looks exactly like a signer mismatch. Re-reading the quote before ruling turns
// that window from a rejection into a refresh.
//
// It is deliberately NOT on the happy path: a quote verification is expensive and
// rate-limit-sensitive, so it runs only when the alternative is rejecting the
// provider outright.
func (r *Router) reverifiedKeys(ctx context.Context, endpoint string) (crypto.PublicKey, string, error) {
	quoteURL, err := deriveQuoteURL(endpoint)
	if err != nil {
		return nil, "", upstream(0, fmt.Errorf("provider endpoint: %w", err))
	}
	res, err := r.verifyAndCache(ctx, quoteURL)
	if err != nil {
		return nil, "", err
	}
	return res.encPub, res.signer, nil
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
		encPub, signer, err := r.verifyQuoteAt(vctx, quoteURL)
		if err != nil {
			return nil, err
		}
		r.quoteCache.put(quoteURL, encPub, signer)
		return quoteResult{encPub: encPub, signer: signer}, nil
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

// verifyQuoteAt is the uncached work behind verifiedKeys: fetch the attestation
// quote from quoteURL and DCAP-verify it, returning the enc_pub + signer bound
// into the verified report_data. Because the keys come out of a genuine, signed
// quote, it does not matter that the untrusted router chose the endpoint: a
// substituted endpoint serving an attacker key would fail verification. On a
// warn-mode measurement miss it logs but still returns the (genuine) keys.
func (r *Router) verifyQuoteAt(ctx context.Context, quoteURL string) (encPub crypto.PublicKey, signer string, err error) {
	// Meter the actually-performed verification (this runs only on a cache miss)
	// and its latency, so the histogram measures the expensive path — quote fetch
	// + go-tdx-guest signature/TCB checks + any collateral fetch — that the warmer
	// and the quote cache exist to keep off the request path.
	start := time.Now()
	defer func() { metrics.QuoteVerification(err == nil, time.Since(start)) }()

	raw, err := r.fetchQuote(ctx, quoteURL)
	if err != nil {
		return nil, "", err
	}
	verified, err := r.verifier.Verify(raw)
	if err != nil {
		return nil, "", upstream(0, fmt.Errorf("provider quote: %w", err))
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
	return verified.EncPub, verified.SignerAddr, nil
}

// groundingOutcome classifies one grounding attempt. The split that matters is
// between the two negatives: a VERDICT is a statement about the provider (the
// chain and the quote disagree, or the chain acknowledges nobody) and is the
// reason enforce mode exists; a lookup failure is a statement about OUR OWN chain
// RPC, and rejecting a provider over it converts our infrastructure's bad day
// into the user's failed request.
type groundingOutcome string

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
// Enforce mode is fail-closed on a VERDICT (mismatch or unacknowledged) — the
// candidate is skipped and core falls back. A lookup failure is treated
// separately: by default it degrades to observe-only even under enforce, because
// the registry lookup sits on the request path for every candidate, so a chain
// RPC outage would otherwise fail every candidate of every request — a total
// self-inflicted outage. onchainRequireLookup opts into the strict reading for a
// deployment that would rather fail than serve ungrounded.
//
// Warn mode is observe-only throughout (log and proceed), mirroring attest warn
// mode for staged rollout.
//
// A negative is never returned on stale evidence: see revalidate.
func (r *Router) groundSignerOnChain(ctx context.Context, providerAddr, signer string) (groundingOutcome, error) {
	got, err := r.registry.AcknowledgedSigner(ctx, providerAddr)
	if err != nil {
		return r.onchainLookupFailed(providerAddr, err)
	}
	// A negative computed from a stale reading is not a verdict. The grace window
	// keeps an expired entry alive across an RPC outage, and a broker upgrade
	// rotates the signer — so a stale entry disagreeing with a freshly quoted
	// signer is the expected shape of a benign rollout, indistinguishable from an
	// attack if we rule on it. Get fresh evidence before saying no.
	if got.Stale && !signerAgrees(got, signer) {
		got, err = r.revalidate(ctx, providerAddr, signer)
		if err != nil {
			return r.onchainLookupFailed(providerAddr, err)
		}
	}
	switch {
	case !got.Acknowledged:
		return r.onchainVerdict(groundingNotAcknowledged,
			fmt.Sprintf("provider %s has no acknowledged on-chain TEE signer", providerAddr))
	case !signerAgrees(got, signer):
		return r.onchainVerdict(groundingMismatch, fmt.Sprintf(
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
	metrics.OnChainGrounding(string(outcome))
	return outcome, nil
}

// revalidate re-reads the signer live, bypassing the cache and its grace window,
// and reports what the fresh evidence says. Only the freshly read value is
// returned: acting on the stale one after going to the trouble of refuting it
// would defeat the point.
func (r *Router) revalidate(ctx context.Context, providerAddr, signer string) (chain.Signer, error) {
	fresh, err := r.registry.RefreshSigner(ctx, providerAddr)
	if err != nil {
		metrics.OnChainRevalidation("lookup_failed")
		return chain.Signer{}, err
	}
	if signerAgrees(fresh, signer) {
		metrics.OnChainRevalidation("ok")
		r.logger.Info("on-chain signer disagreed while stale but agrees when read live; treating as a rotation, not a mismatch",
			"provider", providerAddr, "signer", signer)
	} else {
		metrics.OnChainRevalidation("negative")
	}
	return fresh, nil
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
func (r *Router) onchainVerdict(outcome groundingOutcome, msg string) (groundingOutcome, error) {
	metrics.OnChainGrounding(string(outcome))
	if r.onchainEnforce {
		return outcome, upstream(0, errors.New(msg))
	}
	r.logger.Warn("on-chain signer check failed; proceeding (onchain warn mode)", "detail", msg)
	return outcome, nil
}

// onchainLookupFailed handles a negative that is about our own chain RPC rather
// than the provider. It fails the candidate only when the operator has explicitly
// asked for that (onchainRequireLookup under enforce); otherwise it logs and
// proceeds ungrounded, so an RPC blip degrades the trust chain instead of
// severing the data plane.
func (r *Router) onchainLookupFailed(providerAddr string, cause error) (groundingOutcome, error) {
	metrics.OnChainGrounding(string(groundingLookupFailed))
	msg := fmt.Sprintf("on-chain signer lookup for provider %s failed", providerAddr)
	if r.onchainEnforce && r.onchainRequireLookup {
		return groundingLookupFailed, upstream(0, fmt.Errorf("%s: %w", msg, cause))
	}
	r.logger.Warn("on-chain signer lookup failed; proceeding ungrounded", "detail", msg, "err", cause,
		"enforce", r.onchainEnforce, "require_lookup", r.onchainRequireLookup)
	return groundingLookupFailed, nil
}

// fetchQuote GETs and decodes a provider's /v1/quote reply into raw TDX quote
// bytes (unverified — the caller verifies).
func (r *Router) fetchQuote(ctx context.Context, quoteURL string) ([]byte, error) {
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, quoteURL, nil)
	if err != nil {
		return nil, upstream(0, err)
	}
	resp, err := r.http.Do(httpReq)
	if err != nil {
		return nil, upstream(0, fmt.Errorf("fetch provider quote: %w", err))
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxControlBodyBytes))
	if err != nil {
		return nil, upstream(0, fmt.Errorf("read provider quote: %w", err))
	}
	if resp.StatusCode != http.StatusOK {
		return nil, upstreamBody(resp.StatusCode, body, fmt.Errorf("provider quote returned %d", resp.StatusCode))
	}
	raw, err := attest.DecodeQuoteResponse(body)
	if err != nil {
		return nil, upstream(0, err)
	}
	return raw, nil
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
// the service_type, forwarding the caller's credential and X-0G-* directives so
// the router authenticates/bills and steers exactly as it would for the sealed
// request. "model" is optional and passes through when present (it is not a
// sealed field): present → candidates are that model's providers; omitted →
// candidates are any provider of the service type.
func (r *Router) preview(ctx context.Context, req wire.Request) ([]previewProvider, error) {
	payload := make(map[string]json.RawMessage, len(req)+1)
	for k, v := range req {
		if _, sensitive := r.sensitiveFields[k]; sensitive {
			continue
		}
		payload[k] = v
	}
	// Force the service type the gateway is configured for; a chat body carries no
	// service_type of its own, and the router needs it to route.
	serviceTypeJSON, _ := json.Marshal(r.serviceType)
	payload["service_type"] = serviceTypeJSON

	body, err := json.Marshal(payload)
	if err != nil {
		return nil, upstream(0, fmt.Errorf("marshal preview request: %w", err))
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, r.previewURL, bytes.NewReader(body))
	if err != nil {
		return nil, upstream(0, err)
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
		return nil, upstream(0, fmt.Errorf("route preview request: %w", err))
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxControlBodyBytes))
	if err != nil {
		return nil, upstream(0, fmt.Errorf("read route preview response: %w", err))
	}
	if resp.StatusCode != http.StatusOK {
		// Surface the router's status verbatim (401/404/503 are meaningful) and carry
		// its body as Error.Body; the proxy decides whether to pass the router's
		// client-facing error through (sidecar / structured passthrough) or withhold
		// it (see openaiproxy.errorEnvelope).
		return nil, upstreamBody(resp.StatusCode, raw, fmt.Errorf("route preview returned %d", resp.StatusCode))
	}

	var pr previewResponse
	if err := json.Unmarshal(raw, &pr); err != nil {
		return nil, upstream(0, fmt.Errorf("decode route preview response: %w", err))
	}
	if len(pr.Providers) == 0 {
		return nil, upstream(http.StatusServiceUnavailable, fmt.Errorf("no provider available for %s", modelDesc(req)))
	}
	// The router returns candidates ranked best-first; core pins the head and
	// falls back down the rest (SPEC §4.4). Per-candidate validation is deferred
	// to routeCandidates.Provider so a single malformed candidate is skipped, not
	// fatal to the whole list.
	return pr.Providers, nil
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
	return u.Scheme + "://" + u.Host + base, nil
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
