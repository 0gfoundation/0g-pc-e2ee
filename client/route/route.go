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
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/0gfoundation/0g-pc-e2ee/client/core"
	"github.com/0gfoundation/0g-pc-e2ee/protocol/crypto"
	"github.com/0gfoundation/0g-pc-e2ee/protocol/wire"
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
	serviceType     string
	sensitiveFields map[string]struct{}
	http            *http.Client
	cache           *pubkeyCache
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
	// A dedicated transport with a bounded header wait, mirroring core.New; the
	// control-plane calls are short, so no long-stream concern applies.
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.ResponseHeaderTimeout = 30 * time.Second
	r := &Router{
		previewURL:      base + previewPath,
		completionsURL:  base + completionsPath,
		serviceType:     DefaultServiceType,
		sensitiveFields: sliceToSet(wire.DefaultSealedFields()),
		http:            &http.Client{Transport: tr},
		cache:           newPubkeyCache(defaultPubkeyTTL),
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
	// The candidate endpoint is used only to fetch its published enc key. It is
	// taken as the router returns it; the router is untrusted, so a compromised
	// one could point this at an endpoint it controls and MITM the prompt.
	// Resolving the endpoint (and on-chain teeSignerAddress) from chain instead is
	// tracked in issue #18, and full protection needs quote verification (#7).
	pubkeyURL, err := derivePubkeyURL(prov.Endpoint)
	if err != nil {
		return core.Provider{}, upstream(0, fmt.Errorf("provider endpoint: %w", err))
	}
	encPub, signer, err := c.router.pubkey(ctx, pubkeyURL)
	if err != nil {
		return core.Provider{}, err
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
	}, nil
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
		// Surface the router's status verbatim (401/404/503 are meaningful to the
		// caller) but not its raw body — this error becomes the gateway's response.
		return nil, upstream(resp.StatusCode, fmt.Errorf("route preview returned %d", resp.StatusCode))
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
		return nil, "", upstream(resp.StatusCode, fmt.Errorf("provider pubkey returned %d", resp.StatusCode))
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

// derivePubkeyURL turns a provider endpoint into the broker's e2ee pubkey URL.
// The endpoint may be a bare origin (https://host[:port]), the /v1 base, or the
// full chat-completions URL (…/v1/chat/completions); all three resolve against
// the same /v1 base, so the pubkey path hangs off it consistently.
func derivePubkeyURL(endpoint string) (string, error) {
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
	return u.Scheme + "://" + u.Host + base + "/e2ee/pubkey", nil
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
