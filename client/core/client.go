package core

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"slices"
	"time"

	"github.com/0gfoundation/0g-pc-e2ee/protocol/crypto"
	"github.com/0gfoundation/0g-pc-e2ee/protocol/wire"
)

// providerTimeout aligns the client's bounds with the 0G router's upstream
// timeout: nginx proxy_read_timeout / proxy_send_timeout and the backend
// write_timeout are all 600s, and the streaming path clears its total deadline
// so it is bounded by that same 600s read gap. We size to it plus a small margin
// so the router's own timeout (a clean 504) fires first — the client never cuts
// a request the router would still allow. Used as:
//   - the non-streaming context deadline (applied per call, NOT via
//     http.Client.Timeout, which would also cut a long stream);
//   - the response-header wait (ResponseHeaderTimeout, both paths); and
//   - the streaming idle gap between frames.
const providerTimeout = 10*time.Minute + 30*time.Second

// DefaultProviderURL is where a sealed request is POSTed when Provider.URL is
// empty: the 0G router's OpenAI chat-completions endpoint. (Provider discovery —
// the router's GET /v1/providers — is a separate, later concern.)
const DefaultProviderURL = "https://router-api.0g.ai/v1/chat/completions"

// Stage names where a Complete call failed, so callers (the sidecar) can map it
// to an HTTP status: a bad client request vs an upstream/provider failure vs a
// client-side internal error.
const (
	StageRequest  = "request"  // invalid client request (seal-side)
	StageUpstream = "upstream" // provider transport or sealed-response failure
	StageInternal = "internal" // client-side internal error
)

// Error wraps a Complete failure with the Stage it happened at and, when the
// failure is a non-2xx provider response, the upstream Status to surface as-is.
type Error struct {
	Stage  string
	Status int // upstream HTTP status to surface verbatim; 0 = derive from Stage
	Err    error
	// Body is the raw upstream response body for a non-2xx provider reply, if
	// any. It aids local debugging, but it is untrusted upstream content, so it
	// is deliberately NOT part of Error(): a multi-tenant server (the gateway)
	// must not echo it to end users, while a single-user sidecar can opt in to
	// surfacing it (openaiproxy.WithVerboseUpstreamErrors).
	Body string
}

func (e *Error) Error() string { return e.Err.Error() }
func (e *Error) Unwrap() error { return e.Err }

func stageErr(stage string, err error) error { return &Error{Stage: stage, Err: err} }

// resolveErr maps a Resolver failure onto an *Error. A resolver that already
// staged its error (route mode wraps its router/broker failures as *Error) is
// passed through verbatim; anything else is treated as an upstream failure,
// since provider selection is an outbound dependency, not a client-side bug.
func resolveErr(err error) error {
	var e *Error
	if errors.As(err, &e) {
		return err
	}
	return &Error{Stage: StageUpstream, Err: fmt.Errorf("resolve provider: %w", err)}
}

// Provider identifies the enclave the client seals to. In production EncPubKey
// and SignerAddr are extracted from a verified attestation quote; here they are
// supplied directly — attestation is a later step.
//
// SignerAddr and Address are distinct pins for two different layers and may
// differ:
//   - SignerAddr is the provider's on-chain TEE signer address. It is sealed
//     into _e2ee.signer_addr (SPEC §4.4) — the crypto pin the provider enclave
//     checks against its own teeSignerAddress — and identifies the key that
//     signs responses.
//   - Address is the router-facing provider address, sent as X-0G-Provider-Address
//     so a fronting router forwards to exactly this provider (the routing pin).
//     Empty means "set no routing pin" (a static provider that does not select
//     via the router).
type Provider struct {
	URL        string           // OpenAI-shaped endpoint (router or broker)
	EncPubKey  crypto.PublicKey // provider HPKE recipient key
	SignerAddr string           // on-chain TEE signer; sealed into _e2ee.signer_addr, verifies responses
	Address    string           // router-facing provider address; sent as X-0G-Provider-Address (routing pin)
}

// Client is the shared client core: it seals a request's sensitive fields to
// the provider, sends the envelope, and opens the sealed response. It holds no
// server of its own — the sidecar, the cloud-TEE gateway, and the in-process
// SDK all wrap this. A Client is safe for concurrent use.
//
// The provider it seals to is not fixed on the Client: a Resolver picks it per
// request. NewWithResolver takes a resolver that chooses per request — the route
// resolver (client/route) used by both shipped server forms, the sidecar and the
// gateway. New wraps a single fixed provider in a static resolver, the low-level
// case for a caller that already holds a provider identity.
type Client struct {
	resolver   Resolver
	sealFields []string
	http       *http.Client
}

// Option customizes a Client.
type Option func(*Client)

// WithSealFields overrides the set of request fields the client seals. Each is
// sealed only when present in a given request.
//
// The set must satisfy wire.ValidateSealedFields (non-empty, no duplicates,
// includes "messages"). It is not validated here: SealRequest enforces it per
// request, and callers that want an up-front error (the sidecar does) should
// call wire.ValidateSealedFields before constructing the Client.
// TODO(sdk): if the in-process SDK form exposes this, validate at construction
// (New returning an error) so a misconfig fails once, not on every request.
func WithSealFields(fields []string) Option {
	// Clone so a later mutation of the caller's slice cannot alter this config.
	return func(c *Client) { c.sealFields = slices.Clone(fields) }
}

// New returns a Client that seals every request to one fixed provider — the
// low-level static case (tests, or direct-seal to a provider already known and
// verified). The shipped server forms use NewWithResolver with the route
// resolver instead. An empty Provider.URL defaults to DefaultProviderURL; the
// sealed-field set defaults to wire.DefaultSealedFields.
func New(p Provider, opts ...Option) *Client {
	if p.URL == "" {
		p.URL = DefaultProviderURL
	}
	return NewWithResolver(staticResolver{p}, opts...)
}

// NewWithResolver returns a Client that picks the provider per request via r
// (the gateway's route mode: ask the router, then fetch the chosen provider's
// enc key). The sealed-field set defaults to wire.DefaultSealedFields.
func NewWithResolver(r Resolver, opts ...Option) *Client {
	// Clone the default transport (keeps env proxy, dial timeout, keepalives) and
	// bound the wait for response headers via ResponseHeaderTimeout. No blunt
	// http.Client.Timeout: it would also cut a long stream (see providerTimeout).
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.ResponseHeaderTimeout = providerTimeout
	c := &Client{
		resolver:   r,
		sealFields: wire.DefaultSealedFields(),
		http:       &http.Client{Transport: tr},
	}
	for _, o := range opts {
		o(c)
	}
	return c
}

// Complete performs one non-streaming chat completion. req and the result are
// OpenAI-shaped JSON objects; the sensitive fields are sealed on the way out and
// the sealed response is opened on the way back, so the caller only ever handles
// plaintext. Failures are wrapped in *Error with a Stage.
//
// TODO(attestation): the response is sealed to client_eph_pub, which travels in
// cleartext in the request envelope. Complete does NOT yet authenticate the
// response's origin — a middleman could read that key and seal a forged
// response that OpenResponse accepts as plaintext. Verifying the provider enc
// key out of an attestation quote (§4) and the TEE response signature (§8; the
// "verify response signature" step in doc.go) is a later step. Until then this
// provides confidentiality but NOT response authenticity.
func (c *Client) Complete(ctx context.Context, req wire.Request) (wire.Response, error) {
	ctx, cancel := context.WithTimeout(ctx, providerTimeout)
	defer cancel()

	// Pick the provider to seal to. A static resolver returns the fixed provider;
	// the route resolver consults the router and fetches the chosen provider's enc
	// key, so this may make network calls (bounded by the ctx deadline above).
	provider, err := c.resolver.Resolve(ctx, req)
	if err != nil {
		return nil, resolveErr(err)
	}

	// Fresh ephemeral keypair per request; the enclave seals the response to the
	// public half (§7) and we keep the private half to open it.
	ephPriv, ephPub, err := crypto.GenerateRecipientKey()
	if err != nil {
		return nil, stageErr(StageInternal, fmt.Errorf("generate ephemeral key: %w", err))
	}

	sealed, err := wire.SealRequest(provider.EncPubKey, req, c.sealedFieldsFor(req), provider.SignerAddr, ephPub)
	if err != nil {
		// Given a valid provider config (validated at startup), a seal failure is
		// a bad request — e.g. no messages to seal.
		return nil, stageErr(StageRequest, fmt.Errorf("seal request: %w", err))
	}

	respBody, status, err := c.post(ctx, provider, sealed)
	if err != nil {
		// Surface a non-2xx provider status verbatim (status is 0 for a transport
		// failure, which statusFor maps to 502) so OpenAI clients can key their
		// retry/backoff on it — 429/5xx retry, 4xx fail fast. For a non-2xx,
		// respBody is the upstream body; carry it as Body (not in the message).
		e := &Error{Stage: StageUpstream, Status: status, Err: err}
		if status != 0 {
			e.Body = string(respBody)
		}
		return nil, e
	}

	var sealedResp wire.Response
	if err := json.Unmarshal(respBody, &sealedResp); err != nil {
		return nil, stageErr(StageUpstream, fmt.Errorf("decode sealed response: %w", err))
	}
	out, err := wire.OpenResponse(ephPriv, sealedResp)
	if err != nil {
		return nil, stageErr(StageUpstream, fmt.Errorf("open response: %w", err))
	}
	return out, nil
}

// post sends the envelope and returns the response body plus, for a non-2xx, the
// upstream HTTP status (0 for a transport/read failure, which the caller maps to
// 502). The caller surfaces a non-2xx status verbatim.
//
// On a non-2xx it returns the raw body alongside the status so the caller can
// attach it as Error.Body — kept out of the error message so a multi-tenant
// server never echoes untrusted upstream content (see Error.Body).
func (c *Client) post(ctx context.Context, provider Provider, env wire.Request) ([]byte, int, error) {
	resp, err := c.doRequest(ctx, provider, env)
	if err != nil {
		return nil, 0, fmt.Errorf("post to provider: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, 0, fmt.Errorf("read provider response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return respBody, resp.StatusCode, fmt.Errorf("provider returned %d", resp.StatusCode)
	}
	return respBody, resp.StatusCode, nil
}

// Router routing directives (SPEC §4.4). The client sends its sealed request to
// the router, which authenticates/bills and forwards to the provider; these pin
// the forward to the exact provider the request is sealed to.
const (
	// headerProviderPin pins the request to a provider by its router-facing
	// provider address (Provider.Address) — distinct from the signer address in
	// the envelope's signer_addr, which is the enclave's crypto identity.
	headerProviderPin = "X-0G-Provider-Address"
	// headerAllowFallbacks disables server-side fallback. A sealed request can be
	// opened only by the provider whose enc key it used, so a fallback to another
	// provider would fail to decrypt — the client must pin, not fall back.
	headerAllowFallbacks = "X-0G-Allow-Fallbacks"
)

// doRequest POSTs the sealed envelope to provider.URL and returns the raw
// response; the caller owns resp.Body. Shared by the buffered (post) and
// streaming paths.
func (c *Client) doRequest(ctx context.Context, provider Provider, env wire.Request) (*http.Response, error) {
	body, err := json.Marshal(env)
	if err != nil {
		return nil, fmt.Errorf("marshal envelope: %w", err)
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, provider.URL, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	// Copy the caller's forwarded routing headers (the X-0G-* directives the
	// router consumes) first, so the pin and credential set below always win over
	// anything forwarded.
	for k, vs := range ForwardedHeadersFrom(ctx) {
		for _, v := range vs {
			httpReq.Header.Add(k, v)
		}
	}
	// Pin the forward to the provider this request is sealed to, and disable
	// fallback, so a router routes to exactly that provider — never re-routing or
	// falling back to one whose key cannot open this envelope. The pin is the
	// router-facing provider address (Address), not the signer. When there is no
	// routing pin (Address empty — a static provider) or provider.URL is a
	// provider/broker directly, only the fallback directive is set (and a direct
	// provider ignores it). Set after the forwarded headers so the resolved
	// provider is authoritative over any forwarded pin.
	if provider.Address != "" {
		httpReq.Header.Set(headerProviderPin, provider.Address)
	}
	httpReq.Header.Set(headerAllowFallbacks, "false")
	// Forward the caller's credential (if any) verbatim as the Authorization
	// header, so the router/broker can authenticate and bill the request. Empty
	// when the caller set none — the request then goes out unauthed.
	if cred := CredentialFrom(ctx); cred != "" {
		httpReq.Header.Set("Authorization", cred)
	}
	return c.http.Do(httpReq)
}

// sealedFieldsFor picks the configured sealed fields that are actually present
// in req. A valid chat request always carries "messages"; "tools" (and any
// operator-added field) often is absent. Filtering by presence seals what is
// sent without erroring on a request that omits an optional sealed field.
func (c *Client) sealedFieldsFor(req wire.Request) []string {
	// Non-nil even when empty: SealRequest treats a nil sealedFields as "use the
	// default set", which would silently mask this presence-filter. An empty
	// (non-nil) result instead makes SealRequest fail with "no sealed fields" —
	// the right outcome for a request with nothing sensitive to seal.
	fs := []string{}
	for _, f := range c.sealFields {
		if _, ok := req[f]; ok {
			fs = append(fs, f)
		}
	}
	return fs
}
