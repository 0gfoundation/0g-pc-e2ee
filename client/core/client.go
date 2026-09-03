package core

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"slices"
	"time"

	"github.com/0gfoundation/0g-pc-e2ee/client/endpoint"
	"github.com/0gfoundation/0g-pc-e2ee/protocol/crypto"
	"github.com/0gfoundation/0g-pc-e2ee/protocol/proof"
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

// maxUpstreamErrorBytes bounds a non-2xx provider response body read (it is
// surfaced as Error.Body / passed through), so a broken or hostile upstream
// cannot force an unbounded read. A 2xx sealed response is read unbounded — a
// completion can legitimately be large.
const maxUpstreamErrorBytes = 1 << 20 // 1 MiB

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
	// Header is the upstream (router) response header block for a reply built from
	// a real upstream response — non-2xx or a malformed 2xx. Nil for a transport
	// failure that never produced a response. Like the success-path
	// ResponseMeta.Header it is carried verbatim; a front end surfaces only a
	// curated, non-sensitive subset (e.g. Retry-After and the rate-limit counters
	// on a 429), never the whole block.
	Header http.Header
}

func (e *Error) Error() string { return e.Err.Error() }
func (e *Error) Unwrap() error { return e.Err }

// Source classifies where the failure originated, for the error envelope's
// attribution field: "upstream" for anything from the router/provider chain
// (StageUpstream), "gateway" for a fault in this client itself (a bad request it
// built, or an internal error). It lets a caller tell a gateway/sidecar bug
// apart from a router/provider one without parsing the message.
func (e *Error) Source() string {
	if e.Stage == StageUpstream {
		return "upstream"
	}
	return "gateway"
}

func stageErr(stage string, err error) error { return &Error{Stage: stage, Err: err} }

// Tiers of walk failure, ordered by how much they tell the caller. A flat
// "anything already held wins" rule — which is what this started as — cannot tell a
// provider's verbatim reply apart from an earlier bookkeeping error, so a request cut
// at the budget ceiling could return "candidate 0 is malformed" and never mention
// that it had been held for the full ninety seconds.
const (
	// tierMaterialize: we could not prepare a candidate. Our own bookkeeping, no
	// upstream status, the least actionable of the three.
	tierMaterialize = iota
	// tierBudget: the walk ran out of budget. Says why the request was cut, which no
	// materialize error does — a bare deadline does not name the ceiling that set it.
	tierBudget
	// tierAttempt: a provider answered. Carries its status and headers (a 503 with
	// its Retry-After, surfaced verbatim by the proxy), so nothing outranks it.
	tierAttempt
)

// walkErr keeps the most useful failure seen while walking the candidate chain.
type walkErr struct {
	err  error
	tier int
}

// record keeps err when its tier is at least as informative as what is held. Equal
// tiers let the LATER one win: two candidates that could not be prepared are equally
// ranked, and the second tells you more than the first (an early "no usable address"
// otherwise masks whatever the rest of the chain did).
func (w *walkErr) record(tier int, err error) {
	if w.err == nil || tier >= w.tier {
		w.err, w.tier = err, tier
	}
}

// budgetErr names the ceiling that cut a walk short, wrapping whatever the last
// candidate was doing when it ran out. Recorded at tierBudget so it displaces the
// materialize errors that cannot explain the cut, and never a provider's own reply.
func budgetErr(limit time.Duration, cause error) error {
	return &Error{Stage: StageUpstream, Err: fmt.Errorf(
		"provider selection budget (%s) exhausted: %w", limit, cause)}
}

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
	URL        string           // OpenAI-shaped endpoint (router or broker) the sealed request POSTs to
	EncPubKey  crypto.PublicKey // provider HPKE recipient key
	SignerAddr string           // on-chain TEE signer; sealed into _e2ee.signer_addr, verifies responses
	Address    string           // router-facing provider address; sent as X-0G-Provider-Address (routing pin)
	// Endpoint is the provider's OWN serving URL (the broker, ultimately the
	// on-chain Service.url), distinct from URL when a router fronts the chat POST.
	// The §8 response signature is fetched directly from here — the router does
	// not proxy /v1/proxy/signature/{chatKey}. Empty disables direct fetch (a
	// static provider that is itself the endpoint may set URL only).
	Endpoint string
	// Model is the provider's canonical model id (the route preview's
	// canonical_id). Each candidate may serve a different model — the preview
	// list is heterogeneous when the caller omits "model" — so the client writes
	// this into the envelope's cleartext "model" before sealing, so the request
	// names the model this specific provider actually serves. Empty means "leave
	// the request's model as-is" (a static provider, or a caller that already
	// pinned the model).
	Model string
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
	resolver      Resolver
	sealFields    []string
	unboundFields []string
	// ep is the surface this client serves — one row of endpoint.All; see
	// WithEndpoint. Its Profile fixes which field carries the payload and which
	// the response must seal (SPEC §5.1), so a chat client cannot silently accept
	// an image-shaped response or vice versa, and the whole row is what the
	// resolver is handed per request.
	//
	// Held as the row rather than as the profile and service type it was
	// destructured into: those two were halves of one row held apart, and the
	// service-type half is a lossy projection — /v1/chat/completions and
	// /v1/messages share "chatbot", so a resolver given only that string cannot
	// tell which of them it is ranking for. One field cannot go stale against
	// itself.
	ep endpoint.Endpoint
	// sealFieldsSet records that WithSealFields was passed, so NewWithResolver
	// can derive the default set from the profile without overriding an explicit
	// choice. Needed because the derivation must happen AFTER the options loop:
	// the profile is itself set by an option, so option order would otherwise
	// decide the sealed set.
	sealFieldsSet bool
	http          *http.Client
	debug         *slog.Logger // nil = off; see WithDebugLogger
	metrics       MetricsHook  // nil = off; see WithMetrics
	// Response-signature verification (hop 11), off unless both are set via
	// WithResponseVerification. See verify.go.
	sigFetcher SignatureFetcher
	recover    proof.RecoverFunc
	// resolveBudgetTO bounds total candidate materialization for one call
	// (resolveBudget by default). A field so a test can scale it down; see
	// candidateWalk.
	resolveBudgetTO time.Duration
}

// MetricsHook receives redaction-safe counters for core events, letting a caller
// (the gateway) meter them without core depending on any metrics library — the
// same decoupling as WithDebugLogger's *slog.Logger. Implementations must be
// safe for concurrent use and cheap (they run on the request path). nil is off.
type MetricsHook interface {
	// ResponseOpenFailure is called once per sealed-response frame whose AEAD
	// open failed (streaming counts each failed frame), alongside the debug log.
	ResponseOpenFailure()
	// ResponseVerificationFailure is called once per §8 response-signature
	// verification failure, with a low-cardinality reason: "fetch" when the
	// signature could not be retrieved (missing handle / fetch error, an
	// operational fault) and "signature" when it was retrieved but did not verify
	// against the grounded signer (an integrity/authenticity failure of the
	// provider — the alarming case).
	ResponseVerificationFailure(reason string)
	// UpstreamAttempt is called once per completed data-plane attempt against one
	// provider, with how long the upstream call took. kind is UpstreamBuffered or
	// UpstreamStream; outcome is one of the Upstream* constants.
	//
	// It exists because a caller cannot recover this from its own server-side
	// timings: those measure provider selection plus this, and when the number
	// moves they cannot say which half moved. Only the client core knows where one
	// attempt began and ended, and which of several candidates it was.
	UpstreamAttempt(kind, outcome string, dur time.Duration)
	// StreamFirstFrame is called once per stream, when the first frame is
	// delivered to the caller. A stream's total duration is set by how much the
	// model has to say; the wait for its first token is the part a caller
	// experiences as latency, and the two are unrelated.
	StreamFirstFrame(dur time.Duration)
	// WalkBudgetExhausted is called when resolveBudget running out actually
	// truncated a call's work: it cut a candidate's materialization short, or it
	// denied a fallback the walk would otherwise have made. It is the only signal
	// that a request was cut at that ceiling rather than by anything upstream, and
	// therefore the only way to tell whether the ceiling is set anywhere near
	// right — which is why it must not also fire where the walk was ending anyway.
	WalkBudgetExhausted()
	// CandidateFallback is called each time the client gives up on a candidate and
	// moves to the next, with reason FallbackUpstream (an attempt failed
	// transiently and is re-sealed to the next candidate) or FallbackMaterialize
	// (the candidate could not be prepared at all). Sustained fallback is the only
	// signal that the ranking the untrusted router hands us puts bad providers
	// first — invisible in the request outcome, which the fallback repaired.
	CandidateFallback(reason string)
}

// Attempt kinds and outcomes reported through MetricsHook.UpstreamAttempt, named
// so the vocabulary cannot drift between the buffered and streaming paths (which
// classify the same failures at different call sites).
const (
	UpstreamBuffered = "buffered"
	UpstreamStream   = "stream"

	UpstreamOK = "ok"
	// UpstreamTransport: no response at all — the request never reached the
	// provider, or reached it and it never answered (the response-header timeout).
	UpstreamTransport = "transport"
	// UpstreamBody: a response began but its body dropped mid-read, or a stream
	// ended before its final frame — a delivery failure, not a content one.
	UpstreamBody = "body"
	// UpstreamUndecodable: a 2xx whose sealed body would not decode or open.
	UpstreamUndecodable = "undecodable"
	// UpstreamNotStream: a 200 that was not an event stream (the provider ignored
	// stream:true), which would otherwise read as an empty completion.
	UpstreamNotStream = "not_stream"
	// UpstreamUnverified: a §8 signature was retrieved and did NOT verify against
	// the grounded signer. An integrity claim about the provider — the alarming one.
	UpstreamUnverified = "unverified"
	// UpstreamUnverifiable: the §8 signature could not be retrieved at all, so
	// nothing was proven either way. Operational (the broker's problem, or ours),
	// and deliberately apart from unverified: a runbook that pages on provider
	// integrity must not be firable by one broker's bad minute.
	UpstreamUnverifiable = "unverifiable"
	// UpstreamTimeout: OUR deadline fired — the per-attempt provider timeout, or a
	// stream's idle watchdog between frames. The provider went quiet; the caller
	// did not go away.
	UpstreamTimeout = "timeout"
	// UpstreamCanceled: the CALLER went away mid-attempt. Kept out of every failure
	// bucket on purpose: a user closing a tab is not a provider fault, and folding
	// it in would put our own users' navigation in the router's error rate.
	UpstreamCanceled = "canceled"
	// UpstreamInternal: a fault in THIS client detected mid-attempt. Its own bucket
	// so our bug can never be read as a provider's.
	UpstreamInternal = "internal"
	// Status-derived outcomes, produced by upstreamStatusOutcome. They live here
	// with the rest so this block is the whole vocabulary it claims to be — the
	// same strings appear in the metric's Help, the dashboard and the runbook, and
	// a literal buried in a switch is how those drift apart.
	UpstreamHTTP429   = "http_429"
	UpstreamHTTP4xx   = "http_4xx"
	UpstreamHTTP5xx   = "http_5xx"
	UpstreamHTTPOther = "http_other"

	FallbackUpstream    = "upstream"
	FallbackMaterialize = "materialize"
)

// upstreamStatusOutcome classifies a non-2xx provider status into its attempt
// outcome. 429 is split out from the rest of the 4xx range because it is the one
// that says "this provider is saturated" rather than "this request was wrong" —
// the same reason the fallback logic treats it as transient.
func upstreamStatusOutcome(status int) string {
	switch {
	case status == http.StatusTooManyRequests:
		return UpstreamHTTP429
	case status >= 500 && status <= 599:
		return UpstreamHTTP5xx
	case status >= 400 && status <= 499:
		return UpstreamHTTP4xx
	default:
		return UpstreamHTTPOther
	}
}

// metricUpstreamAttempt reports one data-plane attempt to the hook, if one is
// configured. No-op otherwise, like every other metric call in core.
func (c *Client) metricUpstreamAttempt(kind, outcome string, dur time.Duration) {
	if c.metrics != nil {
		c.metrics.UpstreamAttempt(kind, outcome, dur)
	}
}

// metricFallback reports one move from candidate i (of n) to the next — but only
// when there IS a next one. A failure on the LAST candidate ends the walk, and
// counting it as a fallback would inflate the series on a single-candidate
// deployment, the common shape, where nothing was ever fallen back to.
func (c *Client) metricFallback(reason string, i, n int) {
	if c.metrics != nil && i+1 < n {
		c.metrics.CandidateFallback(reason)
	}
}

// metricWalkBudgetExhausted reports one walk the budget truncated. For the
// materialization sites: that work runs under a deadline derived from what is left,
// so even on the last candidate the ceiling really did cut it.
func (c *Client) metricWalkBudgetExhausted() {
	if c.metrics != nil {
		c.metrics.WalkBudgetExhausted()
	}
}

// metricWalkBudgetBlockedFallback is the same report from an attempt site, where
// the budget cuts nothing — a running attempt is never interrupted by it — and only
// decides whether to move on. Hence the metricFallback guard: with no next
// candidate there was nothing to move on to, so counting it would book every
// upstream slower than resolveBudget as our ceiling firing.
func (c *Client) metricWalkBudgetBlockedFallback(i, n int) {
	if i+1 < n {
		c.metricWalkBudgetExhausted()
	}
}

// metricStreamFirstFrame reports a stream's time to first delivered frame.
func (c *Client) metricStreamFirstFrame(dur time.Duration) {
	if c.metrics != nil {
		c.metrics.StreamFirstFrame(dur)
	}
}

// upstreamFailureOutcome resolves what to blame for a failure whose default reading
// is base (UpstreamTransport for a request that produced no response,
// UpstreamBody for one whose body dropped).
//
// A TIMEOUT is our bound expiring rather than the provider being unreachable, and it
// must land in the same bucket whichever mechanism noticed — the buffered path's
// per-attempt context deadline, or the shared client's ResponseHeaderTimeout, which
// is all the streaming path has since its context carries no deadline of its own.
// Deciding by mechanism split ONE fault (a provider that accepts the connection and
// never answers) across two buckets by kind: timeout on the buffered path, transport
// on the streaming one. That is precisely the drift the shared outcome constants
// exist to prevent.
func upstreamFailureOutcome(parent, attempt context.Context, err error, base string) string {
	if canceledBy(parent) {
		return UpstreamCanceled
	}
	if attempt.Err() != nil || isTimeout(err) {
		return UpstreamTimeout
	}
	return base
}

// isTimeout reports whether err is a deadline expiring, from either layer: a context
// deadline, or a net.Error the transport timed out on (which is how
// ResponseHeaderTimeout surfaces).
func isTimeout(err error) bool {
	if errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}

// canceledBy reports whether parent is done, i.e. whether a failure inside a
// derived (deadline-bearing) context is the CALLER giving up rather than our own
// deadline firing. Both look identical from inside the attempt, and they belong in
// different metric buckets: see UpstreamCanceled vs UpstreamTimeout.
func canceledBy(parent context.Context) bool { return parent.Err() != nil }

// verifyOutcome resolves what to attribute a §8 verification failure to, given
// what the verifier concluded, whether the caller is still there, and whether OUR
// deadline for this attempt has fired.
//
// A signature that did not verify is never re-attributed: that finding is about the
// provider and stands whether or not the caller stayed to hear it, and letting a
// well-timed disconnect erase it would put the one integrity signal here at the
// mercy of client behaviour.
//
// UpstreamUnverifiable — a proof we could not FETCH — is the only re-attributable
// conclusion, and the test is written as an allowlist for the same reason the
// dashboard's ratios are: a denylist has to be revisited every time verify.go can
// conclude something new, and it was already wrong once. UpstreamInternal used to
// fall through it, so a binder of ours that would not produce its text got filed as
// "canceled" whenever the caller had left — a bug of ours in the one bucket every
// alert deliberately ignores.
func verifyOutcome(parent, attempt context.Context, concluded string) string {
	if concluded != UpstreamUnverifiable {
		return concluded
	}
	if canceledBy(parent) {
		return UpstreamCanceled
	}
	if attempt.Err() != nil {
		return UpstreamTimeout
	}
	return concluded
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
	return func(c *Client) {
		c.sealFields = slices.Clone(fields)
		c.sealFieldsSet = true
	}
}

// WithEndpoint binds the client to the surface it serves — one row of
// endpoint.All — which selects the wire profile it seals and opens under, the
// row the resolver is handed per request, and, unless WithSealFields overrides
// it, the default sealed set for that profile ("messages"/"tools" vs "prompt").
//
// The profile is what stops a chat client accepting an image-shaped response
// and vice versa: OpenResponseFor refuses a frame whose sealed set does not
// cover the profile's content field, which is the client's only way to notice
// that its response was never actually sealed (SPEC §12). A client left on the
// default keeps behaving exactly as before (endpoint.Chat).
//
// Taking the row rather than a service-type STRING is what removed this
// package's copy of the string-to-profile mapping, and the row is now what
// crosses the resolver boundary too — a service type cannot name a surface,
// since /v1/chat/completions and /v1/messages share "chatbot". A surface the
// table does not carry is unrepresentable here instead of being caught by an
// allowlist that had to be kept in step with three others.
//
// The zero Endpoint still fails closed: its empty profile makes every seal and
// open fail with "unknown profile" rather than silently applying chat's rules to
// a request shape nobody analysed. That promise is about SEALING only — asking
// the zero row what to withhold from an untrusted router answers "nothing", so
// route.sensitiveFieldsFor keys its own fallback on that empty answer rather
// than trusting the row.
func WithEndpoint(ep endpoint.Endpoint) Option {
	return func(c *Client) {
		c.ep = ep
	}
}

// WithUnboundFields overrides the set of cleartext request fields excluded from
// the AAD (SPEC §5.2) — the fields an intermediary may add, modify, or remove in
// transit without breaking Open. Their values are NOT authenticated by the
// transport crypto (D4); trust must come from elsewhere (the TEE signature).
//
// The set must satisfy wire.ValidateUnboundFields (no duplicates, no reserved
// _e2ee key, disjoint from the sealed set). It is not validated here: SealRequest
// enforces it per request. Pass an empty (non-nil) slice to bind every cleartext
// field. Defaults to wire.DefaultUnboundFields when unset.
func WithUnboundFields(fields []string) Option {
	// Clone so a later mutation of the caller's slice cannot alter this config.
	return func(c *Client) { c.unboundFields = slices.Clone(fields) }
}

// WithDebugLogger enables redaction-safe diagnostics for response open (AEAD)
// failures, written to l. When a sealed response frame fails to open — the
// opaque "chacha20poly1305: message authentication failed" — the client logs a
// structural summary of the offending frame (see logOpenFailure and
// wire.FrameDebug): the frame's ordinal, its cleartext field names, and byte
// lengths, never plaintext, ciphertext, or key material. That summary tells
// apart the causes that all share that one message — a first-frame key/enc/AAD
// mismatch, a dropped or reordered later frame, or an intermediary-injected
// bound field — which the client-facing error alone cannot.
//
// It is safe on the multi-tenant gateway (it logs no tenant content), but off
// (nil) by default so the quiet behavior is the one you get without thinking
// about it. Both shipped server forms enable it against their process logger —
// the same *slog.Logger they use for startup and access logs, so every line the
// binary emits shares one format and sink (see proxycli.NewLogger).
func WithDebugLogger(l *slog.Logger) Option {
	return func(c *Client) { c.debug = l }
}

// WithMetrics attaches a MetricsHook so the client reports redaction-safe
// counters (currently response-open failures) to m. Off (nil) by default, and
// independent of WithDebugLogger: the gateway enables both, so an open failure
// both increments a counter and writes its structural debug line. core does not
// import any metrics library; m is satisfied by client/metrics.CoreMetrics.
func WithMetrics(m MetricsHook) Option {
	return func(c *Client) { c.metrics = m }
}

// logOpenFailure records a redaction-safe structural summary of a frame whose
// AEAD open failed, at frame index frameIdx (0-based; 0 for a non-streaming
// single frame). It is the operator-only counterpart to the opaque client-facing
// error: the summary is what distinguishes a first-frame setup/key/AAD mismatch
// (frame=0) from a dropped or reordered later frame (frame>0, ordering desync),
// and surfaces the cleartext field set so an intermediary-injected bound field
// shows up. No-op when no debug logger is configured.
func (c *Client) logOpenFailure(frameIdx int, frame wire.Response, err error) {
	// Count every open failure, independent of the debug logger: the metric is a
	// security signal the gateway alerts on, while the debug line is operator
	// diagnostics either form may leave off.
	if c.metrics != nil {
		c.metrics.ResponseOpenFailure()
	}
	if c.debug == nil {
		return
	}
	d := frame.Debug()
	c.debug.LogAttrs(context.Background(), slog.LevelWarn, "e2ee open failed",
		slog.Int("frame", frameIdx),
		slog.Bool("final", d.Final),
		slog.Bool("has_enc", d.HasEnc),
		slog.Int("v", d.Version),
		slog.Any("sealed_fields", d.SealedFields),
		slog.Any("unbound_fields", d.UnboundFields),
		slog.Any("cleartext_keys", d.CleartextKeys),
		slog.Int("ct_bytes", d.CiphertextLen),
		slog.String("e2ee_err", d.E2EEErr),
		slog.Any("err", err),
	)
}

// New returns a Client that seals every request to one fixed provider — the
// low-level static case (tests, or direct-seal to a provider already known and
// verified). The shipped server forms use NewWithResolver with the route
// resolver instead. An empty Provider.URL defaults to DefaultProviderURL; the
// sealed-field set defaults to wire.DefaultSealedFields and the unbound-field set
// to wire.DefaultUnboundFields.
func New(p Provider, opts ...Option) *Client {
	if p.URL == "" {
		p.URL = DefaultProviderURL
	}
	return NewWithResolver(staticResolver{p}, opts...)
}

// NewWithResolver returns a Client that picks the provider per request via r
// (the gateway's route mode: ask the router, then fetch the chosen provider's
// enc key). The sealed-field set defaults to wire.DefaultSealedFields and the
// unbound-field set to wire.DefaultUnboundFields.
func NewWithResolver(r Resolver, opts ...Option) *Client {
	// Clone the default transport (keeps env proxy, dial timeout, keepalives) with
	// a server-sized idle-connection pool (see NewPooledTransport — Go's default of
	// 2 per host throttles a proxy that sends every request to the same router),
	// and bound the wait for response headers via ResponseHeaderTimeout. No blunt
	// http.Client.Timeout: it would also cut a long stream (see providerTimeout).
	tr := NewPooledTransport()
	tr.ResponseHeaderTimeout = providerTimeout
	c := &Client{
		resolver:      r,
		ep:            endpoint.Chat,
		unboundFields: wire.DefaultUnboundFields(),
		http:          &http.Client{Transport: tr},

		resolveBudgetTO: resolveBudget,
	}
	for _, o := range opts {
		o(c)
	}
	// Resolved AFTER the options, not as a struct default, so it tracks whichever
	// profile they settled on regardless of the order WithEndpoint and
	// WithSealFields were passed in. An explicit WithSealFields still wins.
	if !c.sealFieldsSet {
		c.sealFields = wire.DefaultSealedFieldsFor(c.ep.Profile)
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
	// Pick the candidates to seal to, best first. A static resolver returns one
	// fixed provider; the route resolver consults the router and returns the
	// fallback chain — a control-plane call bounded by the resolver's own HTTP
	// client (route.New sets ResponseHeaderTimeout), not by a request deadline
	// here; the per-attempt data-plane deadline is applied inside completeOnce.
	cands, err := c.resolver.Resolve(ctx, c.ep, req)
	if err != nil {
		return nil, resolveErr(err)
	}

	// Fresh ephemeral keypair per request; the enclave seals the response to the
	// public half (§7) and we keep the private half to open it. Reused across
	// fallback attempts — it is the client's own response key, independent of
	// which provider a candidate is.
	ephPriv, ephPub, err := crypto.GenerateRecipientKey()
	if err != nil {
		return nil, stageErr(StageInternal, fmt.Errorf("generate ephemeral key: %w", err))
	}

	// Fall back down the candidate chain: attempt a candidate and, on a retryable
	// provider failure, re-seal to the next and retry (SPEC §4.4).
	//
	// The walk charges every materialization and every failed attempt against one
	// shared budget, so a long chain cannot keep the caller waiting indefinitely (see
	// resolveBudget). fail keeps the most USEFUL failure seen rather than the most
	// recent — a provider's own reply outranks a budget cut, which outranks our
	// bookkeeping about a candidate we could not prepare (see walkErr).
	var fail walkErr
	walk := candidateWalk{budget: c.resolveBudgetTO}
	for i := 0; i < cands.Len(); i++ {
		provider, err := walk.provider(ctx, cands, i)
		if err != nil {
			// A caller that went away ends the walk. It is not a fallback and says
			// nothing about the router's ranking — and without this the loop ground on
			// through every remaining candidate, each failing instantly on the dead
			// context, each counted: one disconnect booked seven materialize fallbacks
			// on an eight-candidate chain, into the series documented as the only signal
			// that the router is ranking badly, with an alert on it.
			if canceledBy(ctx) {
				fail.record(tierMaterialize, resolveErr(err))
				break
			}
			if walk.exhausted() {
				// Name the ceiling. Recorded above the materialize tier because a bare
				// "no usable address" from candidate 0 would otherwise be all the caller
				// got for a request we held for the whole budget.
				c.metricWalkBudgetExhausted()
				fail.record(tierBudget, budgetErr(walk.limit(), err))
				break
			}
			fail.record(tierMaterialize, resolveErr(err))
			c.metricFallback(FallbackMaterialize, i, cands.Len())
			continue
		}

		attemptStart := time.Now()
		out, retry, err := c.completeOnce(ctx, provider, req, ephPub, ephPriv)
		if err == nil {
			return out, nil
		}
		// A failed attempt is wasted caller time and is charged to the walk.
		walk.charge(time.Since(attemptStart))
		fail.record(tierAttempt, err)
		if retry {
			// Same two reasons to stop, and for the same reasons: a disconnect mid-body
			// also surfaces as a retryable failure, and counting it would file the
			// caller's own departure as a bad provider.
			if canceledBy(ctx) {
				break
			}
			if walk.exhausted() {
				c.metricWalkBudgetBlockedFallback(i, cands.Len())
				break
			}
			c.metricFallback(FallbackUpstream, i, cands.Len())
			continue
		}
		return nil, err
	}

	// The chain was exhausted without a success. fail is set whenever Len() > 0
	// (a candidate was tried); guard the impossible empty-chain case anyway.
	if fail.err == nil {
		return nil, stageErr(StageUpstream, fmt.Errorf("no provider candidates to try"))
	}
	return nil, fail.err
}

// completeOnce runs one non-streaming attempt against a single provider under
// its own per-attempt deadline (providerTimeout), so each candidate gets a full
// budget rather than sharing one across the whole fallback chain. retry reports
// whether the caller may fall back to the next candidate:
//   - false (terminal): a request-level seal failure, a 4xx (client fault), or a
//     transport failure that never reached the provider (the same router fronts
//     every candidate, so it recurs).
//   - true (fall back): a transient status (429 / 5xx), a response whose body
//     dropped mid-read, or a 2xx whose sealed body will not decode/open — all
//     provider-side failures with nothing yet returned to the caller.
func (c *Client) completeOnce(parent context.Context, provider Provider, req wire.Request, ephPub []byte, ephPriv crypto.PrivateKey) (wire.Response, bool, error) {
	ctx, cancel := context.WithTimeout(parent, providerTimeout)
	defer cancel()

	sealed, err := c.seal(provider, req, ephPub)
	if err != nil {
		// A seal failure depends on the request, not the provider (e.g. no messages
		// to seal), so it would fail identically for every candidate — terminal.
		// Deliberately unmetered as an upstream attempt: nothing went upstream.
		return nil, false, stageErr(StageRequest, fmt.Errorf("seal request: %w", err))
	}

	// Meter the upstream call from here — after the seal, which is local work — to
	// whichever return follows. The outcome is set at each failure site and reported
	// once by this defer, so a new return cannot silently escape the counter.
	start := time.Now()
	outcome := UpstreamOK
	defer func() { c.metricUpstreamAttempt(UpstreamBuffered, outcome, time.Since(start)) }()

	resp, err := c.doRequest(ctx, provider, sealed)
	if err != nil {
		// Never reached the provider (transport failure); the same router fronts
		// every candidate, so it recurs — terminal. A caller that went away mid-flight
		// looks identical here, so attribute it by asking the parent.
		outcome = upstreamFailureOutcome(parent, ctx, err, UpstreamTransport)
		return nil, false, &Error{Stage: StageUpstream, Err: fmt.Errorf("post to provider: %w", err)}
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		// Surface the provider status verbatim so OpenAI clients can key their
		// retry/backoff on it; the body is untrusted upstream content, carried as
		// Body (not in the message) so a multi-tenant gateway never echoes it (see
		// Error.Body). Read it BOUNDED: an error body should be small, and it is now
		// surfaced to the caller (Body / passthrough), so a broken or hostile
		// upstream must not force an unbounded read. (The 2xx sealed body below is
		// intentionally unbounded — a completion can legitimately be large.) Fall
		// back only on a transient status (429 / 5xx).
		body, _ := io.ReadAll(io.LimitReader(resp.Body, maxUpstreamErrorBytes))
		outcome = upstreamStatusOutcome(resp.StatusCode)
		e := &Error{Stage: StageUpstream, Status: resp.StatusCode, Err: fmt.Errorf("provider returned %d", resp.StatusCode), Body: string(body), Header: resp.Header.Clone()}
		return nil, retryableStatus(resp.StatusCode), e
	}

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		// A response began but the body dropped mid-read: a provider-side failure
		// with nothing delivered to the caller — fall back to the next candidate.
		outcome = upstreamFailureOutcome(parent, ctx, err, UpstreamBody)
		return nil, true, stageErr(StageUpstream, fmt.Errorf("read provider response: %w", err))
	}

	var sealedResp wire.Response
	if err := json.Unmarshal(respBody, &sealedResp); err != nil {
		// A 2xx whose body will not decode/open is a provider fault with nothing
		// yet returned to the caller — fall back (as the streaming path does before
		// its first frame).
		outcome = UpstreamUndecodable
		return nil, true, stageErr(StageUpstream, fmt.Errorf("decode sealed response: %w", err))
	}
	out, err := wire.OpenResponseFor(c.ep.Profile, ephPriv, sealedResp)
	if err != nil {
		c.logOpenFailure(0, sealedResp, err)
		outcome = UpstreamUndecodable
		return nil, true, stageErr(StageUpstream, fmt.Errorf("open response: %w", err))
	}
	// Response-signature verification (hop 11), fail-closed. A response that
	// opened but fails the §8 signature is an integrity/authenticity failure of
	// this provider — terminal, not a fall-back to another candidate (which would
	// mask a bad provider). Nothing is returned to the caller on failure.
	if c.verifyEnabled() {
		if vo, err := c.verifyNonStream(ctx, provider, resp.Header, sealed, sealedResp); err != nil {
			outcome = verifyOutcome(parent, ctx, vo)
			return nil, false, stageErr(StageUpstream, err)
		}
	}
	// Surface this response's ZG-Res-Key handle (and header block) to a caller that
	// asked for it (WithResponseMeta), so a front end can re-expose the handle for
	// independent §8 audit and a curated header subset to its own user. Recorded
	// only here, on the success path, so a discarded fallback attempt never leaves
	// stale metadata behind.
	recordMeta(ctx, provider, resp.Header)
	return out, false, nil
}

// retryableStatus reports whether a provider (data-plane) HTTP status is worth
// falling back to the next candidate for. A rate limit (429) or a server error
// (5xx) is transient and provider-specific, so another provider may succeed; a
// 4xx (a client fault: bad request, auth, not found) is not and fails fast. It
// is only called with a real response status — transport failures (no response)
// and unusable-body failures are classified at their own call sites.
func retryableStatus(status int) bool {
	return status == http.StatusTooManyRequests || (status >= 500 && status <= 599)
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

// seal builds the sealed envelope for one provider: it writes the provider's
// canonical model into the cleartext "model" (so the request names the model
// this specific candidate serves — the preview chain is heterogeneous), forces
// usage reporting on a streaming request, then seals the sensitive fields to the
// provider's enc key. Called once per fallback attempt because the canonical
// model and enc key differ per candidate.
func (c *Client) seal(provider Provider, req wire.Request, ephPub []byte) (wire.Request, error) {
	req = withModel(req, provider.Model)
	req = withStreamUsage(c.ep.Profile, req)
	return wire.SealRequestFor(c.ep.Profile, provider.EncPubKey, req, c.sealedFieldsFor(req), provider.SignerAddr, ephPub, c.unboundFields...)
}

// withStreamUsage forces "stream_options":{"include_usage":true} on a streaming
// request (one with "stream": true), so the provider emits a final usage frame —
// the token counts the caller needs for billing/metrics, which OpenAI otherwise
// omits from a stream. It is a no-op when the request is not streaming.
//
// Setting it client-side before sealing keeps "stream_options" a bound field
// (tamper-evident), the approach preferred over listing it as unbound. Any other
// keys the caller put in "stream_options" are preserved; only include_usage is
// overridden. The map is shallow-copied (like withModel) so the caller's request
// is never mutated across fallback attempts.
//
// It applies to ProfileChat ONLY, which is why it takes the profile rather than
// reading "stream" alone. "stream_options" is OpenAI's CHAT convention: the image
// profile has no stream at all (one JSON object), and the Anthropic profile
// streams but reports usage on its own frames with no such field. Ungated, this
// grafted a fabricated chat field onto every other profile's requests whenever
// the caller's body happened to carry "stream" — see
// TestE2E_Image_NoStreamOptionsGrafted. The HTTP layer refuses "stream" on the
// image endpoint too (endpoint.Image.Streams, acted on by openaiproxy.Register);
// this is the half that holds however the request reached the core.
func withStreamUsage(profile wire.Profile, req wire.Request) wire.Request {
	if profile != wire.ProfileChat {
		return req
	}
	// Only act on a streaming request. A present-but-non-boolean "stream" is left
	// for the proxy/provider to reject; treat it as non-streaming here so a
	// malformed value never gets usage options grafted onto it.
	raw, ok := req["stream"]
	if !ok {
		return req
	}
	var stream bool
	if err := json.Unmarshal(raw, &stream); err != nil || !stream {
		return req
	}

	// Merge onto any existing stream_options, overriding include_usage to true. A
	// malformed stream_options unmarshals to an empty map and is replaced — the
	// forced flag still lands, and the provider would have rejected it anyway.
	opts := map[string]json.RawMessage{}
	if rawOpts, ok := req["stream_options"]; ok {
		_ = json.Unmarshal(rawOpts, &opts)
	}
	opts["include_usage"] = json.RawMessage(`true`)
	merged, err := json.Marshal(opts)
	if err != nil {
		// These values always marshal; treat the impossible case as "leave as-is".
		return req
	}

	out := make(wire.Request, len(req)+1)
	for k, v := range req {
		out[k] = v
	}
	out["stream_options"] = merged
	return out
}

// withModel returns req with its cleartext "model" set to model, leaving req
// untouched when model is empty. It shallow-copies the map (values are opaque
// json.RawMessage shared with req) so overwriting the model never mutates the
// caller's request — the same req is re-sealed to each fallback candidate with
// that candidate's model.
func withModel(req wire.Request, model string) wire.Request {
	if model == "" {
		return req
	}
	m, err := json.Marshal(model)
	if err != nil {
		// A plain string always marshals; treat the impossible case as "no override".
		return req
	}
	out := make(wire.Request, len(req)+1)
	for k, v := range req {
		out[k] = v
	}
	out["model"] = m
	return out
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
