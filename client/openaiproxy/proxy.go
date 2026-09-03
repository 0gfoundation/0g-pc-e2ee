// Package openaiproxy is the OpenAI-compatible HTTP front end over the client
// core, shared by the two server forms that expose it: the local sidecar
// (user-operated, on localhost) and the cloud-TEE gateway (0G-operated, in an
// attested CVM). Both accept plain OpenAI chat-completions requests, seal the
// sensitive fields to the provider via the core, and stream or buffer the
// opened response back — so the only difference between the forms is where the
// process runs and how the provider identity is established, not the request
// handling itself.
package openaiproxy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/0gfoundation/0g-pc-e2ee/client/core"
	"github.com/0gfoundation/0g-pc-e2ee/client/endpoint"
	"github.com/0gfoundation/0g-pc-e2ee/client/metrics"
	"github.com/0gfoundation/0g-pc-e2ee/protocol/wire"
)

// MaxRequestBytes caps the request body the proxy will read. It is read fully
// into memory before anything else happens (Register below), so it is also the
// dominant term in what one in-flight request can COST in memory — which is why
// it is exported: the gateway sizes its concurrency ceiling from it, and a copy
// of the number over there could drift from this one.
const MaxRequestBytes = 10 << 20 // 10 MiB

// headerResKey mirrors the provider's ZG-Res-Key response header. The proxy
// re-emits the handle the core captured under the same name, so the front end's
// user gets the same handle a direct call would — to fetch and independently
// audit the §8 signature from the broker. It is a lookup handle, not key
// material, so re-exposing it is safe on both server forms.
const headerResKey = "ZG-Res-Key"

// setResKey re-emits the ZG-Res-Key handle the core captured for this response,
// when the provider sent one. It must be called before the response header is
// written (before WriteHeader or the first body byte), or it is a no-op that Go
// discards with a "superfluous WriteHeader" warning.
func setResKey(w http.ResponseWriter, meta *core.ResponseMeta) {
	if meta != nil && meta.ResKey != "" {
		w.Header().Set(headerResKey, meta.ResKey)
	}
}

// headerProvider names the provider a request was routed to. The gateway
// ORIGINATES it from the address the client itself pinned
// (core.ResponseMeta.Provider) rather than forwarding the upstream's same-named
// header — see setProvider for what the value does and does not assert. The name
// is kept as the router's so existing clients keep reading the field they already
// read; only its provenance changes, from an assertion to a fact.
const headerProvider = "X-Provider"

// passthroughResponseHeaders is the curated set of upstream (router) response
// headers the gateway surfaces back to its own user. All are non-sensitive
// operational metadata a thin client needs to behave correctly: the broker's
// fault attribution (and its legacy alias), the per-IP rate-limit counters with
// their reset/Retry-After hints, and the request-correlation id for bug reports.
//
// Two headers are absent from the list but still reach the user, by different
// routes and for different reasons. ZG-Res-Key is RELAYED, just not from here:
// setResKey re-emits the upstream's value out of core.ResponseMeta, which is where
// the core captured it. X-Provider is ORIGINATED: setProvider ignores the
// upstream's same-named header entirely and emits the client's own routing pin.
// The distinction is the point — one is the provider's value carried faithfully,
// the other is ours because the upstream's could not be trusted to state it.
//
// Everything not on this list stays inside the gateway, so an upstream header can
// never leak untrusted or identifying detail to the user by default.
var passthroughResponseHeaders = []string{
	"ZG-Failure-Source",
	"X-ZG-Failure-Source",
	"Retry-After",
	"X-Request-ID",
	"X-RateLimit-Limit-Requests",
	"X-RateLimit-Remaining-Requests",
	"X-RateLimit-Reset-Requests",
	"X-RateLimit-Limit-Day",
	"X-RateLimit-Remaining-Day",
	"X-RateLimit-Reset-Day",
}

// setProvider emits the address the client resolved, sealed this request to, and
// pinned the route to with X-0G-Provider-Address.
//
// Read that literally: it is what the request was SEALED TO and PINNED TO, not
// proof of who produced the bytes. The response is HPKE-sealed to the client's
// ephemeral public key, which the request carries in its `_e2ee` block —
// AAD-protected, so an intermediary cannot swap it, but readable, and reading it is
// all one needs to seal a response the client will open (HPKE base mode does not
// authenticate the sender). Who answered is established by the §8 signature, and
// only when the deployment enables it (-verify-responses, off by default).
//
// So with verification off this header answers "who did we address" and cannot
// answer "who replied"; with it on, a response that reaches the caller at all is
// one whose signature recovered to the grounded signer, and the two coincide.
//
// Being careful here is the same discipline as the change itself: the previous
// value was wrong because it stated more than the system knew, and a doc comment
// that overstates what this one means would reintroduce that at the layer above.
//
// It replaces forwarding the router's own X-Provider, which was an
// unauthenticated assertion the gateway never checked against its own pin. Nothing
// in the trust chain would have caught a router that routed honestly and then
// misreported where it had routed: the response signature still verifies, because
// the routing was never changed. The value was therefore wrong in exactly the case
// a user would most want it right, and re-emitting it from the pin makes "this
// field names the provider we sealed to" true by construction instead of by a
// runtime comparison that could be forgotten.
//
// What it asserts is available before any byte of the body, which is why it can be
// set on the streaming path too: the claim is "we sealed this to X and pinned the
// route to X", which is settled once a provider is chosen. It is deliberately not
// a claim that X's §8 signature verified — that is decided after the final frame,
// long after headers must be flushed. Whether the pinned address is additionally
// grounded on-chain is a property of the deployment's trust mode (see
// docs/design/trust-chain.md hop 5), not of this header.
//
// Like setResKey it must run before WriteHeader or the first body byte, and it
// emits nothing when the meta carries no address: direct-broker mode, where there
// is no router to pin through, and every failed request, since the core records
// this only on the path that produced a delivered response.
//
// That second case is a deliberate trade, not an oversight. An error is not always
// "nobody answered" — a 429 means a provider did — so dropping the header there
// does cost a caller the attribution it used to get on a rate limit. But what it
// used to get was the router's unverified claim, and the honest replacement is not
// available: with the fallback chain, a request may have tried several candidates,
// and naming one of them would raise the same question this change exists to close
// — which provider is this, really. Absent beats both fabricated and ambiguous.
// The error envelope's _0g.source and the passed-through ZG-Failure-Source still
// attribute the failure to the router or the provider side.
func setProvider(w http.ResponseWriter, meta *core.ResponseMeta) {
	if meta != nil && meta.Provider != "" {
		w.Header().Set(headerProvider, meta.Provider)
	}
}

// setPassthrough re-emits the curated subset of an upstream response header
// block (src) onto the front-end response — used on both the success path
// (core.ResponseMeta.Header) and the error path (core.Error.Header, so a 429's
// Retry-After and rate-limit counters reach the caller). Like setResKey it must
// run before WriteHeader or the first body byte. A nil src or a header the
// upstream did not send is skipped, so nothing is fabricated; multi-valued
// headers are preserved entry-for-entry.
func setPassthrough(w http.ResponseWriter, src http.Header) {
	for _, name := range passthroughResponseHeaders {
		for _, v := range src.Values(name) {
			w.Header().Add(name, v)
		}
	}
}

// upstreamHeader returns the upstream response header block carried by a
// core.Error (a non-2xx or malformed upstream reply), or nil for a transport
// failure or any non-core error — nothing to surface in those cases.
func upstreamHeader(err error) http.Header {
	var e *core.Error
	if errors.As(err, &e) {
		return e.Header
	}
	return nil
}

// Option customizes the proxy's behavior.
type Option func(*options)

type options struct {
	verboseUpstreamErrors bool
}

// WithVerboseUpstreamErrors makes the proxy append the raw upstream response
// body (core.Error.Body) to the error it returns on an upstream failure. This
// aids debugging and is appropriate for the single-user, localhost sidecar. The
// multi-tenant gateway must NOT use it: the upstream body is untrusted content
// and could expose another tenant's or the provider's internal detail. Off by
// default, so the safe behavior is the one you get without thinking about it.
func WithVerboseUpstreamErrors() Option {
	return func(o *options) { o.verboseUpstreamErrors = true }
}

// maxEchoBodyBytes caps the raw upstream body echoed under verbose errors.
const maxEchoBodyBytes = 8 << 10 // 8 KiB

// errorEnvelope builds the JSON response body for a failed request:
//
//	{"error": <object>, "_0g": {"source": ..., "upstream_status": ...}}
//
// When the failure carried a well-formed upstream error object (the router's or
// broker's own client-facing {"error": {...}}), that object is passed through
// VERBATIM — so a client keying off its message/type/code sees exactly what a
// direct call would, restoring the transparency the gateway hop would otherwise
// swallow. Otherwise `error` is a synthesized gateway/sidecar object.
//
// Attribution lives in the sibling `_0g` block, never inside `error`, so it can
// never collide with or overwrite an upstream field (source = gateway|upstream,
// plus the verbatim upstream_status when there was one). The raw upstream body is
// echoed only under verbose errors (the single-user sidecar): a well-formed
// upstream error is already client-facing, but an unparseable/non-JSON body may
// be transport noise or internal detail a multi-tenant gateway must not leak.
func (o options) errorEnvelope(err error) map[string]any {
	var e *core.Error
	if !errors.As(err, &e) {
		return map[string]any{
			"error": map[string]any{"message": err.Error(), "type": "gateway_error"},
			"_0g":   map[string]any{"source": "gateway"},
		}
	}
	attribution := map[string]any{"source": e.Source()}
	if e.Status != 0 {
		attribution["upstream_status"] = e.Status
	}
	if e.Stage == core.StageUpstream {
		if obj, ok := parseUpstreamErrorObject(e.Body); ok {
			return map[string]any{"error": obj, "_0g": attribution}
		}
	}
	if o.verboseUpstreamErrors && e.Body != "" {
		attribution["upstream_body"] = truncate(e.Body, maxEchoBodyBytes)
	}
	return map[string]any{
		"error": map[string]any{"message": e.Error(), "type": e.Source() + "_error"},
		"_0g":   attribution,
	}
}

// parseUpstreamErrorObject returns the upstream reply's `error` object when the
// body is a well-formed OpenAI-shaped error ({"error": {"message": ...}}), so it
// can be passed through verbatim. Returns ok=false for an empty, non-JSON, or
// message-less body.
func parseUpstreamErrorObject(body string) (map[string]any, bool) {
	if body == "" {
		return nil, false
	}
	var wrapper struct {
		Error map[string]any `json:"error"`
	}
	if err := json.Unmarshal([]byte(body), &wrapper); err != nil || wrapper.Error == nil {
		return nil, false
	}
	if msg, ok := wrapper.Error["message"].(string); !ok || msg == "" {
		return nil, false
	}
	return wrapper.Error, true
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…(truncated)"
}

// Handler returns the OpenAI-compatible proxy over the client core with the
// CHAT surface mounted, for a caller that serves only chat: the sidecar, and
// every test that is about the proxy rather than about which surface it carries.
// Callers add their own routes (health, attestation quote) on top of the
// returned mux.
//
// It is a convenience over Register, not a second implementation — one line,
// naming endpoint.Chat. A caller serving more than chat calls Register per row
// of endpoint.All.
func Handler(c *core.Client, opts ...Option) http.Handler {
	mux := http.NewServeMux()
	Register(mux, endpoint.Chat, c, opts...)
	return mux
}

// Register mounts ONE sealed surface — the endpoint ep describes, sealed to c —
// on an existing mux, so a caller can serve several alongside its own routes
// (the gateway's /healthz) on one server.
//
// One handler serves every surface. What differs between them travels in ep:
// the path it mounts on, whether a streaming request is a mode to serve or a
// caller error, and any body normalisation the surface owes before sealing
// (ep.PreSeal). Everything else here — the body cap, the credential and routing
// headers forwarded, the response metadata re-exposed, the error envelope — is
// common to all of them, and was previously copied per surface.
//
// c must be built for ep (core.WithEndpoint): a client's profile fixes which
// field it seals, so a mismatch fails closed at seal time rather than serving
// the wrong rules. Register does not check it, because a *core.Client does not
// publish its endpoint; proxycli builds the two together from one row.
func Register(mux *http.ServeMux, ep endpoint.Endpoint, c *core.Client, opts ...Option) {
	var o options
	for _, opt := range opts {
		opt(&o)
	}
	mux.HandleFunc("POST "+ep.Path, func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, MaxRequestBytes))
		if err != nil {
			var tooLarge *http.MaxBytesError
			if errors.As(err, &tooLarge) {
				writeGatewayError(w, http.StatusRequestEntityTooLarge, "request body too large")
				return
			}
			writeGatewayError(w, http.StatusBadRequest, "read request body")
			return
		}
		var req wire.Request
		if err := json.Unmarshal(body, &req); err != nil {
			writeGatewayError(w, http.StatusBadRequest, "request body is not a JSON object")
			return
		}
		// `stream` is parsed for EVERY surface, so a malformed value gets one
		// answer whichever one the caller hit. What a true means is the surface's
		// property: a mode to serve where ep.Streams, and a caller error where it
		// does not — refused rather than ignored, the same way an explicit
		// `response_format: "url"` is refused rather than rewritten.
		stream, err := streamRequested(req)
		if err != nil {
			writeGatewayError(w, http.StatusBadRequest, err.Error())
			return
		}
		if stream && !ep.Streams {
			writeGatewayError(w, http.StatusBadRequest, fmt.Sprintf(
				"field \"stream\" is not supported for POST %s: the response is a single JSON object", ep.Path))
			return
		}
		if ep.PreSeal != nil {
			if req, err = ep.PreSeal(req); err != nil {
				writeGatewayError(w, http.StatusBadRequest, err.Error())
				return
			}
		}
		// Forward the caller's 0G key (an OpenAI SDK sends it as Authorization, an
		// Anthropic SDK as x-api-key) so the provider can authenticate and bill, plus
		// the X-0G-* routing directives and the app-attribution headers the router
		// consumes. Nothing else is forwarded — arbitrary client headers must not
		// leak to the (untrusted) router.
		ctx := core.WithCredential(r.Context(), credential(r))
		ctx = core.WithForwardedHeaders(ctx, routingHeaders(r.Header))
		// Collect the response's ZG-Res-Key handle so we can re-expose it to our own
		// user, who can fetch and audit the §8 signature from the broker.
		meta := &core.ResponseMeta{}
		ctx = core.WithResponseMeta(ctx, meta)
		if stream {
			serveStream(ctx, w, ep, c, req, o, meta)
			return
		}
		resp, err := c.Complete(ctx, req)
		recordCompletion(err)
		if err != nil {
			o.writeError(w, err)
			return
		}
		out, err := json.Marshal(resp)
		if err != nil {
			writeGatewayError(w, http.StatusInternalServerError, "encode response")
			return
		}
		setPassthrough(w, meta.Header)
		setResKey(w, meta)
		setProvider(w, meta)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(out)
	})
}

// routingHeaderPrefix is the router-owned namespace of cleartext routing
// directives (provider pin, sort, trust mode, fallbacks, require-parameters).
// Only headers in this namespace are forwarded to the provider; matching is
// case-insensitive since HTTP header names are.
const routingHeaderPrefix = "x-0g-"

// attributionHeaders are the request headers the router also consumes for
// traffic attribution but which sit outside the X-0G-* namespace: the
// OpenRouter-convention app identity (HTTP-Referer is intentionally the
// misspelled form the router matches; X-Title is the app title). They are the
// same self-reported, unauthenticated class as X-0G-Source-Id — the router
// drops unknown values — so forwarding them keeps partner/app attribution
// working when traffic enters at the gateway instead of the router, without
// widening the leak surface beyond metadata that carries no prompt content.
// Keys are lower-cased for the case-insensitive match.
var attributionHeaders = map[string]bool{
	"http-referer": true,
	"x-title":      true,
}

// routingHeaders selects the headers the router legitimately consumes — the
// X-0G-* routing directives and the app-attribution headers — from the inbound
// request to forward upstream. Restricting to this set is deliberate: it lets an
// app steer routing and report attribution via standard headers without the
// proxy leaking arbitrary client headers (cookies, app-internal metadata) to the
// untrusted router.
func routingHeaders(h http.Header) http.Header {
	var out http.Header
	for k, vs := range h {
		lk := strings.ToLower(k)
		if !strings.HasPrefix(lk, routingHeaderPrefix) && !attributionHeaders[lk] {
			continue
		}
		if out == nil {
			out = make(http.Header)
		}
		out[k] = vs
	}
	return out
}

// credential extracts the caller's 0G key as an Authorization value for the
// provider request. It prefers the Authorization header verbatim (an OpenAI SDK
// sends `Bearer <key>`); absent that it accepts the Anthropic-convention
// x-api-key header and wraps it as a bearer credential — the router's
// Authorization parse requires the `Bearer ` prefix, while x-api-key is sent
// raw, so the raw key must be wrapped rather than passed through as-is. Returns
// "" when neither is present, which leaves the provider request unauthenticated
// (the core sets no Authorization for an empty credential).
func credential(r *http.Request) string {
	if auth := r.Header.Get("Authorization"); auth != "" {
		return auth
	}
	if apiKey := r.Header.Get("x-api-key"); apiKey != "" {
		return "Bearer " + apiKey
	}
	return ""
}

// streamRequested reports whether the request asked for a streamed (SSE)
// response. A present-but-non-boolean "stream" is an error, so a malformed value
// is rejected rather than silently treated as non-streaming.
func streamRequested(req wire.Request) (bool, error) {
	raw, ok := req["stream"]
	if !ok {
		return false, nil
	}
	var stream bool
	if err := json.Unmarshal(raw, &stream); err != nil {
		return false, fmt.Errorf(`field "stream" must be a boolean`)
	}
	return stream, nil
}

// recordCompletion meters one chat-completion outcome (streaming or buffered),
// attributing a failure to where it originated via core.Error.Source/Stage so a
// gateway-side fault is countable apart from a router/provider one. A success
// carries neutral source/stage; a non-core error (should not occur on this path)
// is attributed to the gateway with an "unknown" stage rather than dropped.
func recordCompletion(err error) {
	if err == nil {
		metrics.Completion("success", "none", "none")
		return
	}
	var e *core.Error
	if errors.As(err, &e) {
		metrics.Completion("error", e.Source(), e.Stage)
		return
	}
	metrics.Completion("error", "gateway", "unknown")
}

// statusFor maps a Complete failure to an HTTP status. A non-2xx provider status
// is surfaced verbatim (so OpenAI clients keep their retry/backoff on 429/5xx vs
// 4xx); otherwise a bad client request is 400, a client-side internal error is
// 500, and anything upstream (transport failure, bad sealed response) is 502.
func statusFor(err error) int {
	var e *core.Error
	if errors.As(err, &e) {
		if e.Status != 0 {
			return e.Status
		}
		switch e.Stage {
		case core.StageRequest:
			return http.StatusBadRequest
		case core.StageInternal:
			return http.StatusInternalServerError
		}
	}
	return http.StatusBadGateway
}

// serveStream proxies a streaming completion as Server-Sent Events: it opens
// each sealed frame from the core and re-emits it to the user. Status is only
// settable before the first frame; once bytes are on the wire an error can only
// end the stream.
//
// The FRAMING follows the surface, which is why this takes the row. An OpenAI
// chat stream is unnamed events terminated by a `[DONE]` sentinel; a frame-typed
// stream (Anthropic) names every event and ends with a terminal frame of its
// own. Emitting the chat framing for both is not a lesser version of the
// protocol — an Anthropic SDK dispatches on the event name, so unnamed frames
// arrive unusable, and the trailing `[DONE]` is an event its taxonomy has no
// rule for.
func serveStream(ctx context.Context, w http.ResponseWriter, ep endpoint.Endpoint, c *core.Client, req wire.Request, o options, meta *core.ResponseMeta) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		writeGatewayError(w, http.StatusInternalServerError, "streaming not supported by server")
		return
	}

	wroteHeader := false
	writeHeader := func() {
		if wroteHeader {
			return
		}
		// The core records the metadata at stream commit, before the first frame
		// reaches this callback, so it is available here before we write headers —
		// including which provider the stream committed to, which is settled at that
		// point and cannot change for the rest of the stream.
		setPassthrough(w, meta.Header)
		setResKey(w, meta)
		setProvider(w, meta)
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		w.Header().Set("X-Accel-Buffering", "no") // ask a fronting proxy (nginx) not to buffer
		w.WriteHeader(http.StatusOK)
		wroteHeader = true
	}

	err := c.CompleteStream(ctx, req, func(frame wire.Response) error {
		// Rebuilt from the OPENED frame's own bound discriminator, which is what
		// §7.2 requires of a receiver: the `event:` line sits outside the JSON and
		// so outside the AAD, meaning an intermediary can rewrite it undetected —
		// the sender drops the upstream's line and we derive our own. "" for a
		// profile with no event taxonomy, which is how the chat surface keeps
		// emitting exactly the bytes it always has.
		name, err := wire.ResponseEventName(ep.Profile, frame)
		if err != nil {
			return err
		}
		b, err := json.Marshal(frame)
		if err != nil {
			return err
		}
		writeHeader()
		if err := writeSSEEvent(w, name, b); err != nil {
			return err
		}
		flusher.Flush()
		return nil
	})
	recordCompletion(err)
	if err != nil {
		if !wroteHeader {
			// Nothing sent yet — a normal error response with a real status.
			o.writeError(w, err)
			return
		}
		// Mid-stream: surface as a final SSE error event, then stop. Build the
		// payload with json.Marshal — %q is not JSON-safe for arbitrary bytes.
		envelope := o.errorEnvelope(err)
		errName := ""
		if wire.ResponseFramesAreTyped(ep.Profile) {
			// Announce it as the surface's own error event, and carry the top-level
			// discriminator its clients read. The envelope already holds an `error`
			// object with `type`/`message` plus the `_0g` attribution, so this adds
			// the one field that makes it dispatchable rather than reshaping a
			// documented body — an unnamed event here would be silently ignored by
			// an SDK and the stream would simply stop with no reason given.
			errName = "error"
			envelope["type"] = "error"
		}
		errEvent, _ := json.Marshal(envelope)
		_ = writeSSEEvent(w, errName, errEvent)
		flusher.Flush()
		return
	}
	// A successful stream always delivered its final frame, so wroteHeader is
	// already true here; this is a defensive no-op guard.
	writeHeader()
	// `[DONE]` is an OpenAI CHAT convention. A frame-typed stream already ended
	// with its own terminal frame (message_stop, or error on a turn that failed
	// partway), and the core refuses a stream that arrives without one — so there
	// is nothing left to terminate, and an extra unnamed event would be one the
	// taxonomy has no rule for. Image never reaches here (Register refuses
	// `stream` on a row that does not stream).
	if !wire.ResponseFramesAreTyped(ep.Profile) {
		fmt.Fprint(w, "data: [DONE]\n\n")
	}
	flusher.Flush()
}

// writeSSEEvent writes one Server-Sent Event, announcing it by name when the
// surface has an event taxonomy and omitting the `event:` line entirely when it
// does not — so a chat stream stays byte-for-byte what it was.
func writeSSEEvent(w io.Writer, name string, payload []byte) error {
	if name != "" {
		if _, err := fmt.Fprintf(w, "event: %s\n", name); err != nil {
			return err
		}
	}
	_, err := fmt.Fprintf(w, "data: %s\n\n", payload)
	return err
}

// writeErrorObject emits a JSON error response body at the given status.
func writeErrorObject(w http.ResponseWriter, code int, body map[string]any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(body)
}

// WriteError emits the proxy's canonical JSON error envelope — the same shape
// errorEnvelope produces — at the given status:
//
//	{"error": {"message": msg, "type": source+"_error"}, "_0g": {"source": source}}
//
// It is exported so a caller mounting its own routes on the shared mux (the
// gateway's catch-all reverse proxy to the router) can fail with the same
// structured body a thin client already parses on the sealed path, instead of a
// bespoke plaintext error. source is the attribution: "gateway" for a fault in
// the proxy itself, "upstream" for a failure reaching or among the
// router/provider. Pass a generic msg — never a raw transport error — so a
// multi-tenant gateway does not leak internal detail (router host, key material).
func WriteError(w http.ResponseWriter, status int, source, msg string) {
	writeErrorObject(w, status, map[string]any{
		"error": map[string]any{"message": msg, "type": source + "_error"},
		"_0g":   map[string]any{"source": source},
	})
}

// writeGatewayError emits a gateway-origin error — a fault in this proxy itself,
// before or around the core call (bad request, encode failure) — attributed to
// source "gateway".
func writeGatewayError(w http.ResponseWriter, code int, msg string) {
	WriteError(w, code, "gateway", msg)
}

// writeError emits a core.Error (or any error) as the attributed envelope, with
// the upstream status surfaced verbatim (statusFor). It first re-emits the
// curated upstream response headers (Retry-After / rate-limit on a 429, the
// broker's fault attribution), which must be set before writeErrorObject writes
// the status line.
func (o options) writeError(w http.ResponseWriter, err error) {
	setPassthrough(w, upstreamHeader(err))
	writeErrorObject(w, statusFor(err), o.errorEnvelope(err))
}
