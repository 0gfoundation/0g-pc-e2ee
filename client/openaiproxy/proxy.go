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
	"github.com/0gfoundation/0g-pc-e2ee/protocol/wire"
)

// maxRequestBytes caps the request body the proxy will read.
const maxRequestBytes = 10 << 20 // 10 MiB

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

// Handler returns the OpenAI-compatible proxy over the client core, mounted at
// POST /v1/chat/completions. It is the whole request-handling surface both
// server forms share; callers add their own routes (health, attestation quote)
// on top of the returned mux.
func Handler(c *core.Client, opts ...Option) http.Handler {
	mux := http.NewServeMux()
	Register(mux, c, opts...)
	return mux
}

// Register mounts the proxy's routes on an existing mux, so a caller can serve
// the OpenAI endpoint alongside its own (e.g. the gateway's /healthz and
// /quote) on one server.
func Register(mux *http.ServeMux, c *core.Client, opts ...Option) {
	var o options
	for _, opt := range opts {
		opt(&o)
	}
	mux.HandleFunc("POST /v1/chat/completions", func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxRequestBytes))
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
		stream, err := streamRequested(req)
		if err != nil {
			writeGatewayError(w, http.StatusBadRequest, err.Error())
			return
		}
		// Forward the caller's Authorization header (the 0G key an OpenAI SDK sends)
		// so the provider can authenticate and bill, plus the X-0G-* routing
		// directives the router consumes. Nothing else is forwarded — arbitrary
		// client headers must not leak to the (untrusted) router.
		ctx := core.WithCredential(r.Context(), r.Header.Get("Authorization"))
		ctx = core.WithForwardedHeaders(ctx, routingHeaders(r.Header))
		// Collect the response's ZG-Res-Key handle so we can re-expose it to our own
		// user, who can fetch and audit the §8 signature from the broker.
		meta := &core.ResponseMeta{}
		ctx = core.WithResponseMeta(ctx, meta)
		if stream {
			serveStream(ctx, w, c, req, o, meta)
			return
		}
		resp, err := c.Complete(ctx, req)
		if err != nil {
			o.writeError(w, err)
			return
		}
		out, err := json.Marshal(resp)
		if err != nil {
			writeGatewayError(w, http.StatusInternalServerError, "encode response")
			return
		}
		setResKey(w, meta)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(out)
	})
}

// routingHeaderPrefix is the router-owned namespace of cleartext routing
// directives (provider pin, sort, trust mode, fallbacks, require-parameters).
// Only headers in this namespace are forwarded to the provider; matching is
// case-insensitive since HTTP header names are.
const routingHeaderPrefix = "x-0g-"

// routingHeaders selects the X-0G-* routing directives from the inbound request
// to forward upstream. Restricting to this namespace is deliberate: it lets an
// app steer routing via standard headers without the proxy leaking arbitrary
// client headers (cookies, app-internal metadata) to the untrusted router.
func routingHeaders(h http.Header) http.Header {
	var out http.Header
	for k, vs := range h {
		if !strings.HasPrefix(strings.ToLower(k), routingHeaderPrefix) {
			continue
		}
		if out == nil {
			out = make(http.Header)
		}
		out[k] = vs
	}
	return out
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
// each sealed frame from the core and re-emits it as `data: <json>` to the user,
// terminating with `data: [DONE]`. Status is only settable before the first
// frame; once bytes are on the wire an error can only end the stream.
func serveStream(ctx context.Context, w http.ResponseWriter, c *core.Client, req wire.Request, o options, meta *core.ResponseMeta) {
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
		// The core records the handle at stream commit, before the first frame
		// reaches this callback, so it is available here before we write headers.
		setResKey(w, meta)
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		w.Header().Set("X-Accel-Buffering", "no") // ask a fronting proxy (nginx) not to buffer
		w.WriteHeader(http.StatusOK)
		wroteHeader = true
	}

	err := c.CompleteStream(ctx, req, func(frame wire.Response) error {
		b, err := json.Marshal(frame)
		if err != nil {
			return err
		}
		writeHeader()
		if _, err := fmt.Fprintf(w, "data: %s\n\n", b); err != nil {
			return err
		}
		flusher.Flush()
		return nil
	})
	if err != nil {
		if !wroteHeader {
			// Nothing sent yet — a normal error response with a real status.
			o.writeError(w, err)
			return
		}
		// Mid-stream: surface as a final SSE error event, then stop. Build the
		// payload with json.Marshal — %q is not JSON-safe for arbitrary bytes.
		errEvent, _ := json.Marshal(o.errorEnvelope(err))
		fmt.Fprintf(w, "data: %s\n\n", errEvent)
		flusher.Flush()
		return
	}
	// A successful stream always delivered its final frame, so wroteHeader is
	// already true here; this is a defensive no-op guard.
	writeHeader()
	fmt.Fprint(w, "data: [DONE]\n\n")
	flusher.Flush()
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
// the upstream status surfaced verbatim (statusFor).
func (o options) writeError(w http.ResponseWriter, err error) {
	writeErrorObject(w, statusFor(err), o.errorEnvelope(err))
}
