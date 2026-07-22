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

// Handler returns the OpenAI-compatible proxy over the client core, mounted at
// POST /v1/chat/completions. It is the whole request-handling surface both
// server forms share; callers add their own routes (health, attestation quote)
// on top of the returned mux.
func Handler(c *core.Client) http.Handler {
	mux := http.NewServeMux()
	Register(mux, c)
	return mux
}

// Register mounts the proxy's routes on an existing mux, so a caller can serve
// the OpenAI endpoint alongside its own (e.g. the gateway's /healthz and
// /quote) on one server.
func Register(mux *http.ServeMux, c *core.Client) {
	mux.HandleFunc("POST /v1/chat/completions", func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxRequestBytes))
		if err != nil {
			var tooLarge *http.MaxBytesError
			if errors.As(err, &tooLarge) {
				writeError(w, http.StatusRequestEntityTooLarge, "request body too large")
				return
			}
			writeError(w, http.StatusBadRequest, "read request body")
			return
		}
		var req wire.Request
		if err := json.Unmarshal(body, &req); err != nil {
			writeError(w, http.StatusBadRequest, "request body is not a JSON object")
			return
		}
		stream, err := streamRequested(req)
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		// Forward the caller's Authorization header (the 0G key an OpenAI SDK sends)
		// so the provider can authenticate and bill, plus the X-0G-* routing
		// directives the router consumes. Nothing else is forwarded — arbitrary
		// client headers must not leak to the (untrusted) router.
		ctx := core.WithCredential(r.Context(), r.Header.Get("Authorization"))
		ctx = core.WithForwardedHeaders(ctx, routingHeaders(r.Header))
		if stream {
			serveStream(ctx, w, c, req)
			return
		}
		resp, err := c.Complete(ctx, req)
		if err != nil {
			writeError(w, statusFor(err), err.Error())
			return
		}
		out, err := json.Marshal(resp)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "encode response")
			return
		}
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
func serveStream(ctx context.Context, w http.ResponseWriter, c *core.Client, req wire.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		writeError(w, http.StatusInternalServerError, "streaming not supported by server")
		return
	}

	wroteHeader := false
	writeHeader := func() {
		if wroteHeader {
			return
		}
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
			writeError(w, statusFor(err), err.Error())
			return
		}
		// Mid-stream: surface as a final SSE error event, then stop. Build the
		// payload with json.Marshal — %q is not JSON-safe for arbitrary bytes.
		errEvent, _ := json.Marshal(map[string]any{"error": map[string]string{"message": err.Error()}})
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

// writeError emits an OpenAI-shaped error object.
func writeError(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"error": map[string]string{"message": msg},
	})
}
