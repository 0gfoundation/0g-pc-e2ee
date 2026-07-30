package openaiproxy

import (
	"crypto/rand"
	"encoding/hex"
	"log/slog"
	"net/http"
	"time"

	"github.com/0gfoundation/0g-pc-e2ee/client/metrics"
)

// requestIDHeader is the correlation id the proxy honors on the way in and
// echoes on the way out, so one request can be stitched across a fronting proxy,
// the proxy's own access log, and (later) a provider's logs. A caller or ingress
// may supply one; absent or malformed, the proxy mints its own.
const requestIDHeader = "X-Request-Id"

// providerPinHeader is the routing directive a caller sets to pin a specific
// provider (routingHeaders forwards it to the router). The access log records
// only whether it was present — a boolean, never the address — as a cheap signal
// distinguishing pinned from router-chosen traffic.
const providerPinHeader = "X-0G-Provider-Address"

// healthzPath is skipped by the access log: an orchestrator's liveness probes
// hit it continuously and would otherwise drown the log in noise that carries no
// per-request information. Only the gateway mounts it; the sidecar never serves
// this path, so the skip is a harmless no-op there.
const healthzPath = "/healthz"

// maxForwardedRequestIDLen bounds a caller-supplied request id. A longer (or
// non-printable) value is not trusted and is replaced with a freshly minted id
// rather than truncated — a truncated id is not the caller's id.
const maxForwardedRequestIDLen = 128

// LogRequests wraps h so every request (health probes excepted) emits exactly
// one structured, redaction-safe log line when it completes: HTTP metadata only
// — request id, method, path, status, latency, response byte count, whether the
// caller pinned a provider, and whether the response was streamed — and never
// request or response content, credentials, or key material. Both proxy forms
// share it so their logs don't drift.
//
// The discipline is load-bearing for the cloud-TEE gateway: it is a confidential
// enclave (docs/design/cloud-gateway.md), so its operator-visible logs must not
// become a side channel for the plaintext the E2EE seal protects. The local
// sidecar has no such constraint, but there is no reason for it to log
// differently, so it runs the same middleware. This is the request-level
// counterpart to the core's open-failure debug logger, which is likewise
// metadata-only.
//
// The wrapper preserves http.Flusher so the streaming (SSE) path keeps flushing
// frame by frame; a ResponseWriter that silently dropped Flush would buffer the
// whole stream into one delivery.
func LogRequests(logger *slog.Logger, h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == healthzPath {
			h.ServeHTTP(w, r)
			return
		}

		// Metric and log the same requests, from the same wrapper, so the two never
		// drift; health probes are excluded above (they carry no per-request signal
		// and would swamp both). The route label is a bounded template, never the raw
		// path (see metrics.RouteLabel) — the same redaction discipline as the log.
		route := metrics.RouteLabel(r.URL.Path)
		metrics.IncInFlight()
		defer metrics.DecInFlight()

		id := requestID(r)
		w.Header().Set(requestIDHeader, id)

		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		start := time.Now()
		h.ServeHTTP(rec, r)
		dur := time.Since(start)

		metrics.HTTPRequest(route, r.Method, rec.status, dur)

		// Level tracks status so a fronting log system (Phala today, GCP Cloud
		// Logging later) maps 5xx to error and 4xx to warning severity for free.
		level := slog.LevelInfo
		switch {
		case rec.status >= 500:
			level = slog.LevelError
		case rec.status >= 400:
			level = slog.LevelWarn
		}
		logger.LogAttrs(r.Context(), level, "request",
			slog.String("request_id", id),
			slog.String("method", r.Method),
			slog.String("path", r.URL.Path),
			slog.Int("status", rec.status),
			slog.Int64("duration_ms", dur.Milliseconds()),
			slog.Int("bytes_out", rec.bytes),
			slog.Bool("provider_pinned", r.Header.Get(providerPinHeader) != ""),
			slog.Bool("stream", rec.streamed()),
		)
	})
}

// requestID returns the caller-supplied X-Request-Id when it is present and
// well-formed, otherwise a freshly minted 64-bit hex id. The minted id is opaque
// and carries no request content, so it is safe to log and to echo back.
func requestID(r *http.Request) string {
	if v := r.Header.Get(requestIDHeader); validForwardedID(v) {
		return v
	}
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		// crypto/rand failing is unexpected; a fixed sentinel keeps the log line
		// well-formed rather than propagating the error into the request path.
		return "unknown"
	}
	return hex.EncodeToString(b[:])
}

// validForwardedID accepts a caller id only if it is non-empty, within the
// length bound, and printable ASCII — enough to keep log lines clean without
// trusting the value's meaning (the slog handler already escapes it safely).
func validForwardedID(v string) bool {
	if v == "" || len(v) > maxForwardedRequestIDLen {
		return false
	}
	for i := 0; i < len(v); i++ {
		if v[i] < 0x20 || v[i] > 0x7e {
			return false
		}
	}
	return true
}

// statusRecorder wraps an http.ResponseWriter to capture the status code and the
// number of body bytes written, for the access log. It forwards Flush so the SSE
// streaming path is unaffected.
type statusRecorder struct {
	http.ResponseWriter
	status      int
	bytes       int
	wroteHeader bool
}

func (s *statusRecorder) WriteHeader(code int) {
	if s.wroteHeader {
		return
	}
	s.status = code
	s.wroteHeader = true
	s.ResponseWriter.WriteHeader(code)
}

func (s *statusRecorder) Write(b []byte) (int, error) {
	if !s.wroteHeader {
		s.WriteHeader(http.StatusOK)
	}
	n, err := s.ResponseWriter.Write(b)
	s.bytes += n
	return n, err
}

// Flush forwards to the underlying writer's Flush so serveStream can push each
// SSE frame immediately; without it, wrapping the writer would silently turn a
// streamed response into a buffered one.
func (s *statusRecorder) Flush() {
	if f, ok := s.ResponseWriter.(http.Flusher); ok {
		s.wroteHeader = true
		f.Flush()
	}
}

// streamed reports whether the response was served as Server-Sent Events, so the
// access log can distinguish streaming from buffered completions. It reads the
// response Content-Type the handler set (serveStream sets text/event-stream).
func (s *statusRecorder) streamed() bool {
	return s.Header().Get("Content-Type") == "text/event-stream"
}
