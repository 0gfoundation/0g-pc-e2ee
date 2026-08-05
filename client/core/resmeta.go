package core

import (
	"context"
	"net/http"
)

// responseMetaKey is the unexported context key under which a *ResponseMeta sink
// travels back out of a completion.
type responseMetaKey struct{}

// ResponseMeta is a sink for out-of-band metadata about a single completion —
// data that is neither part of the opened response body nor an error. The caller
// allocates one, attaches it with WithResponseMeta, and reads it after
// Complete/CompleteStream returns.
//
// It currently carries only the ZG-Res-Key handle, so a front end (the sidecar
// or gateway) can re-expose it to its own user, who can then fetch the §8
// signature from the broker and audit it independently. The value is a lookup
// handle, not key material and not the response encryption key, so surfacing it
// is safe even on the multi-tenant gateway.
type ResponseMeta struct {
	// ResKey is the provider's ZG-Res-Key response header (the broker's chatKey).
	// Empty when the provider sent none (e.g. a provider that does not cache a §8
	// signature), which the caller treats as "no handle", not an error.
	ResKey string

	// Header is a clone of the upstream response's header block — the router's
	// response, since the sealed request goes through the router for auth/billing.
	// The core captures it verbatim and takes no view on which entries are safe to
	// surface; a front end decides that (the gateway re-emits a curated,
	// non-sensitive subset — rate-limit counters, Retry-After, the broker's
	// fault-attribution and the request-correlation id — back to its own user).
	// Nil when no response was received (a failed attempt); recorded only on the
	// path that produced the delivered response, so it never reflects a discarded
	// fallback attempt.
	Header http.Header
}

// WithResponseMeta returns a context carrying a sink the core fills with
// per-response metadata (currently the ZG-Res-Key handle). A nil sink is a
// no-op, so a caller that does not want the metadata changes nothing.
func WithResponseMeta(ctx context.Context, m *ResponseMeta) context.Context {
	if m == nil {
		return ctx
	}
	return context.WithValue(ctx, responseMetaKey{}, m)
}

// recordMeta stores per-response metadata from an upstream response header into
// the sink carried by ctx, if one is attached: the ZG-Res-Key handle and a clone
// of the full header block for a front end to surface a curated subset. It is
// called only on the path that produces the response the caller receives — the
// successful non-stream attempt, or a committed stream — so the recorded data
// always matches the delivered response and is never left stale by a discarded
// fallback attempt. A missing ZG-Res-Key records the empty string. Independent
// of verification: the handle is surfaced even when §8 verification is off,
// precisely so a caller can fetch and check the signature out of band.
func recordMeta(ctx context.Context, header http.Header) {
	if m, ok := ctx.Value(responseMetaKey{}).(*ResponseMeta); ok {
		m.ResKey = header.Get(headerResKey)
		m.Header = header.Clone()
	}
}
