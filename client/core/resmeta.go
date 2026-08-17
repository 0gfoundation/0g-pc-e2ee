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
// It carries the ZG-Res-Key handle, so a front end (the sidecar or gateway) can
// re-expose it to its own user, who can then fetch the §8 signature from the
// broker and audit it independently; the provider this response actually came
// from; and the raw upstream header block. None of it is key material, so
// surfacing it is safe even on the multi-tenant gateway.
type ResponseMeta struct {
	// ResKey is the provider's ZG-Res-Key response header (the broker's chatKey).
	// Empty when the provider sent none (e.g. a provider that does not cache a §8
	// signature), which the caller treats as "no handle", not an error.
	ResKey string

	// Provider is the router-facing address this request was ADDRESSED to —
	// Provider.Address, the value the client itself resolved and sent as the
	// X-0G-Provider-Address routing pin, NOT anything the upstream reported back.
	//
	// It is where the request went, not proof of who answered: a sealed response is
	// HPKE-sealed to the client's ephemeral key, which travels in cleartext, so
	// opening one does not identify the sender. Only §8 verification
	// (WithResponseVerification) establishes that, and it is off by default — a
	// caller that surfaces this value should say what it means accordingly.
	//
	// That distinction is the point of surfacing it. The router also states a served
	// provider in its own X-Provider response header, but that is an unauthenticated
	// assertion: a router could forward the request to the pinned provider exactly as
	// asked and still name a different address on the way back, and nothing in the
	// signature or seal would notice, because the routing was never changed. Only
	// the value the client pinned is worth showing a user, so the client is the one
	// that reports it (see openaiproxy, which emits it instead of forwarding the
	// router's).
	//
	// Empty when the resolver pinned no address — direct-broker mode, where the
	// client talks to one configured provider and there is no router to pin through.
	// A caller treats empty as "no address to report" and omits it rather than
	// substituting anything else.
	Provider string

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

// recordMeta stores per-response metadata into the sink carried by ctx, if one is
// attached: the ZG-Res-Key handle, the address of the provider this response came
// from, and a clone of the full header block for a front end to surface a curated
// subset. It is called only on the path that produces the response the caller
// receives — the successful non-stream attempt, or a committed stream — so the
// recorded data always matches the delivered response and is never left stale by a
// discarded fallback attempt. A missing ZG-Res-Key records the empty string.
// Independent of verification: the handle is surfaced even when §8 verification is
// off, precisely so a caller can fetch and check the signature out of band.
//
// provider is the resolved provider this attempt was sealed and pinned to, so the
// recorded address is the client's own, never the upstream's claim about itself.
func recordMeta(ctx context.Context, provider Provider, header http.Header) {
	if m, ok := ctx.Value(responseMetaKey{}).(*ResponseMeta); ok {
		m.ResKey = header.Get(headerResKey)
		m.Provider = provider.Address
		m.Header = header.Clone()
	}
}
