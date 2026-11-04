package core

import (
	"context"
	"errors"

	"github.com/0gfoundation/0g-pc-e2ee/client/endpoint"
	"github.com/0gfoundation/0g-pc-e2ee/protocol/wire"
)

// Encrypted transit (0g-router issue #1215, step G1): the router merges the
// account's, the API key's and the request's `encrypted_transit` and returns
// the effective value from route-preview. This client acts on it:
//
//   - off: the caller allowed plaintext. A front end that has a cleartext path
//     (WithCleartextFallback) forwards the request there instead of sealing it.
//   - preferred (the default, and what an older router that sends no value
//     means): seal when the request can be sealed — today's behaviour.
//   - required: seal or refuse. The router has already narrowed the candidates
//     to providers that can be sealed to, and refuses a plaintext request
//     itself; a front end refuses, rather than downgrades, a request it cannot
//     seal.
const (
	TransitOff       = "off"
	TransitPreferred = "preferred"
	TransitRequired  = "required"
)

// ErrEncryptedTransitOff is returned by Resolve (through Complete,
// CompleteStream and SubmitAsync) when the effective encrypted_transit is off
// and the caller said it can forward in the clear (WithCleartextFallback).
// Nothing has been sent upstream yet: the front end forwards the original
// request on its cleartext path.
var ErrEncryptedTransitOff = errors.New("encrypted_transit is off: forward the request in the clear")

type cleartextFallbackKey struct{}

// WithCleartextFallback marks ctx as belonging to a request the front end can
// forward in the clear, so a resolver may answer ErrEncryptedTransitOff
// instead of sealing it. Without it an `off` request is sealed anyway: off
// PERMITS plaintext, it does not demand it, so a client with no cleartext path
// (the sidecar) keeps sealing.
func WithCleartextFallback(ctx context.Context) context.Context {
	return context.WithValue(ctx, cleartextFallbackKey{}, true)
}

// CleartextFallbackFrom reports whether WithCleartextFallback marked ctx.
func CleartextFallbackFrom(ctx context.Context) bool {
	v, _ := ctx.Value(cleartextFallbackKey{}).(bool)
	return v
}

// TransitPolicyResolver is implemented by a resolver that can tell the
// effective encrypted_transit of a request without materializing candidates —
// for a front end that must decide, before sealing, what to do with a request
// that cannot be sealed (an async image submit asking for a URL).
type TransitPolicyResolver interface {
	EncryptedTransit(ctx context.Context, ep endpoint.Endpoint, req wire.Request) (string, error)
}

// EncryptedTransit returns the effective encrypted_transit of req: one of the
// Transit* values, or "" when the resolver cannot tell (a static resolver, or a
// router that does not send one), which callers treat as preferred.
func (c *Client) EncryptedTransit(ctx context.Context, req wire.Request) (string, error) {
	r, ok := c.resolver.(TransitPolicyResolver)
	if !ok {
		return "", nil
	}
	return r.EncryptedTransit(ctx, c.ep, req)
}
