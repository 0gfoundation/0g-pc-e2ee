package core

import (
	"context"

	"github.com/0gfoundation/0g-pc-e2ee/protocol/wire"
)

// Resolver decides, for a given request, which provider enclave the client
// should seal to. It exists so the same client core serves both trust shapes
// without branching in the seal path:
//
//   - the pin-only path (sidecar, and the gateway's pinned mode) uses a static
//     resolver that always returns one flag-configured provider;
//   - the gateway's route mode uses a resolver that, per request, asks the 0G
//     router which provider to use and fetches that provider's enc key (see
//     client/route).
//
// Resolve runs on the request path, before sealing, so an implementation that
// makes network calls (route mode) should honor ctx for cancellation/deadline.
// A failure should be returned as a staged *Error so the proxy maps it to a
// sensible HTTP status; a plain error is treated as an upstream (502) failure.
type Resolver interface {
	Resolve(ctx context.Context, req wire.Request) (Provider, error)
}

// staticResolver always returns the same provider, ignoring the request. It is
// the pin-only path: the provider identity is fixed at construction (today from
// flags, later from a verified quote) rather than chosen per request.
type staticResolver struct{ provider Provider }

func (s staticResolver) Resolve(context.Context, wire.Request) (Provider, error) {
	return s.provider, nil
}
