package core

import "context"

// credentialKey is the unexported context key under which a per-request
// provider credential travels. Unexported so only this package can set/read it.
type credentialKey struct{}

// WithCredential returns a context carrying the caller's provider credential —
// the raw Authorization header value (e.g. "Bearer sk-...") — to forward
// verbatim on the provider request made with that context. An empty cred is a
// no-op, so a caller with no credential leaves the outgoing request unauthed
// exactly as before.
//
// The credential is per-request, not per-Client: a Client is shared across
// concurrent callers, each of which may present its own key, so it rides the
// context rather than the Client. It transits to the provider in cleartext (an
// Authorization header on the envelope), like the other routing/billing
// cleartext fields — the router/broker needs it to authenticate and bill. Only
// the sealed fields (prompt, tool defs) stay confidential; the credential is
// deliberately not one of them.
func WithCredential(ctx context.Context, cred string) context.Context {
	if cred == "" {
		return ctx
	}
	return context.WithValue(ctx, credentialKey{}, cred)
}

// CredentialFrom returns the credential carried by ctx, or "" if none was set.
// It is exported so a Resolver (route mode) can forward the same credential on
// its control-plane call to the router, which authenticates and bills it like
// the sealed request. The context key stays unexported, so only WithCredential
// can set it.
func CredentialFrom(ctx context.Context) string {
	cred, _ := ctx.Value(credentialKey{}).(string)
	return cred
}
