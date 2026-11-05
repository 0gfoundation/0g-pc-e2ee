package core

import (
	"context"
	"errors"

	"github.com/0gfoundation/0g-pc-e2ee/client/endpoint"
	"github.com/0gfoundation/0g-pc-e2ee/protocol/wire"
)

// Encrypted transit (0g-router issue #1215, step G1). The values of
// `encrypted_transit`, from least to most strict:
//
//   - off: plaintext is fine;
//   - preferred: encrypt when the model can be, otherwise plaintext;
//   - required: encrypt or refuse.
//
// Two parties speak about it, and they are not trusted alike:
//
//   - The CALLER, through its own X-0G-Encrypted-Transit request header, which
//     the front end reads directly. Only this can permit plaintext for a request
//     this client would otherwise seal: the front end marks such a request with
//     WithPlaintextPermitted.
//   - The ROUTER, which merges the account's, the API key's and the header's
//     values and reports the result in route-preview. The router is untrusted
//     (it must never be able to make a sealed model's prompt go out in the
//     clear), so its value can only make the requirement STRICTER: under its
//     required nothing is downgraded, and its off or preferred permit nothing.
//
// Plaintext therefore needs the caller's header AND a router that does not say
// required. A permission set only in the Console (account or key rules) is not
// honoured here; it would have to reach the gateway by a path the router cannot
// forge.
const (
	TransitOff       = "off"
	TransitPreferred = "preferred"
	TransitRequired  = "required"
)

// ErrNoEncryptedProvider is returned by Complete, CompleteStream and
// SubmitAsync when no candidate could be prepared for sealing — every one
// failed before anything was sent (no key to seal to, an attestation that did
// not verify) — and plaintext is permitted: the caller's own header permits it
// (WithPlaintextPermitted) and the router does not say required. The request
// has reached no provider; the front end forwards it in the clear and says why.
//
// Never for a walk that sent a request (a provider may already be serving it,
// and sending it again in the clear would run it twice), one cut short by the
// walk budget (the caller has already waited all of it), or a caller that went
// away.
var ErrNoEncryptedProvider = errors.New("no provider could be sealed to: forward the request in the clear")

type plaintextPermittedKey struct{}

// WithPlaintextPermitted marks ctx as belonging to a request whose CALLER, in
// its own X-0G-Encrypted-Transit header, permits plaintext, and which the front
// end can forward in the clear. Only a front end that read that header itself
// may set it: nothing the router says can.
func WithPlaintextPermitted(ctx context.Context) context.Context {
	return context.WithValue(ctx, plaintextPermittedKey{}, true)
}

// PlaintextPermittedFrom reports whether WithPlaintextPermitted marked ctx.
func PlaintextPermittedFrom(ctx context.Context) bool {
	v, _ := ctx.Value(plaintextPermittedKey{}).(bool)
	return v
}

// TransitCandidates is implemented by Candidates that know the router's
// encrypted_transit for the request (the route resolver's, from route-preview,
// already folded onto the Transit* values or "").
type TransitCandidates interface {
	EncryptedTransit() string
}

// downgradeUnsent reports whether a walk that ended without a success may be
// handed back as ErrNoEncryptedProvider: nothing was sent and the walk was not
// cut short (spent false), the caller is still there, the caller permitted
// plaintext (WithPlaintextPermitted), and the router does not veto it by saying
// required. The router's value can only veto; it never grants.
func downgradeUnsent(ctx context.Context, cands Candidates, spent bool) bool {
	if spent || canceledBy(ctx) || !PlaintextPermittedFrom(ctx) {
		return false
	}
	if t, ok := cands.(TransitCandidates); ok && t.EncryptedTransit() == TransitRequired {
		return false
	}
	return true
}

// TransitPolicyResolver is implemented by a resolver that can tell the router's
// encrypted_transit for a request without materializing candidates — for a
// front end that must decide, before sealing, what to do with a request that
// cannot be sealed (an async image submit asking for a URL).
type TransitPolicyResolver interface {
	EncryptedTransit(ctx context.Context, ep endpoint.Endpoint, req wire.Request) (string, error)
}

// EncryptedTransit returns the router's encrypted_transit for req: one of the
// Transit* values, or "" when the resolver cannot tell (a static resolver, or a
// router that does not send one). It is the router's word, so callers may use
// it to refuse (required) but never as permission for plaintext.
func (c *Client) EncryptedTransit(ctx context.Context, req wire.Request) (string, error) {
	r, ok := c.resolver.(TransitPolicyResolver)
	if !ok {
		return "", nil
	}
	return r.EncryptedTransit(ctx, c.ep, req)
}
