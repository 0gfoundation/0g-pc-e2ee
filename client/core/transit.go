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
//
// What this does NOT give a caller that sent preferred is confidentiality from
// the router. Whether a candidate can be prepared for sealing is decided by
// facts the router controls — the candidate list itself, and the endpoints in it
// — so a router that wants the prompt can list nothing, or nothing reachable, and
// receive it in the clear. "Stricter only" holds for the router's encrypted_transit
// VALUE; under preferred the router still decides the OUTCOME. What this client
// does refuse is to downgrade on its own verification's refusal
// (ErrProviderRefused): that is a sign of an attack, not of a model without
// encryption, and answering it with plaintext would point the wrong way.
const (
	TransitOff       = "off"
	TransitPreferred = "preferred"
	TransitRequired  = "required"
)

// ErrNoEncryptedProvider is returned by Complete, CompleteStream and
// SubmitAsync when no candidate could be prepared for sealing — every one
// failed before anything was sent (no key to seal to, a quote that could not
// be fetched) and none was refused by verification — and plaintext is
// permitted: the caller's own header permits it (WithPlaintextPermitted) and
// the router does not say required. The request has reached no provider; the
// front end forwards it in the clear and says why.
//
// Never for a walk that sent a request (a provider may already be serving it,
// and sending it again in the clear would run it twice), one cut short by the
// walk budget (the caller has already waited all of it), one in which this
// client's own verification refused a candidate (ErrProviderRefused), or a
// caller that went away.
var ErrNoEncryptedProvider = errors.New("no provider could be sealed to: forward the request in the clear")

// ErrProviderRefused marks a candidate this client's own verification looked at
// and refused: an attestation quote that did not verify, a quote-bound signer
// the on-chain registry contradicts or does not acknowledge, or a provider the
// provider checks refused. Candidates resolvers wrap such errors so that
// errors.Is finds it (the message is theirs, unchanged).
//
// A walk that met one is never downgraded to plaintext (downgradeUnsent). Not
// because it stops a router that wants the prompt — that router can list nothing
// instead — but because a refused verification is the signal of an attack, and
// the answer to it must be an error someone sees, not the prompt in the clear.
// Failures that say nothing about the provider (a quote that could not be
// fetched, a chain read that failed, a malformed candidate) are not marked:
// they may be how a model without an encrypted provider shows up.
var ErrProviderRefused = errors.New("provider refused by verification")

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
// handed back as ErrNoEncryptedProvider: nothing was sent (attempted false), the
// walk was not cut short by its budget, no candidate was refused by
// verification (ErrProviderRefused), the caller is still there, the caller
// permitted plaintext (WithPlaintextPermitted), and the router does not veto it
// by saying required. The router's value can only veto; it never grants.
func downgradeUnsent(ctx context.Context, cands Candidates, walk *candidateWalk, attempted bool) bool {
	if attempted || walk.exhausted() || walk.refused || canceledBy(ctx) || !PlaintextPermittedFrom(ctx) {
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
