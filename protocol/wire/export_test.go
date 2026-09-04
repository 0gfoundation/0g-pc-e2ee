package wire

import "github.com/0gfoundation/0g-pc-e2ee/protocol/crypto"

// newNonConformingResponseSealer returns a sealer that skips the profile-level
// checks SealFrame applies, so tests can build the frames a hostile or
// third-party enclave would emit.
//
// It exists because those frames are exactly what the receiver-side checks are
// for, and a conforming sealer can no longer produce them — which is the point
// of the seal-time half. Without an escape hatch the receiver tests would have
// to assert against frames the library refuses to build, i.e. not test the
// threat at all.
//
// This file is _test.go, so the field it sets has no way to be set in a build of
// the package. The frames it produces are still well-formed on the wire: only
// the profile's own requirements are dropped, never the AEAD, the AAD, or the
// invariants that hold for every profile.
func newNonConformingResponseSealer(clientEphPub crypto.PublicKey, unboundFields ...string) (*ResponseSealer, error) {
	rs, err := NewResponseSealerFor(ProfileChat, clientEphPub, unboundFields...)
	if err != nil {
		return nil, err
	}
	rs.nonConforming = true
	return rs, nil
}

// SealResponseNonConforming seals a single final frame through such a sealer.
// Exported so the external wire_test package can reach it; it is still test-only
// (export_test.go is compiled only into the test binary).
func SealResponseNonConforming(clientEphPub crypto.PublicKey, resp Response, sealedFields []string, unboundFields ...string) (Response, error) {
	rs, err := newNonConformingResponseSealer(clientEphPub, unboundFields...)
	if err != nil {
		return nil, err
	}
	return rs.SealFrame(resp, sealedFields, true)
}

// NewResponseSealerNonConforming exposes the streaming form, for a test that
// needs a sealer which starts out conforming and stops partway.
func NewResponseSealerNonConforming(clientEphPub crypto.PublicKey, unboundFields ...string) (*ResponseSealer, error) {
	return newNonConformingResponseSealer(clientEphPub, unboundFields...)
}

// ValidateResponseSealedFieldsForTest exposes the PROFILE-WIDE response
// validator, which no production path calls directly any more (SealFrame and
// OpenFrame go through the frame-aware one). A test still needs to reach it, to
// pin that it refuses a frame-typed profile outright instead of resolving against
// an empty spec.responsePayload and waving through a frame that seals nothing.
func ValidateResponseSealedFieldsForTest(p Profile, fields []string) error {
	return validateResponseSealedFieldsFor(p, fields)
}
