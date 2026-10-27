package wire

import (
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/json"
	"fmt"

	"github.com/0gfoundation/0g-pc-e2ee/protocol/crypto"
)

// Response binding (SPEC §7.6).
//
// A response is sealed to `client_eph_pub`, which travels in the clear in the
// request envelope, and HPKE base mode does not authenticate the sender: anyone
// who saw the request — the router included — can seal a response the client
// will open. A non-streaming response is still caught before delivery by the §8
// signature, but a stream is handed to the caller frame by frame and checked
// only at its end, so a router that answers with a stream of its own has its
// text rendered before anything objects. An async result has no §8 check the
// sender can tie to its request at all (§7.5.1).
//
// The binding closes that by making the response context depend on a secret
// only the client and the enclave the request was sealed to can know:
//
//   - the client derives `bind` from its ephemeral PRIVATE key and seals it into
//     the request as `_bind` (the router never sees it);
//   - the enclave takes `_bind` out of the opened request before the upstream
//     call and seals the response in HPKE mode_psk with psk = bind;
//   - the client opens in mode_psk with the bind it derived. A context set up
//     by anyone else — a router that never learned `bind` — opens nothing, so
//     the forgery is refused at the FIRST frame, before any byte reaches the
//     caller.
//
// One check covers every frame: all frames of a stream share the one HPKE
// context the first frame sets up, and the AEAD sequence ties each later frame
// to it. Nothing is added to the frames themselves, so no profile's frame-shape
// rules change (Anthropic's message_start must seal nothing, for one).
//
// Opt-in per request on the synchronous profiles. A request without `_bind` gets
// a base-mode response, as before, so a client only attaches it to an enclave
// that is known to support it — an older one would forward `_bind` upstream and
// seal in base mode, and the client would refuse every response. How the client
// learns that is outside the wire format (the gateway reads it from the
// provider's quote reply). On async-image it is mandatory: the request must
// carry it and the result is always bound (profileSpec.requiresBind).

const (
	// RespBindInfo is the HKDF info string for the response-binding value.
	RespBindInfo = "0g-pc/v1/resp-bind"
	// RespBindPSKID is the HPKE psk_id a bound response context is set up with.
	RespBindPSKID = "0g-pc/v1/resp-bind"
	// FeatureResponseBind is the entry an enclave implementing §7.6 lists in the
	// `e2ee_features` array of its /v1/quote reply, so a sender knows it may attach
	// `_bind` on the synchronous profiles. A sender MUST read it only over a path the
	// router cannot redirect (SPEC §7.6).
	FeatureResponseBind = "resp-bind"
	// respBindLen is the byte length of the binding value — RFC 9180 §9.5's
	// floor for a PSK.
	respBindLen = 32
)

// ResponseBindApplies reports whether the response binding (§7.6) is an
// OPTIONAL, per-request choice on profile — every known synchronous profile. A
// caller that decides per provider whether to bind asks this first. It is false
// for async-image, where the binding is not a choice: the request always carries
// it (AttachAsyncBind) and the result is always bound.
func ResponseBindApplies(profile Profile) bool {
	spec, err := profile.spec()
	return err == nil && !spec.requiresBind()
}

// DeriveResponseBind derives the response-binding value from the client's
// ephemeral private key: HKDF-SHA256(ikm = eph_priv, salt = empty,
// info = RespBindInfo, L = 32).
//
// Derived rather than drawn so a caller holding the key needs no second secret
// to keep between sealing the request and opening the response.
func DeriveResponseBind(ephPriv crypto.PrivateKey) ([]byte, error) {
	if len(ephPriv) != ephPrivLen {
		return nil, fmt.Errorf("ephemeral private key must be %d bytes, got %d", ephPrivLen, len(ephPriv))
	}
	return hkdf.Key(sha256.New, ephPriv, nil, RespBindInfo, respBindLen)
}

// AttachResponseBind returns a copy of req carrying the `_bind` field derived
// from ephPriv. The caller must seal it: name `_bind` in the sealed set, or pass
// a nil set to SealRequestFor, whose default picks it up. A request carrying
// `_bind` in the clear is refused at seal and at open (§7.6), since the router
// could then bind a response of its own.
//
// A request that already carries `_bind` is refused: a caller-supplied value
// would be sealed as if derived, and the response opened under the derived one.
func AttachResponseBind(profile Profile, req Request, ephPriv crypto.PrivateKey) (Request, error) {
	if _, err := profile.spec(); err != nil {
		return nil, err
	}
	if _, ok := req[fieldBind]; ok {
		return nil, fmt.Errorf("request already carries %q, which the response binding reserves", fieldBind)
	}
	bind, err := DeriveResponseBind(ephPriv)
	if err != nil {
		return nil, err
	}
	raw, err := json.Marshal(b64.EncodeToString(bind))
	if err != nil {
		return nil, err
	}
	out := make(Request, len(req)+1)
	for k, v := range req {
		out[k] = v
	}
	out[fieldBind] = raw
	return out, nil
}

// TakeResponseBind is the enclave's half on the request side: given a request
// OpenRequestFor reconstructed, it returns the binding value — nil when the
// client did not ask for a bound response — and the request WITHOUT `_bind`,
// the one to forward upstream. `_bind` is protocol metadata, not a model
// parameter, and an upstream that rejects unknown fields would otherwise fail
// every bound request.
//
// A non-nil bind means the response MUST be sealed with it
// (NewBoundResponseSealerFor / SealBoundResponseFor): the client will open
// nothing else.
func TakeResponseBind(profile Profile, opened Request) (bind []byte, forward Request, err error) {
	spec, err := profile.spec()
	if err != nil {
		return nil, nil, err
	}
	raw, ok := opened[fieldBind]
	if !ok {
		if spec.requiresBind() {
			// OpenRequestFor already refuses this (the field is mandatory payload);
			// checked again so a caller holding a request from anywhere else cannot
			// end up sealing an always-bound profile in base mode.
			return nil, nil, fmt.Errorf("opened %s-profile request carries no %q", profile, fieldBind)
		}
		return nil, opened, nil
	}
	bind, err = decodeBind(raw)
	if err != nil {
		return nil, nil, err
	}
	forward = make(Request, len(opened)-1)
	for k, v := range opened {
		if k != fieldBind {
			forward[k] = v
		}
	}
	return bind, forward, nil
}

// NewBoundResponseSealerFor is NewResponseSealerFor for a request that carried
// `_bind` (§7.6): the response context is set up in HPKE mode_psk with
// psk = bind, so only a receiver holding the request's ephemeral private key —
// and so able to derive bind — opens it. bind is what TakeResponseBind returned.
func NewBoundResponseSealerFor(profile Profile, clientEphPub crypto.PublicKey, bind []byte, unboundFields ...string) (*ResponseSealer, error) {
	if len(bind) != respBindLen {
		return nil, fmt.Errorf("binding value must be %d bytes, got %d", respBindLen, len(bind))
	}
	return newResponseSealer(profile, clientEphPub, bind, unboundFields)
}

// SealBoundResponseFor is SealResponseFor for a request that carried `_bind`:
// a complete non-streaming response as a single final frame, sealed in
// mode_psk (§7.6).
func SealBoundResponseFor(profile Profile, clientEphPub crypto.PublicKey, bind []byte, resp Response, sealedFields []string, unboundFields ...string) (Response, error) {
	rs, err := NewBoundResponseSealerFor(profile, clientEphPub, bind, unboundFields...)
	if err != nil {
		return nil, err
	}
	return rs.SealFrame(resp, sealedFields, true)
}

// NewBoundResponseOpenerFor is NewResponseOpenerFor for a request this client
// sealed with AttachResponseBind (§7.6): it derives the binding value from
// clientEphPriv and sets up the receive context in mode_psk. A response sealed
// by anyone who does not hold that value — including a genuine enclave that
// ignored `_bind`, and any party that sealed in base mode to the cleartext
// client_eph_pub — fails at the first OpenFrame.
func NewBoundResponseOpenerFor(profile Profile, clientEphPriv crypto.PrivateKey, firstFrame Response) (*ResponseOpener, error) {
	bind, err := DeriveResponseBind(clientEphPriv)
	if err != nil {
		return nil, err
	}
	return newResponseOpener(profile, clientEphPriv, firstFrame, bind)
}

// OpenBoundResponseFor is OpenResponseFor for a request sealed with
// AttachResponseBind: a complete non-streaming (single-frame) response, opened
// in mode_psk (§7.6).
func OpenBoundResponseFor(profile Profile, clientEphPriv crypto.PrivateKey, resp Response) (Response, error) {
	e2ee, err := resp.E2EE()
	if err != nil {
		return nil, err
	}
	if !e2ee.Final {
		return nil, fmt.Errorf("non-streaming response frame is not marked final: a single-frame response must be the final frame, and the checks that fall due on it would otherwise be skipped")
	}
	ro, err := NewBoundResponseOpenerFor(profile, clientEphPriv, resp)
	if err != nil {
		return nil, err
	}
	return ro.OpenFrame(resp)
}
