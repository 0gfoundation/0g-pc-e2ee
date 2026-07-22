package wire

import (
	"encoding/json"
	"fmt"

	"github.com/0gfoundation/0g-pc-e2ee/protocol/crypto"
)

// RespInfo is the HPKE info string for response sealing (SPEC §7). It differs
// from the request's SealInfo, so a request context cannot open a response.
const RespInfo = "0g-pc/v1/resp"

// Response is one response frame: cleartext fields (usage, model, id, created,
// system_fingerprint) plus an `_e2ee` object holding the sealed choices. A
// non-streaming response is a single frame; a streaming (SSE) response is a
// sequence of frames sharing one HPKE context.
type Response map[string]json.RawMessage

// ResponseE2EE is the `_e2ee` object on a response frame (§7). v and enc appear
// on the first frame only; the rest of a streaming response reuses that context.
type ResponseE2EE struct {
	V            int      `json:"v,omitempty"`
	Enc          string   `json:"enc,omitempty"` // base64url; first frame only
	SealedFields []string `json:"sealed_fields"`
	Final        bool     `json:"final"`
	Ciphertext   string   `json:"ciphertext"` // base64url; excluded from the AAD
}

// defaultResponseSealedFields is the v1 default set of response fields to seal
// (SPEC §7): the generated content.
func defaultResponseSealedFields() []string { return []string{"choices"} }

// validateResponseSealedFields requires a non-empty set with no duplicates.
// Unlike the request there is no single mandatory field pinned in v1.
func validateResponseSealedFields(fields []string) error {
	if len(fields) == 0 {
		return fmt.Errorf("no sealed fields")
	}
	seen := make(map[string]struct{}, len(fields))
	for _, f := range fields {
		if _, dup := seen[f]; dup {
			return fmt.Errorf("duplicate sealed field %q", f)
		}
		seen[f] = struct{}{}
	}
	return nil
}

// ResponseSealer seals a sequence of response frames under one HPKE context (the
// enclave is the sender, the client's ephemeral key the recipient). Frames MUST
// be sealed in order; the receiver opens them in the same order.
type ResponseSealer struct {
	sealer *crypto.Sealer
	enc    string // base64url; emitted on the first frame only
	first  bool
}

// NewResponseSealer sets up response sealing to the client's ephemeral public
// key (carried in the request's _e2ee.client_eph_pub).
func NewResponseSealer(clientEphPub crypto.PublicKey) (*ResponseSealer, error) {
	enc, s, err := crypto.SetupSender(clientEphPub, []byte(RespInfo))
	if err != nil {
		return nil, err
	}
	return &ResponseSealer{sealer: s, enc: b64.EncodeToString(enc), first: true}, nil
}

// SealFrame seals one frame: it removes sealedFields (nil → the v1 default,
// "choices") from frame, seals their values, and returns the frame carrying
// `_e2ee`. final marks the last frame.
func (rs *ResponseSealer) SealFrame(frame Response, sealedFields []string, final bool) (Response, error) {
	if sealedFields == nil {
		sealedFields = defaultResponseSealedFields()
	}
	if err := validateResponseSealedFields(sealedFields); err != nil {
		return nil, err
	}

	sealedObj := make(map[string]json.RawMessage, len(sealedFields))
	for _, f := range sealedFields {
		v, ok := frame[f]
		if !ok {
			return nil, fmt.Errorf("sealed field %q not present in frame", f)
		}
		sealedObj[f] = v
	}
	pt, err := canonicalJSON(sealedObj)
	if err != nil {
		return nil, fmt.Errorf("canonicalize sealed object: %w", err)
	}

	out := make(Response, len(frame)+1)
	sealedSet := toSet(sealedFields)
	for k, v := range frame {
		if k == e2eeKey {
			return nil, fmt.Errorf("frame already contains %q", e2eeKey)
		}
		if _, sealed := sealedSet[k]; sealed {
			continue
		}
		out[k] = v
	}

	e2ee := ResponseE2EE{SealedFields: sealedFields, Final: final}
	if rs.first {
		e2ee.V = Version
		e2ee.Enc = rs.enc
	}
	if err := setResponseE2EE(out, e2ee); err != nil {
		return nil, err
	}

	aad, err := aadFromEnvelope(out)
	if err != nil {
		return nil, err
	}
	ct, err := rs.sealer.Seal(pt, aad)
	if err != nil {
		return nil, err
	}
	e2ee.Ciphertext = b64.EncodeToString(ct)
	if err := setResponseE2EE(out, e2ee); err != nil {
		return nil, err
	}
	rs.first = false
	return out, nil
}

// ResponseOpener opens a sequence of response frames in seal order.
type ResponseOpener struct {
	opener *crypto.Opener
}

// NewResponseOpener builds the receive context from the first frame (which
// carries enc) and the client's ephemeral private key.
func NewResponseOpener(clientEphPriv crypto.PrivateKey, firstFrame Response) (*ResponseOpener, error) {
	e2ee, err := firstFrame.E2EE()
	if err != nil {
		return nil, err
	}
	if e2ee.V != Version {
		return nil, fmt.Errorf("unsupported response envelope version %d", e2ee.V)
	}
	if e2ee.Enc == "" {
		return nil, fmt.Errorf("first response frame missing enc")
	}
	enc, err := b64.DecodeString(e2ee.Enc)
	if err != nil {
		return nil, fmt.Errorf("bad enc: %w", err)
	}
	o, err := crypto.SetupReceiver(clientEphPriv, enc, []byte(RespInfo))
	if err != nil {
		return nil, err
	}
	return &ResponseOpener{opener: o}, nil
}

// OpenFrame opens one frame and returns it reconstructed (cleartext ∪
// decrypted). Frames MUST be opened in seal order — the underlying AEAD sequence
// increments per frame, so an out-of-order or missing frame fails.
func (ro *ResponseOpener) OpenFrame(frame Response) (Response, error) {
	e2ee, err := frame.E2EE()
	if err != nil {
		return nil, err
	}
	ct, err := b64.DecodeString(e2ee.Ciphertext)
	if err != nil {
		return nil, fmt.Errorf("bad ciphertext: %w", err)
	}
	aad, err := aadFromEnvelope(frame)
	if err != nil {
		return nil, err
	}
	pt, err := ro.opener.Open(ct, aad) // fail-closed on tamper / wrong order / wrong key
	if err != nil {
		return nil, err
	}

	var sealedObj map[string]json.RawMessage
	if err := json.Unmarshal(pt, &sealedObj); err != nil {
		return nil, fmt.Errorf("decrypted object is not a JSON object: %w", err)
	}
	if !sameKeys(sealedObj, e2ee.SealedFields) {
		return nil, fmt.Errorf("decrypted fields do not match sealed_fields")
	}

	out := make(Response, len(frame)+len(sealedObj))
	for k, v := range frame {
		if k == e2eeKey {
			continue
		}
		out[k] = v
	}
	for k, v := range sealedObj {
		if _, clash := out[k]; clash {
			return nil, fmt.Errorf("sealed field %q collides with a cleartext field", k)
		}
		out[k] = v
	}
	return out, nil
}

// SealResponse seals a complete non-streaming response as a single final frame.
func SealResponse(clientEphPub crypto.PublicKey, resp Response, sealedFields []string) (Response, error) {
	rs, err := NewResponseSealer(clientEphPub)
	if err != nil {
		return nil, err
	}
	return rs.SealFrame(resp, sealedFields, true)
}

// OpenResponse opens a complete non-streaming (single-frame) response.
func OpenResponse(clientEphPriv crypto.PrivateKey, resp Response) (Response, error) {
	ro, err := NewResponseOpener(clientEphPriv, resp)
	if err != nil {
		return nil, err
	}
	return ro.OpenFrame(resp)
}

// E2EE decodes the `_e2ee` metadata on a response frame.
func (r Response) E2EE() (ResponseE2EE, error) {
	raw, ok := r[e2eeKey]
	if !ok {
		return ResponseE2EE{}, fmt.Errorf("frame missing %q", e2eeKey)
	}
	var e ResponseE2EE
	if err := json.Unmarshal(raw, &e); err != nil {
		return ResponseE2EE{}, fmt.Errorf("decode %q: %w", e2eeKey, err)
	}
	return e, nil
}

func setResponseE2EE(r Response, e ResponseE2EE) error {
	raw, err := json.Marshal(e)
	if err != nil {
		return fmt.Errorf("encode %q: %w", e2eeKey, err)
	}
	r[e2eeKey] = raw
	return nil
}
