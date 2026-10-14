package wire

import (
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"slices"
	"strings"

	"github.com/0gfoundation/0g-pc-e2ee/protocol/crypto"
)

// Async image (SPEC §7.5) — the image profile split in time.
//
// The request is sealed and submitted; the broker answers 202 with a job id and
// stores the sealed envelope; a worker opens it inside the enclave, generates,
// and seals the result to the client's ephemeral key ONCE, at completion; every
// later poll returns that stored frame. Nothing about the HPKE changes — the
// result needs only `client_eph_pub`, never the request's context — so what this
// file adds is the three things the time split breaks:
//
//  1. Result binding. In the synchronous flow the sender holds `reqH` in memory
//     and checks the §8 signature against it. A stateless sender (the cloud
//     gateway) has nothing to compare at poll time, and `client_eph_pub` is
//     cleartext in the request envelope, so a router can submit a request OF ITS
//     OWN carrying the victim's key: a genuine enclave serves it, seals the result
//     to the victim, signs it — under the router's `reqH` — and the router returns
//     that frame on the victim's poll. It opens; it verifies; the content is the
//     router's. `_bind` closes it without state: a value derived from the
//     ephemeral PRIVATE key, sealed inside the request, echoed sealed inside the
//     result. Only the victim's request carries it, and only the enclave that
//     request was sealed to can learn it, so a frame that opens AND carries it
//     came from that enclave for that request.
//  2. Which job. The result frame's cleartext `jobId` is bound in its AAD, and
//     the receiver compares it with the id it is polling, so a frame from another
//     job — a replay of the victim's own request included — is refused.
//  3. Where `eph_priv` lives between submit and poll. It rides in the id the user
//     keeps (UserJobID), so the sender needs no key and no state of its own.

const (
	// AsyncBindInfo is the HKDF info string for the result-binding value.
	AsyncBindInfo = "0g-pc/v1/async-bind"
	// asyncBindLen is the byte length of the binding value.
	asyncBindLen = 32
	// ephPrivLen is the byte length of a marshaled X25519 private key.
	ephPrivLen = 32
	// fieldJobID / fieldStatus are the poll envelope's cleartext fields that the
	// result frame binds (§7.5): which job, and that it is the terminal one.
	fieldJobID  = "jobId"
	fieldStatus = "status"
	// AsyncStatusCompleted is the only status a result frame may carry.
	AsyncStatusCompleted = "completed"
	// userJobIDSep separates the broker job id from the key segment. Neither part's
	// alphabet contains it, so the split is unambiguous; parsing still splits on
	// the LAST one and validates both halves, so a future id format that
	// introduces it fails loudly instead of splitting wrongly.
	userJobIDSep = "."
	// maxJobIDLen bounds the job-id half. Generous on purpose: the protocol must
	// not encode one router's internal limit, only refuse the absurd.
	maxJobIDLen = 128
)

// asyncImageResultUnbound is the unbound set every async-image result frame
// declares, and the only one a receiver accepts (any subset of it, since
// declaring less is binding more).
//
// It must be declared by the ENCLAVE at completion: `unbound_fields` lives inside
// `_e2ee`, which is bound, so nothing can add to it later — and the router
// injects `x_0g_trace` on completed polls, so a frame without it fails to open
// on the first poll that carries a trace. `model` matches the synchronous
// profiles (DefaultUnboundFields' TODO(model-binding)).
//
// `jobId` and `status` are deliberately absent: the receiver's checks key off
// them, and an unbound one could be rewritten in transit with Open still
// succeeding.
var asyncImageResultUnbound = []string{"model", "x_0g_trace"}

// AsyncImageResultUnboundFields returns the unbound set an enclave declares on an
// async-image result frame. A fresh slice; callers may not need it at all, since
// SealAsyncImageResult applies it.
func AsyncImageResultUnboundFields() []string {
	return slices.Clone(asyncImageResultUnbound)
}

// DeriveAsyncBind derives the result-binding value from the client's ephemeral
// private key: HKDF-SHA256(ikm = eph_priv, salt = empty, info = AsyncBindInfo,
// L = 32).
//
// Deriving it rather than drawing it at random is what keeps the sender
// stateless: the key is already carried in the user's job id, so the value can
// be recomputed at poll time instead of stored.
func DeriveAsyncBind(ephPriv crypto.PrivateKey) ([]byte, error) {
	if len(ephPriv) != ephPrivLen {
		return nil, fmt.Errorf("ephemeral private key must be %d bytes, got %d", ephPrivLen, len(ephPriv))
	}
	return hkdf.Key(sha256.New, ephPriv, nil, AsyncBindInfo, asyncBindLen)
}

// AttachAsyncBind returns a copy of req carrying the `_bind` field derived from
// ephPriv, ready for SealRequestFor(ProfileAsyncImage, …), whose default sealed
// set then seals it alongside the prompt.
//
// A request that already carries `_bind` is refused: the name is reserved by
// this profile, and a caller-supplied value would be sealed as if derived.
func AttachAsyncBind(req Request, ephPriv crypto.PrivateKey) (Request, error) {
	if _, ok := req[fieldBind]; ok {
		return nil, fmt.Errorf("request already carries %q, which the async-image profile reserves", fieldBind)
	}
	bind, err := DeriveAsyncBind(ephPriv)
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

// TakeAsyncBind is the enclave's half on the request side: given a request that
// OpenRequestFor(ProfileAsyncImage, …) reconstructed, it returns the binding
// value to echo in the result, and the request WITHOUT `_bind` — the one to
// forward upstream. `_bind` is protocol metadata, not a model parameter, and an
// upstream that rejects unknown fields would otherwise fail every sealed job.
func TakeAsyncBind(opened Request) (bind []byte, forward Request, err error) {
	raw, ok := opened[fieldBind]
	if !ok {
		return nil, nil, fmt.Errorf("opened async-image request carries no %q", fieldBind)
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

// SealAsyncImageResult is the enclave's half on the result side: it seals a
// completed job's poll response as the async-image result frame (§7.5).
//
// result is the poll envelope as the broker will return it, minus `_e2ee`: the
// cleartext `jobId`, `status`, timestamps, `model` and `usage.output_images`,
// plus `data` — the provider JSON — which is sealed. bind is what TakeAsyncBind
// returned for this job's request.
//
// It refuses a frame that does not name its job or is not `completed`, since
// those are the two fields the receiver keys off, and declares the profile's
// unbound set itself.
func SealAsyncImageResult(clientEphPub crypto.PublicKey, result Response, bind []byte) (Response, error) {
	if len(bind) != asyncBindLen {
		return nil, fmt.Errorf("binding value must be %d bytes, got %d", asyncBindLen, len(bind))
	}
	if _, ok := result[fieldBind]; ok {
		return nil, fmt.Errorf("result already carries %q", fieldBind)
	}
	if _, err := cleartextString(result, fieldJobID); err != nil {
		return nil, err
	}
	status, err := cleartextString(result, fieldStatus)
	if err != nil {
		return nil, err
	}
	if status != AsyncStatusCompleted {
		return nil, fmt.Errorf("only a %q job has a result frame, got status %q", AsyncStatusCompleted, status)
	}
	raw, err := json.Marshal(b64.EncodeToString(bind))
	if err != nil {
		return nil, err
	}
	frame := make(Response, len(result)+1)
	for k, v := range result {
		frame[k] = v
	}
	frame[fieldBind] = raw
	return SealResponseFor(ProfileAsyncImage, clientEphPub, frame, nil, asyncImageResultUnbound...)
}

// OpenAsyncImageResult is the sender's half at poll time: it opens an
// async-image result frame and proves it answers THIS job's request.
//
// wantJobID is the broker-assigned id the caller is polling — the job-id half of
// the user's id (ParseUserJobID). In order, it requires:
//
//   - an unbound set within the profile's own, so `jobId` and `status` are bound;
//   - `status` == "completed" and `jobId` == wantJobID, both in cleartext;
//   - every OpenResponseFor(ProfileAsyncImage) check — `data` and `_bind` sealed,
//     a final frame, a cleartext `usage.output_images` — and the AEAD itself,
//     which authenticates the two fields above as AAD;
//   - the sealed `_bind` equal to the value derived from ephPriv.
//
// The returned response has `_bind` removed: the caller gets the poll envelope
// in its ordinary shape, `data` restored.
func OpenAsyncImageResult(ephPriv crypto.PrivateKey, frame Response, wantJobID string) (Response, error) {
	if len(ephPriv) != ephPrivLen {
		return nil, fmt.Errorf("ephemeral private key must be %d bytes, got %d", ephPrivLen, len(ephPriv))
	}
	e2ee, err := frame.E2EE()
	if err != nil {
		return nil, err
	}
	for _, f := range e2ee.UnboundFields {
		if !slices.Contains(asyncImageResultUnbound, f) {
			return nil, fmt.Errorf("async-image result frame declares %q unbound; only %s may be, so an intermediary cannot rewrite the fields this check keys off", f, quotedList(asyncImageResultUnbound))
		}
	}
	status, err := cleartextString(frame, fieldStatus)
	if err != nil {
		return nil, err
	}
	if status != AsyncStatusCompleted {
		return nil, fmt.Errorf("a result frame must be %q, got status %q", AsyncStatusCompleted, status)
	}
	jobID, err := cleartextString(frame, fieldJobID)
	if err != nil {
		return nil, err
	}
	if jobID != wantJobID {
		// Neither id is echoed: the caller's may sit next to a key in its logs.
		return nil, fmt.Errorf("result frame names a different job than the one polled")
	}
	// The profile checks, the AEAD, and the `_bind` comparison (the opener derives
	// the expected value from ephPriv; see profileSpec.bindsResult).
	opened, err := OpenResponseFor(ProfileAsyncImage, ephPriv, frame)
	if err != nil {
		return nil, err
	}
	delete(opened, fieldBind)
	return opened, nil
}

// UserJobID returns the id the user keeps for an async job: the broker job id,
// a ".", and base64url(eph_priv) (§7.5). It is a credential — whoever holds it
// can open that one job's result — and the sender MUST NOT forward the key
// segment or log the whole id.
func UserJobID(jobID string, ephPriv crypto.PrivateKey) (string, error) {
	if err := validateJobID(jobID); err != nil {
		return "", err
	}
	if len(ephPriv) != ephPrivLen {
		return "", fmt.Errorf("ephemeral private key must be %d bytes, got %d", ephPrivLen, len(ephPriv))
	}
	return jobID + userJobIDSep + b64.EncodeToString(ephPriv), nil
}

// ParseUserJobID splits a UserJobID back into the broker job id and the
// ephemeral private key. It splits on the LAST ".", requires the job-id half to
// be 1–128 characters of [A-Za-z0-9_-], and requires the key half to be
// unpadded base64url decoding to exactly 32 bytes.
//
// Its errors never echo the input: the key segment is secret, and an error
// message is a log line waiting to happen.
func ParseUserJobID(s string) (jobID string, ephPriv crypto.PrivateKey, err error) {
	i := strings.LastIndex(s, userJobIDSep)
	if i < 0 {
		return "", nil, fmt.Errorf("job id carries no key segment")
	}
	jobID, keyPart := s[:i], s[i+len(userJobIDSep):]
	if err := validateJobID(jobID); err != nil {
		return "", nil, err
	}
	key, err := b64.Strict().DecodeString(keyPart)
	if err != nil {
		return "", nil, fmt.Errorf("job id key segment is not unpadded base64url")
	}
	if len(key) != ephPrivLen {
		return "", nil, fmt.Errorf("job id key segment must decode to %d bytes, got %d", ephPrivLen, len(key))
	}
	return jobID, crypto.PrivateKey(key), nil
}

// HasUserJobIDKey reports whether a job id carries a key segment at all — the
// one fact a sender's poll handler branches on (§7.5: present → sealed handling,
// absent → cleartext passthrough). It does not validate the segment; parse it
// with ParseUserJobID before use.
func HasUserJobIDKey(s string) bool {
	return strings.Contains(s, userJobIDSep)
}

// validateJobID applies the job-id half's alphabet and length rule. Like
// ParseUserJobID it never echoes the value.
func validateJobID(jobID string) error {
	if jobID == "" {
		return fmt.Errorf("job id is empty")
	}
	if len(jobID) > maxJobIDLen {
		return fmt.Errorf("job id longer than %d characters", maxJobIDLen)
	}
	for i := 0; i < len(jobID); i++ {
		c := jobID[i]
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
			return fmt.Errorf("job id contains a character outside [A-Za-z0-9_-]")
		}
	}
	return nil
}

// decodeBind decodes a `_bind` value: a JSON string of unpadded base64url
// encoding exactly 32 bytes.
func decodeBind(raw json.RawMessage) ([]byte, error) {
	if raw == nil {
		return nil, fmt.Errorf("missing %q", fieldBind)
	}
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		return nil, fmt.Errorf("%q must be a JSON string: %w", fieldBind, err)
	}
	b, err := b64.Strict().DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("%q is not unpadded base64url", fieldBind)
	}
	if len(b) != asyncBindLen {
		return nil, fmt.Errorf("%q must decode to %d bytes, got %d", fieldBind, asyncBindLen, len(b))
	}
	return b, nil
}

// cleartextString reads a required top-level JSON-string field of a frame.
func cleartextString(frame Response, field string) (string, error) {
	raw, ok := frame[field]
	if !ok {
		return "", fmt.Errorf("async-image result frame carries no cleartext %q", field)
	}
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		return "", fmt.Errorf("async-image result frame %q must be a JSON string: %w", field, err)
	}
	if s == "" {
		return "", fmt.Errorf("async-image result frame %q is empty", field)
	}
	return s, nil
}
