package evidence

// mrconfig.go reads the dstack compose hash a verified TDX quote commits to, whatever
// layout its mr_config_id uses.
//
// V1 carries the hash in the clear (attest.ComposeHashFromMRConfigID). dstack 0.6
// launches with V3, which carries none of it in the clear:
//
//	mr_config_id = 0x03 ‖ SHA-256("dstack-mr-config-v3:" ‖ 0x00 ‖ document) ‖ zero padding
//
// where the document is a JSON object the HOST writes at launch (dstack-types
// mr_config.rs, MrConfigV3) and the guest checks before it boots the app
// (dstack-util config_id_verifier.rs, verify_mr_config_v3_document): every field the
// document declares must equal what the guest itself observed. The document is not in
// the quote reply. What is, is the event log — and the guest writes every value the
// document can declare into RTMR3 during boot (dstack-util system_setup.rs):
// app-id, compose-hash, each init-script-hash, gpu-policy-hash, instance-id, and
// key-provider.
//
// So the document is rebuilt rather than read. The log is replayed to the VERIFIED
// quote's RTMR3 first, which makes every value in it as good as the quote. Then the
// candidates: version, compose_hash and key_provider are always present, instance_id
// whenever it is non-empty (the guest treats an absent one as empty, so a non-empty one
// cannot be omitted), and each of app_id, gpu_policy_hash, key_provider_id and
// init_script_hashes either omitted or equal to the logged value — the only value the
// guest would have accepted. Sixteen candidates at most, each serialized as dstack
// does (RFC 8785 JCS) and hashed under the V3 domain; the compose hash is established
// when one of them reproduces mr_config_id exactly.
//
// WHAT THAT ESTABLISHES is what V1 did: the host committed to this compose hash at
// launch, in a register inside the signed report, and the guest — an OS the boot chain
// pins — refused to boot unless the app-compose it loaded hashed to it. A match also
// cross-checks the log against the register: the document's compose_hash IS the
// logged one, so the two cannot disagree. No match is not a finding against the CVM —
// a host may write a field this reader does not know — it is a compose hash this
// reader could not establish, reported as such.

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/0gfoundation/0g-pc-e2ee/protocol/attest"
)

// mrConfigV3Domain is dstack's domain separator for the V3 document hash
// (MR_CONFIG_V3_DOCUMENT_HASH_DOMAIN), followed by a zero byte.
const mrConfigV3Domain = "dstack-mr-config-v3:"

// The boot events a V3 document can be rebuilt from (dstack-util system_setup.rs).
const (
	evAppID          = "app-id"
	evComposeHash    = "compose-hash"
	evInitScriptHash = "init-script-hash"
	evGPUPolicyHash  = "gpu-policy-hash"
	evInstanceID     = "instance-id"
	evKeyProvider    = "key-provider"
)

// keyProviderKinds maps the key-provider event's name to the document's key_provider
// (dstack-types KeyProviderKind, snake_case). The guest writes "local-sgx" for Local.
var keyProviderKinds = map[string]string{"none": "none", "kms": "kms", "local-sgx": "local", "tpm": "tpm"}

// ComposeHashOf returns the compose hash the verified quote's mr_config_id commits to.
// reply is the /v1/quote reply (or evidence quote.json) the quote came from, and rtmr3
// the VERIFIED quote's RTMR3; both are read only for a V3 mr_config_id. An error wraps
// attest.ErrUnsupportedMRConfig when this reader cannot establish a hash, whatever the
// reason, so callers that treat "no hash" as a check that did not run keep doing so.
func ComposeHashOf(mrConfigID [48]byte, reply []byte, rtmr3 [RTMRLen]byte) ([attest.ComposeHashLen]byte, error) {
	if mrConfigID[0] != 3 {
		return attest.ComposeHashFromMRConfigID(mrConfigID)
	}
	var out [attest.ComposeHashLen]byte
	log, err := replayRTMR3(reply, rtmr3)
	if err != nil {
		return out, fmt.Errorf("%w: version 3 commits to a document rebuilt from the event log, and %v",
			attest.ErrUnsupportedMRConfig, err)
	}
	ev, err := bootEvents(log)
	if err != nil {
		return out, fmt.Errorf("%w: version 3: %v", attest.ErrUnsupportedMRConfig, err)
	}
	docs, err := v3Candidates(ev)
	if err != nil {
		return out, fmt.Errorf("%w: version 3: %v", attest.ErrUnsupportedMRConfig, err)
	}
	for _, doc := range docs {
		if mrConfigIDV3(doc) == mrConfigID {
			copy(out[:], ev.composeHash)
			return out, nil
		}
	}
	return out, fmt.Errorf("%w: version 3: none of the %d documents the event log allows reproduces mr_config_id "+
		"(the host may have declared a field this reader does not know)", attest.ErrUnsupportedMRConfig, len(docs))
}

// mrConfigIDV3 is the TDX mr_config_id of a V3 document (MrConfigV3::tdx_mr_config_id_from_document).
func mrConfigIDV3(document []byte) [48]byte {
	h := sha256.New()
	h.Write([]byte(mrConfigV3Domain))
	h.Write([]byte{0})
	h.Write(document)
	var id [48]byte
	id[0] = 3
	copy(id[1:], h.Sum(nil))
	return id
}

// bootLog is the boot events a V3 document is rebuilt from.
type bootLog struct {
	appID, composeHash, gpuPolicyHash, instanceID []byte
	haveGPUPolicyHash                             bool
	initScriptHashes                              [][]byte
	keyProvider, keyProviderID                    string
}

// bootEvents reads the boot events written before system-ready. Each but
// init-script-hash is written once per boot; a second one is a log this reader will not
// guess about.
func bootEvents(log []rtmr3Entry) (bootLog, error) {
	var b bootLog
	seen := map[string]bool{}
	once := func(name string) error {
		if seen[name] {
			return fmt.Errorf("the event log carries %q twice before system-ready", name)
		}
		seen[name] = true
		return nil
	}
	ready := false
	for _, e := range log {
		if e.Event == systemReady {
			ready = true
			break
		}
		switch e.Event {
		case evAppID, evComposeHash, evGPUPolicyHash, evInstanceID, evKeyProvider:
			if err := once(e.Event); err != nil {
				return b, err
			}
		}
		switch e.Event {
		case evAppID:
			b.appID = e.payload
		case evComposeHash:
			b.composeHash = e.payload
		case evGPUPolicyHash:
			b.gpuPolicyHash, b.haveGPUPolicyHash = e.payload, true
		case evInstanceID:
			b.instanceID = e.payload
		case evInitScriptHash:
			b.initScriptHashes = append(b.initScriptHashes, e.payload)
		case evKeyProvider:
			var kp struct {
				Name string `json:"name"`
				ID   string `json:"id"`
			}
			if err := json.Unmarshal(e.payload, &kp); err != nil {
				return b, fmt.Errorf("the key-provider event is not JSON: %v", err)
			}
			kind, ok := keyProviderKinds[kp.Name]
			if !ok {
				return b, fmt.Errorf("the key-provider event names %q, a provider this reader does not know", kp.Name)
			}
			if _, err := hex.DecodeString(kp.ID); err != nil {
				return b, fmt.Errorf("the key-provider event's id is not hex: %v", err)
			}
			b.keyProvider, b.keyProviderID = kind, kp.ID
		}
	}
	switch {
	case !ready:
		return b, errors.New("the event log has no system-ready entry")
	case len(b.composeHash) != attest.ComposeHashLen:
		return b, fmt.Errorf("the event log's compose-hash is %d bytes, want %d", len(b.composeHash),
			attest.ComposeHashLen)
	case b.keyProvider == "":
		return b, errors.New("the event log has no key-provider entry")
	}
	return b, nil
}

// v3Candidates is every document the guest would have accepted for this boot, in JCS.
func v3Candidates(b bootLog) ([][]byte, error) {
	type field struct {
		key   string
		value any
	}
	var optional []field
	if len(b.appID) > 0 {
		optional = append(optional, field{"app_id", hex.EncodeToString(b.appID)})
	}
	if b.haveGPUPolicyHash {
		optional = append(optional, field{"gpu_policy_hash", hex.EncodeToString(b.gpuPolicyHash)})
	}
	if b.keyProviderID != "" {
		optional = append(optional, field{"key_provider_id", b.keyProviderID})
	}
	scripts := make([]string, 0, len(b.initScriptHashes))
	for _, h := range b.initScriptHashes {
		scripts = append(scripts, hex.EncodeToString(h))
	}
	optional = append(optional, field{"init_script_hashes", scripts})

	var docs [][]byte
	for mask := 0; mask < 1<<len(optional); mask++ {
		doc := map[string]any{
			"version":      3,
			"compose_hash": hex.EncodeToString(b.composeHash),
			"key_provider": b.keyProvider,
		}
		if len(b.instanceID) > 0 {
			doc["instance_id"] = hex.EncodeToString(b.instanceID)
		}
		for i, f := range optional {
			if mask&(1<<i) != 0 {
				doc[f.key] = f.value
			}
		}
		raw, err := jcs(doc)
		if err != nil {
			return nil, err
		}
		docs = append(docs, raw)
	}
	return docs, nil
}

// jcs serializes a document of string, integer and string-list values the way RFC 8785
// does, which for these values is encoding/json of a map — keys sorted, no whitespace —
// without HTML escaping. Every key is ASCII, so the map's byte order is JCS's UTF-16
// order.
func jcs(doc map[string]any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(doc); err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(buf.Bytes(), []byte("\n")), nil
}

// LoggedAppID returns the app_id the guest wrote into RTMR3 at boot (the app-id event),
// hex, once the reply's event log has replayed to rtmr3 — the verified quote's RTMR3.
// It is the app_id the quote vouches for, which neither a DNS record nor compose_hash's
// prefix is; under a V3 mr_config_id the host's launch document commits to it too.
func LoggedAppID(reply []byte, rtmr3 [RTMRLen]byte) (string, error) {
	log, err := replayRTMR3(reply, rtmr3)
	if err != nil {
		return "", err
	}
	ev, err := bootEvents(log)
	if err != nil {
		return "", err
	}
	if len(ev.appID) != attest.AppIDLen {
		return "", fmt.Errorf("the event log's app-id is %d bytes, want %d", len(ev.appID), attest.AppIDLen)
	}
	return hex.EncodeToString(ev.appID), nil
}
