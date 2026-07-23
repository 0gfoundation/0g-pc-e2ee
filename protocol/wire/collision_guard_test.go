package wire

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/0gfoundation/0g-pc-e2ee/protocol/crypto"
)

// Phase 1: the `_e2ee` reserved-key guards (design notes §8 H2). A decrypted
// object must never carry the `_e2ee` metadata key, and the seal-field
// validators must refuse to declare it (or an empty name).

func TestValidateSealedFieldsRejectsReservedAndEmpty(t *testing.T) {
	cases := map[string][]string{
		"reserved _e2ee": {"messages", e2eeKey},
		"empty name":     {"messages", ""},
	}
	for name, fields := range cases {
		if err := ValidateSealedFields(fields); err == nil {
			t.Errorf("%s: expected ValidateSealedFields to reject %v, got nil", name, fields)
		}
	}
	// The reserved key alone (without messages) must also fail.
	if err := ValidateSealedFields([]string{e2eeKey}); err == nil {
		t.Error("expected rejection of a sealed set that is only the reserved key")
	}
}

func TestValidateResponseSealedFieldsRejectsReservedAndEmpty(t *testing.T) {
	if err := validateResponseSealedFields([]string{"choices", e2eeKey}); err == nil {
		t.Error("expected rejection of reserved _e2ee in response sealed fields")
	}
	if err := validateResponseSealedFields([]string{"choices", ""}); err == nil {
		t.Error("expected rejection of an empty response sealed field name")
	}
}

var guardProviderID = "0x" + strings.Repeat("b", 40)

// OpenRequest must reject an envelope whose decrypted object contains `_e2ee`,
// even when the (malicious/non-conformant) sealer declared it in sealed_fields
// so the keys-match check passes. This is hand-crafted because SealRequest's
// ValidateSealedFields now refuses to produce such an envelope.
func TestOpenRequestRejectsDecryptedE2EE(t *testing.T) {
	priv, pub, err := crypto.GenerateRecipientKey()
	if err != nil {
		t.Fatal(err)
	}
	_, ephPub, err := crypto.GenerateRecipientKey()
	if err != nil {
		t.Fatal(err)
	}
	enc, sealer, err := crypto.SetupSender(pub, []byte(SealInfo))
	if err != nil {
		t.Fatal(err)
	}

	sealedObj := map[string]json.RawMessage{
		"messages": json.RawMessage(`[{"role":"user","content":"x"}]`),
		e2eeKey:    json.RawMessage(`{"evil":true}`),
	}
	pt, err := json.Marshal(sealedObj)
	if err != nil {
		t.Fatal(err)
	}

	env := Request{"model": json.RawMessage(`"m"`)}
	e2ee := E2EE{
		V:            Version,
		KEMID:        KEMID,
		KeyID:        b64.EncodeToString(keyID(pub)),
		ProviderID:   guardProviderID,
		ClientEphPub: b64.EncodeToString(ephPub),
		Enc:          b64.EncodeToString(enc),
		SealedFields: []string{"messages", e2eeKey},
	}
	if err := env.setE2EE(e2ee); err != nil {
		t.Fatal(err)
	}
	aad, err := aadFromEnvelope(env)
	if err != nil {
		t.Fatal(err)
	}
	ct, err := sealer.Seal(pt, aad)
	if err != nil {
		t.Fatal(err)
	}
	e2ee.Ciphertext = b64.EncodeToString(ct)
	if err := env.setE2EE(e2ee); err != nil {
		t.Fatal(err)
	}

	if _, err := OpenRequest(priv, env); err == nil {
		t.Fatal("expected OpenRequest to reject a decrypted _e2ee key, got nil")
	}
}

// OpenFrame must reject a decrypted `_e2ee` on the response path, same as
// OpenRequest.
func TestOpenFrameRejectsDecryptedE2EE(t *testing.T) {
	ephPriv, ephPub, err := crypto.GenerateRecipientKey()
	if err != nil {
		t.Fatal(err)
	}
	enc, sealer, err := crypto.SetupSender(ephPub, []byte(RespInfo))
	if err != nil {
		t.Fatal(err)
	}

	sealedObj := map[string]json.RawMessage{
		"choices": json.RawMessage(`[{"index":0,"message":{"role":"assistant","content":"a"}}]`),
		e2eeKey:   json.RawMessage(`{"evil":true}`),
	}
	pt, err := json.Marshal(sealedObj)
	if err != nil {
		t.Fatal(err)
	}

	frame := Response{"model": json.RawMessage(`"m"`)}
	e2ee := ResponseE2EE{
		V:            Version,
		Enc:          b64.EncodeToString(enc),
		SealedFields: []string{"choices", e2eeKey},
		Final:        true,
	}
	if err := setResponseE2EE(frame, e2ee); err != nil {
		t.Fatal(err)
	}
	aad, err := aadFromEnvelope(frame)
	if err != nil {
		t.Fatal(err)
	}
	ct, err := sealer.Seal(pt, aad)
	if err != nil {
		t.Fatal(err)
	}
	e2ee.Ciphertext = b64.EncodeToString(ct)
	if err := setResponseE2EE(frame, e2ee); err != nil {
		t.Fatal(err)
	}

	opener, err := NewResponseOpener(ephPriv, frame)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := opener.OpenFrame(frame); err == nil {
		t.Fatal("expected OpenFrame to reject a decrypted _e2ee key, got nil")
	}
}
