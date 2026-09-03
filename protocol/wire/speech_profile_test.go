package wire_test

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"github.com/0gfoundation/0g-pc-e2ee/protocol/crypto"
	"github.com/0gfoundation/0g-pc-e2ee/protocol/wire"
)

// A representative JSON-ified transcription request (SPEC §5.3). The audio that
// was a multipart file part is base64 in `file_base64`; `model`,
// `response_format` and `stream` are what the router reads.
var sampleSpeechReq = `{
  "model": "whisper-large-v3",
  "response_format": "json",
  "file_base64": "` + sampleAudioB64 + `",
  "filename": "board-meeting-2026Q3.m4a",
  "language": "en",
  "prompt": "attendee names: Alice, Bob"
}`

// sampleAudio / sampleAudioB64 are the §10 KAT fixture for a binary payload
// field, chosen so the encoding cannot pass by accident. Its triples, ALIGNED on
// multiples of three, which is the part that has to be got right:
//
//	52 49 46 -> "UklG"   (ordinary bytes, to make the string readable)
//	FB EF BE -> "++++"   (alphabet index 62 four times; base64url renders "-")
//	FF FF FF -> "////"   (index 63 four times;          base64url renders "_")
//	7F       -> "fw=="   (a 1-byte remainder, so padding is required)
//
// So the fixture differs from base64url in BOTH of the characters where the two
// alphabets diverge, and separately requires padding. Three ways of getting the
// encoding wrong are therefore all caught, and all three are silent — they
// corrupt the audio inside the enclave rather than failing Open, which is why
// SPEC §10 requires this vector:
//
//   - base64url without padding (§3's wire encoding, the tempting mistake in
//     this codebase, since every other binary field uses it);
//   - base64url WITH padding, which the previous version of this fixture did
//     not catch at all — see the test;
//   - standard base64 without padding.
//
// The alignment is the trap. An earlier fixture put these bytes after a 4-byte
// prefix, which offset the grouping so the intended triples were never triples:
// the real groups came out `(46 FB EF)` and `(BE FF 00)`, encoding to "Rvvv" and
// "vv8A" with neither a "+" nor a "/" anywhere. Its output was byte-identical
// under standard and padded-URL-safe base64, so the assertion that was supposed
// to distinguish the alphabets was only ever testing padding.
var sampleAudio = []byte{0x52, 0x49, 0x46, 0xFB, 0xEF, 0xBE, 0xFF, 0xFF, 0xFF, 0x7F}

var sampleAudioB64 = base64.StdEncoding.EncodeToString(sampleAudio)

// TestSpeechBinaryPayloadEncodingKAT is the §10 known-answer vector for the
// encoding choice itself. It pins the exact string, so a change of alphabet or
// padding fails here rather than in an enclave's audio decoder.
func TestSpeechBinaryPayloadEncodingKAT(t *testing.T) {
	const want = "UklG++++////fw=="
	if sampleAudioB64 != want {
		t.Fatalf("standard base64 of the fixture = %q, want %q", sampleAudioB64, want)
	}

	// The fixture must exercise both characters where the alphabets diverge, or
	// the comparisons below can pass for a fixture that distinguishes nothing.
	// Asserted rather than assumed: this is exactly what the previous fixture got
	// wrong, and it got it wrong in a comment that did the arithmetic by hand.
	if !strings.Contains(sampleAudioB64, "+") || !strings.Contains(sampleAudioB64, "/") {
		t.Fatalf("the fixture must contain both %q and %q — the two characters standard base64 and base64url disagree on; got %q", "+", "/", sampleAudioB64)
	}
	if !strings.HasSuffix(sampleAudioB64, "==") {
		t.Error("the fixture must require padding, so an unpadded encoder is caught")
	}

	// base64url WITH padding is the case the previous fixture missed entirely:
	// its output was byte-identical to standard base64, so a decoder wired to
	// base64.URLEncoding passed the KAT and would then have silently corrupted
	// every audio payload containing a 62 or 63 sextet.
	if padded := base64.URLEncoding.EncodeToString(sampleAudio); padded == sampleAudioB64 {
		t.Fatalf("the fixture does not distinguish standard base64 from PADDED base64url (both %q); pick bytes that encode differently", padded)
	}
	// And §3's wire alphabet, which a binary payload field must not use.
	if raw := base64.RawURLEncoding.EncodeToString(sampleAudio); raw == sampleAudioB64 {
		t.Fatal("the fixture does not distinguish standard base64 from base64url; pick bytes that encode differently")
	}

	if decoded, err := base64.StdEncoding.DecodeString(sampleAudioB64); err != nil || string(decoded) != string(sampleAudio) {
		t.Fatalf("round trip: %v / %q", err, decoded)
	}
}

func speechKeys(t *testing.T) (crypto.PrivateKey, crypto.PublicKey, crypto.PublicKey) {
	t.Helper()
	priv, pub, err := crypto.GenerateRecipientKey()
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	_, ephPub, err := crypto.GenerateRecipientKey()
	if err != nil {
		t.Fatalf("eph keygen: %v", err)
	}
	return priv, pub, ephPub
}

// The audio, the filename, the language hint and the biasing prompt all leave in
// the ciphertext; only what the router routes and bills on stays readable.
func TestSpeechProfileSealsAudioAndLeavesRoutingFieldsCleartext(t *testing.T) {
	priv, pub, ephPub := speechKeys(t)

	env, err := wire.SealRequestFor(wire.ProfileSpeech, pub, mustReq(t, sampleSpeechReq),
		nil, testProvider, ephPub)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}

	for _, f := range []string{"file_base64", "filename", "language", "prompt"} {
		if _, ok := env[f]; ok {
			t.Errorf("%q must not remain as a cleartext field", f)
		}
	}
	for _, f := range []string{"model", "response_format"} {
		if _, ok := env[f]; !ok {
			t.Errorf("routing field %q must stay cleartext", f)
		}
	}

	raw, err := json.Marshal(env)
	if err != nil {
		t.Fatalf("marshal envelope: %v", err)
	}
	for _, secret := range []string{sampleAudioB64, "board-meeting-2026Q3.m4a", "Alice, Bob"} {
		if strings.Contains(string(raw), secret) {
			t.Errorf("payload %q leaked into the sealed envelope", secret)
		}
	}

	got, err := wire.OpenRequestFor(wire.ProfileSpeech, priv, env)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	var audio string
	if err := json.Unmarshal(got["file_base64"], &audio); err != nil {
		t.Fatalf("decode file_base64: %v", err)
	}
	if audio != sampleAudioB64 {
		t.Fatalf("round-tripped audio = %q, want %q", audio, sampleAudioB64)
	}
}

// The payload field is the audio: a sealed set without it defeats the profile,
// and both ends must refuse it.
func TestSpeechProfileRejectsSealedSetWithoutAudio(t *testing.T) {
	if err := wire.ValidateSealedFieldsFor(wire.ProfileSpeech, []string{"prompt", "filename"}); err == nil {
		t.Fatal("a sealed set omitting file_base64 must be refused")
	} else if !strings.Contains(err.Error(), "file_base64") {
		t.Errorf("error should name the payload field, got %v", err)
	}
}

// `filename`, `language` and `prompt` are CONDITIONALLY REQUIRED, not merely
// defaulted: a default is droppable, so without this a conforming envelope could
// hand the filename to the router in the clear — which would undercut the
// profile's own argument for JSON-ifying the request in the first place.
//
// Both ends, and the enclave's half is the load-bearing one: a third-party
// client runs no seal-time check.
func TestSpeechConditionalPayloadFieldsMustBeSealedWhenPresent(t *testing.T) {
	for _, field := range []string{"filename", "language", "prompt"} {
		t.Run(field, func(t *testing.T) {
			priv, pub, ephPub := speechKeys(t)

			// A sender that seals only the audio and leaves this field readable.
			_, err := wire.SealRequestFor(wire.ProfileSpeech, pub, mustReq(t, sampleSpeechReq),
				[]string{"file_base64"}, testProvider, ephPub)
			if err == nil {
				t.Fatalf("a request carrying %q in cleartext must be refused at seal time", field)
			}

			// And the receiver's half, on an envelope built without the field so it
			// can be added afterwards the way a third-party client would send it.
			req := mustReq(t, sampleSpeechReq)
			for _, f := range []string{"filename", "language", "prompt"} {
				delete(req, f)
			}
			env, err := wire.SealRequestFor(wire.ProfileSpeech, pub, req,
				[]string{"file_base64"}, testProvider, ephPub)
			if err != nil {
				t.Fatalf("seal without the optional fields: %v", err)
			}
			env[field] = json.RawMessage(`"leaked"`)

			if _, err := wire.OpenRequestFor(wire.ProfileSpeech, priv, env); err == nil {
				t.Fatalf("the enclave must refuse an envelope carrying %q in the clear", field)
			} else if !strings.Contains(err.Error(), field) {
				t.Errorf("the profile check should fire before the AEAD, naming the field; got %v", err)
			}
		})
	}
}

// The flip side: they are OPTIONAL, so a request that omits them must still
// seal. `required` would have rejected this.
func TestSpeechConditionalPayloadFieldsMayBeAbsent(t *testing.T) {
	priv, pub, ephPub := speechKeys(t)
	req := mustReq(t, sampleSpeechReq)
	for _, f := range []string{"filename", "language", "prompt"} {
		delete(req, f)
	}

	env, err := wire.SealRequestFor(wire.ProfileSpeech, pub, req, []string{"file_base64"}, testProvider, ephPub)
	if err != nil {
		t.Fatalf("a request with only the audio must seal: %v", err)
	}
	if _, err := wire.OpenRequestFor(wire.ProfileSpeech, priv, env); err != nil {
		t.Fatalf("open: %v", err)
	}
}

// ---------------------------------------------------------------------------
// response_format: a pin with TWO permitted values (SPEC §5.3.2)
// ---------------------------------------------------------------------------

func TestSpeechProfilePermitsBothJSONFormats(t *testing.T) {
	for _, format := range []string{"json", "verbose_json"} {
		t.Run(format, func(t *testing.T) {
			priv, pub, ephPub := speechKeys(t)
			req := mustReq(t, sampleSpeechReq)
			req["response_format"] = json.RawMessage(`"` + format + `"`)

			env, err := wire.SealRequestFor(wire.ProfileSpeech, pub, req, nil, testProvider, ephPub)
			if err != nil {
				t.Fatalf("seal %s: %v", format, err)
			}
			if _, err := wire.OpenRequestFor(wire.ProfileSpeech, priv, env); err != nil {
				t.Fatalf("open %s: %v", format, err)
			}
		})
	}
}

// text / srt / vtt return a body that is not a JSON object, so a sealed exchange
// cannot express them at all — there is nowhere to put `_e2ee` and no aad for
// the §8 binding.
func TestSpeechProfileRefusesNonJSONResponseFormats(t *testing.T) {
	for _, format := range []string{"text", "srt", "vtt", "json_but_wrong"} {
		t.Run(format, func(t *testing.T) {
			_, pub, ephPub := speechKeys(t)
			req := mustReq(t, sampleSpeechReq)
			req["response_format"] = json.RawMessage(`"` + format + `"`)

			_, err := wire.SealRequestFor(wire.ProfileSpeech, pub, req, nil, testProvider, ephPub)
			if err == nil {
				t.Fatalf("response_format %q must be refused", format)
			}
			if !strings.Contains(err.Error(), "verbose_json") {
				t.Errorf("error should name the permitted values, got %v", err)
			}
		})
	}
}

// Two permitted values do not make the field optional: an absent one takes the
// server's default, which is what a pin guards against.
func TestSpeechProfileStillRequiresResponseFormatToBePresent(t *testing.T) {
	_, pub, ephPub := speechKeys(t)
	req := mustReq(t, sampleSpeechReq)
	delete(req, "response_format")

	_, err := wire.SealRequestFor(wire.ProfileSpeech, pub, req, nil, testProvider, ephPub)
	if err == nil {
		t.Fatal("an absent response_format must be refused, not defaulted")
	}
	if !strings.Contains(err.Error(), "explicitly") {
		t.Errorf("error should say the field must be set explicitly, got %v", err)
	}
}

// Widening image's pin to a set must not have widened image's pin.
func TestImagePinIsStillExactlyB64JSON(t *testing.T) {
	_, pub, ephPub := speechKeys(t)
	req := mustReq(t, sampleImageReq)
	req["response_format"] = json.RawMessage(`"verbose_json"`)

	if _, err := wire.SealRequestFor(wire.ProfileImage, pub, req, nil, testProvider, ephPub); err == nil {
		t.Fatal("the image profile must still permit only b64_json")
	}
}

func TestSpeechPinnedFormatCannotBeSealedOrUnbound(t *testing.T) {
	if err := wire.ValidateSealedFieldsFor(wire.ProfileSpeech, []string{"file_base64", "response_format"}); err == nil {
		t.Error("sealing the pinned response_format must be refused")
	}
	if err := wire.ValidateUnboundFieldsFor(wire.ProfileSpeech, []string{"response_format"}, []string{"file_base64"}); err == nil {
		t.Error("declaring the pinned response_format unbound must be refused")
	}
}

// ---------------------------------------------------------------------------
// stream: a REFUSED cleartext value, where absence is compliant (SPEC §5.3.3)
// ---------------------------------------------------------------------------

// The trap this test exists for: implementing the refusal with the pinned-field
// machinery would demand `stream` be PRESENT and reject every conforming
// request. The common case sends no `stream` at all.
func TestSpeechProfileAcceptsAnAbsentStreamField(t *testing.T) {
	priv, pub, ephPub := speechKeys(t)
	req := mustReq(t, sampleSpeechReq)
	if _, present := req["stream"]; present {
		t.Fatal("fixture should not carry stream")
	}

	env, err := wire.SealRequestFor(wire.ProfileSpeech, pub, req, nil, testProvider, ephPub)
	if err != nil {
		t.Fatalf("an absent stream field must be accepted: %v", err)
	}
	if _, err := wire.OpenRequestFor(wire.ProfileSpeech, priv, env); err != nil {
		t.Fatalf("open: %v", err)
	}
}

// Whitespace around the value must not decide the outcome: the comparison is on
// the DECODED value's materialized token, not on the sender's bytes.
func TestSpeechStreamRefusalIgnoresSenderWhitespace(t *testing.T) {
	_, pub, ephPub := speechKeys(t)
	req := mustReq(t, sampleSpeechReq)
	req["stream"] = json.RawMessage("  true ")

	if _, err := wire.SealRequestFor(wire.ProfileSpeech, pub, req, nil, testProvider, ephPub); err == nil {
		t.Fatal("stream: ` true ` must be refused like `true`")
	}
}

// THE test for this rule, and the one an earlier version of this profile got
// backwards. The pin is a whitelist, not a blacklist of refused values, because
// the enclave re-materializes this request as multipart/form-data — where every
// value is a STRING and `stream=true` is exactly how a real streaming request is
// written. A blacklist over JSON types let `"true"`, `1`, `"1"` and `"yes"`
// through on the one profile whose premise makes them equivalent to `true`.
//
// The earlier tests here asserted that bypass as intended behaviour, justified
// by "the upstream rejects such junk". That holds for a JSON endpoint and not
// for a JSON-ified one, which is the whole point of §5.3.
func TestSpeechStreamRefusesEveryValueThatMaterializesAsTruthy(t *testing.T) {
	for _, value := range []string{`true`, `"true"`, `1`, `"1"`, `"yes"`, `"on"`, `null`, `2`, `-1`} {
		t.Run(value, func(t *testing.T) {
			priv, pub, ephPub := speechKeys(t)
			req := mustReq(t, sampleSpeechReq)
			req["stream"] = json.RawMessage(value)

			_, err := wire.SealRequestFor(wire.ProfileSpeech, pub, req, nil, testProvider, ephPub)
			if err == nil {
				t.Fatalf("stream=%s must be refused: only the safe value is permitted, since the set of truthy multipart renderings is open", value)
			}

			// And the receiver's half, on an envelope the field is added to after
			// sealing — the shape a third-party client produces.
			clean := mustReq(t, sampleSpeechReq)
			env, err := wire.SealRequestFor(wire.ProfileSpeech, pub, clean, nil, testProvider, ephPub)
			if err != nil {
				t.Fatalf("seal: %v", err)
			}
			env["stream"] = json.RawMessage(value)
			if _, err := wire.OpenRequestFor(wire.ProfileSpeech, priv, env); err == nil {
				t.Fatalf("the enclave must refuse a received envelope with stream=%s", value)
			}
		})
	}
}

// A composite has no multipart rendering at all, so it cannot be the permitted
// value: refused, and without panicking or mis-decoding.
func TestSpeechStreamRefusesCompositeValues(t *testing.T) {
	for _, value := range []string{`{"enabled":true}`, `[true]`, `{}`, `[]`} {
		t.Run(value, func(t *testing.T) {
			_, pub, ephPub := speechKeys(t)
			req := mustReq(t, sampleSpeechReq)
			req["stream"] = json.RawMessage(value)

			if _, err := wire.SealRequestFor(wire.ProfileSpeech, pub, req, nil, testProvider, ephPub); err == nil {
				t.Fatalf("stream=%s must be refused", value)
			}
		})
	}
}

// Both spellings of the SAFE value are accepted, and that is deliberate rather
// than lax: §5.3's conversion turns form fields into JSON, and a sender that
// carries them across as strings is doing nothing wrong — the form it came from
// had no types. It is also what keeps the error message from being a trap: it
// says `must be "false"`, and a reader who sends the quoted string lands on the
// safe value rather than on a bypass.
func TestSpeechStreamAcceptsBothSpellingsOfFalse(t *testing.T) {
	for _, value := range []string{`false`, `"false"`} {
		t.Run(value, func(t *testing.T) {
			priv, pub, ephPub := speechKeys(t)
			req := mustReq(t, sampleSpeechReq)
			req["stream"] = json.RawMessage(value)

			env, err := wire.SealRequestFor(wire.ProfileSpeech, pub, req, nil, testProvider, ephPub)
			if err != nil {
				t.Fatalf("stream=%s is the safe value and must be accepted: %v", value, err)
			}
			if _, err := wire.OpenRequestFor(wire.ProfileSpeech, priv, env); err != nil {
				t.Fatalf("open: %v", err)
			}
		})
	}
}

// The error message must name the PERMITTED value, not the refused one. Naming
// the refused value is how an operator following the message walks into the
// bypass this rule exists to close.
func TestSpeechStreamErrorNamesThePermittedValue(t *testing.T) {
	_, pub, ephPub := speechKeys(t)
	req := mustReq(t, sampleSpeechReq)
	req["stream"] = json.RawMessage(`true`)

	_, err := wire.SealRequestFor(wire.ProfileSpeech, pub, req, nil, testProvider, ephPub)
	if err == nil {
		t.Fatal("expected a refusal")
	}
	msg := err.Error()
	if !strings.Contains(msg, `must be "false"`) {
		t.Errorf("message should tell the caller what IS allowed, got %v", err)
	}
	if !strings.Contains(msg, "omitted entirely") {
		t.Errorf("message should also offer omission, which is the common case: %v", err)
	}
}

// Malformed JSON in the field is an error, not a skip: the field is there and
// unparseable, and letting it through would mean sealing a request no receiver
// can evaluate.
func TestSpeechStreamRejectsMalformedJSON(t *testing.T) {
	_, pub, ephPub := speechKeys(t)
	req := mustReq(t, sampleSpeechReq)
	req["stream"] = json.RawMessage(`tru`)

	if _, err := wire.SealRequestFor(wire.ProfileSpeech, pub, req, nil, testProvider, ephPub); err == nil {
		t.Fatal("a malformed stream value must be refused")
	}
}

// Sealing `stream` is refused for a reason DIFFERENT from an unconditional
// pinned field's. A
// pin sealed away leaves the server on its own default; here the enclave
// reconstructs `cleartext ∪ decrypted` and forwards the result, so the router
// would see a non-streaming request while the enclave asks the upstream to
// stream.
func TestSpeechStreamCannotBeSealedAway(t *testing.T) {
	err := wire.ValidateSealedFieldsFor(wire.ProfileSpeech, []string{"file_base64", "stream"})
	if err == nil {
		t.Fatal("sealing stream must be refused")
	}
	if !strings.Contains(err.Error(), "disagree") {
		t.Errorf("error should explain the router/enclave disagreement, got %v", err)
	}
}

func TestSpeechStreamCannotBeDeclaredUnbound(t *testing.T) {
	err := wire.ValidateUnboundFieldsFor(wire.ProfileSpeech, []string{"stream"}, []string{"file_base64"})
	if err == nil {
		t.Fatal("declaring stream unbound must be refused: an intermediary could set it in transit")
	}
}

// The receiver half, which is the load-bearing one: a third-party client is
// under no obligation to run any of the checks above, so the enclave must refuse
// an envelope that arrives carrying stream:true.
func TestSpeechEnclaveRefusesAnEnvelopeArrivingWithStreamTrue(t *testing.T) {
	priv, pub, ephPub := speechKeys(t)
	env, err := wire.SealRequestFor(wire.ProfileSpeech, pub, mustReq(t, sampleSpeechReq),
		nil, testProvider, ephPub)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	// A router (or a non-conforming client) adds it after sealing. The AAD covers
	// it, so Open would fail anyway — but the profile check must fire FIRST, with
	// a message naming the cause, rather than surfacing as an opaque AEAD failure.
	env["stream"] = json.RawMessage(`true`)

	_, err = wire.OpenRequestFor(wire.ProfileSpeech, priv, env)
	if err == nil {
		t.Fatal("the enclave must refuse a received envelope carrying stream:true")
	}
	if !strings.Contains(err.Error(), "stream") {
		t.Errorf("the profile check should fire before the AEAD, naming the field; got %v", err)
	}
}

// Chat and image declare no conditionally pinned fields, so the new machinery
// must be completely inert for them — including for a chat request that
// legitimately streams.
func TestConditionalPinIsInertForOtherProfiles(t *testing.T) {
	priv, pub, ephPub := speechKeys(t)
	req := mustReq(t, `{"model":"gpt-4o","stream":true,"messages":[{"role":"user","content":"hi"}]}`)

	env, err := wire.SealRequestFor(wire.ProfileChat, pub, req, []string{"messages"}, testProvider, ephPub)
	if err != nil {
		t.Fatalf("a streaming chat request must still seal: %v", err)
	}
	if _, err := wire.OpenRequestFor(wire.ProfileChat, priv, env); err != nil {
		t.Fatalf("open: %v", err)
	}
	if err := wire.ValidateUnboundFieldsFor(wire.ProfileChat, []string{"stream"}, []string{"messages"}); err != nil {
		t.Errorf("chat pins nothing conditionally, so unbinding stream is its own business: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Profile bookkeeping
// ---------------------------------------------------------------------------

func TestSpeechProfileIsEnumeratedWithItsPayloadFields(t *testing.T) {
	var found bool
	for _, p := range wire.Profiles() {
		if p == wire.ProfileSpeech {
			found = true
		}
	}
	if !found {
		t.Fatal("ProfileSpeech must appear in Profiles(): the client's fail-safe withholding is the union over that list")
	}
	defaults := wire.DefaultSealedFieldsFor(wire.ProfileSpeech)
	for _, want := range []string{"file_base64", "filename", "language", "prompt"} {
		if !containsString(defaults, want) {
			t.Errorf("default sealed set %v should contain %q", defaults, want)
		}
	}
}

func containsString(hay []string, needle string) bool {
	for _, h := range hay {
		if h == needle {
			return true
		}
	}
	return false
}
