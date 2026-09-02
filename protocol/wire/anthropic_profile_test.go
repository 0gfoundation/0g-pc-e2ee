package wire_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/0gfoundation/0g-pc-e2ee/protocol/crypto"
	"github.com/0gfoundation/0g-pc-e2ee/protocol/wire"
)

// A representative /v1/messages request. `system` is the field that makes this
// profile more than "chat with a different path": Anthropic carries the system
// prompt at the TOP LEVEL rather than as a message, so nothing about sealing
// `messages` covers it.
const sampleAnthropicReq = `{
  "model": "claude-x",
  "max_tokens": 1024,
  "stream": true,
  "system": "my secret system prompt",
  "messages": [{"role": "user", "content": "my secret question"}]
}`

const (
	secretSystem   = "my secret system prompt"
	secretQuestion = "my secret question"
)

func anthropicKeys(t *testing.T) (encPriv crypto.PrivateKey, encPub crypto.PublicKey, ephPriv crypto.PrivateKey, ephPub crypto.PublicKey) {
	t.Helper()
	encPriv, encPub, err := crypto.GenerateRecipientKey()
	if err != nil {
		t.Fatalf("enc keygen: %v", err)
	}
	ephPriv, ephPub, err = crypto.GenerateRecipientKey()
	if err != nil {
		t.Fatalf("eph keygen: %v", err)
	}
	return encPriv, encPub, ephPriv, ephPub
}

func TestAnthropicProfileSealsSystemAlongsideMessages(t *testing.T) {
	encPriv, encPub, _, ephPub := anthropicKeys(t)

	// The default set also names "tools", which this request does not carry; a
	// caller filters the defaults by presence (the client core does), so the set
	// is passed explicitly here.
	env, err := wire.SealRequestFor(wire.ProfileAnthropic, encPub, mustReq(t, sampleAnthropicReq),
		[]string{"messages", "system"}, testProvider, ephPub)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}

	for _, f := range []string{"system", "messages"} {
		if _, ok := env[f]; ok {
			t.Errorf("%q must not remain as a cleartext field", f)
		}
	}
	for _, f := range []string{"model", "max_tokens", "stream"} {
		if _, ok := env[f]; !ok {
			t.Errorf("routing field %q must stay cleartext", f)
		}
	}
	raw, err := json.Marshal(env)
	if err != nil {
		t.Fatalf("marshal envelope: %v", err)
	}
	for _, secret := range []string{secretSystem, secretQuestion} {
		if strings.Contains(string(raw), secret) {
			t.Errorf("plaintext %q leaked into the sealed envelope", secret)
		}
	}

	// And it round-trips through the receiver entry point.
	got, err := wire.OpenRequestFor(wire.ProfileAnthropic, encPriv, env)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	var system string
	if err := json.Unmarshal(got["system"], &system); err != nil {
		t.Fatalf("reconstructed request has no system: %v", err)
	}
	if system != secretSystem {
		t.Errorf("system = %q, want %q", system, secretSystem)
	}
}

// The sender half: a set that covers `messages` but not `system` satisfies every
// unconditional rule, and is exactly the set a chat-shaped client would pick.
func TestAnthropicProfileRefusesToSealAroundThePresentSystemPrompt(t *testing.T) {
	_, encPub, _, ephPub := anthropicKeys(t)

	_, err := wire.SealRequestFor(wire.ProfileAnthropic, encPub, mustReq(t, sampleAnthropicReq),
		[]string{"messages"}, testProvider, ephPub)
	if err == nil {
		t.Fatal("sealing a request whose system prompt stays cleartext must be refused")
	}
	if !strings.Contains(err.Error(), "system") {
		t.Errorf("error should name the field left in the clear, got %v", err)
	}
}

// The receiver half, which is the load-bearing one (SPEC §12): a third-party
// client runs no seal-time check. Sealing the same request under the CHAT
// profile succeeds and leaves `system` cleartext — that envelope is well formed,
// so only the enclave can refuse it.
func TestAnthropicEnclaveRefusesAnEnvelopeCarryingSystemInTheClear(t *testing.T) {
	encPriv, encPub, _, ephPub := anthropicKeys(t)

	env, err := wire.SealRequestFor(wire.ProfileChat, encPub, mustReq(t, sampleAnthropicReq),
		[]string{"messages"}, testProvider, ephPub)
	if err != nil {
		t.Fatalf("chat-profile seal: %v", err)
	}
	if _, ok := env["system"]; !ok {
		t.Fatal("precondition: the chat profile should have left system cleartext")
	}
	// It opens fine as a chat request — nothing in the envelope is malformed.
	if _, err := wire.OpenRequestFor(wire.ProfileChat, encPriv, env); err != nil {
		t.Fatalf("precondition: the envelope itself is valid: %v", err)
	}

	_, err = wire.OpenRequestFor(wire.ProfileAnthropic, encPriv, env)
	if err == nil {
		t.Fatal("an enclave serving /v1/messages must refuse a request whose system prompt arrived in the clear")
	}
	if !strings.Contains(err.Error(), "system") {
		t.Errorf("error should name the field that arrived in the clear, got %v", err)
	}
}

// A request with no system prompt is the common case and must not be burdened
// with one: `system` is required only when present.
func TestAnthropicProfileAcceptsARequestWithNoSystemPrompt(t *testing.T) {
	encPriv, encPub, _, ephPub := anthropicKeys(t)
	const noSystem = `{"model":"claude-x","max_tokens":16,"messages":[{"role":"user","content":"hi"}]}`

	env, err := wire.SealRequestFor(wire.ProfileAnthropic, encPub, mustReq(t, noSystem),
		[]string{"messages"}, testProvider, ephPub)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	if _, err := wire.OpenRequestFor(wire.ProfileAnthropic, encPriv, env); err != nil {
		t.Fatalf("open: %v", err)
	}
}

// Non-streaming: one frame, `content` sealed, and every field the router bills
// and attributes on left readable.
func TestAnthropicNonStreamResponseSealsContentAndLeavesUsageCleartext(t *testing.T) {
	_, _, ephPriv, ephPub := anthropicKeys(t)

	resp := wire.Response{
		"id":          json.RawMessage(`"msg_1"`),
		"type":        json.RawMessage(`"message"`),
		"role":        json.RawMessage(`"assistant"`),
		"model":       json.RawMessage(`"claude-x"`),
		"stop_reason": json.RawMessage(`"end_turn"`),
		"usage":       json.RawMessage(`{"input_tokens":10,"output_tokens":20}`),
		"content":     json.RawMessage(`[{"type":"text","text":"the secret answer"}]`),
	}
	frame, err := wire.SealResponseFor(wire.ProfileAnthropic, ephPub, resp, nil, "model", "x_0g_trace")
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	if _, ok := frame["content"]; ok {
		t.Error("content must not remain cleartext")
	}
	for _, f := range []string{"usage", "model", "id", "type", "stop_reason"} {
		if _, ok := frame[f]; !ok {
			t.Errorf("%q must stay cleartext for the router", f)
		}
	}
	raw, err := json.Marshal(frame)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if strings.Contains(string(raw), "the secret answer") {
		t.Error("the answer leaked into the sealed frame")
	}

	got, err := wire.OpenResponseFor(wire.ProfileAnthropic, ephPriv, frame)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if !strings.Contains(string(got["content"]), "the secret answer") {
		t.Errorf("content did not survive the round trip: %s", got["content"])
	}
}

// anthropicStream is the event sequence of a real /v1/messages stream: two
// shapes carry generated content, four are sequencing, and the input token count
// rides inside message_start's cleartext `message`.
var anthropicStream = []wire.Response{
	{
		"type":    json.RawMessage(`"message_start"`),
		"message": json.RawMessage(`{"id":"msg_1","type":"message","role":"assistant","model":"claude-x","content":[],"usage":{"input_tokens":11,"output_tokens":1}}`),
	},
	{
		"type":          json.RawMessage(`"content_block_start"`),
		"index":         json.RawMessage(`0`),
		"content_block": json.RawMessage(`{"type":"text","text":""}`),
	},
	{
		"type":  json.RawMessage(`"content_block_delta"`),
		"index": json.RawMessage(`0`),
		"delta": json.RawMessage(`{"type":"text_delta","text":"the secret answer"}`),
	},
	{
		"type":  json.RawMessage(`"content_block_stop"`),
		"index": json.RawMessage(`0`),
	},
	{
		"type":  json.RawMessage(`"message_delta"`),
		"delta": json.RawMessage(`{"stop_reason":"end_turn","stop_sequence":null}`),
		"usage": json.RawMessage(`{"output_tokens":20}`),
	},
	{"type": json.RawMessage(`"message_stop"`)},
}

// The whole point of the frame-typed profile: what a frame must seal is a
// property of the frame. A nil sealedFields resolves per frame, so the sequencing
// events seal nothing (and keep the router's token counts readable) while the
// content events seal their own field.
func TestAnthropicStreamSealsPerFrameShape(t *testing.T) {
	_, _, ephPriv, ephPub := anthropicKeys(t)

	sealer, err := wire.NewResponseSealerFor(wire.ProfileAnthropic, ephPub, "model", "x_0g_trace")
	if err != nil {
		t.Fatalf("sealer: %v", err)
	}
	wantSealed := [][]string{{}, {"content_block"}, {"delta"}, {}, {"delta"}, {}}

	var sealed []wire.Response
	for i, frame := range anthropicStream {
		final := i == len(anthropicStream)-1
		out, err := sealer.SealFrame(cloneFrame(frame), nil, final)
		if err != nil {
			t.Fatalf("seal frame %d (%s): %v", i, frame["type"], err)
		}
		e2ee, err := out.E2EE()
		if err != nil {
			t.Fatalf("frame %d has no _e2ee: %v", i, err)
		}
		if !equalStrings(e2ee.SealedFields, wantSealed[i]) {
			t.Errorf("frame %d (%s) sealed_fields = %v, want %v", i, frame["type"], e2ee.SealedFields, wantSealed[i])
		}
		// Every frame is sealed, even one that seals nothing: it still carries
		// `_e2ee`, so the stream stays uniform and the §8 binding covers it.
		if e2ee.Ciphertext == "" {
			t.Errorf("frame %d carries no ciphertext", i)
		}
		// And an empty sealed set goes on the wire as `[]`, never `null` or
		// omitted. It is inside the AAD, so the three spellings are three
		// different hashes: a peer that wrote one and verified another would fail
		// §8 verification with every other check passing. The proof package's
		// Anthropic KATs pin the same bytes.
		if len(wantSealed[i]) == 0 && !strings.Contains(string(out[e2eeKeyForTest]), `"sealed_fields":[]`) {
			t.Errorf("frame %d must spell an empty sealed set as []: %s", i, out[e2eeKeyForTest])
		}
		if raw, err := json.Marshal(out); err == nil && strings.Contains(string(raw), "the secret answer") {
			t.Errorf("frame %d leaked the answer in cleartext", i)
		}
		sealed = append(sealed, out)
	}

	// The router's inputs: input tokens inside message_start's cleartext
	// `message`, output tokens in message_delta's top-level `usage`.
	if !strings.Contains(string(sealed[0]["message"]), `"input_tokens":11`) {
		t.Errorf("message_start must keep the input token count readable: %s", sealed[0]["message"])
	}
	if !strings.Contains(string(sealed[4]["usage"]), `"output_tokens":20`) {
		t.Errorf("message_delta must keep the output token count readable: %s", sealed[4]["usage"])
	}

	opener, err := wire.NewResponseOpenerFor(wire.ProfileAnthropic, ephPriv, sealed[0])
	if err != nil {
		t.Fatalf("opener: %v", err)
	}
	for i, frame := range sealed {
		got, err := opener.OpenFrame(frame)
		if err != nil {
			t.Fatalf("open frame %d: %v", i, err)
		}
		if i == 2 && !strings.Contains(string(got["delta"]), "the secret answer") {
			t.Errorf("the delta did not survive the round trip: %s", got["delta"])
		}
	}
}

// Mislabeling is the attack the shape rules would otherwise invite: a frame that
// claims a sequencing shape satisfies "seal nothing" exactly, and its cleartext
// `delta` reads to an SDK as a stray field on a stop event — while every
// intermediary has the delta. The rule is keyed off the field NAMES, so it holds
// whatever the frame calls itself.
func TestAnthropicRefusesAMislabeledContentFrame(t *testing.T) {
	_, _, ephPriv, ephPub := anthropicKeys(t)

	sealer, err := wire.NewResponseSealerFor(wire.ProfileAnthropic, ephPub)
	if err != nil {
		t.Fatalf("sealer: %v", err)
	}
	mislabeled := wire.Response{
		"type":  json.RawMessage(`"message_stop"`),
		"delta": json.RawMessage(`{"type":"text_delta","text":"the secret answer"}`),
	}
	// Sender half: refuse to build it, whether the caller resolves the set or
	// hands in the empty one the shape requires.
	for _, fields := range [][]string{nil, {}} {
		if _, err := sealer.SealFrame(cloneFrame(mislabeled), fields, false); err == nil {
			t.Fatalf("sealing a message_stop carrying a cleartext delta must be refused (fields=%v)", fields)
		}
	}

	// Receiver half: the same frame as a non-conforming enclave would emit it —
	// a legitimately sealed message_stop with a delta grafted into its cleartext.
	frame, err := sealer.SealFrame(wire.Response{"type": json.RawMessage(`"message_stop"`)}, nil, true)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	frame["delta"] = json.RawMessage(`{"type":"text_delta","text":"the secret answer"}`)

	opener, err := wire.NewResponseOpenerFor(wire.ProfileAnthropic, ephPriv, frame)
	if err != nil {
		t.Fatalf("opener: %v", err)
	}
	_, err = opener.OpenFrame(frame)
	if err == nil {
		t.Fatal("opening a frame with content in its cleartext half must be refused")
	}
	// Specifically for the reason under test — not as a side effect of the AAD
	// mismatch the graft also causes, which would make this test pass for the
	// wrong reason (and would not fire at all had the sealer emitted it).
	if !strings.Contains(err.Error(), "cleartext") || !strings.Contains(err.Error(), "delta") {
		t.Errorf("refusal should name the content field carried in cleartext, got %v", err)
	}
}

// message_start keeps `message` cleartext because the router's input token count
// is inside it, which leaves `message.content` as the one part of it that could
// carry the answer. Anthropic's schema fixes it to []; nothing but this check
// would notice if an enclave disagreed.
func TestAnthropicRefusesContentInsideMessageStart(t *testing.T) {
	_, _, ephPriv, ephPub := anthropicKeys(t)

	sealer, err := wire.NewResponseSealerFor(wire.ProfileAnthropic, ephPub)
	if err != nil {
		t.Fatalf("sealer: %v", err)
	}
	loaded := wire.Response{
		"type":    json.RawMessage(`"message_start"`),
		"message": json.RawMessage(`{"id":"msg_1","content":[{"type":"text","text":"the secret answer"}],"usage":{"input_tokens":11}}`),
	}
	if _, err := sealer.SealFrame(cloneFrame(loaded), nil, false); err == nil {
		t.Fatal("sealing a message_start whose message.content carries content must be refused")
	}

	// Receiver half.
	frame, err := sealer.SealFrame(cloneFrame(anthropicStream[0]), nil, false)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	frame["message"] = json.RawMessage(`{"id":"msg_1","content":[{"type":"text","text":"the secret answer"}],"usage":{"input_tokens":11}}`)
	opener, err := wire.NewResponseOpenerFor(wire.ProfileAnthropic, ephPriv, frame)
	if err != nil {
		t.Fatalf("opener: %v", err)
	}
	if _, err := opener.OpenFrame(frame); err == nil {
		t.Fatal("opening a message_start carrying content must be refused")
	} else if !strings.Contains(err.Error(), "message.content") {
		t.Errorf("refusal should name message.content, got %v", err)
	}
}

// Every shape check keys off the frame's own `type`, so that field must be
// neither sealed away nor freed from the AAD — otherwise the check is one the
// sender can decline (SPEC §12).
func TestAnthropicDiscriminatorMustStayCleartextAndBound(t *testing.T) {
	_, _, ephPriv, ephPub := anthropicKeys(t)

	sealer, err := wire.NewResponseSealerFor(wire.ProfileAnthropic, ephPub)
	if err != nil {
		t.Fatalf("sealer: %v", err)
	}
	frame := wire.Response{
		"type":  json.RawMessage(`"content_block_delta"`),
		"delta": json.RawMessage(`{"type":"text_delta","text":"x"}`),
	}
	if _, err := sealer.SealFrame(cloneFrame(frame), []string{"delta", "type"}, false); err == nil {
		t.Error("sealing the frame discriminator must be refused")
	}
	if _, err := wire.NewResponseSealerFor(wire.ProfileAnthropic, ephPub, "type"); err == nil {
		t.Error("declaring the frame discriminator unbound must be refused at sealer setup")
	}

	// Receiver half: a frame that declares it unbound. An intermediary could then
	// relabel a content frame as a sequencing one and every shape check would
	// apply the wrong rules and pass.
	sealed, err := sealer.SealFrame(cloneFrame(frame), nil, true)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	var e2ee map[string]json.RawMessage
	if err := json.Unmarshal(sealed[e2eeKeyForTest], &e2ee); err != nil {
		t.Fatalf("read _e2ee: %v", err)
	}
	e2ee["unbound_fields"] = json.RawMessage(`["type"]`)
	rewritten, err := json.Marshal(e2ee)
	if err != nil {
		t.Fatalf("marshal _e2ee: %v", err)
	}
	sealed[e2eeKeyForTest] = rewritten

	opener, err := wire.NewResponseOpenerFor(wire.ProfileAnthropic, ephPriv, sealed)
	if err != nil {
		t.Fatalf("opener: %v", err)
	}
	if _, err := opener.OpenFrame(sealed); err == nil {
		t.Error("opening a frame that frees the discriminator must be refused")
	} else if !strings.Contains(err.Error(), "bound") {
		t.Errorf("refusal should say the discriminator must stay bound, got %v", err)
	}
}

// An unrecognized shape may carry content, and nothing about it says it does
// not, so it is refused rather than passed through under a guess.
func TestAnthropicRefusesAnUnknownFrameShape(t *testing.T) {
	_, _, _, ephPub := anthropicKeys(t)

	sealer, err := wire.NewResponseSealerFor(wire.ProfileAnthropic, ephPub)
	if err != nil {
		t.Fatalf("sealer: %v", err)
	}
	for _, frame := range []wire.Response{
		{"type": json.RawMessage(`"thinking_block_delta"`)}, // a shape this taxonomy predates
		{"type": json.RawMessage(`123`)},                    // not a string
		{"index": json.RawMessage(`0`)},                     // no discriminator at all
	} {
		if _, err := sealer.SealFrame(cloneFrame(frame), nil, false); err == nil {
			t.Errorf("frame %v must be refused, not sealed under a guess", frame)
		}
	}
}

// The profile-wide helpers have no answer for a frame-typed profile, and must
// say so rather than resolve to something plausible and wrong. An empty non-nil
// response default keeps a caller that feeds it back into SealFrame failing
// closed on every content frame instead of sealing nothing.
func TestAnthropicProfileDefaults(t *testing.T) {
	if got, want := wire.DefaultSealedFieldsFor(wire.ProfileAnthropic), []string{"messages", "system", "tools"}; !equalStrings(got, want) {
		t.Errorf("request defaults = %v, want %v", got, want)
	}
	respDefaults := wire.DefaultResponseSealedFieldsFor(wire.ProfileAnthropic)
	if respDefaults == nil || len(respDefaults) != 0 {
		t.Fatalf("response defaults = %v, want an empty NON-nil slice", respDefaults)
	}

	_, _, _, ephPub := anthropicKeys(t)
	sealer, err := wire.NewResponseSealerFor(wire.ProfileAnthropic, ephPub)
	if err != nil {
		t.Fatalf("sealer: %v", err)
	}
	content := wire.Response{
		"type":  json.RawMessage(`"content_block_delta"`),
		"delta": json.RawMessage(`{"type":"text_delta","text":"the secret answer"}`),
	}
	if _, err := sealer.SealFrame(cloneFrame(content), respDefaults, false); err == nil {
		t.Error("a profile-wide default held for a whole stream must fail on a content frame, not seal nothing")
	}
}

// A hostile frame that declares the content field sealed AND ships it in
// cleartext gets past the shape rules (they skip a field the frame claims to
// seal) and is refused by OpenFrame's own collision check instead. Asserted so
// the "unless it is sealed" clause in validateNoCleartextContent stays provably
// not a way through.
func TestAnthropicRefusesAContentFieldThatIsBothSealedAndCleartext(t *testing.T) {
	_, _, ephPriv, ephPub := anthropicKeys(t)

	sealer, err := wire.NewResponseSealerFor(wire.ProfileAnthropic, ephPub)
	if err != nil {
		t.Fatalf("sealer: %v", err)
	}
	frame, err := sealer.SealFrame(wire.Response{
		"type":  json.RawMessage(`"content_block_delta"`),
		"delta": json.RawMessage(`{"type":"text_delta","text":"decoy"}`),
	}, nil, true)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	// Graft the real content back into the cleartext half, alongside the sealed
	// decoy — what a non-conforming enclave would emit to leak it.
	frame["delta"] = json.RawMessage(`{"type":"text_delta","text":"the secret answer"}`)

	opener, err := wire.NewResponseOpenerFor(wire.ProfileAnthropic, ephPriv, frame)
	if err != nil {
		t.Fatalf("opener: %v", err)
	}
	if _, err := opener.OpenFrame(frame); err == nil {
		t.Fatal("a frame carrying its content in both halves must be refused")
	}
}

// The profile-wide validator has no answer for a frame-typed profile and must
// say so, rather than resolving to spec.responseRequired — which is "" for such a
// profile, and would reject every frame for not sealing a field named "".
func TestFrameTypedProfileRefusesTheProfileWideValidator(t *testing.T) {
	err := wire.ValidateResponseSealedFieldsForTest(wire.ProfileAnthropic, []string{"delta"})
	if err == nil {
		t.Fatal("the profile-wide response validator must refuse a frame-typed profile")
	}
	if !strings.Contains(err.Error(), "typed") {
		t.Errorf("the error should say the frames are typed, got %v", err)
	}
	// The single-shape profiles still answer it.
	if err := wire.ValidateResponseSealedFieldsForTest(wire.ProfileChat, []string{"choices"}); err != nil {
		t.Errorf("chat must still validate profile-wide: %v", err)
	}
}

// ResponseSealedFieldsForFrame is the exported resolver, so an enclave streaming
// this profile names the taxonomy in one place rather than restating it.
func TestResponseSealedFieldsForFrame(t *testing.T) {
	for i, frame := range anthropicStream {
		got, err := wire.ResponseSealedFieldsForFrame(wire.ProfileAnthropic, frame)
		if err != nil {
			t.Fatalf("frame %d: %v", i, err)
		}
		want := [][]string{{}, {"content_block"}, {"delta"}, {}, {"delta"}, {}}[i]
		if !equalStrings(got, want) {
			t.Errorf("frame %d (%s) = %v, want %v", i, frame["type"], got, want)
		}
	}
	// A single-shape profile answers the same for any frame, including one it
	// would never see.
	got, err := wire.ResponseSealedFieldsForFrame(wire.ProfileChat, wire.Response{"type": json.RawMessage(`"message_stop"`)})
	if err != nil {
		t.Fatalf("chat: %v", err)
	}
	if !equalStrings(got, []string{"choices"}) {
		t.Errorf("chat = %v, want [choices]", got)
	}
	if _, err := wire.ResponseSealedFieldsForFrame("audio", wire.Response{}); err == nil {
		t.Error("an unknown profile must be rejected")
	}
}

// Sealing the same Anthropic request under either single-shape profile must not
// work by accident: the sealed sets do not overlap enough to pass.
func TestAnthropicSealedSetIsNotInterchangeableWithTheOthers(t *testing.T) {
	if err := wire.ValidateSealedFieldsFor(wire.ProfileAnthropic, []string{"prompt"}); err == nil {
		t.Error("the anthropic profile must reject an image sealed set")
	}
	if err := wire.ValidateSealedFieldsFor(wire.ProfileImage, []string{"messages", "system"}); err == nil {
		t.Error("the image profile must reject an anthropic sealed set")
	}
	// The unconditional half is shared with chat, so a chat set validates on
	// names alone — the conditional half is what separates them, and it needs the
	// request (see TestAnthropicEnclaveRefusesAnEnvelopeCarryingSystemInTheClear).
	if err := wire.ValidateSealedFieldsFor(wire.ProfileAnthropic, []string{"messages"}); err != nil {
		t.Errorf("a set covering messages is valid on names alone: %v", err)
	}
}

// cloneFrame copies a frame so a seal (which removes the fields it seals) does
// not consume a shared fixture.
func cloneFrame(f wire.Response) wire.Response {
	out := make(wire.Response, len(f))
	for k, v := range f {
		out[k] = v
	}
	return out
}
