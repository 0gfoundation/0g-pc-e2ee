package wire_test

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"

	"github.com/0gfoundation/0g-pc-e2ee/protocol/crypto"
	"github.com/0gfoundation/0g-pc-e2ee/protocol/wire"
)

// The response-binding value must be reproduced bit for bit by every
// implementation, so it is pinned to a known answer. Computed independently from
// RFC 5869 (HMAC-SHA256, empty salt = 32 zero bytes, one output block).
func TestDeriveResponseBindKnownAnswer(t *testing.T) {
	key := make(crypto.PrivateKey, 32)
	for i := range key {
		key[i] = byte(i)
	}
	got, err := wire.DeriveResponseBind(key)
	if err != nil {
		t.Fatal(err)
	}
	const want = "99711ebcd2996833c92f9fd7ddc8ac3e9c2bb5513b36d3ce72049b34c21e4a8b"
	if hex.EncodeToString(got) != want {
		t.Fatalf("DeriveResponseBind KAT = %x, want %s", got, want)
	}
}

func TestDeriveResponseBindRejectsWrongKeyLength(t *testing.T) {
	for _, n := range []int{0, 31, 33, 64} {
		if _, err := wire.DeriveResponseBind(make(crypto.PrivateKey, n)); err == nil {
			t.Errorf("a %d-byte key was accepted", n)
		}
	}
}

func TestAttachResponseBind(t *testing.T) {
	priv, _, err := crypto.GenerateRecipientKey()
	if err != nil {
		t.Fatal(err)
	}
	req := wire.Request{"messages": json.RawMessage(`[]`)}
	out, err := wire.AttachResponseBind(wire.ProfileChat, req, priv)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := req["_bind"]; ok {
		t.Fatal("AttachResponseBind mutated its input")
	}
	if _, ok := out["_bind"]; !ok {
		t.Fatal("AttachResponseBind returned no _bind")
	}
	if _, err := wire.AttachResponseBind(wire.ProfileChat, out, priv); err == nil {
		t.Fatal("a request already carrying _bind was accepted: a caller-supplied value would be sealed as if derived")
	}
	if _, err := wire.AttachResponseBind(wire.Profile("nope"), req, priv); err == nil {
		t.Fatal("an unknown profile was accepted")
	}
}

// boundChatRequest seals a chat request carrying the response binding, with the
// default sealed set, and returns the envelope plus the keys on both ends.
func boundChatRequest(t *testing.T) (env wire.Request, encPriv crypto.PrivateKey, ephPriv crypto.PrivateKey, ephPub crypto.PublicKey) {
	t.Helper()
	encPriv, encPub, err := crypto.GenerateRecipientKey()
	if err != nil {
		t.Fatal(err)
	}
	ephPriv, ephPub, err = crypto.GenerateRecipientKey()
	if err != nil {
		t.Fatal(err)
	}
	req := wire.Request{
		"model":    json.RawMessage(`"m"`),
		"messages": json.RawMessage(`[{"role":"user","content":"hi"}]`),
	}
	req, err = wire.AttachResponseBind(wire.ProfileChat, req, ephPriv)
	if err != nil {
		t.Fatal(err)
	}
	env, err = wire.SealRequestFor(wire.ProfileChat, encPub, req, nil, testProvider, ephPub)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	return env, encPriv, ephPriv, ephPub
}

// The default sealed set seals `_bind`, the enclave recovers exactly the value
// the client derived, and the request it forwards upstream no longer carries it.
func TestResponseBindRequestRoundTrip(t *testing.T) {
	env, encPriv, ephPriv, _ := boundChatRequest(t)
	if _, ok := env["_bind"]; ok {
		t.Fatal("_bind is in the envelope's cleartext half")
	}
	opened, err := wire.OpenRequestFor(wire.ProfileChat, encPriv, env)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	bind, forward, err := wire.TakeResponseBind(wire.ProfileChat, opened)
	if err != nil {
		t.Fatal(err)
	}
	want, err := wire.DeriveResponseBind(ephPriv)
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(bind) != hex.EncodeToString(want) {
		t.Fatal("the enclave recovered a different binding value than the client derived")
	}
	if _, ok := forward["_bind"]; ok {
		t.Fatal("the request forwarded upstream still carries _bind")
	}
	if _, ok := forward["messages"]; !ok {
		t.Fatal("TakeResponseBind dropped the payload")
	}
}

// A request without `_bind` asks for a base-mode response: TakeResponseBind
// returns no binding and leaves the request as it is.
func TestTakeResponseBindAbsent(t *testing.T) {
	opened := wire.Request{"messages": json.RawMessage(`[]`)}
	bind, forward, err := wire.TakeResponseBind(wire.ProfileChat, opened)
	if err != nil {
		t.Fatal(err)
	}
	if bind != nil {
		t.Fatal("a binding was reported for a request that carried none")
	}
	if len(forward) != 1 {
		t.Fatalf("forward = %v", forward)
	}
	if _, _, err := wire.TakeResponseBind(wire.ProfileChat, wire.Request{"_bind": json.RawMessage(`"short"`)}); err == nil {
		t.Fatal("a malformed binding value was accepted")
	}
	if _, _, err := wire.TakeResponseBind(wire.ProfileAsyncImage, wire.Request{"prompt": json.RawMessage(`"p"`)}); err == nil {
		t.Fatal("an async-image request without _bind was accepted: its result would have nothing to be bound with")
	}
}

// A binding value in the clear is one the router holds, so it is refused on
// both ends: by the sealer and by the enclave.
func TestResponseBindInCleartextIsRefused(t *testing.T) {
	_, encPub, err := crypto.GenerateRecipientKey()
	if err != nil {
		t.Fatal(err)
	}
	ephPriv, ephPub, err := crypto.GenerateRecipientKey()
	if err != nil {
		t.Fatal(err)
	}
	req, err := wire.AttachResponseBind(wire.ProfileChat, wire.Request{
		"model":    json.RawMessage(`"m"`),
		"messages": json.RawMessage(`[]`),
	}, ephPriv)
	if err != nil {
		t.Fatal(err)
	}
	_, err = wire.SealRequestFor(wire.ProfileChat, encPub, req, []string{"messages"}, testProvider, ephPub)
	if err == nil || !strings.Contains(err.Error(), "_bind") {
		t.Fatalf("sealing with _bind left in the clear: err = %v", err)
	}

	// The enclave's half. A conforming sender cannot produce such an envelope, so
	// build the one shape that reaches the check intact: a request that declares
	// `_bind` unbound, which leaves an intermediary free to add it in the clear
	// without breaking the AAD.
	encPriv, encPub2, err := crypto.GenerateRecipientKey()
	if err != nil {
		t.Fatal(err)
	}
	env, err := wire.SealRequestFor(wire.ProfileChat, encPub2, wire.Request{
		"model":    json.RawMessage(`"m"`),
		"messages": json.RawMessage(`[]`),
	}, nil, testProvider, ephPub, "_bind")
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	env["_bind"] = json.RawMessage(`"AAAA"`)
	if _, err := wire.OpenRequestFor(wire.ProfileChat, encPriv, env); err == nil || !strings.Contains(err.Error(), "_bind") {
		t.Fatalf("an envelope carrying a cleartext _bind was opened: err = %v", err)
	}
}

func chatFrame(content string) wire.Response {
	return wire.Response{
		"model":   json.RawMessage(`"m"`),
		"choices": json.RawMessage(`[{"index":0,"delta":{"content":` + mustJSON(content) + `}}]`),
	}
}

func mustJSON(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}

// sealStream seals frames with rs, the last one final.
func sealStream(t *testing.T, rs *wire.ResponseSealer, contents ...string) []wire.Response {
	t.Helper()
	out := make([]wire.Response, 0, len(contents))
	for i, c := range contents {
		f, err := rs.SealFrame(chatFrame(c), nil, i == len(contents)-1)
		if err != nil {
			t.Fatalf("seal frame %d: %v", i, err)
		}
		out = append(out, f)
	}
	return out
}

// The genuine path: the enclave seals with the binding it took from the request,
// and the client opens every frame with the one it derived.
func TestBoundResponseStreamRoundTrip(t *testing.T) {
	env, encPriv, ephPriv, ephPub := boundChatRequest(t)
	opened, err := wire.OpenRequestFor(wire.ProfileChat, encPriv, env)
	if err != nil {
		t.Fatal(err)
	}
	bind, _, err := wire.TakeResponseBind(wire.ProfileChat, opened)
	if err != nil {
		t.Fatal(err)
	}
	rs, err := wire.NewBoundResponseSealerFor(wire.ProfileChat, ephPub, bind)
	if err != nil {
		t.Fatal(err)
	}
	frames := sealStream(t, rs, "a", "b", "c")
	ro, err := wire.NewBoundResponseOpenerFor(wire.ProfileChat, ephPriv, frames[0])
	if err != nil {
		t.Fatal(err)
	}
	for i, f := range frames {
		out, err := ro.OpenFrame(f)
		if err != nil {
			t.Fatalf("open frame %d: %v", i, err)
		}
		if _, ok := out["_bind"]; ok {
			t.Fatalf("frame %d carries _bind: the binding must not appear in the response", i)
		}
	}
}

// The attack (§7.6): anyone who saw the request can seal a stream to the
// cleartext client_eph_pub in base mode, and a base-mode client opens it. A
// bound client refuses it at the FIRST frame — before a caller sees any of it.
func TestBoundOpenerRefusesAStreamSealedWithoutTheBinding(t *testing.T) {
	env, _, ephPriv, _ := boundChatRequest(t)
	var e2ee wire.E2EE
	if err := json.Unmarshal(env["_e2ee"], &e2ee); err != nil {
		t.Fatal(err)
	}
	// What the router holds: the request envelope, and so client_eph_pub.
	pub, err := b64dec(e2ee.ClientEphPub)
	if err != nil {
		t.Fatal(err)
	}
	forger, err := wire.NewResponseSealerFor(wire.ProfileChat, pub)
	if err != nil {
		t.Fatal(err)
	}
	forged := sealStream(t, forger, "forged", "text")

	// The status quo, for contrast: an unbound opener accepts it.
	plain, err := wire.NewResponseOpenerFor(wire.ProfileChat, ephPriv, forged[0])
	if err != nil {
		t.Fatal(err)
	}
	if _, err := plain.OpenFrame(forged[0]); err != nil {
		t.Fatalf("precondition: an unbound opener should accept the forged frame, got %v", err)
	}

	ro, err := wire.NewBoundResponseOpenerFor(wire.ProfileChat, ephPriv, forged[0])
	if err != nil {
		t.Fatal(err)
	}
	if out, err := ro.OpenFrame(forged[0]); err == nil {
		t.Fatalf("a bound opener accepted a frame sealed without the binding: %v", out)
	}
}

// A PSK context keyed by anything other than this request's binding is refused
// the same way: knowing the mechanism is not enough without the value.
func TestBoundOpenerRefusesAWrongBinding(t *testing.T) {
	_, _, ephPriv, ephPub := boundChatRequest(t)
	other, _, err := crypto.GenerateRecipientKey()
	if err != nil {
		t.Fatal(err)
	}
	wrong, err := wire.DeriveResponseBind(other)
	if err != nil {
		t.Fatal(err)
	}
	rs, err := wire.NewBoundResponseSealerFor(wire.ProfileChat, ephPub, wrong)
	if err != nil {
		t.Fatal(err)
	}
	frames := sealStream(t, rs, "x")
	ro, err := wire.NewBoundResponseOpenerFor(wire.ProfileChat, ephPriv, frames[0])
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ro.OpenFrame(frames[0]); err == nil {
		t.Fatal("a bound opener accepted a frame sealed under another request's binding")
	}
}

// The non-streaming helpers, on a profile other than chat: one final frame,
// bound, round-trips; the same frame does not open unbound, so a client that
// did not ask for a binding is never handed one it cannot read.
func TestBoundNonStreamingRoundTrip(t *testing.T) {
	ephPriv, ephPub, err := crypto.GenerateRecipientKey()
	if err != nil {
		t.Fatal(err)
	}
	bind, err := wire.DeriveResponseBind(ephPriv)
	if err != nil {
		t.Fatal(err)
	}
	resp := wire.Response{
		"model": json.RawMessage(`"m"`),
		"data":  json.RawMessage(`[{"b64_json":"AAAA"}]`),
		"usage": json.RawMessage(`{"output_images":1}`),
	}
	sealed, err := wire.SealBoundResponseFor(wire.ProfileImage, ephPub, bind, resp, nil)
	if err != nil {
		t.Fatal(err)
	}
	out, err := wire.OpenBoundResponseFor(wire.ProfileImage, ephPriv, sealed)
	if err != nil {
		t.Fatalf("open bound: %v", err)
	}
	if string(out["data"]) != string(resp["data"]) {
		t.Fatalf("data = %s", out["data"])
	}
	if _, err := wire.OpenResponseFor(wire.ProfileImage, ephPriv, sealed); err == nil {
		t.Fatal("a bound response opened in base mode")
	}
}

// Anthropic's message_start must seal nothing (§7.2). The binding adds nothing
// to a frame, so a bound stream is subject to the same shape rules and opens.
func TestBoundAnthropicMessageStart(t *testing.T) {
	ephPriv, ephPub, err := crypto.GenerateRecipientKey()
	if err != nil {
		t.Fatal(err)
	}
	bind, err := wire.DeriveResponseBind(ephPriv)
	if err != nil {
		t.Fatal(err)
	}
	rs, err := wire.NewBoundResponseSealerFor(wire.ProfileAnthropic, ephPub, bind)
	if err != nil {
		t.Fatal(err)
	}
	start := wire.Response{
		"type":    json.RawMessage(`"message_start"`),
		"message": json.RawMessage(`{"id":"msg_1","type":"message","role":"assistant","model":"m","content":[],"usage":{"input_tokens":3,"output_tokens":0}}`),
	}
	sealed, err := rs.SealFrame(start, nil, false)
	if err != nil {
		t.Fatalf("seal message_start: %v", err)
	}
	ro, err := wire.NewBoundResponseOpenerFor(wire.ProfileAnthropic, ephPriv, sealed)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ro.OpenFrame(sealed); err != nil {
		t.Fatalf("open message_start: %v", err)
	}
}

func TestBoundSealerRefusesAShortBinding(t *testing.T) {
	ephPriv, ephPub, err := crypto.GenerateRecipientKey()
	if err != nil {
		t.Fatal(err)
	}
	bind, err := wire.DeriveResponseBind(ephPriv)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := wire.NewBoundResponseSealerFor(wire.ProfileChat, ephPub, bind[:16]); err == nil {
		t.Error("a 16-byte binding value was accepted")
	}
}

func b64dec(s string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(s)
}

func TestResponseBindApplies(t *testing.T) {
	for _, p := range []wire.Profile{wire.ProfileChat, wire.ProfileAnthropic, wire.ProfileImage, wire.ProfileSpeech, wire.ProfileEmbedding} {
		if !wire.ResponseBindApplies(p) {
			t.Errorf("%s: the response binding should apply", p)
		}
	}
	for _, p := range []wire.Profile{wire.ProfileAsyncImage, wire.Profile("nope")} {
		if wire.ResponseBindApplies(p) {
			t.Errorf("%s: the response binding should not apply", p)
		}
	}
}
