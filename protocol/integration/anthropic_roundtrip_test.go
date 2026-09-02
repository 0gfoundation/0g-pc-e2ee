package integration

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/0gfoundation/0g-pc-e2ee/protocol/crypto"
	"github.com/0gfoundation/0g-pc-e2ee/protocol/wire"
)

// sampleAnthropicRequest is a /v1/messages request. Both secrets are payload:
// the conversation, and the top-level system prompt the chat profile's rules do
// not reach.
func sampleAnthropicRequest() wire.Request {
	return wire.Request{
		"model":      json.RawMessage(`"claude-x"`),
		"max_tokens": json.RawMessage(`1024`),
		"stream":     json.RawMessage(`true`),
		"system":     json.RawMessage(`"the secret system prompt"`),
		"messages":   json.RawMessage(`[{"role":"user","content":"the secret prompt"}]`),
	}
}

// The full Anthropic streaming path, with the router's view asserted at every
// step: it must be able to bill (both token counts readable with no key) and
// unable to read a word of the exchange.
func TestAnthropicRoundTripStreaming(t *testing.T) {
	encPriv, encPub, err := crypto.GenerateRecipientKey()
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	broker := &mockBroker{encPriv: encPriv, signerAddr: brokerSigner}
	ephPriv, ephPub, err := crypto.GenerateRecipientKey()
	if err != nil {
		t.Fatalf("eph keygen: %v", err)
	}

	env, err := wire.SealRequestFor(wire.ProfileAnthropic, encPub, sampleAnthropicRequest(),
		[]string{"messages", "system"}, brokerSigner, ephPub)
	if err != nil {
		t.Fatalf("SealRequestFor: %v", err)
	}
	// The router's view of the request: routable, unreadable.
	for _, f := range []string{"model", "max_tokens", "stream"} {
		if _, ok := env[f]; !ok {
			t.Errorf("the router needs %q to route", f)
		}
	}
	envRaw, err := json.Marshal(env)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	for _, secret := range []string{"the secret prompt", "the secret system prompt"} {
		if bytes.Contains(envRaw, []byte(secret)) {
			t.Errorf("%q reached the router in the clear", secret)
		}
	}

	req, clientEphPub := broker.openRequestFor(t, wire.ProfileAnthropic, env)
	if !bytes.Contains(req["messages"], []byte("the secret prompt")) {
		t.Errorf("broker did not recover the conversation: %s", req["messages"])
	}
	if !bytes.Contains(req["system"], []byte("the secret system prompt")) {
		t.Errorf("broker did not recover the system prompt: %s", req["system"])
	}

	// The broker streams the six shapes, letting each frame resolve its own
	// sealed set (nil) — the whole point of a frame-typed profile.
	deltas := []string{"he", "ll", "o"}
	plaintext := []wire.Response{{
		"type":    json.RawMessage(`"message_start"`),
		"message": json.RawMessage(`{"id":"msg_1","type":"message","role":"assistant","model":"claude-x","content":[],"usage":{"input_tokens":11,"output_tokens":1}}`),
	}, {
		"type":          json.RawMessage(`"content_block_start"`),
		"index":         json.RawMessage(`0`),
		"content_block": json.RawMessage(`{"type":"text","text":""}`),
	}}
	for _, d := range deltas {
		plaintext = append(plaintext, wire.Response{
			"type":  json.RawMessage(`"content_block_delta"`),
			"index": json.RawMessage(`0`),
			"delta": json.RawMessage(`{"type":"text_delta","text":"` + d + `"}`),
		})
	}
	plaintext = append(plaintext,
		wire.Response{"type": json.RawMessage(`"content_block_stop"`), "index": json.RawMessage(`0`)},
		wire.Response{
			"type":  json.RawMessage(`"message_delta"`),
			"delta": json.RawMessage(`{"stop_reason":"end_turn","stop_sequence":null}`),
			"usage": json.RawMessage(`{"output_tokens":20}`),
		},
		wire.Response{"type": json.RawMessage(`"message_stop"`)},
	)

	sealer, err := wire.NewResponseSealerFor(wire.ProfileAnthropic, clientEphPub, "model", "x_0g_trace")
	if err != nil {
		t.Fatalf("NewResponseSealerFor: %v", err)
	}
	var frames []wire.Response
	for i, frame := range plaintext {
		final := i == len(plaintext)-1
		s, err := sealer.SealFrame(frame, nil, final)
		if err != nil {
			t.Fatalf("SealFrame %d: %v", i, err)
		}
		frames = append(frames, s)
	}

	// The router's view of the stream: every frame identifiable and billable,
	// none of the text readable.
	var inputTokens, outputTokens int
	for i, f := range frames {
		raw, err := json.Marshal(f)
		if err != nil {
			t.Fatalf("marshal frame %d: %v", i, err)
		}
		for _, d := range deltas {
			if bytes.Contains(raw, []byte(`"text":"`+d+`"`)) {
				t.Errorf("frame %d leaked a delta to the router", i)
			}
		}
		// It classifies the frame without a key, from the bound discriminator —
		// never from the SSE `event:` line, which is outside the AAD.
		var kind string
		if err := json.Unmarshal(f["type"], &kind); err != nil {
			t.Fatalf("frame %d has no readable type: %v", i, err)
		}
		switch kind {
		case "message_start":
			var msg struct {
				Usage struct {
					InputTokens int `json:"input_tokens"`
				} `json:"usage"`
			}
			if err := json.Unmarshal(f["message"], &msg); err != nil {
				t.Fatalf("message_start usage unreadable: %v", err)
			}
			inputTokens = msg.Usage.InputTokens
		case "message_delta":
			var u struct {
				OutputTokens int `json:"output_tokens"`
			}
			if err := json.Unmarshal(f["usage"], &u); err != nil {
				t.Fatalf("message_delta usage unreadable: %v", err)
			}
			outputTokens = u.OutputTokens
		}
	}
	if inputTokens != 11 || outputTokens != 20 {
		t.Errorf("router billed on (%d, %d) tokens, want (11, 20) — a sealed stream must stay billable", inputTokens, outputTokens)
	}

	// The client opens in order and reassembles the text.
	opener, err := wire.NewResponseOpenerFor(wire.ProfileAnthropic, ephPriv, frames[0])
	if err != nil {
		t.Fatalf("NewResponseOpenerFor: %v", err)
	}
	var text strings.Builder
	sawFinal := false
	for i, f := range frames {
		got, err := opener.OpenFrame(f)
		if err != nil {
			t.Fatalf("OpenFrame %d: %v", i, err)
		}
		e2ee, err := f.E2EE()
		if err != nil {
			t.Fatalf("frame %d _e2ee: %v", i, err)
		}
		sawFinal = sawFinal || e2ee.Final
		if !bytes.Equal(got["type"], json.RawMessage(`"content_block_delta"`)) {
			continue
		}
		var delta struct {
			Text string `json:"text"`
		}
		if err := json.Unmarshal(got["delta"], &delta); err != nil {
			t.Fatalf("parse delta %d: %v", i, err)
		}
		text.WriteString(delta.Text)
	}
	if text.String() != "hello" {
		t.Errorf("reassembled stream = %q, want %q", text.String(), "hello")
	}
	// message_stop is guaranteed last, so it carries `final` — no synthetic
	// terminal frame is needed for this profile (SPEC §7.2).
	if !sawFinal {
		t.Error("the stream must carry a final frame; its absence is a truncation")
	}
}

// openRequestFor is openRequest through the profile-aware entry point, which is
// what an enclave serving a known endpoint uses: it runs the receiver-side
// profile checks (payload coverage, conditional payload, pins) before decrypting.
func (b *mockBroker) openRequestFor(t *testing.T, p wire.Profile, env wire.Request) (wire.Request, crypto.PublicKey) {
	t.Helper()
	e2ee, err := env.E2EE()
	if err != nil {
		t.Fatalf("read _e2ee: %v", err)
	}
	if e2ee.SignerAddr != b.signerAddr {
		t.Fatalf("signer_addr %q is not this broker %q", e2ee.SignerAddr, b.signerAddr)
	}
	req, err := wire.OpenRequestFor(p, b.encPriv, env)
	if err != nil {
		t.Fatalf("broker OpenRequestFor: %v", err)
	}
	ephPub, err := b64.DecodeString(e2ee.ClientEphPub)
	if err != nil {
		t.Fatalf("bad client_eph_pub: %v", err)
	}
	return req, ephPub
}
