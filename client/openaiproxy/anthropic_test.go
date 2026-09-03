package openaiproxy_test

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/0gfoundation/0g-pc-e2ee/client/core"
	"github.com/0gfoundation/0g-pc-e2ee/client/endpoint"
	"github.com/0gfoundation/0g-pc-e2ee/client/openaiproxy"
	"github.com/0gfoundation/0g-pc-e2ee/protocol/crypto"
	"github.com/0gfoundation/0g-pc-e2ee/protocol/wire"
)

// anthropicFrames is one streaming turn in the /v1/messages event taxonomy
// (SPEC §7.2), as plaintext frames the mock broker seals one at a time.
//
// message_start carries the input token count the router bills on, in a
// `message` the profile protects as cleartext — so its content array must be
// empty, checked on every frame rather than just this one. The deltas carry the
// generated text. message_stop is terminal: it is what ENDS an Anthropic stream,
// in place of OpenAI's `[DONE]` sentinel.
func anthropicFrames() []wire.Response {
	return []wire.Response{
		{
			"type":    json.RawMessage(`"message_start"`),
			"message": json.RawMessage(`{"id":"msg_1","role":"assistant","content":[],"usage":{"input_tokens":11}}`),
		},
		{
			"type":          json.RawMessage(`"content_block_start"`),
			"index":         json.RawMessage(`0`),
			"content_block": json.RawMessage(`{"type":"text","text":""}`),
		},
		{
			"type":  json.RawMessage(`"content_block_delta"`),
			"index": json.RawMessage(`0`),
			"delta": json.RawMessage(`{"type":"text_delta","text":"he"}`),
		},
		{
			"type":  json.RawMessage(`"content_block_delta"`),
			"index": json.RawMessage(`0`),
			"delta": json.RawMessage(`{"type":"text_delta","text":"llo"}`),
		},
		{"type": json.RawMessage(`"content_block_stop"`), "index": json.RawMessage(`0`)},
		{
			"type":  json.RawMessage(`"message_delta"`),
			"delta": json.RawMessage(`{"stop_reason":"end_turn","stop_sequence":null}`),
			"usage": json.RawMessage(`{"output_tokens":3}`),
		},
		{"type": json.RawMessage(`"message_stop"`)},
	}
}

// mockAnthropicBroker is a provider enclave serving the /v1/messages surface: it
// opens the sealed request, asserts on the PLAINTEXT it recovered, and seals each
// frame under the field set that frame's shape requires.
//
// It emits `event:` lines of its own, as the broker does — and the client must
// NOT trust them. §7.2 puts the event name outside the JSON and therefore outside
// the AAD, so an intermediary can rewrite it undetected; a receiver rebuilds it
// from the frame's own bound `type`. sawSystem/sawStreamOptions report what
// reached the enclave.
func mockAnthropicBroker(t *testing.T, encPriv crypto.PrivateKey, sawSystem, sawStreamOptions *string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var env wire.Request
		if err := json.Unmarshal(body, &env); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		e2ee, _ := env.E2EE()
		opened, err := wire.OpenRequest(encPriv, env)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		// The system prompt must arrive SEALED — recovered here, absent from the
		// cleartext envelope. The Anthropic profile requires it when present; a
		// request sealed under the chat profile would have left it at the top level.
		if raw, ok := opened["system"]; ok {
			*sawSystem = string(raw)
		}
		if raw, ok := opened["stream_options"]; ok {
			*sawStreamOptions = string(raw)
		}

		ephPub, _ := base64.RawURLEncoding.DecodeString(e2ee.ClientEphPub)
		// The ANTHROPIC sealer, not the chat shorthand. A chat-profile sealer is
		// single-shape, so it refuses a metadata frame's empty sealed set outright
		// ("no sealed fields") — the library catching an enclave that would have
		// sealed this surface under the wrong rules.
		sealer, err := wire.NewResponseSealerFor(wire.ProfileAnthropic, crypto.PublicKey(ephPub))
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "text/event-stream")
		flusher := w.(http.Flusher)
		frames := anthropicFrames()
		for i, frame := range frames {
			fields, err := wire.ResponseSealedFieldsForFrame(wire.ProfileAnthropic, frame)
			if err != nil {
				t.Errorf("sealed fields for frame %d: %v", i, err)
				return
			}
			sealed, err := sealer.SealFrame(frame, fields, i == len(frames)-1)
			if err != nil {
				t.Errorf("seal frame %d: %v", i, err)
				return
			}
			b, _ := json.Marshal(sealed)
			// A DELIBERATELY WRONG event name. The client must ignore it and derive
			// the name from the sealed frame's own bound discriminator; if it ever
			// forwarded this line, the assertions below would see "not_the_real_event".
			_, _ = w.Write([]byte("event: not_the_real_event\ndata: "))
			_, _ = w.Write(b)
			_, _ = w.Write([]byte("\n\n"))
			flusher.Flush()
		}
	}))
}

// The gateway's /v1/messages leg end to end, against an enclave that speaks the
// real §7.2 frame protocol. Four properties, each of which was wrong before the
// Anthropic row existed:
//
//   - the surface is SERVED at all (it used to 404, so an Anthropic SDK could not
//     reach the sealed path);
//   - the top-level `system` is sealed, not sent in the clear;
//   - every event is announced by name, rebuilt from the frame's own bound `type`
//     rather than forwarded from the upstream's line;
//   - the stream ends with `message_stop` and NO `[DONE]`.
func TestAnthropicStreamingSurface(t *testing.T) {
	encPriv, encPub, _ := crypto.GenerateRecipientKey()
	signer := "0x" + strings.Repeat("a", 40)
	var sawSystem, sawStreamOptions string
	broker := mockAnthropicBroker(t, encPriv, &sawSystem, &sawStreamOptions)
	defer broker.Close()

	client := core.New(
		core.Provider{URL: broker.URL, EncPubKey: encPub, SignerAddr: signer},
		core.WithEndpoint(endpoint.Anthropic),
	)
	mux := http.NewServeMux()
	openaiproxy.Register(mux, endpoint.Anthropic, client)
	proxy := httptest.NewServer(mux)
	defer proxy.Close()

	const userReq = `{"model":"claude-x","max_tokens":1024,"stream":true,` +
		`"system":"the secret system prompt",` +
		`"messages":[{"role":"user","content":"the secret prompt"}]}`
	httpResp, err := http.Post(proxy.URL+endpoint.Anthropic.Path, "application/json", strings.NewReader(userReq))
	if err != nil {
		t.Fatalf("post to proxy: %v", err)
	}
	defer httpResp.Body.Close()
	if httpResp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(httpResp.Body)
		t.Fatalf("stream: got %d: %s", httpResp.StatusCode, b)
	}
	raw, _ := io.ReadAll(httpResp.Body)

	// The enclave recovered the system prompt, so it travelled sealed.
	if want := `"the secret system prompt"`; sawSystem != want {
		t.Errorf("the enclave opened system = %s, want %s — it must be sealed, not cleartext", sawSystem, want)
	}
	// stream_options is an OpenAI CHAT convention. Grafting it here would put a
	// field /v1/messages does not define into every streaming request, and it
	// would be BOUND, so the enclave could not ignore it either.
	if sawStreamOptions != "" {
		t.Errorf("stream_options=%s was grafted onto an Anthropic request", sawStreamOptions)
	}
	for _, secret := range []string{"the secret prompt", "the secret system prompt"} {
		if bytes.Contains(raw, []byte(secret)) {
			t.Errorf("%q appeared in the response stream", secret)
		}
	}

	// Walk the emitted SSE: pair each `event:` name with the `type` of the frame
	// that follows it, and reassemble the text.
	var names []string
	var types []string
	var text string
	for _, block := range strings.Split(string(raw), "\n\n") {
		if strings.TrimSpace(block) == "" {
			continue
		}
		var name, data string
		for _, line := range strings.Split(block, "\n") {
			if v, ok := strings.CutPrefix(line, "event: "); ok {
				name = v
			}
			if v, ok := strings.CutPrefix(line, "data: "); ok {
				data = v
			}
		}
		if data == "[DONE]" {
			t.Error("an Anthropic stream must not be terminated with [DONE]: it is an OpenAI chat convention and the taxonomy has no rule for it")
			continue
		}
		var frame struct {
			Type  string `json:"type"`
			Delta struct {
				Text string `json:"text"`
			} `json:"delta"`
		}
		if err := json.Unmarshal([]byte(data), &frame); err != nil {
			t.Fatalf("bad SSE frame %q: %v", data, err)
		}
		names = append(names, name)
		types = append(types, frame.Type)
		text += frame.Delta.Text
	}

	if text != "hello" {
		t.Errorf("reassembled text = %q, want %q", text, "hello")
	}
	// Every event named, and named as its own frame says — not as the upstream's
	// (rewritable, unbound) line claimed.
	for i, name := range names {
		if name == "" {
			t.Errorf("frame %d (%s) has no event: line; an Anthropic SDK dispatches on it", i, types[i])
			continue
		}
		if name != types[i] {
			t.Errorf("frame %d announced as %q but its bound type is %q", i, name, types[i])
		}
	}
	if n := len(types); n == 0 || types[n-1] != "message_stop" {
		t.Errorf("stream ended with %v, want it to end with message_stop", types)
	}
}

// The chat surface must be byte-for-byte unchanged by the framing split: no
// `event:` lines, and still terminated by `[DONE]`. Asserted alongside the
// Anthropic test because the two are one decision — a receiver that emits the
// same framing for both is wrong for one of them, and this is the half that says
// which half stayed put.
func TestChatStreamingKeepsItsOpenAIFraming(t *testing.T) {
	encPriv, encPub, _ := crypto.GenerateRecipientKey()
	signer := "0x" + strings.Repeat("b", 40)
	broker := mockStreamingBroker(t, encPriv, signer, []string{`{"content":"hi"}`})
	defer broker.Close()

	client := core.New(core.Provider{URL: broker.URL, EncPubKey: encPub, SignerAddr: signer})
	proxy := httptest.NewServer(openaiproxy.Handler(client))
	defer proxy.Close()

	httpResp, err := http.Post(proxy.URL+endpoint.Chat.Path, "application/json",
		strings.NewReader(`{"model":"gpt-4o","stream":true,"messages":[{"role":"user","content":"hi"}]}`))
	if err != nil {
		t.Fatalf("post to proxy: %v", err)
	}
	defer httpResp.Body.Close()
	raw, _ := io.ReadAll(httpResp.Body)

	if bytes.Contains(raw, []byte("event:")) {
		t.Errorf("a chat stream must carry no event: lines, got:\n%s", raw)
	}
	if !bytes.Contains(raw, []byte("data: [DONE]")) {
		t.Errorf("a chat stream must still end with [DONE], got:\n%s", raw)
	}
}
