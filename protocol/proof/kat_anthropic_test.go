package proof

import (
	"encoding/json"
	"testing"
)

// Golden vectors for the ANTHROPIC profile (SPEC §7.2). The §8 binding math is
// profile-independent — aad‖ciphertext, whatever the frame holds — so what these
// pin is the pairing of that math with the frame shapes: a stream whose frames
// have DIFFERENT cleartext keys and different (sometimes empty) sealed_fields
// still aggregates to one respH, in send order, with the terminal message_stop
// last.
//
// That combination is what a hand-written broker gets wrong first. The empty
// `sealed_fields: []` on the sequencing frames is in the AAD like any other
// metadata, so a broker that omitted the key instead of emitting an empty array
// would produce a different hash and a signature the client cannot verify —
// silently, since every other check still passes. Pinning the aggregate makes
// that a loud test failure in either repository.
//
// Fixtures are hand-crafted sealed envelopes (fixed cleartext + fixed base64url
// ciphertext); no HPKE is involved, so the vectors are deterministic and need no
// keys. Regenerate deliberately, and only alongside a §9 scheme bump.
const (
	katAnthReqEnv = `{"model":"claude-x","max_tokens":1024,"stream":true,"_e2ee":{"v":1,"kem_id":"X25519","key_id":"AAAAAAAAAAA","client_eph_pub":"Y2xpZW50ZXBo","enc":"ZW5jYXBz","sealed_fields":["messages","system"],"ciphertext":"AAECAwQF"}}`

	// The six shapes of a real stream: two carry content, four are sequencing and
	// seal nothing. message_start keeps `message` cleartext (the router's input
	// token count is inside it) and message_delta keeps top-level `usage`.
	katAnthStart      = `{"type":"message_start","message":{"id":"msg_1","type":"message","role":"assistant","model":"claude-x","content":[],"usage":{"input_tokens":11,"output_tokens":1}},"_e2ee":{"v":1,"enc":"cmVzcGVuYw","sealed_fields":[],"unbound_fields":["model","x_0g_trace"],"final":false,"ciphertext":"DA0ODxAR"}}`
	katAnthBlockStart = `{"type":"content_block_start","index":0,"_e2ee":{"sealed_fields":["content_block"],"unbound_fields":["model","x_0g_trace"],"final":false,"ciphertext":"EhMUFRYX"}}`
	katAnthDelta      = `{"type":"content_block_delta","index":0,"_e2ee":{"sealed_fields":["delta"],"unbound_fields":["model","x_0g_trace"],"final":false,"ciphertext":"GBkaGxwd"}}`
	katAnthBlockStop  = `{"type":"content_block_stop","index":0,"_e2ee":{"sealed_fields":[],"unbound_fields":["model","x_0g_trace"],"final":false,"ciphertext":"Hh8gISIj"}}`
	katAnthMsgDelta   = `{"type":"message_delta","usage":{"output_tokens":20},"_e2ee":{"sealed_fields":["delta"],"unbound_fields":["model","x_0g_trace"],"final":false,"ciphertext":"JCUmJygp"}}`
	katAnthStop       = `{"type":"message_stop","_e2ee":{"sealed_fields":[],"unbound_fields":["model","x_0g_trace"],"final":true,"ciphertext":"Kissa7"}}`

	// Non-streaming: one frame, `content` sealed, everything the router bills and
	// attributes on cleartext.
	katAnthRespEnv = `{"id":"msg_1","type":"message","role":"assistant","model":"claude-x","stop_reason":"end_turn","usage":{"input_tokens":11,"output_tokens":20},"_e2ee":{"v":1,"enc":"cmVzcGVuYw","sealed_fields":["content"],"unbound_fields":["model","x_0g_trace"],"final":true,"ciphertext":"BgcICQoL"}}`

	katAnthReqH  = "825a8bc801a6cf1ee932bb418adda99904ab3cb733f148b8dd6c347341b43a18"
	katAnthRespH = "4b8cd57f0bf32b7f0f7944eec8b290d78959b2472738c6b16857fbff6317aa39"

	katAnthNonStream = "zg-sig-v1/e2ee-ct:" + katAnthReqH + ":" + katAnthRespH
	katAnthStream    = "zg-sig-v1/e2ee-ct-stream:" + katAnthReqH + ":ada3a8ced7de16aa56938e0561f8ab2c5ea48f41f86f540c7e106f95ee2f7ffd"
)

// katAnthFrames is the stream in SEND order, terminal frame last — the order the
// aggregate is defined over (§8.1), so a reordered or dropped frame changes it.
func katAnthFrames(t *testing.T) []map[string]json.RawMessage {
	t.Helper()
	out := make([]map[string]json.RawMessage, 0, 6)
	for _, s := range []string{
		katAnthStart, katAnthBlockStart, katAnthDelta,
		katAnthBlockStop, katAnthMsgDelta, katAnthStop,
	} {
		out = append(out, katEnv(t, s))
	}
	return out
}

func TestKAT_AnthropicSignedText(t *testing.T) {
	got, err := SignedTextE2EE(katEnv(t, katAnthReqEnv), katEnv(t, katAnthRespEnv))
	if err != nil {
		t.Fatal(err)
	}
	if got != katAnthNonStream {
		t.Fatalf("anthropic non-stream signed-text drift:\n got  %s\n want %s", got, katAnthNonStream)
	}
}

func TestKAT_AnthropicSignedTextStream(t *testing.T) {
	got, err := SignedTextE2EEStream(katEnv(t, katAnthReqEnv), katAnthFrames(t))
	if err != nil {
		t.Fatal(err)
	}
	if got != katAnthStream {
		t.Fatalf("anthropic stream signed-text drift:\n got  %s\n want %s", got, katAnthStream)
	}
}

// The aggregate is order- and count-sensitive across MIXED frame shapes, which
// is the property the streaming binding exists for: dropping the sequencing
// frame that seals nothing changes respH just as much as dropping a delta, so a
// stream truncated at any shape is caught.
func TestKAT_AnthropicStreamAggregateIsShapeSensitive(t *testing.T) {
	frames := katAnthFrames(t)
	full, err := SignedTextE2EEStream(katEnv(t, katAnthReqEnv), frames)
	if err != nil {
		t.Fatal(err)
	}
	for _, tt := range []struct {
		name   string
		frames []map[string]json.RawMessage
	}{
		{"without the empty-seal content_block_stop", append(append([]map[string]json.RawMessage{}, frames[:3]...), frames[4:]...)},
		{"without the terminal message_stop", frames[:5]},
		{"with the two content frames swapped", []map[string]json.RawMessage{
			frames[0], frames[2], frames[1], frames[3], frames[4], frames[5],
		}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			got, err := SignedTextE2EEStream(katEnv(t, katAnthReqEnv), tt.frames)
			if err != nil {
				t.Fatal(err)
			}
			if got == full {
				t.Error("the aggregate must change: it is what makes a truncated or reordered stream detectable")
			}
		})
	}
}
