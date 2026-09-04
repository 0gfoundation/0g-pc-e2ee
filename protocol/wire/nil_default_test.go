package wire_test

import (
	"encoding/json"
	"testing"

	"github.com/0gfoundation/0g-pc-e2ee/protocol/wire"
)

// A nil sealed set resolves to the profile default NARROWED to what the request
// carries, and this is the property that makes the narrowing safe rather than
// lax: a payload field the request HAS must always end up sealed. Filtering may
// only ever drop a field that is absent, and an absent field cannot ride in the
// cleartext half.
//
// Asserted across every profile, from the profile's own default rather than a
// list written here, so a profile that gains a payload field is covered by
// existing.
func TestNilSealedSetNeverLeavesPayloadCleartext(t *testing.T) {
	_, encPub, ephPub := toolsKeys(t)

	// Each body carries every payload field its profile defines, so there is
	// something for the filter to get wrong.
	bodies := map[wire.Profile]string{
		wire.ProfileChat: `{"model":"m","messages":[{"role":"user","content":"hi"}],` +
			`"tools":[{"type":"function","function":{"name":"f"}}],` +
			`"tool_choice":{"type":"function","function":{"name":"f"}}}`,
		wire.ProfileAnthropic: `{"model":"m","max_tokens":16,"messages":[],"system":"s",` +
			`"tools":[{"name":"f","input_schema":{"type":"object"}}],` +
			`"tool_choice":{"type":"tool","name":"f"}}`,
		wire.ProfileSpeech: `{"model":"m","file_base64":"AA","filename":"board-meeting.m4a",` +
			`"language":"en","prompt":"hint","response_format":"json"}`,
		wire.ProfileImage: `{"model":"m","prompt":"a cat","response_format":"b64_json"}`,
	}

	for _, p := range wire.Profiles() {
		body, ok := bodies[p]
		if !ok {
			t.Errorf("profile %q has no body here: add one carrying its payload fields, "+
				"or this test silently stops covering it", p)
			continue
		}
		t.Run(string(p), func(t *testing.T) {
			var req wire.Request
			if err := json.Unmarshal([]byte(body), &req); err != nil {
				t.Fatalf("fixture: %v", err)
			}
			env, err := wire.SealRequestFor(p, encPub, req, nil, testProvider, ephPub)
			if err != nil {
				t.Fatalf("a nil set must seal a request carrying every default field: %v", err)
			}
			for _, f := range wire.DefaultSealedFieldsFor(p) {
				if _, inReq := req[f]; !inReq {
					continue
				}
				if _, leaked := env[f]; leaked {
					t.Errorf("%q was in the request and reached the cleartext half: "+
						"the filter dropped a field that is PRESENT", f)
				}
			}
		})
	}
}

// The narrowing must not rescue a request that has no payload at all. It cannot
// — the filtered set cannot contain what the request does not have — and this
// pins that the failure is still closed rather than an empty seal going out.
func TestNilSealedSetFailsClosedWithNoPayload(t *testing.T) {
	_, encPub, ephPub := toolsKeys(t)
	for _, p := range wire.Profiles() {
		t.Run(string(p), func(t *testing.T) {
			req := wire.Request{
				"model":       json.RawMessage(`"m"`),
				"temperature": json.RawMessage(`0.5`),
			}
			if _, err := wire.SealRequestFor(p, encPub, req, nil, testProvider, ephPub); err == nil {
				t.Error("a request carrying no payload field must not seal under a nil set")
			}
		})
	}
}

// An explicit set is NOT narrowed: it is the caller stating exactly what to
// seal, and shrinking it silently would hide a mistake rather than serve one.
func TestExplicitSealedSetIsNotNarrowed(t *testing.T) {
	_, encPub, ephPub := toolsKeys(t)
	req := mustReq(t, `{"model":"m","messages":[{"role":"user","content":"hi"}]}`)

	_, err := wire.SealRequestFor(wire.ProfileChat, encPub, req,
		[]string{"messages", "tools"}, testProvider, ephPub)
	if err == nil {
		t.Fatal("an explicit set naming a field the request lacks must still fail")
	}
}
