package wire_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/0gfoundation/0g-pc-e2ee/protocol/crypto"
	"github.com/0gfoundation/0g-pc-e2ee/protocol/wire"
)

// toolsJSON is written to look like a real schema list rather than a placeholder,
// because the argument for sealing it is what the names ARE: an operation the
// calling application performs, in the caller's own vocabulary. `lookup` in the
// shared fixture understates it.
const toolsJSON = `[{"type":"function","function":{"name":"transfer_funds",` +
	`"description":"Move money between the customer's accounts",` +
	`"parameters":{"type":"object","properties":{"iban":{"type":"string"}}}}}]`

func toolsReq(t *testing.T, profile wire.Profile) wire.Request {
	t.Helper()
	body := `{"model":"gpt-4o","messages":[{"role":"user","content":"hi"}],"tools":` + toolsJSON + `}`
	if profile == wire.ProfileAnthropic {
		body = `{"model":"claude-x","max_tokens":16,"messages":[{"role":"user","content":"hi"}],"tools":` + toolsJSON + `}`
	}
	return mustReq(t, body)
}

func toolsKeys(t *testing.T) (crypto.PrivateKey, crypto.PublicKey, crypto.PublicKey) {
	t.Helper()
	encPriv, encPub, err := crypto.GenerateRecipientKey()
	if err != nil {
		t.Fatalf("enc keygen: %v", err)
	}
	_, ephPub, err := crypto.GenerateRecipientKey()
	if err != nil {
		t.Fatalf("eph keygen: %v", err)
	}
	return encPriv, encPub, ephPub
}

// The sender half. A set covering `messages` alone satisfies every
// unconditional rule — it is the set a client would pick if it thought of
// "the prompt" as the only payload — and it hands the tool schemas to the
// router. Both profiles that carry `tools` must refuse it.
//
// This is the test the rule change exists for, and its absence is why the
// change was invisible to the suite before: every existing case either seals
// the profile default (which contains `tools`) or sends no tools at all.
func TestToolsMustBeSealedWheneverPresent(t *testing.T) {
	for _, p := range []wire.Profile{wire.ProfileChat, wire.ProfileAnthropic} {
		t.Run(string(p), func(t *testing.T) {
			_, encPub, ephPub := toolsKeys(t)

			_, err := wire.SealRequestFor(p, encPub, toolsReq(t, p),
				[]string{"messages"}, testProvider, ephPub)
			if err == nil {
				t.Fatal("sealing a request whose tool schemas stay cleartext must be refused")
			}
			if !strings.Contains(err.Error(), "tools") {
				t.Errorf("error should name the field left in the clear, got %v", err)
			}
		})
	}
}

// The receiver half, which is the load-bearing one (SPEC §12): a third-party
// client runs no seal-time check, so the enclave is the only party that can
// refuse an envelope built elsewhere.
//
// The hostile envelope is built by sealing a request that has no tools and then
// adding them to the cleartext half — which is what a non-conforming sealer
// produces directly. The payload check runs before any decryption, so it is the
// check that must reject this; without it the request would open cleanly, since
// nothing else in the envelope is malformed.
func TestEnclaveRefusesAnEnvelopeCarryingToolsInTheClear(t *testing.T) {
	for _, p := range []wire.Profile{wire.ProfileChat, wire.ProfileAnthropic} {
		t.Run(string(p), func(t *testing.T) {
			encPriv, encPub, ephPub := toolsKeys(t)

			noTools := toolsReq(t, p)
			delete(noTools, "tools")
			env, err := wire.SealRequestFor(p, encPub, noTools, []string{"messages"}, testProvider, ephPub)
			if err != nil {
				t.Fatalf("precondition: a request without tools seals fine: %v", err)
			}
			if _, err := wire.OpenRequestFor(p, encPriv, env); err != nil {
				t.Fatalf("precondition: that envelope opens: %v", err)
			}

			env["tools"] = json.RawMessage(toolsJSON)
			_, err = wire.OpenRequestFor(p, encPriv, env)
			if err == nil {
				t.Fatal("an enclave must refuse a request whose tool schemas arrived in the clear")
			}
			if !strings.Contains(err.Error(), "tools") {
				t.Errorf("error should name the field that arrived in the clear, got %v", err)
			}
		})
	}
}

// A request with no tools is the common case and must not be burdened by the
// rule — the whole point of the optional flag. Getting this backwards would
// reject every conforming request that does not use tool calling.
func TestRequestWithoutToolsIsUnaffected(t *testing.T) {
	for _, p := range []wire.Profile{wire.ProfileChat, wire.ProfileAnthropic} {
		t.Run(string(p), func(t *testing.T) {
			encPriv, encPub, ephPub := toolsKeys(t)

			req := toolsReq(t, p)
			delete(req, "tools")
			env, err := wire.SealRequestFor(p, encPub, req, []string{"messages"}, testProvider, ephPub)
			if err != nil {
				t.Fatalf("a request with no tools must seal under a messages-only set: %v", err)
			}
			if _, err := wire.OpenRequestFor(p, encPriv, env); err != nil {
				t.Errorf("and must open: %v", err)
			}
		})
	}
}

// Sealing tools is what the default does, and the round trip must return them —
// the rule is "seal it", not "drop it".
func TestSealedToolsSurviveTheRoundTripAndLeaveNoCleartext(t *testing.T) {
	for _, p := range []wire.Profile{wire.ProfileChat, wire.ProfileAnthropic} {
		t.Run(string(p), func(t *testing.T) {
			encPriv, encPub, ephPub := toolsKeys(t)
			req := toolsReq(t, p)

			// The profile default filtered to the fields this request actually
			// carries, which is what a client does (core.Client.sealedFieldsFor):
			// passing the raw default would demand Anthropic's `system`, which this
			// fixture has no reason to set.
			var fields []string
			for _, f := range wire.DefaultSealedFieldsFor(p) {
				if _, present := req[f]; present {
					fields = append(fields, f)
				}
			}
			env, err := wire.SealRequestFor(p, encPub, req, fields, testProvider, ephPub)
			if err != nil {
				t.Fatalf("seal with the presence-filtered profile default %v: %v", fields, err)
			}
			if _, leaked := env["tools"]; leaked {
				t.Error("the default sealed set left tools in the cleartext half")
			}
			raw, err := json.Marshal(env)
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}
			if strings.Contains(string(raw), "transfer_funds") {
				t.Error("a tool name appears in the sealed envelope's bytes")
			}

			got, err := wire.OpenRequestFor(p, encPriv, env)
			if err != nil {
				t.Fatalf("open: %v", err)
			}
			if !strings.Contains(string(got["tools"]), "transfer_funds") {
				t.Errorf("reconstructed request lost its tools: %s", got["tools"])
			}
		})
	}
}

// The default sealed set must CONTAIN tools for every profile that treats it as
// payload — otherwise the default itself produces the envelope the rule above
// refuses, and every tool-using request fails on a conforming client.
func TestToolsIsInTheDefaultSealedSet(t *testing.T) {
	for _, p := range []wire.Profile{wire.ProfileChat, wire.ProfileAnthropic} {
		got := wire.DefaultSealedFieldsFor(p)
		found := false
		for _, f := range got {
			if f == "tools" {
				found = true
			}
		}
		if !found {
			t.Errorf("%s default sealed set %v omits tools", p, got)
		}
	}
}
