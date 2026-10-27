package wire_test

import (
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"

	"github.com/0gfoundation/0g-pc-e2ee/protocol/crypto"
	"github.com/0gfoundation/0g-pc-e2ee/protocol/wire"
)

func TestAttachAsyncBindRefusesACallerSuppliedBind(t *testing.T) {
	priv, _, err := crypto.GenerateRecipientKey()
	if err != nil {
		t.Fatal(err)
	}
	req := wire.Request{"prompt": json.RawMessage(`"p"`), "_bind": json.RawMessage(`"x"`)}
	if _, err := wire.AttachAsyncBind(req, priv); err == nil {
		t.Fatal("a request already carrying _bind was accepted: a caller-supplied value would be sealed as if derived")
	}
}

func TestAttachAsyncBindDoesNotMutateTheInput(t *testing.T) {
	priv, _, err := crypto.GenerateRecipientKey()
	if err != nil {
		t.Fatal(err)
	}
	req := wire.Request{"prompt": json.RawMessage(`"p"`)}
	out, err := wire.AttachAsyncBind(req, priv)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := req["_bind"]; ok {
		t.Fatal("AttachAsyncBind mutated its input")
	}
	if _, ok := out["_bind"]; !ok {
		t.Fatal("AttachAsyncBind returned no _bind")
	}
}

// The enclave must strip `_bind` before the upstream call, and refuse a request
// whose value is not a well-formed 32-byte binding.
func TestTakeAsyncBind(t *testing.T) {
	priv, _, err := crypto.GenerateRecipientKey()
	if err != nil {
		t.Fatal(err)
	}
	req, err := wire.AttachAsyncBind(wire.Request{"prompt": json.RawMessage(`"p"`), "n": json.RawMessage(`2`)}, priv)
	if err != nil {
		t.Fatal(err)
	}
	bind, fwd, err := wire.TakeAsyncBind(req)
	if err != nil {
		t.Fatal(err)
	}
	want, _ := wire.DeriveResponseBind(priv)
	if hex.EncodeToString(bind) != hex.EncodeToString(want) {
		t.Fatal("TakeAsyncBind returned a different value than was attached")
	}
	if _, ok := fwd["_bind"]; ok {
		t.Fatal("the forwarded request still carries _bind; it would reach the upstream")
	}
	if len(fwd) != 2 {
		t.Fatalf("forwarded request lost fields: %v", fwd)
	}

	for name, raw := range map[string]string{
		"missing":       "",
		"not a string":  `7`,
		"bad base64":    `"!!!"`,
		"padded":        `"` + strings.Repeat("A", 43) + `="`,
		"short":         `"AAAA"`,
		"null":          `null`,
		"object":        `{"v":"x"}`,
		"33 bytes long": `"` + strings.Repeat("A", 44) + `"`,
	} {
		t.Run(name, func(t *testing.T) {
			r := wire.Request{"prompt": json.RawMessage(`"p"`)}
			if raw != "" {
				r["_bind"] = json.RawMessage(raw)
			}
			if _, _, err := wire.TakeAsyncBind(r); err == nil {
				t.Fatal("accepted")
			}
		})
	}
}

func TestUserJobIDRoundTrip(t *testing.T) {
	priv, _, err := crypto.GenerateRecipientKey()
	if err != nil {
		t.Fatal(err)
	}
	for _, jobID := range []string{"a", "job_123-ABC", strings.Repeat("z", 128)} {
		id, err := wire.UserJobID(jobID, priv)
		if err != nil {
			t.Fatalf("%q: %v", jobID, err)
		}
		if !wire.HasUserJobIDKey(id) {
			t.Fatalf("%q: HasUserJobIDKey false on a keyed id", jobID)
		}
		gotJob, gotKey, err := wire.ParseUserJobID(id)
		if err != nil {
			t.Fatalf("%q: parse: %v", jobID, err)
		}
		if gotJob != jobID || hex.EncodeToString(gotKey) != hex.EncodeToString(priv) {
			t.Fatalf("%q: round trip changed the value", jobID)
		}
	}
	if wire.HasUserJobIDKey("job_123") {
		t.Fatal("HasUserJobIDKey true on a bare job id")
	}
}

func TestUserJobIDRefusesBadJobIDs(t *testing.T) {
	priv, _, err := crypto.GenerateRecipientKey()
	if err != nil {
		t.Fatal(err)
	}
	for _, jobID := range []string{"", "a.b", "a/b", "a b", "ä", strings.Repeat("z", 129)} {
		if _, err := wire.UserJobID(jobID, priv); err == nil {
			t.Errorf("job id %q was accepted", jobID)
		}
	}
	if _, err := wire.UserJobID("ok", make(crypto.PrivateKey, 31)); err == nil {
		t.Error("a 31-byte key was accepted")
	}
}

// Parsing errors must not echo the input: the key segment is a secret, and an
// error string is a log line. Every rejection is checked for the secret.
func TestParseUserJobIDRefusesWithoutEchoingTheInput(t *testing.T) {
	const secret = "SECRETSECRETSECRETSECRETSECRETSECRETSECRET"
	for name, in := range map[string]string{
		"no separator":         "job_123",
		"bad job charset":      "job/1." + secret,
		"dot inside the job":   "a.b." + secret, // last-dot split leaves "a.b": refused, not mis-split
		"job too long":         strings.Repeat("z", 129) + "." + secret,
		"empty job":            "." + secret,
		"key not base64url":    "job." + secret + "+/",
		"key padded":           "job." + secret + "AA==",
		"key too short":        "job." + secret[:20],
		"key too long":         "job." + secret + "AAAAAAAA",
		"empty key":            "job.",
		"standard base64 char": "job." + strings.Repeat("A", 42) + "+",
	} {
		t.Run(name, func(t *testing.T) {
			_, _, err := wire.ParseUserJobID(in)
			if err == nil {
				t.Fatal("accepted")
			}
			if strings.Contains(err.Error(), "SECRET") || strings.Contains(err.Error(), in) {
				t.Fatalf("error echoes the input: %v", err)
			}
		})
	}
}

// asyncFrame is a completed async-image poll body, before sealing.
func asyncFrame() wire.Response {
	return wire.Response{
		"jobId":  json.RawMessage(`"job_1"`),
		"status": json.RawMessage(`"completed"`),
		"usage":  json.RawMessage(`{"output_images":1}`),
		"data":   json.RawMessage(`{"data":[{"b64_json":"x"}]}`),
	}
}

func mustBind(t *testing.T, ephPriv crypto.PrivateKey) []byte {
	t.Helper()
	bind, err := wire.DeriveResponseBind(ephPriv)
	if err != nil {
		t.Fatal(err)
	}
	return bind
}

// `jobId` and `status` are bound by PROFILE declaration, so every seal and open
// path enforces it — not only the OpenAsyncImageResult wrapper. A conforming
// sealer refuses to free or seal them; a frame a non-conforming sealer emits
// anyway is refused by the generic opener and by the wrapper.
func TestAsyncImageJobIDAndStatusAreBoundOnEveryPath(t *testing.T) {
	ephPriv, ephPub, err := crypto.GenerateRecipientKey()
	if err != nil {
		t.Fatal(err)
	}
	bind := mustBind(t, ephPriv)
	for _, f := range []string{"jobId", "status"} {
		t.Run(f, func(t *testing.T) {
			if _, err := wire.SealBoundResponseFor(wire.ProfileAsyncImage, ephPub, bind, asyncFrame(), nil, f, "x_0g_trace"); err == nil {
				t.Fatalf("a conforming sealer declared %q unbound", f)
			}
			if _, err := wire.SealBoundResponseFor(wire.ProfileAsyncImage, ephPub, bind, asyncFrame(), []string{"data", f}); err == nil {
				t.Fatalf("a conforming sealer sealed %q away", f)
			}
			// What a non-conforming enclave would emit.
			sealed, err := wire.SealBoundResponseNonConforming(ephPub, bind, asyncFrame(), []string{"data"}, f, "x_0g_trace")
			if err != nil {
				t.Fatal(err)
			}
			if _, err := wire.OpenBoundResponseFor(wire.ProfileAsyncImage, ephPriv, sealed); err == nil {
				t.Fatalf("the generic opener accepted a frame with %q unbound", f)
			}
			if _, err := wire.OpenAsyncImageResult(ephPriv, sealed, "job_1"); err == nil {
				t.Fatalf("OpenAsyncImageResult accepted a frame with %q unbound", f)
			}
		})
	}
}

// The binding is not a property of the wrapper: async-image responses are
// always bound, so neither end will set up a base-mode context for the profile,
// whichever entry point a caller uses.
func TestAsyncImageIsAlwaysBound(t *testing.T) {
	ephPriv, ephPub, err := crypto.GenerateRecipientKey()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := wire.SealResponseFor(wire.ProfileAsyncImage, ephPub, asyncFrame(), nil, wire.AsyncImageResultUnboundFields()...); err == nil {
		t.Fatal("an async-image result was sealed in base mode")
	}
	honest, err := wire.SealAsyncImageResult(ephPub, asyncFrame(), mustBind(t, ephPriv))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := wire.OpenResponseFor(wire.ProfileAsyncImage, ephPriv, honest); err == nil {
		t.Fatal("an async-image result was opened in base mode")
	}
	if _, ok := honest["_bind"]; ok {
		t.Fatal("the result frame carries _bind: the binding keys the context, it does not ride in the frame")
	}
}

// The attack of §7.5.1: the router submits a request of its own carrying the
// victim's client_eph_pub, and a genuine enclave seals the result to the victim
// under the ROUTER's binding value. It does not open for the victim.
func TestAsyncImageResultForAnotherRequestIsRefused(t *testing.T) {
	victimPriv, victimPub, err := crypto.GenerateRecipientKey()
	if err != nil {
		t.Fatal(err)
	}
	attackerPriv, _, err := crypto.GenerateRecipientKey()
	if err != nil {
		t.Fatal(err)
	}
	forged, err := wire.SealAsyncImageResult(victimPub, asyncFrame(), mustBind(t, attackerPriv))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := wire.OpenAsyncImageResult(victimPriv, forged, "job_1"); err == nil {
		t.Fatal("a result sealed under another request's binding was accepted")
	}
	honest, err := wire.SealAsyncImageResult(victimPub, asyncFrame(), mustBind(t, victimPriv))
	if err != nil {
		t.Fatal(err)
	}
	opened, err := wire.OpenAsyncImageResult(victimPriv, honest, "job_1")
	if err != nil {
		t.Fatalf("honest result refused: %v", err)
	}
	if string(opened["data"]) != `{"data":[{"b64_json":"x"}]}` {
		t.Fatalf("data = %s", opened["data"])
	}
}
