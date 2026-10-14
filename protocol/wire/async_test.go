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

// The binding value is the one derived quantity in the async-image profile that a
// second implementation (a TS gateway, a Rust enclave) must reproduce bit for bit,
// so it is pinned to a known answer rather than only round-tripped. Computed
// independently from RFC 5869 (HMAC-SHA256, empty salt = 32 zero bytes, one
// output block).
func TestDeriveAsyncBindKnownAnswer(t *testing.T) {
	key := make(crypto.PrivateKey, 32)
	for i := range key {
		key[i] = byte(i)
	}
	got, err := wire.DeriveAsyncBind(key)
	if err != nil {
		t.Fatal(err)
	}
	const want = "b52d9b2bf6b7e94c9be3c8b73539ab2dbebfa058562c80c839af86de2a52abb3"
	if hex.EncodeToString(got) != want {
		t.Fatalf("DeriveAsyncBind KAT = %x, want %s", got, want)
	}
}

func TestDeriveAsyncBindRejectsWrongKeyLength(t *testing.T) {
	for _, n := range []int{0, 31, 33, 64} {
		if _, err := wire.DeriveAsyncBind(make(crypto.PrivateKey, n)); err == nil {
			t.Errorf("a %d-byte key was accepted", n)
		}
	}
}

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
	want, _ := wire.DeriveAsyncBind(priv)
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
func asyncFrame(t *testing.T, ephPriv crypto.PrivateKey) wire.Response {
	t.Helper()
	bind, err := wire.DeriveAsyncBind(ephPriv)
	if err != nil {
		t.Fatal(err)
	}
	bindJSON, _ := json.Marshal(base64.RawURLEncoding.EncodeToString(bind))
	return wire.Response{
		"jobId":  json.RawMessage(`"job_1"`),
		"status": json.RawMessage(`"completed"`),
		"usage":  json.RawMessage(`{"output_images":1}`),
		"data":   json.RawMessage(`{"data":[{"b64_json":"x"}]}`),
		"_bind":  bindJSON,
	}
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
	for _, f := range []string{"jobId", "status"} {
		t.Run(f, func(t *testing.T) {
			if _, err := wire.SealResponseFor(wire.ProfileAsyncImage, ephPub, asyncFrame(t, ephPriv), nil, f, "x_0g_trace"); err == nil {
				t.Fatalf("a conforming sealer declared %q unbound", f)
			}
			if _, err := wire.SealResponseFor(wire.ProfileAsyncImage, ephPub, asyncFrame(t, ephPriv), []string{"data", "_bind", f}); err == nil {
				t.Fatalf("a conforming sealer sealed %q away", f)
			}
			// What a non-conforming enclave would emit.
			sealed, err := wire.SealResponseNonConforming(ephPub, asyncFrame(t, ephPriv), []string{"data", "_bind"}, f, "x_0g_trace")
			if err != nil {
				t.Fatal(err)
			}
			if _, err := wire.OpenResponseFor(wire.ProfileAsyncImage, ephPriv, sealed); err == nil {
				t.Fatalf("the generic opener accepted a frame with %q unbound", f)
			}
			if _, err := wire.OpenAsyncImageResult(ephPriv, sealed, "job_1"); err == nil {
				t.Fatalf("OpenAsyncImageResult accepted a frame with %q unbound", f)
			}
		})
	}
}

// The `_bind` comparison runs in the generic opener, so a caller that opens with
// OpenResponseFor(ProfileAsyncImage, …) instead of the wrapper still refuses a
// result produced for someone else's request sealed to its key.
func TestAsyncImageGenericOpenerChecksTheBinding(t *testing.T) {
	victimPriv, victimPub, err := crypto.GenerateRecipientKey()
	if err != nil {
		t.Fatal(err)
	}
	attackerPriv, _, err := crypto.GenerateRecipientKey()
	if err != nil {
		t.Fatal(err)
	}
	// Sealed to the victim's key, carrying the attacker's binding value — what a
	// genuine enclave produces for a router-submitted request reusing the
	// victim's client_eph_pub.
	forged, err := wire.SealResponseFor(wire.ProfileAsyncImage, victimPub, asyncFrame(t, attackerPriv), nil, wire.AsyncImageResultUnboundFields()...)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := wire.OpenResponseFor(wire.ProfileAsyncImage, victimPriv, forged); err == nil {
		t.Fatal("the generic opener accepted a frame bound to a different request")
	}
	// And the honest frame opens on the generic path too, `_bind` still present
	// for the caller to drop.
	honest, err := wire.SealResponseFor(wire.ProfileAsyncImage, victimPub, asyncFrame(t, victimPriv), nil, wire.AsyncImageResultUnboundFields()...)
	if err != nil {
		t.Fatal(err)
	}
	opened, err := wire.OpenResponseFor(wire.ProfileAsyncImage, victimPriv, honest)
	if err != nil {
		t.Fatalf("honest frame refused on the generic path: %v", err)
	}
	if _, ok := opened["_bind"]; !ok {
		t.Fatal("generic open dropped _bind; only the wrapper strips it")
	}
}
