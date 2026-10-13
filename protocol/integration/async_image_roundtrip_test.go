package integration

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/0gfoundation/0g-pc-e2ee/protocol/crypto"
	"github.com/0gfoundation/0g-pc-e2ee/protocol/wire"
)

// The async-image profile (SPEC §7.5), played end to end in one process: the
// gateway seals and later opens, the enclave opens, generates and seals the
// result once, the router stores nothing but relays and rewrites what it is
// allowed to. Each attack below is something the router can actually do with
// what it sees.

const asyncSigner = "0x1111111111111111111111111111111111111111"

type asyncParty struct {
	encPriv crypto.PrivateKey
	encPub  crypto.PublicKey
}

func newEnclave(t *testing.T) asyncParty {
	t.Helper()
	priv, pub, err := crypto.GenerateRecipientKey()
	if err != nil {
		t.Fatal(err)
	}
	return asyncParty{encPriv: priv, encPub: pub}
}

func asyncRequest(prompt string) wire.Request {
	return wire.Request{
		"model":           json.RawMessage(`"z-image"`),
		"n":               json.RawMessage(`2`),
		"size":            json.RawMessage(`"1024x1024"`),
		"response_format": json.RawMessage(`"b64_json"`),
		"prompt":          json.RawMessage(`"` + prompt + `"`),
	}
}

// gatewaySubmit is the gateway's submit half: a fresh eph keypair per job, the
// binding value attached, the request sealed under the async-image profile.
func gatewaySubmit(t *testing.T, enc asyncParty, req wire.Request) (env wire.Request, ephPriv crypto.PrivateKey, ephPub crypto.PublicKey) {
	t.Helper()
	ephPriv, ephPub, err := crypto.GenerateRecipientKey()
	if err != nil {
		t.Fatal(err)
	}
	bound, err := wire.AttachAsyncBind(req, ephPriv)
	if err != nil {
		t.Fatal(err)
	}
	env, err = wire.SealRequestFor(wire.ProfileAsyncImage, enc.encPub, bound, nil, asyncSigner, ephPub, wire.DefaultUnboundFields()...)
	if err != nil {
		t.Fatal(err)
	}
	return env, ephPriv, ephPub
}

// enclaveComplete is the broker's whole job lifetime: open at dispatch, strip
// `_bind` before the upstream, then seal the completed poll envelope once.
func enclaveComplete(t *testing.T, enc asyncParty, env wire.Request, jobID string) wire.Response {
	t.Helper()
	opened, err := wire.OpenRequestFor(wire.ProfileAsyncImage, enc.encPriv, env)
	if err != nil {
		t.Fatalf("enclave open: %v", err)
	}
	bind, forward, err := wire.TakeAsyncBind(opened)
	if err != nil {
		t.Fatalf("enclave take bind: %v", err)
	}
	if _, ok := forward["_bind"]; ok {
		t.Fatal("_bind would reach the upstream")
	}
	var prompt string
	if err := json.Unmarshal(forward["prompt"], &prompt); err != nil {
		t.Fatal(err)
	}
	e2ee, err := env.E2EE()
	if err != nil {
		t.Fatal(err)
	}
	ephPub, err := b64url(e2ee.ClientEphPub)
	if err != nil {
		t.Fatal(err)
	}
	// The "upstream": images derived from the prompt, so a test can tell whose
	// request produced a result.
	data := `{"created":1,"data":[{"b64_json":"img-of:` + prompt + `"},{"b64_json":"img2"}]}`
	result := wire.Response{
		"jobId":     json.RawMessage(`"` + jobID + `"`),
		"status":    json.RawMessage(`"completed"`),
		"createdAt": json.RawMessage(`"2026-10-13T00:00:00Z"`),
		"updatedAt": json.RawMessage(`"2026-10-13T00:00:09Z"`),
		"model":     json.RawMessage(`"z-image"`),
		"usage":     json.RawMessage(`{"output_images":2}`),
		"data":      json.RawMessage(data),
	}
	frame, err := wire.SealAsyncImageResult(crypto.PublicKey(ephPub), result, bind)
	if err != nil {
		t.Fatalf("enclave seal result: %v", err)
	}
	return frame
}

// routerRelay is what an honest router does to a completed poll body: decode,
// inject x_0g_trace, re-encode (key order and escaping change; values do not).
func routerRelay(t *testing.T, frame wire.Response) wire.Response {
	t.Helper()
	var m map[string]any
	b, _ := json.Marshal(frame)
	dec := json.NewDecoder(strings.NewReader(string(b)))
	dec.UseNumber()
	if err := dec.Decode(&m); err != nil {
		t.Fatal(err)
	}
	m["x_0g_trace"] = map[string]any{"request_id": "r-1", "billing": map[string]any{"total_cost": "12"}}
	out, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	var r wire.Response
	if err := json.Unmarshal(out, &r); err != nil {
		t.Fatal(err)
	}
	return r
}

func dataOf(t *testing.T, opened wire.Response) string {
	t.Helper()
	return string(opened["data"])
}

func TestAsyncImageRoundTrip(t *testing.T) {
	enc := newEnclave(t)
	env, ephPriv, _ := gatewaySubmit(t, enc, asyncRequest("a red fox"))

	// The router sees the routing and billing fields and nothing of the prompt
	// or the binding value.
	if _, ok := env["prompt"]; ok {
		t.Fatal("prompt is cleartext in the submitted envelope")
	}
	if _, ok := env["_bind"]; ok {
		t.Fatal("_bind is cleartext in the submitted envelope: a router could copy it into a request of its own")
	}
	for _, f := range []string{"model", "n", "size", "response_format"} {
		if _, ok := env[f]; !ok {
			t.Fatalf("routing field %q missing from the envelope", f)
		}
	}

	frame := enclaveComplete(t, enc, env, "job_1")
	if _, ok := frame["data"]; ok {
		t.Fatal("data is cleartext in the result frame")
	}
	var usage struct {
		OutputImages *int `json:"output_images"`
	}
	if err := json.Unmarshal(frame["usage"], &usage); err != nil || usage.OutputImages == nil || *usage.OutputImages != 2 {
		t.Fatalf("router cannot read usage.output_images: %s", frame["usage"])
	}

	userID, err := wire.UserJobID("job_1", ephPriv)
	if err != nil {
		t.Fatal(err)
	}
	jobID, key, err := wire.ParseUserJobID(userID)
	if err != nil {
		t.Fatal(err)
	}
	opened, err := wire.OpenAsyncImageResult(key, routerRelay(t, frame), jobID)
	if err != nil {
		t.Fatalf("gateway open after an honest relay (trace injected, re-encoded): %v", err)
	}
	if !strings.Contains(dataOf(t, opened), "img-of:a red fox") {
		t.Fatalf("opened data is not the victim's: %s", opened["data"])
	}
	if _, ok := opened["_bind"]; ok {
		t.Fatal("_bind leaked into the opened response")
	}
}

// The attack §7.5 exists for. The router reads the victim's client_eph_pub off
// the cleartext envelope and submits a request OF ITS OWN to the same genuine
// enclave, sealed to the victim's key. It cannot derive the victim's _bind, so it
// attaches one from a key of its own.
func TestAsyncImageForeignRequestWithVictimsKeyIsRefused(t *testing.T) {
	enc := newEnclave(t)
	victimEnv, victimPriv, victimPub := gatewaySubmit(t, enc, asyncRequest("victim prompt"))
	_ = enclaveComplete(t, enc, victimEnv, "job_victim")

	attackerPriv, _, err := crypto.GenerateRecipientKey()
	if err != nil {
		t.Fatal(err)
	}
	forged, err := wire.AttachAsyncBind(asyncRequest("router-chosen prompt"), attackerPriv)
	if err != nil {
		t.Fatal(err)
	}
	forgedEnv, err := wire.SealRequestFor(wire.ProfileAsyncImage, enc.encPub, forged, nil, asyncSigner, victimPub, wire.DefaultUnboundFields()...)
	if err != nil {
		t.Fatal(err)
	}
	// Same job id as the victim's, so the jobId check cannot be what saves us:
	// this isolates the binding check.
	forgedFrame := enclaveComplete(t, enc, forgedEnv, "job_victim")

	if _, err := wire.OpenAsyncImageResult(victimPriv, routerRelay(t, forgedFrame), "job_victim"); err == nil {
		t.Fatal("a result for the router's own request, sealed to the victim's key, was accepted: the content would be router-chosen")
	} else if !strings.Contains(err.Error(), "_bind") {
		t.Fatalf("refused, but not by the binding check: %v", err)
	}
}

// Without any _bind the forged request never reaches generation: the enclave
// refuses it by name before decryption.
func TestAsyncImageEnclaveRefusesARequestWithoutBind(t *testing.T) {
	enc := newEnclave(t)
	_, ephPub, err := crypto.GenerateRecipientKey()
	if err != nil {
		t.Fatal(err)
	}
	// Sealed under the synchronous image profile, which has no _bind.
	env, err := wire.SealRequestFor(wire.ProfileImage, enc.encPub, asyncRequest("p"), nil, asyncSigner, ephPub)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := wire.OpenRequestFor(wire.ProfileAsyncImage, enc.encPriv, env); err == nil {
		t.Fatal("the enclave opened an async-image request with no sealed _bind")
	}
}

// A replay of the victim's exact envelope yields a second job with the SAME
// binding value — so the binding check passes — and a new broker job id. Returned
// on the original job's poll, it is refused by the jobId check.
func TestAsyncImageReplayedResultOnTheOriginalJobIsRefused(t *testing.T) {
	enc := newEnclave(t)
	env, ephPriv, _ := gatewaySubmit(t, enc, asyncRequest("victim prompt"))
	_ = enclaveComplete(t, enc, env, "job_original")
	replay := enclaveComplete(t, enc, env, "job_replay")

	if _, err := wire.OpenAsyncImageResult(ephPriv, routerRelay(t, replay), "job_original"); err == nil {
		t.Fatal("a replay's result was accepted on the original job's poll")
	}
	// The same frame IS valid for the job it belongs to: this is the accepted
	// residual (the router answering the submit with the replay's 202), and its
	// content is still the victim's own prompt.
	opened, err := wire.OpenAsyncImageResult(ephPriv, routerRelay(t, replay), "job_replay")
	if err != nil {
		t.Fatalf("the replay is a genuine result for its own job id: %v", err)
	}
	if !strings.Contains(dataOf(t, opened), "img-of:victim prompt") {
		t.Fatal("replay content is not the victim's own prompt")
	}
}

// Two jobs of one user: each is sealed to its own fresh eph key, so job B's frame
// does not open under job A's key, even polled under B's id.
func TestAsyncImageAnotherJobOfTheSameUserDoesNotOpen(t *testing.T) {
	enc := newEnclave(t)
	envA, privA, _ := gatewaySubmit(t, enc, asyncRequest("job a"))
	envB, _, _ := gatewaySubmit(t, enc, asyncRequest("job b"))
	_ = enclaveComplete(t, enc, envA, "job_a")
	frameB := enclaveComplete(t, enc, envB, "job_b")

	if _, err := wire.OpenAsyncImageResult(privA, routerRelay(t, frameB), "job_a"); err == nil {
		t.Fatal("job b's frame was accepted on job a's poll")
	}
	if _, err := wire.OpenAsyncImageResult(privA, routerRelay(t, frameB), "job_b"); err == nil {
		t.Fatal("job b's frame opened under job a's key")
	}
}

// Every bound cleartext field the router could edit: each edit is refused.
func TestAsyncImageCleartextEditsAreRefused(t *testing.T) {
	enc := newEnclave(t)
	env, ephPriv, _ := gatewaySubmit(t, enc, asyncRequest("p"))
	frame := enclaveComplete(t, enc, env, "job_1")

	edits := map[string]func(wire.Response){
		"usage.output_images": func(f wire.Response) { f["usage"] = json.RawMessage(`{"output_images":9}`) },
		"jobId":               func(f wire.Response) { f["jobId"] = json.RawMessage(`"job_2"`) },
		"status":              func(f wire.Response) { f["status"] = json.RawMessage(`"processing"`) },
		"createdAt":           func(f wire.Response) { f["createdAt"] = json.RawMessage(`"1999-01-01T00:00:00Z"`) },
		"added bound field":   func(f wire.Response) { f["errorMessage"] = json.RawMessage(`"x"`) },
		"removed usage":       func(f wire.Response) { delete(f, "usage") },
	}
	for name, edit := range edits {
		t.Run(name, func(t *testing.T) {
			f := routerRelay(t, frame)
			edit(f)
			if _, err := wire.OpenAsyncImageResult(ephPriv, f, "job_1"); err == nil {
				t.Fatal("edit accepted")
			}
		})
	}
	// `model` is unbound, as on every sealed response: a rewrite still opens.
	f := routerRelay(t, frame)
	f["model"] = json.RawMessage(`"alias"`)
	if _, err := wire.OpenAsyncImageResult(ephPriv, f, "job_1"); err != nil {
		t.Fatalf("an unbound model rewrite was refused: %v", err)
	}
}

// A non-conforming enclave that unbinds `jobId` would let a router relabel a
// frame; the receiver refuses any unbound field outside the profile's own set.
func TestAsyncImageFrameUnbindingJobIDIsRefused(t *testing.T) {
	ephPriv, ephPub, err := crypto.GenerateRecipientKey()
	if err != nil {
		t.Fatal(err)
	}
	bind, _ := wire.DeriveAsyncBind(ephPriv)
	bindJSON, _ := json.Marshal(b64urlEncode(bind))
	frame := wire.Response{
		"jobId":  json.RawMessage(`"job_1"`),
		"status": json.RawMessage(`"completed"`),
		"usage":  json.RawMessage(`{"output_images":1}`),
		"data":   json.RawMessage(`{"data":[{"b64_json":"x"}]}`),
		"_bind":  bindJSON,
	}
	sealed, err := wire.SealResponseFor(wire.ProfileAsyncImage, ephPub, frame, nil, "jobId", "x_0g_trace")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := wire.OpenAsyncImageResult(ephPriv, sealed, "job_1"); err == nil {
		t.Fatal("a frame with jobId unbound was accepted")
	}
}

// A result sealed without `_bind` — e.g. by an enclave serving it as a plain
// image response — is refused by the profile check before anything opens.
func TestAsyncImageFrameWithoutSealedBindIsRefused(t *testing.T) {
	ephPriv, ephPub, err := crypto.GenerateRecipientKey()
	if err != nil {
		t.Fatal(err)
	}
	frame := wire.Response{
		"jobId":  json.RawMessage(`"job_1"`),
		"status": json.RawMessage(`"completed"`),
		"usage":  json.RawMessage(`{"output_images":1}`),
		"data":   json.RawMessage(`{"data":[{"b64_json":"x"}]}`),
	}
	sealed, err := wire.SealResponseFor(wire.ProfileImage, ephPub, frame, nil, wire.AsyncImageResultUnboundFields()...)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := wire.OpenAsyncImageResult(ephPriv, sealed, "job_1"); err == nil {
		t.Fatal("a result frame with no sealed _bind was accepted")
	}
}

// The enclave's sealer refuses what the receiver keys off: a missing job id, a
// non-terminal status, a missing billable count.
func TestSealAsyncImageResultRefusesNonTerminalOrUnnamedFrames(t *testing.T) {
	ephPriv, ephPub, err := crypto.GenerateRecipientKey()
	if err != nil {
		t.Fatal(err)
	}
	bind, _ := wire.DeriveAsyncBind(ephPriv)
	base := func() wire.Response {
		return wire.Response{
			"jobId":  json.RawMessage(`"job_1"`),
			"status": json.RawMessage(`"completed"`),
			"usage":  json.RawMessage(`{"output_images":1}`),
			"data":   json.RawMessage(`{"data":[]}`),
		}
	}
	for name, edit := range map[string]func(wire.Response){
		"no jobId":      func(f wire.Response) { delete(f, "jobId") },
		"empty jobId":   func(f wire.Response) { f["jobId"] = json.RawMessage(`""`) },
		"processing":    func(f wire.Response) { f["status"] = json.RawMessage(`"processing"`) },
		"failed":        func(f wire.Response) { f["status"] = json.RawMessage(`"failed"`) },
		"no usage":      func(f wire.Response) { delete(f, "usage") },
		"preset _bind":  func(f wire.Response) { f["_bind"] = json.RawMessage(`"x"`) },
		"numeric jobId": func(f wire.Response) { f["jobId"] = json.RawMessage(`7`) },
	} {
		t.Run(name, func(t *testing.T) {
			f := base()
			edit(f)
			if _, err := wire.SealAsyncImageResult(ephPub, f, bind); err == nil {
				t.Fatal("sealed")
			}
		})
	}
	if _, err := wire.SealAsyncImageResult(ephPub, base(), bind[:31]); err == nil {
		t.Fatal("a 31-byte binding value was sealed")
	}
}

func b64url(s string) ([]byte, error) { return b64.DecodeString(s) }

func b64urlEncode(b []byte) string { return b64.EncodeToString(b) }
