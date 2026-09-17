package integration

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/0gfoundation/0g-pc-e2ee/protocol/crypto"
	"github.com/0gfoundation/0g-pc-e2ee/protocol/proof"
	"github.com/0gfoundation/0g-pc-e2ee/protocol/wire"
)

// The full embedding path, end to end through the profile-aware API: a client
// seals a batch of corpus text to the enclave, a router in the middle routes and
// bills on the cleartext half without being able to read the text or the vectors,
// the enclave opens the batch and seals the vectors back, and the client recovers
// them.
//
// Written against the `For` variants throughout, unlike the chat round trips in
// this package, which use the profile-less ones. That is the whole point of the
// test: the profile-less path cannot tell an embedding request from anything else
// and so exercises none of the rules that make this profile a profile.
func TestEmbeddingRoundTrip(t *testing.T) {
	encPriv, encPub, err := crypto.GenerateRecipientKey()
	if err != nil {
		t.Fatalf("enclave keygen: %v", err)
	}
	// No mockBroker here, unlike the chat round trips: its openRequest helper
	// calls the profile-LESS wire.OpenRequest, which is exactly the path this
	// test exists not to take. The enclave's two steps are inlined below against
	// the `For` variants instead.

	ephPriv, ephPub, err := crypto.GenerateRecipientKey()
	if err != nil {
		t.Fatalf("client eph keygen: %v", err)
	}

	const corpus0 = "patient chart 4471: presenting complaint"
	const corpus1 = "internal roadmap Q3: acquisition targets"
	req := wire.Request{
		"model":           json.RawMessage(`"qwen3.7-text-embedding"`),
		"encoding_format": json.RawMessage(`"base64"`),
		"dimensions":      json.RawMessage(`256`),
		"input":           json.RawMessage(`["` + corpus0 + `","` + corpus1 + `"]`),
	}

	// --- client: seal the request (nil = this profile's default set) ---
	env, err := wire.SealRequestFor(wire.ProfileEmbedding, encPub, req, nil, brokerSigner, ephPub)
	if err != nil {
		t.Fatalf("SealRequestFor: %v", err)
	}

	// --- router in the middle ---
	if _, ok := env["input"]; ok {
		t.Fatal("router can see input — the corpus leaked")
	}
	// It routes on `model` and, because this profile pins nothing, it also still
	// sees the two knobs a provider has to satisfy. That is the trade this profile
	// makes: both are metadata about the request, neither is its content.
	for f, want := range map[string]string{
		"model":           `"qwen3.7-text-embedding"`,
		"encoding_format": `"base64"`,
		"dimensions":      `256`,
	} {
		if got := string(env[f]); got != want {
			t.Errorf("router cannot read %s for routing: got %s, want %s", f, got, want)
		}
	}
	wireBytes, _ := json.Marshal(env)
	for _, secret := range []string{corpus0, corpus1} {
		if bytes.Contains(wireBytes, []byte(secret)) {
			t.Fatalf("%q leaked into the transmitted request", secret)
		}
	}

	// --- enclave: open, "embed", seal the vectors back ---
	e2ee, err := env.E2EE()
	if err != nil {
		t.Fatalf("read _e2ee: %v", err)
	}
	if e2ee.SignerAddr != brokerSigner {
		t.Fatalf("signer_addr %q is not this broker %q", e2ee.SignerAddr, brokerSigner)
	}
	opened, err := wire.OpenRequestFor(wire.ProfileEmbedding, encPriv, env)
	if err != nil {
		t.Fatalf("enclave OpenRequestFor: %v", err)
	}
	var input []string
	if err := json.Unmarshal(opened["input"], &input); err != nil {
		t.Fatalf("enclave could not decode input: %v", err)
	}
	if len(input) != 2 || input[0] != corpus0 || input[1] != corpus1 {
		t.Fatalf("enclave did not recover the batch: %v", input)
	}
	// The reconstructed request must also carry the cleartext half back, since the
	// enclave forwards it upstream: `cleartext ∪ decrypted` (§6).
	if got := string(opened["encoding_format"]); got != `"base64"` {
		t.Errorf("reconstructed request lost encoding_format: %s", got)
	}

	clientEphPub, err := b64.DecodeString(e2ee.ClientEphPub)
	if err != nil {
		t.Fatalf("bad client_eph_pub: %v", err)
	}
	resp := wire.Response{
		"object": json.RawMessage(`"list"`),
		"model":  json.RawMessage(`"qwen3.7-text-embedding"`),
		"usage":  json.RawMessage(`{"prompt_tokens":14,"total_tokens":14}`),
		"data": json.RawMessage(`[
			{"object":"embedding","index":0,"embedding":[0.0231,-0.0917]},
			{"object":"embedding","index":1,"embedding":[0.1104,0.2280]}
		]`),
	}
	sealedResp, err := wire.SealResponseFor(wire.ProfileEmbedding, clientEphPub, resp, nil)
	if err != nil {
		t.Fatalf("SealResponseFor: %v", err)
	}

	// --- router on the return path: bills on usage, cannot read the vectors ---
	if _, ok := sealedResp["data"]; ok {
		t.Fatal("router can see data — the vectors leaked")
	}
	var billing struct {
		Usage struct {
			PromptTokens int `json:"prompt_tokens"`
		} `json:"usage"`
	}
	respBytes, _ := json.Marshal(sealedResp)
	if err := json.Unmarshal(respBytes, &billing); err != nil {
		t.Fatalf("router could not parse the frame it bills on: %v", err)
	}
	if billing.Usage.PromptTokens != 14 {
		t.Fatalf("router bills on prompt_tokens and read %d, want 14",
			billing.Usage.PromptTokens)
	}
	if bytes.Contains(respBytes, []byte("0.0231")) {
		t.Fatal("a vector coordinate leaked into the sealed response")
	}

	// --- client: open the response ---
	got, err := wire.OpenResponseFor(wire.ProfileEmbedding, ephPriv, sealedResp)
	if err != nil {
		t.Fatalf("OpenResponseFor: %v", err)
	}
	var data []struct {
		Index     int       `json:"index"`
		Embedding []float64 `json:"embedding"`
	}
	if err := json.Unmarshal(got["data"], &data); err != nil {
		t.Fatalf("client could not decode data: %v", err)
	}
	if len(data) != 2 || data[1].Index != 1 || len(data[1].Embedding) != 2 {
		t.Fatalf("client did not recover the vectors: %v", data)
	}

	// --- §8: the signature binds this exchange, with no profile-specific arm ---
	// Asserted here because it is the claim a reader is most likely to doubt for a
	// new profile: the binding hashes envelopes, not payloads, so the non-stream
	// scheme covers embedding the day the profile exists, with nothing added to
	// protocol/proof. A profile that needed its own signature arm would fail here.
	text, err := proof.SignedTextE2EE(env, sealedResp)
	if err != nil {
		t.Fatalf("SignedTextE2EE: %v", err)
	}
	if !strings.HasPrefix(text, proof.SchemeE2EECiphertext+":") {
		t.Fatalf("signed text = %q, want the non-stream e2ee scheme", text)
	}
}

// An embedding response is NOT frame-typed, and a receiver reads that off the
// profile to decide how to frame the stream it serves: a frame-typed profile
// announces every event by name and ends with a terminal frame of its own, so
// `[DONE]` must not be appended, while a single-shape one is the opposite on both
// counts.
//
// Asserted because the wrong answer here is silent in the direction a new profile
// is likely to get it: `/v1/embeddings` does not stream at all, so nothing in a
// round trip would notice a profile that had been copied from the Anthropic row
// and claimed an event taxonomy it has no frames for.
//
// The finality of the single frame is NOT re-asserted here — OpenResponseFor
// requires it for every profile and TestNonStreamingOpenRequiresTheFinalFrame
// covers both spellings of getting it wrong.
func TestEmbeddingResponsesAreNotFrameTyped(t *testing.T) {
	if wire.ResponseFramesAreTyped(wire.ProfileEmbedding) {
		t.Error("the embedding profile must not be frame-typed: it has no event taxonomy, " +
			"and a receiver that believes it does will withhold the [DONE] sentinel")
	}
	if got := wire.DefaultResponseSealedFieldsFor(wire.ProfileEmbedding); len(got) != 1 || got[0] != "data" {
		t.Errorf("a single-shape profile must have a constant response default; got %v", got)
	}
}
