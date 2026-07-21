package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/0gfoundation/0g-pc/client/core"
	"github.com/0gfoundation/0g-pc/protocol/crypto"
	"github.com/0gfoundation/0g-pc/protocol/wire"
)

// mockBroker is a minimal provider enclave: it opens the sealed request and
// seals a canned response back to the client's ephemeral key. It exists only to
// smoke-test that the gateway mounts the shared proxy route; the full proxy
// behavior is covered in the openaiproxy package.
func mockBroker(t *testing.T, encPriv crypto.PrivateKey) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var env wire.Request
		if err := json.Unmarshal(body, &env); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if _, leaked := env["messages"]; leaked {
			t.Error("prompt reached the broker in cleartext")
			http.Error(w, "prompt not sealed", http.StatusBadRequest)
			return
		}
		e2ee, _ := env.E2EE()
		if _, err := wire.OpenRequest(encPriv, env); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		ephPub, _ := base64.RawURLEncoding.DecodeString(e2ee.ClientEphPub)
		resp := wire.Response{
			"id":      json.RawMessage(`"chatcmpl-mock"`),
			"choices": json.RawMessage(`[{"index":0,"message":{"role":"assistant","content":"mock answer"},"finish_reason":"stop"}]`),
		}
		sealed, _ := wire.SealResponse(crypto.PublicKey(ephPub), resp, nil)
		_ = json.NewEncoder(w).Encode(sealed)
	}))
}

func TestGatewayHealthz(t *testing.T) {
	_, encPub, _ := crypto.GenerateRecipientKey()
	client := core.New(core.Provider{URL: "http://unused", EncPubKey: encPub, SignerAddr: "0x" + strings.Repeat("a", 40)})
	gw := httptest.NewServer(newHandler(client))
	defer gw.Close()

	resp, err := http.Get(gw.URL + "/healthz")
	if err != nil {
		t.Fatalf("get /healthz: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("/healthz: got %d, want 200", resp.StatusCode)
	}
}

// /quote is a stub in the pin-only phase: it must answer 501 (Not Implemented),
// not 404, so a validator can tell the endpoint exists but attestation is not
// wired yet.
func TestGatewayQuoteStub(t *testing.T) {
	_, encPub, _ := crypto.GenerateRecipientKey()
	client := core.New(core.Provider{URL: "http://unused", EncPubKey: encPub, SignerAddr: "0x" + strings.Repeat("a", 40)})
	gw := httptest.NewServer(newHandler(client))
	defer gw.Close()

	resp, err := http.Get(gw.URL + "/quote")
	if err != nil {
		t.Fatalf("get /quote: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotImplemented {
		t.Fatalf("/quote: got %d, want 501", resp.StatusCode)
	}
}

// The gateway mounts the shared OpenAI proxy: a plain request seals to the
// pinned provider and returns opened plaintext, confirming the wiring. Exhaustive
// proxy behavior is tested in the openaiproxy package, not here.
func TestGatewayProxiesChatCompletions(t *testing.T) {
	encPriv, encPub, _ := crypto.GenerateRecipientKey()
	signer := "0x" + strings.Repeat("a", 40)
	broker := mockBroker(t, encPriv)
	defer broker.Close()

	client := core.New(core.Provider{URL: broker.URL, EncPubKey: encPub, SignerAddr: signer})
	gw := httptest.NewServer(newHandler(client))
	defer gw.Close()

	userReq := `{"model":"gpt-4o","messages":[{"role":"user","content":"hi"}]}`
	resp, err := http.Post(gw.URL+"/v1/chat/completions", "application/json", strings.NewReader(userReq))
	if err != nil {
		t.Fatalf("post to gateway: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("got %d: %s", resp.StatusCode, body)
	}
	if !bytes.Contains(body, []byte("mock answer")) {
		t.Fatalf("user did not get plaintext choices back: %s", body)
	}
}
