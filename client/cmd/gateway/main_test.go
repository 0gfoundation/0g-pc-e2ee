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

	"github.com/0gfoundation/0g-pc-e2ee/client/core"
	"github.com/0gfoundation/0g-pc-e2ee/client/route"
	"github.com/0gfoundation/0g-pc-e2ee/client/tee"
	"github.com/0gfoundation/0g-pc-e2ee/protocol/crypto"
	"github.com/0gfoundation/0g-pc-e2ee/protocol/wire"
)

// routeClient builds the gateway's client the way main does: route-only, no
// pinned provider. The preview URL is unused by the operational-route tests.
func routeClient() *core.Client {
	return core.NewWithResolver(route.New("http://router.unused"))
}

// testQuoteHandler is a mock /quote handler wired the way newQuoteHandler would,
// for exercising the gateway routes without a TEE.
func testQuoteHandler() http.Handler { return tee.NewHandler(tee.Mock{}, nil) }

// newQuoteHandler must fail closed: an unset/unknown -tee never silently selects
// an attestor, and -tee=dstack refuses to run without a cert to bind (a quote
// binding nothing is worse than none).
func TestNewQuoteHandlerFailsClosed(t *testing.T) {
	if _, err := newQuoteHandler("", tee.DefaultDstackSocket, ""); err == nil {
		t.Error("unset -tee should be rejected, not defaulted")
	}
	if _, err := newQuoteHandler("bogus", tee.DefaultDstackSocket, ""); err == nil {
		t.Error("unknown -tee should be rejected")
	}
	if _, err := newQuoteHandler("dstack", tee.DefaultDstackSocket, ""); err == nil {
		t.Error("-tee=dstack without -tls-cert should be rejected")
	}
	if _, err := newQuoteHandler("mock", "", ""); err != nil {
		t.Errorf("-tee=mock should be allowed for dev: %v", err)
	}
}

func TestGatewayHealthz(t *testing.T) {
	gw := httptest.NewServer(newHandler(routeClient(), testQuoteHandler()))
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

// /quote serves the enclave attestation quote for download: 200 with the JSON
// quote body. (Verifying the quote is the downloader's job, out of scope here.)
func TestGatewayQuoteServed(t *testing.T) {
	gw := httptest.NewServer(newHandler(routeClient(), testQuoteHandler()))
	defer gw.Close()

	resp, err := http.Get(gw.URL + "/quote")
	if err != nil {
		t.Fatalf("get /quote: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("/quote: got %d, want 200", resp.StatusCode)
	}
	var q tee.Quote
	if err := json.NewDecoder(resp.Body).Decode(&q); err != nil {
		t.Fatalf("decode quote: %v", err)
	}
	if !strings.HasPrefix(q.Quote, "mock-quote:") {
		t.Fatalf("unexpected quote body %q", q.Quote)
	}
}

// In route mode the gateway holds no pinned provider: it previews against a
// router, fetches the chosen provider's key, seals, and streams plaintext back.
// This confirms the route resolver is wired into the same shared proxy, and that
// the quote service coexists with it; exhaustive route behavior lives in the
// route package.
func TestGatewayRouteMode(t *testing.T) {
	encPriv, encPub, _ := crypto.GenerateRecipientKey()
	signer := "0x" + strings.Repeat("a", 40)       // broker signer_address (envelope pin)
	providerAddr := "0x" + strings.Repeat("c", 40) // router provider address (routing pin)

	// The broker serves only the provider's e2ee pubkey (control plane).
	brokerMux := http.NewServeMux()
	brokerMux.HandleFunc("GET /v1/e2ee/pubkey", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"v":              wire.Version,
			"kem_id":         wire.KEMID,
			"enc_pub":        base64.RawURLEncoding.EncodeToString(encPub),
			"key_id":         "k",
			"signer_address": signer,
		})
	})
	broker := httptest.NewServer(brokerMux)
	defer broker.Close()

	// The router serves route-preview (pointing at the broker) and the chat data
	// plane — the sealed request goes here, and the router forwards to the pinned
	// provider (which the mock stands in for by opening the seal).
	routerMux := http.NewServeMux()
	routerMux.HandleFunc("POST /v1/routing/preview", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"object": "routing.preview",
			"type":   "chat",
			"providers": []map[string]string{{
				"address":  providerAddr,
				"endpoint": broker.URL,
				"model_id": "gpt-4o",
			}},
		})
	})
	routerMux.HandleFunc("POST /v1/chat/completions", func(w http.ResponseWriter, r *http.Request) {
		// The routing pin is the provider address, not the signer.
		if r.Header.Get("X-0G-Provider-Address") != providerAddr {
			t.Errorf("chat not pinned to provider address: %q", r.Header.Get("X-0G-Provider-Address"))
		}
		body, _ := io.ReadAll(r.Body)
		var env wire.Request
		_ = json.Unmarshal(body, &env)
		if _, leaked := env["messages"]; leaked {
			t.Error("prompt reached the router in cleartext")
		}
		e2ee, _ := env.E2EE()
		if _, err := wire.OpenRequest(encPriv, env); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		ephPub, _ := base64.RawURLEncoding.DecodeString(e2ee.ClientEphPub)
		resp := wire.Response{
			"id":      json.RawMessage(`"chatcmpl-route"`),
			"choices": json.RawMessage(`[{"index":0,"message":{"role":"assistant","content":"routed answer"},"finish_reason":"stop"}]`),
		}
		sealed, _ := wire.SealResponse(crypto.PublicKey(ephPub), resp, nil)
		_ = json.NewEncoder(w).Encode(sealed)
	})
	router := httptest.NewServer(routerMux)
	defer router.Close()

	client := core.NewWithResolver(route.New(router.URL))
	gw := httptest.NewServer(newHandler(client, testQuoteHandler()))
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
	if !bytes.Contains(body, []byte("routed answer")) {
		t.Fatalf("user did not get routed plaintext back: %s", body)
	}
}
