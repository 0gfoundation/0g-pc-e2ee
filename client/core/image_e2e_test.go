package core_test

// End-to-end for the image profile: the client seals a request under it, a
// provider that holds the real enc key OPENS it under the same profile, seals an
// image response back, and the client opens that.
//
// The request half is what makes this worth writing separately from the chat
// e2e above, whose fixture discards the enc private key and so only ever
// exercises the response direction. Here the provider runs
// wire.OpenRequestFor(ProfileImage, …) — the same call the broker makes — so a
// client that seals the wrong field, or drops the pinned response_format, fails
// here rather than passing silently.

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/0gfoundation/0g-pc-e2ee/client/core"
	"github.com/0gfoundation/0g-pc-e2ee/protocol/crypto"
	"github.com/0gfoundation/0g-pc-e2ee/protocol/wire"
)

// imageProvider is a provider enclave for the image profile: it opens what it is
// sent and seals what it returns, both under ProfileImage.
type imageProvider struct {
	encPriv crypto.PrivateKey
	// lastOpened records the reconstructed plaintext request, so a test can
	// assert the prompt actually travelled sealed and came back intact.
	lastOpened wire.Request
	openErr    string
}

func (p *imageProvider) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/images/generations", func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var env wire.Request
		if err := json.Unmarshal(body, &env); err != nil {
			http.Error(w, "not a JSON object", http.StatusBadRequest)
			return
		}
		// The load-bearing call: every image-profile receive-side rule at once —
		// the sealed set covers `prompt`, and `response_format` is present,
		// b64_json, cleartext and bound.
		opened, err := wire.OpenRequestFor(wire.ProfileImage, p.encPriv, env)
		if err != nil {
			p.openErr = err.Error()
			http.Error(w, "open: "+err.Error(), http.StatusBadRequest)
			return
		}
		p.lastOpened = opened

		meta, err := env.E2EE()
		if err != nil {
			http.Error(w, "no _e2ee", http.StatusBadRequest)
			return
		}
		ephPub, err := base64.RawURLEncoding.DecodeString(meta.ClientEphPub)
		if err != nil {
			http.Error(w, "bad eph pub", http.StatusBadRequest)
			return
		}
		sealed, err := wire.SealResponseFor(wire.ProfileImage, crypto.PublicKey(ephPub), wire.Response{
			"created": json.RawMessage(`1700000000`),
			"model":   json.RawMessage(`"z-image"`),
			"usage":   json.RawMessage(`{"output_images":1}`),
			"data":    json.RawMessage(`[{"b64_json":"aW1hZ2VieXRlcw=="}]`),
		}, nil)
		if err != nil {
			http.Error(w, "seal: "+err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(sealed)
	})
	return mux
}

func newImageClient(t *testing.T, srv *httptest.Server, encPub crypto.PublicKey) *core.Client {
	t.Helper()
	return core.New(core.Provider{
		URL:        srv.URL + "/v1/images/generations",
		Endpoint:   srv.URL,
		EncPubKey:  encPub,
		SignerAddr: "0x000000000000000000000000000000000000dEaD",
	}, core.WithServiceType(core.ServiceTypeTextToImage))
}

func imageReq() wire.Request {
	return wire.Request{
		"model":           json.RawMessage(`"z-image"`),
		"prompt":          json.RawMessage(`"a secret prompt"`),
		"n":               json.RawMessage(`1`),
		"response_format": json.RawMessage(`"b64_json"`),
	}
}

func TestE2E_Image_SealsPromptAndOpensImages(t *testing.T) {
	encPriv, encPub, err := crypto.GenerateRecipientKey()
	if err != nil {
		t.Fatalf("enc key: %v", err)
	}
	prov := &imageProvider{encPriv: encPriv}
	srv := httptest.NewServer(prov.handler())
	defer srv.Close()

	out, err := newImageClient(t, srv, encPub).Complete(context.Background(), imageReq())
	if err != nil {
		t.Fatalf("Complete: %v (provider open error: %s)", err, prov.openErr)
	}

	// The images came back opened.
	if !strings.Contains(string(out["data"]), "aW1hZ2VieXRlcw==") {
		t.Errorf("images not opened: %s", out["data"])
	}
	// The billable count stayed cleartext, which is what the router reads.
	if got := string(out["usage"]); !strings.Contains(got, `"output_images":1`) {
		t.Errorf("usage = %s, want a cleartext output_images", got)
	}
	// And the prompt reached the provider only through the sealed channel.
	if got := string(prov.lastOpened["prompt"]); got != `"a secret prompt"` {
		t.Errorf("provider reconstructed prompt = %s", got)
	}
}

// A chat-profile client must not be able to serve the image endpoint: its
// sealed set is chat's, so the image provider's OpenRequestFor refuses the
// envelope. This is the profile binding doing its job — before core knew about
// profiles, this client is what the gateway would have used.
func TestE2E_Image_ChatProfileClientIsRefused(t *testing.T) {
	encPriv, encPub, err := crypto.GenerateRecipientKey()
	if err != nil {
		t.Fatalf("enc key: %v", err)
	}
	prov := &imageProvider{encPriv: encPriv}
	srv := httptest.NewServer(prov.handler())
	defer srv.Close()

	// No WithServiceType → the chat default, exactly as before this change.
	chatClient := core.New(core.Provider{
		URL:        srv.URL + "/v1/images/generations",
		Endpoint:   srv.URL,
		EncPubKey:  encPub,
		SignerAddr: "0x000000000000000000000000000000000000dEaD",
	})
	if _, err := chatClient.Complete(context.Background(), imageReq()); err == nil {
		t.Fatal("a chat-profile client must not be able to seal an image request the provider accepts")
	}
}
