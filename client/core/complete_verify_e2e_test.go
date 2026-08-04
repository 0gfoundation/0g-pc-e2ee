package core_test

// End-to-end coverage of the response-verification hooks in completeOnce /
// streamOnce: a fake provider seals a response to the client's ephemeral key,
// stamps ZG-Res-Key, and serves a §8 signature over the sealed request/response.
// The client's Complete / CompleteStream then fetch and verify it. This exercises
// the wiring the unit tests bypass (they call verifyNonStream/verifyStream
// directly): gating, envelope threading, header read, and fail-closed behaviour.

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
	"golang.org/x/crypto/sha3"

	"github.com/0gfoundation/0g-pc-e2ee/client/core"
	"github.com/0gfoundation/0g-pc-e2ee/client/sig"
	"github.com/0gfoundation/0g-pc-e2ee/protocol/crypto"
	"github.com/0gfoundation/0g-pc-e2ee/protocol/proof"
	"github.com/0gfoundation/0g-pc-e2ee/protocol/wire"
)

// --- in-test signer (decred), broker [R||S||V] layout ----------------------

type e2eSigner struct {
	priv *secp256k1.PrivateKey
	addr string
}

func newE2ESigner(t *testing.T) e2eSigner {
	t.Helper()
	priv, err := secp256k1.GeneratePrivateKey()
	if err != nil {
		t.Fatalf("gen key: %v", err)
	}
	raw := priv.PubKey().SerializeUncompressed()
	h := sha3.NewLegacyKeccak256()
	h.Write(raw[1:])
	return e2eSigner{priv: priv, addr: "0x" + hex.EncodeToString(h.Sum(nil)[12:])}
}

func (s e2eSigner) sign(text string) proof.ChatSignature {
	dh := sha3.NewLegacyKeccak256()
	dh.Write([]byte("\x19Ethereum Signed Message:\n" + strconv.Itoa(len(text))))
	dh.Write([]byte(text))
	compact := ecdsa.SignCompact(s.priv, dh.Sum(nil), false) // [V||R||S]
	rsv := make([]byte, 65)
	copy(rsv[0:32], compact[1:33])
	copy(rsv[32:64], compact[33:65])
	rsv[64] = compact[0]
	return proof.ChatSignature{
		Text:           text,
		Signature:      "0x" + hex.EncodeToString(rsv),
		SigningAddress: s.addr,
		SigningAlgo:    "ecdsa",
	}
}

// --- inline direct-to-broker signature fetcher -----------------------------

type httpFetcher struct{ hc *http.Client }

func (f httpFetcher) FetchSignature(ctx context.Context, provider core.Provider, chatKey string) (proof.ChatSignature, error) {
	url := strings.TrimRight(provider.Endpoint, "/") + "/v1/proxy/signature/" + chatKey
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return proof.ChatSignature{}, err
	}
	resp, err := f.hc.Do(req)
	if err != nil {
		return proof.ChatSignature{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return proof.ChatSignature{}, fmt.Errorf("sig endpoint %d", resp.StatusCode)
	}
	var s proof.ChatSignature
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<16)).Decode(&s); err != nil {
		return proof.ChatSignature{}, err
	}
	return s, nil
}

// --- fake provider server --------------------------------------------------

type fakeProvider struct {
	signer e2eSigner
	mu     sync.Mutex
	n      int
	sigs   map[string]proof.ChatSignature
}

func newFakeProvider(s e2eSigner) *fakeProvider {
	return &fakeProvider{signer: s, sigs: map[string]proof.ChatSignature{}}
}

func (p *fakeProvider) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/proxy/signature/", func(w http.ResponseWriter, r *http.Request) {
		key := strings.TrimPrefix(r.URL.Path, "/v1/proxy/signature/")
		p.mu.Lock()
		s, ok := p.sigs[key]
		p.mu.Unlock()
		if !ok {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		_ = json.NewEncoder(w).Encode(s)
	})
	mux.HandleFunc("/", p.complete)
	return mux
}

// clientEphPub pulls the cleartext response ephemeral key out of the sealed request.
func clientEphPub(reqEnv map[string]json.RawMessage) (crypto.PublicKey, error) {
	var e struct {
		ClientEphPub string `json:"client_eph_pub"`
	}
	if err := json.Unmarshal(reqEnv["_e2ee"], &e); err != nil {
		return nil, fmt.Errorf("decode _e2ee: %w", err)
	}
	raw, err := base64.RawURLEncoding.DecodeString(e.ClientEphPub)
	if err != nil {
		return nil, fmt.Errorf("decode client_eph_pub: %w", err)
	}
	return crypto.PublicKey(raw), nil
}

func (p *fakeProvider) complete(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	var reqEnv map[string]json.RawMessage
	if err := json.Unmarshal(body, &reqEnv); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	stream := strings.Contains(string(reqEnv["stream"]), "true")

	// Seal a response to the client's ephemeral key (cleartext in the request).
	ephPub, err := clientEphPub(reqEnv)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	p.mu.Lock()
	p.n++
	chatKey := "ck-" + strconv.Itoa(p.n)
	p.mu.Unlock()

	if stream {
		p.streamResponse(w, reqEnv, ephPub, chatKey)
		return
	}
	p.bufferedResponse(w, reqEnv, ephPub, chatKey)
}

func (p *fakeProvider) bufferedResponse(w http.ResponseWriter, reqEnv map[string]json.RawMessage, ephPub crypto.PublicKey, chatKey string) {
	resp := wire.Response{
		"model":   json.RawMessage(`"gpt-4o"`),
		"usage":   json.RawMessage(`{"total_tokens":3}`),
		"choices": json.RawMessage(`[{"index":0,"message":{"role":"assistant","content":"pong"}}]`),
	}
	sealed, err := wire.SealResponse(ephPub, resp, nil)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	text, err := proof.SignedTextE2EE(reqEnv, sealed)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	p.store(chatKey, text)

	w.Header().Set("ZG-Res-Key", chatKey)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(sealed)
}

func (p *fakeProvider) streamResponse(w http.ResponseWriter, reqEnv map[string]json.RawMessage, ephPub crypto.PublicKey, chatKey string) {
	rs, err := wire.NewResponseSealer(ephPub)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	const n = 3
	frames := make([]map[string]json.RawMessage, n)
	for i := 0; i < n; i++ {
		frame := wire.Response{
			"model":   json.RawMessage(`"gpt-4o"`),
			"choices": json.RawMessage(`[{"index":0,"delta":{"content":"x"}}]`),
		}
		sealed, err := rs.SealFrame(frame, nil, i == n-1)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		frames[i] = sealed
	}
	text, err := proof.SignedTextE2EEStream(reqEnv, frames)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	p.store(chatKey, text)

	w.Header().Set("ZG-Res-Key", chatKey)
	w.Header().Set("Content-Type", "text/event-stream")
	w.WriteHeader(http.StatusOK)
	for _, f := range frames {
		b, _ := json.Marshal(f)
		fmt.Fprintf(w, "data: %s\n\n", b)
	}
	fmt.Fprint(w, "data: [DONE]\n\n")
}

func (p *fakeProvider) store(chatKey, text string) {
	p.mu.Lock()
	p.sigs[chatKey] = p.signer.sign(text)
	p.mu.Unlock()
}

// --- the tests -------------------------------------------------------------

func newVerifyingClient(t *testing.T, srv *httptest.Server, signerAddr string) *core.Client {
	t.Helper()
	_, encPub, err := crypto.GenerateRecipientKey()
	if err != nil {
		t.Fatalf("enc key: %v", err)
	}
	prov := core.Provider{
		URL:        srv.URL + "/v1/chat/completions",
		Endpoint:   srv.URL,
		EncPubKey:  encPub,
		SignerAddr: signerAddr,
	}
	return core.New(prov, core.WithResponseVerification(httpFetcher{hc: srv.Client()}, sig.Recover))
}

func chatReq(stream bool) wire.Request {
	r := wire.Request{
		"model":    json.RawMessage(`"gpt-4o"`),
		"messages": json.RawMessage(`[{"role":"user","content":"ping"}]`),
	}
	if stream {
		r["stream"] = json.RawMessage(`true`)
	}
	return r
}

func TestE2E_Complete_VerifiesAndOpens(t *testing.T) {
	signer := newE2ESigner(t)
	prov := newFakeProvider(signer)
	srv := httptest.NewServer(prov.handler())
	defer srv.Close()

	client := newVerifyingClient(t, srv, signer.addr)
	out, err := client.Complete(context.Background(), chatReq(false))
	if err != nil {
		t.Fatalf("Complete with verification failed: %v", err)
	}
	if !strings.Contains(string(out["choices"]), "pong") {
		t.Fatalf("response not opened: %v", out)
	}
}

func TestE2E_Complete_FailClosedOnWrongSigner(t *testing.T) {
	signer := newE2ESigner(t)
	prov := newFakeProvider(signer)
	srv := httptest.NewServer(prov.handler())
	defer srv.Close()

	// Client expects a DIFFERENT on-chain signer than the one that signed.
	client := newVerifyingClient(t, srv, "0x0000000000000000000000000000000000000009")
	_, err := client.Complete(context.Background(), chatReq(false))
	if err == nil || !strings.Contains(err.Error(), "signature") {
		t.Fatalf("want fail-closed on wrong signer, got %v", err)
	}
}

func TestE2E_CompleteStream_VerifiesAfterFinal(t *testing.T) {
	signer := newE2ESigner(t)
	prov := newFakeProvider(signer)
	srv := httptest.NewServer(prov.handler())
	defer srv.Close()

	client := newVerifyingClient(t, srv, signer.addr)
	var n int
	err := client.CompleteStream(context.Background(), chatReq(true), func(f wire.Response) error {
		n++
		return nil
	})
	if err != nil {
		t.Fatalf("CompleteStream with verification failed: %v", err)
	}
	if n != 3 {
		t.Fatalf("expected 3 opened frames, got %d", n)
	}
}

func TestE2E_CompleteStream_FailClosedOnWrongSigner(t *testing.T) {
	signer := newE2ESigner(t)
	prov := newFakeProvider(signer)
	srv := httptest.NewServer(prov.handler())
	defer srv.Close()

	client := newVerifyingClient(t, srv, "0x0000000000000000000000000000000000000009")
	err := client.CompleteStream(context.Background(), chatReq(true), func(f wire.Response) error { return nil })
	if err == nil || !strings.Contains(err.Error(), "signature") {
		t.Fatalf("want fail-closed on wrong signer, got %v", err)
	}
}
