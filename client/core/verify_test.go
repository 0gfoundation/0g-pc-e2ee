package core

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"testing"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
	"golang.org/x/crypto/sha3"

	"github.com/0gfoundation/0g-pc-e2ee/client/sig"
	"github.com/0gfoundation/0g-pc-e2ee/protocol/crypto"
	"github.com/0gfoundation/0g-pc-e2ee/protocol/proof"
	"github.com/0gfoundation/0g-pc-e2ee/protocol/wire"
)

// --- in-test broker signer (decred), producing the broker's [R||S||V] layout ---

type testSigner struct {
	priv *secp256k1.PrivateKey
	addr string
}

func newTestSigner(t *testing.T) testSigner {
	t.Helper()
	priv, err := secp256k1.GeneratePrivateKey()
	if err != nil {
		t.Fatalf("gen key: %v", err)
	}
	raw := priv.PubKey().SerializeUncompressed()
	h := sha3.NewLegacyKeccak256()
	h.Write(raw[1:])
	sum := h.Sum(nil)
	return testSigner{priv: priv, addr: "0x" + hex.EncodeToString(sum[12:])}
}

// sign produces a ChatSignature over text exactly as the broker would: EIP-191
// personal_sign, [R||S||V] with V normalized to 27/28.
func (s testSigner) sign(text string) proof.ChatSignature {
	dh := sha3.NewLegacyKeccak256()
	dh.Write([]byte("\x19Ethereum Signed Message:\n" + strconv.Itoa(len(text))))
	dh.Write([]byte(text))
	digest := dh.Sum(nil)

	compact := ecdsa.SignCompact(s.priv, digest, false) // [V(27-based)||R||S]
	rsv := make([]byte, 65)
	copy(rsv[0:32], compact[1:33])
	copy(rsv[32:64], compact[33:65])
	rsv[64] = compact[0] // already 27-based
	return proof.ChatSignature{
		Text:           text,
		Signature:      "0x" + hex.EncodeToString(rsv),
		SigningAddress: s.addr,
		SigningAlgo:    "ecdsa",
	}
}

// --- fake fetcher ---

type fakeFetcher struct {
	sig     proof.ChatSignature
	err     error
	gotKey  string
	gotProv Provider
}

func (f *fakeFetcher) FetchSignature(_ context.Context, p Provider, chatKey string) (proof.ChatSignature, error) {
	f.gotKey, f.gotProv = chatKey, p
	return f.sig, f.err
}

// --- fixtures ---

func ephKeys(t *testing.T) (crypto.PrivateKey, crypto.PublicKey) {
	t.Helper()
	priv, pub, err := crypto.GenerateRecipientKey()
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	return priv, pub
}

func sealReqResp(t *testing.T) (wire.Request, wire.Response, crypto.PublicKey) {
	t.Helper()
	_, encPub := ephKeys(t)
	_, ephPub := ephKeys(t)
	req := wire.Request{"messages": json.RawMessage(`[{"role":"user","content":"hi"}]`)}
	sealedReq, err := wire.SealRequest(encPub, req, []string{"messages"},
		"0x1111111111111111111111111111111111111111", ephPub)
	if err != nil {
		t.Fatalf("SealRequest: %v", err)
	}
	resp := wire.Response{
		"model":   json.RawMessage(`"gpt-4o"`),
		"choices": json.RawMessage(`[{"index":0,"message":{"role":"assistant","content":"yo"}}]`),
	}
	sealedResp, err := wire.SealResponse(ephPub, resp, nil)
	if err != nil {
		t.Fatalf("SealResponse: %v", err)
	}
	return sealedReq, sealedResp, ephPub
}

func headerWith(chatKey string) http.Header {
	h := http.Header{}
	if chatKey != "" {
		h.Set(headerResKey, chatKey)
	}
	return h
}

// --- non-stream ---

func TestVerifyNonStream_OK(t *testing.T) {
	signer := newTestSigner(t)
	req, resp, _ := sealReqResp(t)
	text, err := proof.SignedTextE2EE(req, resp)
	if err != nil {
		t.Fatal(err)
	}
	ff := &fakeFetcher{sig: signer.sign(text)}
	c := New(Provider{SignerAddr: signer.addr}, WithResponseVerification(ff, sig.Recover))

	if vo, err := c.verifyNonStream(context.Background(), Provider{SignerAddr: signer.addr}, headerWith("ck-1"), req, resp); err != nil {
		t.Fatalf("verifyNonStream OK failed: %v (outcome %q)", err, vo)
	}
	if ff.gotKey != "ck-1" {
		t.Fatalf("fetcher got chatKey %q, want ck-1", ff.gotKey)
	}
}

func TestVerifyNonStream_WrongSigner(t *testing.T) {
	signer := newTestSigner(t)
	req, resp, _ := sealReqResp(t)
	text, _ := proof.SignedTextE2EE(req, resp)
	ff := &fakeFetcher{sig: signer.sign(text)}
	c := New(Provider{}, WithResponseVerification(ff, sig.Recover))

	// provider.SignerAddr is someone else → recovered signer must not match.
	prov := Provider{SignerAddr: "0x0000000000000000000000000000000000000009"}
	vo, err := c.verifyNonStream(context.Background(), prov, headerWith("ck-1"), req, resp)
	if err == nil || !strings.Contains(err.Error(), "!= on-chain acknowledged") {
		t.Fatalf("want signer mismatch, got %v", err)
	}
	// A proof WAS retrieved and did not verify: the integrity bucket the runbook
	// pages on, never the operational one.
	if vo != UpstreamUnverified {
		t.Errorf("outcome = %q, want %q", vo, UpstreamUnverified)
	}
}

func TestVerifyNonStream_TamperedResponse(t *testing.T) {
	signer := newTestSigner(t)
	req, resp, ephPub := sealReqResp(t)
	text, _ := proof.SignedTextE2EE(req, resp)
	ff := &fakeFetcher{sig: signer.sign(text)}
	c := New(Provider{}, WithResponseVerification(ff, sig.Recover))

	// Verify against a different sealed response than the one signed.
	other := wire.Response{"model": json.RawMessage(`"gpt-4o"`), "choices": json.RawMessage(`[{"index":0,"message":{"content":"evil"}}]`)}
	otherSealed, err := wire.SealResponse(ephPub, other, nil)
	if err != nil {
		t.Fatal(err)
	}
	vo, err := c.verifyNonStream(context.Background(), Provider{SignerAddr: signer.addr}, headerWith("ck-1"), req, otherSealed)
	if err == nil || !strings.Contains(err.Error(), "content-binding mismatch") {
		t.Fatalf("want content-binding mismatch, got %v", err)
	}
	if vo != UpstreamUnverified {
		t.Errorf("outcome = %q, want %q", vo, UpstreamUnverified)
	}
}

func TestVerifyNonStream_MissingHeader(t *testing.T) {
	signer := newTestSigner(t)
	req, resp, _ := sealReqResp(t)
	text, _ := proof.SignedTextE2EE(req, resp)
	c := New(Provider{}, WithResponseVerification(&fakeFetcher{sig: signer.sign(text)}, sig.Recover))

	vo, err := c.verifyNonStream(context.Background(), Provider{SignerAddr: signer.addr}, headerWith(""), req, resp)
	if err == nil || !strings.Contains(err.Error(), headerResKey) {
		t.Fatalf("want missing-header error, got %v", err)
	}
	// No proof could be retrieved, so nothing is proven either way — this must NOT
	// land in the bucket that accuses a provider.
	if vo != UpstreamUnverifiable {
		t.Errorf("outcome = %q, want %q", vo, UpstreamUnverifiable)
	}
}

// --- stream ---

func sealStream(t *testing.T, ephPub crypto.PublicKey, n int) []wire.Response {
	t.Helper()
	rs, err := wire.NewResponseSealer(ephPub)
	if err != nil {
		t.Fatal(err)
	}
	frames := make([]wire.Response, n)
	for i := 0; i < n; i++ {
		f := wire.Response{"model": json.RawMessage(`"gpt-4o"`), "choices": json.RawMessage(`[{"index":0,"delta":{"content":"x"}}]`)}
		sealed, err := rs.SealFrame(f, nil, i == n-1)
		if err != nil {
			t.Fatal(err)
		}
		frames[i] = sealed
	}
	return frames
}

func TestVerifyStream_OK(t *testing.T) {
	signer := newTestSigner(t)
	_, encPub := ephKeys(t)
	_, ephPub := ephKeys(t)
	req := wire.Request{"messages": json.RawMessage(`[{"role":"user","content":"hi"}]`)}
	sealedReq, err := wire.SealRequest(encPub, req, []string{"messages"}, "0x1111111111111111111111111111111111111111", ephPub)
	if err != nil {
		t.Fatal(err)
	}
	frames := sealStream(t, ephPub, 3)

	text, err := proof.SignedTextE2EEStream(sealedReq, framesAsMaps(frames))
	if err != nil {
		t.Fatal(err)
	}
	ff := &fakeFetcher{sig: signer.sign(text)}
	c := New(Provider{}, WithResponseVerification(ff, sig.Recover))

	// Fold frames exactly as streamOnce does.
	binder, err := proof.NewStreamBinder(sealedReq)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range frames {
		if err := binder.AddFrame(f); err != nil {
			t.Fatal(err)
		}
	}
	if vo, err := c.verifyStream(context.Background(), Provider{SignerAddr: signer.addr}, headerWith("ck-s"), binder); err != nil {
		t.Fatalf("verifyStream OK failed: %v (outcome %q)", err, vo)
	}
}

func framesAsMaps(frames []wire.Response) []map[string]json.RawMessage {
	out := make([]map[string]json.RawMessage, len(frames))
	for i, f := range frames {
		out[i] = f
	}
	return out
}
