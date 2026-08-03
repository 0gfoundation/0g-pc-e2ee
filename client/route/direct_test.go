package route

import (
	"bytes"
	"context"
	"testing"

	"github.com/0gfoundation/0g-pc-e2ee/protocol/wire"
)

// TestNewDirect_RejectsEmptyURL: direct mode needs a provider to seal to; an
// empty URL is a construction error, not a per-request one.
func TestNewDirect_RejectsEmptyURL(t *testing.T) {
	if _, err := NewDirect("   "); err == nil {
		t.Fatal("NewDirect(\"\") should error")
	}
}

// TestNewDirect_RejectsMalformedURL: a non-absolute URL fails loud up front.
func TestNewDirect_RejectsMalformedURL(t *testing.T) {
	if _, err := NewDirect("not-a-url"); err == nil {
		t.Fatal("NewDirect with a relative URL should error")
	}
}

// TestDirect_ResolveSealsStraightToBroker: the direct resolver returns a single
// candidate whose key + signer come from the broker's pubkey endpoint, whose URL
// is the provider's OWN chat endpoint (no router), whose Endpoint carries the
// provider base for the §8 signature fetch, and whose Address / Model are left
// empty (no routing pin, caller's model passes through).
func TestDirect_ResolveSealsStraightToBroker(t *testing.T) {
	broker := newMockBroker(t)

	res, err := NewDirect(broker.srv.URL)
	if err != nil {
		t.Fatalf("NewDirect: %v", err)
	}
	cands, err := res.Resolve(context.Background(), wire.Request{})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if cands.Len() != 1 {
		t.Fatalf("direct mode should yield exactly one candidate, got %d", cands.Len())
	}
	prov, err := cands.Provider(context.Background(), 0)
	if err != nil {
		t.Fatalf("Provider: %v", err)
	}

	if want := broker.srv.URL + "/v1/chat/completions"; prov.URL != want {
		t.Errorf("chat URL: got %q, want %q (direct to the broker, not a router)", prov.URL, want)
	}
	if prov.Endpoint != broker.srv.URL {
		t.Errorf("endpoint: got %q, want %q (for the §8 signature fetch)", prov.Endpoint, broker.srv.URL)
	}
	if prov.SignerAddr != testSigner {
		t.Errorf("signer: got %q, want %q", prov.SignerAddr, testSigner)
	}
	if !bytes.Equal(prov.EncPubKey, broker.encPub) {
		t.Errorf("enc key: got %x, want %x", prov.EncPubKey, broker.encPub)
	}
	if prov.Address != "" {
		t.Errorf("address: got %q, want empty (no router pin in direct mode)", prov.Address)
	}
	if prov.Model != "" {
		t.Errorf("model: got %q, want empty (caller's model passes through)", prov.Model)
	}
}

// TestDirect_PubkeyFetchFailurePropagates: a broker that fails the pubkey fetch
// surfaces as a materialization error (so a caller sees a real cause), not a
// silent success.
func TestDirect_PubkeyFetchFailurePropagates(t *testing.T) {
	broker := newMockBroker(t)
	broker.pubkeyStatus = 503

	res, err := NewDirect(broker.srv.URL)
	if err != nil {
		t.Fatalf("NewDirect: %v", err)
	}
	cands, err := res.Resolve(context.Background(), wire.Request{})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if _, err := cands.Provider(context.Background(), 0); err == nil {
		t.Fatal("Provider should error when the broker pubkey fetch fails")
	}
}
