package route

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"

	"github.com/0gfoundation/0g-pc-e2ee/client/core"
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
// is the broker's OWN /v1/proxy/chat/completions (its "/v1/proxy" service prefix,
// NOT the router's top-level /v1/chat/completions), whose Endpoint carries the
// provider base for the §8 signature fetch, and whose Address / Model are left
// empty (no routing pin, caller's model passes through).
func TestDirect_ResolveSealsStraightToBroker(t *testing.T) {
	broker := newMockBroker(t)

	res, err := NewDirect(broker.srv.URL)
	if err != nil {
		t.Fatalf("NewDirect: %v", err)
	}
	cands, err := res.Resolve(context.Background(), DefaultServiceType, wire.Request{})
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

	if want := broker.srv.URL + "/v1/proxy/chat/completions"; prov.URL != want {
		t.Errorf("chat URL: got %q, want %q (broker's /v1/proxy prefix, not a router)", prov.URL, want)
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

// TestDirect_RoundTripHitsBrokerProxyPath: a core client on the direct resolver
// seals a request, POSTs it straight to the broker's /v1/proxy/chat/completions
// (its "/v1/proxy" prefix — a router-style /v1/chat/completions path would 404),
// and opens the sealed answer, with the prompt never leaving cleartext and no
// router pin set. This is the guard the URL string alone can't give: it exercises
// the actual POST path end to end.
func TestDirect_RoundTripHitsBrokerProxyPath(t *testing.T) {
	broker := newMockBroker(t)

	res, err := NewDirect(broker.srv.URL)
	if err != nil {
		t.Fatalf("NewDirect: %v", err)
	}
	client := core.NewWithResolver(res)

	out, err := client.Complete(context.Background(), chatReq())
	if err != nil {
		t.Fatalf("Complete: %v", err)
	}
	if broker.chatHits != 1 {
		t.Fatalf("broker /v1/proxy/chat/completions hits: got %d, want 1 (wrong derived path?)", broker.chatHits)
	}
	if broker.lastChatPin != "" {
		t.Errorf("direct mode set a router pin X-0G-Provider-Address=%q, want none", broker.lastChatPin)
	}
	var got struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
	}
	raw, _ := json.Marshal(out)
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("decode opened response: %v", err)
	}
	if len(got.Choices) != 1 || got.Choices[0].Message.Content != "direct answer" {
		t.Errorf("opened content: got %+v, want \"direct answer\"", got.Choices)
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
	cands, err := res.Resolve(context.Background(), DefaultServiceType, wire.Request{})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if _, err := cands.Provider(context.Background(), 0); err == nil {
		t.Fatal("Provider should error when the broker pubkey fetch fails")
	}
}
