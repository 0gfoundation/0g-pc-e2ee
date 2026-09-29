package route

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"sync/atomic"
	"testing"

	"github.com/0gfoundation/0g-pc-e2ee/client/core"
	"github.com/0gfoundation/0g-pc-e2ee/client/endpoint"
	"github.com/0gfoundation/0g-pc-e2ee/protocol/attest"
	"github.com/0gfoundation/0g-pc-e2ee/protocol/crypto"
	"github.com/0gfoundation/0g-pc-e2ee/protocol/wire"
)

// Legacy pubkey path: a refresh re-fetches the rotated key, and a second
// refresh for the same stale key (another in-flight request) reuses it.
func TestRefreshProviderRefetchesRotatedPubkey(t *testing.T) {
	broker := newMockBroker(t)
	router := newMockRouter(t, broker)
	r := New(router.srv.URL)
	ctx := context.Background()

	cands, err := r.Resolve(ctx, endpoint.Chat, chatReq())
	if err != nil {
		t.Fatal(err)
	}
	stale, err := cands.Provider(ctx, 0)
	if err != nil {
		t.Fatal(err)
	}

	_, rotated, _ := crypto.GenerateRecipientKey()
	raw, _ := json.Marshal(pubkeyResponse{V: wire.Version, KEMID: wire.KEMID,
		EncPub: base64.RawURLEncoding.EncodeToString(rotated), KeyID: "x", SignerAddress: testSigner})
	broker.pubkeyRaw = string(raw)

	kr := cands.(core.KeyRefresher)
	for i := 0; i < 2; i++ {
		fresh, err := kr.RefreshProvider(ctx, 0, stale)
		if err != nil {
			t.Fatalf("refresh #%d: %v", i, err)
		}
		if !bytes.Equal(fresh.EncPubKey, rotated) {
			t.Fatalf("refresh #%d: got the stale key back", i)
		}
	}
	if hits := atomic.LoadInt32(&broker.pubkeyHits); hits != 2 {
		t.Fatalf("pubkey fetched %d times, want 2 (initial + one refresh)", hits)
	}
}

// Quote path: the refresh re-runs quote verification, and a forged-409 storm
// cannot turn it into a DCAP verify per request.
func TestRefreshProviderReverifiesQuoteThrottled(t *testing.T) {
	srv := qvServer(t, 0)
	m := qvMeasurement(0xaa)
	rd := qvReportData(t)
	var parses int32
	v := attest.New(attest.BootChainPolicy{Allowed: []attest.BootChain{attest.BootChainOf(m)}},
		attest.WithQuoteParser(func([]byte) (attest.Measurement, [64]byte, error) {
			atomic.AddInt32(&parses, 1)
			return m, rd, nil
		}))
	r := New(srv.URL, WithQuoteVerification(v, nil))
	ctx := context.Background()

	cands, err := r.Resolve(ctx, endpoint.Chat, wire.Request{})
	if err != nil {
		t.Fatal(err)
	}
	stale, err := cands.Provider(ctx, 0)
	if err != nil {
		t.Fatal(err)
	}
	kr := cands.(core.KeyRefresher)
	if _, err := kr.RefreshProvider(ctx, 0, stale); err != nil {
		t.Fatalf("first refresh: %v", err)
	}
	if got := atomic.LoadInt32(&parses); got != 2 {
		t.Fatalf("quote verified %d times, want 2 (initial + refresh)", got)
	}
	if _, err := kr.RefreshProvider(ctx, 0, stale); err == nil {
		t.Fatal("second refresh within the quote TTL should be throttled")
	}
	if got := atomic.LoadInt32(&parses); got != 2 {
		t.Fatalf("throttled refresh still verified: %d", got)
	}
}
