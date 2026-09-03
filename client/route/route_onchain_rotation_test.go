package route

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/0gfoundation/0g-pc-e2ee/client/chain"
	"github.com/0gfoundation/0g-pc-e2ee/client/endpoint"
	"github.com/0gfoundation/0g-pc-e2ee/protocol/attest"
	"github.com/0gfoundation/0g-pc-e2ee/protocol/wire"
)

// The signer a rotated (upgraded) broker would report, distinct from qvSignerStr.
const (
	rotatedSignerHex = "aabbccddeeff00112233445566778899aabbccdd"
	rotatedSignerStr = "0x" + rotatedSignerHex
)

// rotatingQuoteServer serves the route preview and a /v1/quote endpoint, counting
// quote fetches so a test can assert whether a re-verification actually happened.
func rotatingQuoteServer(t *testing.T, quoteHits *int32) *httptest.Server {
	t.Helper()
	var srv *httptest.Server
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/routing/preview", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(previewResponse{
			Object:      "routing.preview",
			ServiceType: "chatbot",
			Providers: []previewProvider{{
				Address:     testProviderAddr,
				CanonicalID: "canon-1",
				Endpoint:    srv.URL,
				ModelID:     "gpt-4o@v1",
			}},
		})
	})
	mux.HandleFunc("GET /v1/quote", func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(quoteHits, 1)
		_, _ = w.Write([]byte(`{"quote":"00"}`))
	})
	srv = httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

// mutableReportData builds report_data naming the given signer, so a test can
// change what the "provider's quote" says between verifications.
func mutableReportData(t *testing.T, signerHex string) [64]byte {
	t.Helper()
	var rd [64]byte
	copy(rd[0:32], mustHex(t, qvEncPubHex))
	copy(rd[32:52], mustHex(t, signerHex))
	rd[55] = 1 // version = 1
	return rd
}

// rotatingVerifier returns a verifier whose parser reads its report_data from
// *rd, so flipping rd models a broker upgrade rotating enc_pub + signer.
func rotatingVerifier(t *testing.T, m attest.Measurement, rd *[64]byte) *attest.Verifier {
	t.Helper()
	return attest.New(
		attest.BootChainPolicy{Allowed: []attest.BootChain{attest.BootChainOf(m)}},
		attest.WithQuoteParser(func([]byte) (attest.Measurement, [64]byte, error) { return m, *rd, nil }),
	)
}

// A broker upgrade rotates the signer, so a CACHED quote can name the old enclave
// while the chain already names the new one. Rejecting on that pairing would turn
// every rollout into an outage, so the resolver must re-read the quote before
// ruling — and then find that everything agrees.
func TestProvider_MismatchAgainstCachedQuote_ReverifiesAndPasses(t *testing.T) {
	var quoteHits int32
	srv := rotatingQuoteServer(t, &quoteHits)
	m := qvMeasurement(0xaa)

	// The live quote already reports the post-upgrade signer...
	rd := mutableReportData(t, rotatedSignerHex)
	// ...and so does the chain.
	reg := &stubRegistry{signer: rotatedSignerStr, ack: true}

	r := New(srv.URL,
		WithQuoteVerification(rotatingVerifier(t, m, &rd), discardLogger()),
		WithOnChainVerification(reg, true, discardLogger()))

	// Seed the quote cache with the PRE-upgrade keys, as a live gateway's cache
	// would hold them for up to the quote TTL after a rollout.
	quoteURL, err := deriveQuoteURL(srv.URL)
	if err != nil {
		t.Fatalf("deriveQuoteURL: %v", err)
	}
	r.quoteCache.put(quoteURL, quoteResult{encPub: mustHex(t, qvEncPubHex), signer: qvSignerStr})

	cands, err := r.Resolve(context.Background(), endpoint.Chat, wire.Request{})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	prov, err := cands.Provider(context.Background(), 0)
	if err != nil {
		t.Fatalf("a rotation visible only in a stale cache entry must not reject the provider: %v", err)
	}
	if prov.SignerAddr != rotatedSignerStr {
		t.Errorf("SignerAddr = %s, want the re-verified %s", prov.SignerAddr, rotatedSignerStr)
	}
	if got := hex.EncodeToString(prov.EncPubKey); got != qvEncPubHex {
		t.Errorf("EncPubKey = %s, want the re-verified %s", got, qvEncPubHex)
	}
	if got := atomic.LoadInt32(&quoteHits); got != 1 {
		t.Errorf("quote fetches = %d, want exactly 1 (one re-verification)", got)
	}
}

// A mismatch that survives a fresh quote is a real disagreement between the chain
// and the enclave that answered: still fail-closed.
func TestProvider_MismatchSurvivesReverification(t *testing.T) {
	var quoteHits int32
	srv := rotatingQuoteServer(t, &quoteHits)
	m := qvMeasurement(0xaa)
	rd := mutableReportData(t, qvSignerHex)
	// The chain names someone else entirely, and re-reading the quote will not
	// change that.
	reg := &stubRegistry{signer: rotatedSignerStr, ack: true}

	r := New(srv.URL,
		WithQuoteVerification(rotatingVerifier(t, m, &rd), discardLogger()),
		WithOnChainVerification(reg, true, discardLogger()))

	quoteURL, err := deriveQuoteURL(srv.URL)
	if err != nil {
		t.Fatalf("deriveQuoteURL: %v", err)
	}
	r.quoteCache.put(quoteURL, quoteResult{encPub: mustHex(t, qvEncPubHex), signer: qvSignerStr})

	cands, err := r.Resolve(context.Background(), endpoint.Chat, wire.Request{})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if _, err := cands.Provider(context.Background(), 0); err == nil {
		t.Error("a mismatch confirmed against a freshly verified quote must fail-closed")
	}
}

// The re-verification is reserved for the case where the cached quote could be
// the stale side. A quote verified live moments ago is already the best evidence
// available, so a mismatch against it must not buy a second (expensive, rate-
// limit-sensitive) DCAP verification — which would also let a hostile provider
// force one per request.
func TestProvider_MismatchAgainstFreshQuote_DoesNotReverify(t *testing.T) {
	var quoteHits int32
	srv := rotatingQuoteServer(t, &quoteHits)
	m := qvMeasurement(0xaa)
	rd := mutableReportData(t, qvSignerHex)
	reg := &stubRegistry{signer: rotatedSignerStr, ack: true}

	r := New(srv.URL,
		WithQuoteVerification(rotatingVerifier(t, m, &rd), discardLogger()),
		WithOnChainVerification(reg, true, discardLogger()))

	cands, err := r.Resolve(context.Background(), endpoint.Chat, wire.Request{})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if _, err := cands.Provider(context.Background(), 0); err == nil {
		t.Error("want fail-closed on a mismatch")
	}
	if got := atomic.LoadInt32(&quoteHits); got != 1 {
		t.Errorf("quote fetches = %d, want 1 (no re-verification for an uncached quote)", got)
	}
}

// Sanity: the stub registry the rotation tests use satisfies the real interface.
var _ chain.SignerRegistry = (*stubRegistry)(nil)

// The re-verification must be rate-limited, not merely gated on "the quote was
// cached". Re-verifying REFILLS the cache entry, so the cached-quote condition is
// true again on the very next request: without a throttle, a provider that keeps
// mismatching — a stuck registration, or one arranging it — forces a live quote
// fetch plus DCAP verify on every request, which is exactly the cost the guard is
// supposed to prevent.
func TestProvider_ReverificationIsRateLimited(t *testing.T) {
	var quoteHits int32
	srv := rotatingQuoteServer(t, &quoteHits)
	m := qvMeasurement(0xaa)
	rd := mutableReportData(t, qvSignerHex)
	// The chain names someone else and keeps naming them: every request mismatches.
	reg := &stubRegistry{signer: rotatedSignerStr, ack: true}

	r := New(srv.URL,
		WithQuoteVerification(rotatingVerifier(t, m, &rd), discardLogger()),
		WithOnChainVerification(reg, true, discardLogger()))

	quoteURL, err := deriveQuoteURL(srv.URL)
	if err != nil {
		t.Fatalf("deriveQuoteURL: %v", err)
	}

	for i := 0; i < 5; i++ {
		// Seed a cached quote each round, as a live gateway's cache would hold one.
		r.quoteCache.put(quoteURL, quoteResult{encPub: mustHex(t, qvEncPubHex), signer: qvSignerStr})
		cands, err := r.Resolve(context.Background(), endpoint.Chat, wire.Request{})
		if err != nil {
			t.Fatalf("round %d: Resolve: %v", i, err)
		}
		if _, err := cands.Provider(context.Background(), 0); err == nil {
			t.Fatalf("round %d: want fail-closed on a persistent mismatch", i)
		}
	}

	// One re-verification total, not one per request.
	if got := atomic.LoadInt32(&quoteHits); got != 1 {
		t.Errorf("quote fetches = %d across 5 mismatching requests, want 1 (throttled)", got)
	}
}

// The rotation recovery has to run in WARN mode too, which the deployed gateway no
// longer uses but the library still defaults to. The verdict was never the only thing
// at stake: the stale quote carries a stale enc_pub, so without re-verifying, warn mode
// goes on sealing to an enclave that has rotated and the request fails at the provider
// — while every request also files a `mismatch`, the counter an operator reads as an
// accusation against that provider.
func TestProvider_RotationRecoveryRunsInWarnMode(t *testing.T) {
	var quoteHits int32
	srv := rotatingQuoteServer(t, &quoteHits)
	m := qvMeasurement(0xaa)
	rd := mutableReportData(t, rotatedSignerHex) // the live quote has rotated
	reg := &stubRegistry{signer: rotatedSignerStr, ack: true}

	r := New(srv.URL,
		WithQuoteVerification(rotatingVerifier(t, m, &rd), discardLogger()),
		WithOnChainVerification(reg, false, discardLogger())) // WARN

	quoteURL, err := deriveQuoteURL(srv.URL)
	if err != nil {
		t.Fatalf("deriveQuoteURL: %v", err)
	}
	r.quoteCache.put(quoteURL, quoteResult{encPub: mustHex(t, qvEncPubHex), signer: qvSignerStr}) // pre-rotation

	cands, err := r.Resolve(context.Background(), endpoint.Chat, wire.Request{})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	prov, err := cands.Provider(context.Background(), 0)
	if err != nil {
		t.Fatalf("warn mode should still materialize the provider: %v", err)
	}
	// The functional half: without the recovery this would still be the stale
	// signer, and the request would be sealed to an enc_pub the provider has
	// rotated away from.
	if prov.SignerAddr != rotatedSignerStr {
		t.Errorf("SignerAddr = %s, want the re-verified %s — warn mode skipped the recovery",
			prov.SignerAddr, rotatedSignerStr)
	}
	if got := atomic.LoadInt32(&quoteHits); got != 1 {
		t.Errorf("quote fetches = %d, want 1 (the recovery ran)", got)
	}
}
