package route

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/0gfoundation/0g-pc-e2ee/protocol/attest"
	"github.com/0gfoundation/0g-pc-e2ee/protocol/wire"
)

// TDX v4 quote offsets, restated here because attest keeps them unexported (they
// are pinned against a real dstack quote in that package's KAT). The tests need a
// structurally valid quote — not just any bytes — because the compose hash is read
// by a re-parse of the verified bytes, and a fake parser that ignores its input
// would happily hide a broken read.
const (
	pidQuoteLen      = 632
	pidMRTDOff       = 184
	pidMRConfigIDOff = 232
	pidRTMR0Off      = 376
	pidRTMR1Off      = 424
	pidRTMR2Off      = 472
	pidRTMR3Off      = 520
)

// pidComposeHashHex is the compose hash the synthetic quote's mr_config_id carries.
const pidComposeHashHex = "8779f38c1b2d4e5a6071829304a5b6c7d8e9f00112233445566778899aabbccd"

// pidQuote builds a structurally valid TDX quote prefix carrying m and mrConfigID.
// report_data is left zero: the fake parser supplies the §4.2 binding separately,
// and these bytes exist for the structural re-parse the compose hash comes from.
func pidQuote(t *testing.T, m attest.Measurement, mrConfigID []byte) []byte {
	t.Helper()
	raw := make([]byte, pidQuoteLen)
	copy(raw[pidMRTDOff:], m.MRTD[:])
	copy(raw[pidMRConfigIDOff:], mrConfigID)
	copy(raw[pidRTMR0Off:], m.RTMR0[:])
	copy(raw[pidRTMR1Off:], m.RTMR1[:])
	copy(raw[pidRTMR2Off:], m.RTMR2[:])
	copy(raw[pidRTMR3Off:], m.RTMR3[:])
	return raw
}

// pidMRConfigID returns an mr_config_id of the given dstack layout version
// carrying composeHashHex (v1 exposes the hash in the clear; v2/v3 do not, so for
// those the bytes are there but must not be read as a commitment).
func pidMRConfigID(t *testing.T, version byte, composeHashHex string) []byte {
	t.Helper()
	out := make([]byte, 48)
	out[0] = version
	copy(out[1:], mustHex(t, composeHashHex))
	return out
}

// pidServer serves the route preview (one candidate at this same server), a
// /v1/quote carrying raw, and the legacy e2ee pubkey endpoint. Quote fetches are
// counted so a test can prove the identity lookup itself fetches nothing.
func pidServer(t *testing.T, raw []byte, hits *int32) *httptest.Server {
	t.Helper()
	var srv *httptest.Server
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/routing/preview", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(previewResponse{
			Object:      "routing.preview",
			ServiceType: "chatbot",
			Providers: []previewProvider{{
				Address: testProviderAddr, CanonicalID: "canon-1", Endpoint: srv.URL, ModelID: "m",
			}},
		})
	})
	mux.HandleFunc("GET /v1/quote", func(w http.ResponseWriter, r *http.Request) {
		if hits != nil {
			atomic.AddInt32(hits, 1)
		}
		_, _ = fmt.Fprintf(w, `{"quote":%q}`, hex.EncodeToString(raw))
	})
	mux.HandleFunc("GET /v1/e2ee/pubkey", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(pubkeyResponse{
			V: wire.Version, KEMID: wire.KEMID, EncPub: b64.EncodeToString(mustHex(t, qvEncPubHex)),
			KeyID: "k1", SignerAddress: qvSignerStr,
		})
	})
	srv = httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

// pidRouter builds a Router whose verifier accepts the fake quote, with the given
// boot-chain policy, measurement mode and (optionally) an on-chain registry.
func pidRouter(t *testing.T, srvURL string, policy attest.BootChainPolicy, mode attest.MeasurementMode, reg *stubRegistry) *Router {
	t.Helper()
	v := attest.New(policy,
		attest.WithQuoteParser(qvParser(qvMeasurement(0xaa), qvReportData(t))),
		attest.WithMeasurementMode(mode))
	opts := []Option{WithQuoteVerification(v, discardLogger())}
	if reg != nil {
		opts = append(opts, WithOnChainVerification(reg, false, discardLogger()))
	}
	return New(srvURL, opts...)
}

// pidAllowAll is the policy that allowlists the fake quote's boot chain.
func pidAllowAll() attest.BootChainPolicy {
	return attest.BootChainPolicy{Allowed: []attest.BootChain{attest.BootChainOf(qvMeasurement(0xaa))}}
}

// pidResolve materializes the head candidate, i.e. runs exactly the checks a real
// request runs before sealing.
func pidResolve(t *testing.T, r *Router) {
	t.Helper()
	cands, err := r.Resolve(context.Background(), wire.Request{})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if _, err := cands.Provider(context.Background(), 0); err != nil {
		t.Fatalf("Provider: %v", err)
	}
}

// A request records what the checks actually established: the DCAP verdict, the
// on-chain comparison, the boot-chain verdict, the provider's origin, the URL the
// quote came from, and the compose hash out of the verified mr_config_id.
func TestProviderIdentity_RecordsWhatWasVerified(t *testing.T) {
	srv := pidServer(t, pidQuote(t, qvMeasurement(0xaa), pidMRConfigID(t, 1, pidComposeHashHex)), nil)
	// The on-chain signer must match the one bound into the quote's report_data, which
	// is what the grounding check compares.
	r := pidRouter(t, srv.URL, pidAllowAll(), attest.ModeEnforce, &stubRegistry{signer: qvSignerStr, ack: true})
	pidResolve(t, r)

	id, ok := r.ProviderIdentity(testProviderAddr)
	if !ok {
		t.Fatal("no record for the provider this request sealed to")
	}
	if id.Address != testProviderAddr {
		t.Errorf("Address = %q, want the preview's spelling %q", id.Address, testProviderAddr)
	}
	if id.Endpoint != srv.URL {
		t.Errorf("Endpoint = %q, want the provider origin %q", id.Endpoint, srv.URL)
	}
	if want := srv.URL + "/v1/quote?legacy=false"; id.QuoteURL != want {
		t.Errorf("QuoteURL = %q, want %q", id.QuoteURL, want)
	}
	if id.QuoteDCAP != VerdictPass {
		t.Errorf("QuoteDCAP = %q, want %q", id.QuoteDCAP, VerdictPass)
	}
	if id.OnChainSigner != VerdictPass {
		t.Errorf("OnChainSigner = %q, want %q", id.OnChainSigner, VerdictPass)
	}
	if id.Measurement != VerdictPass {
		t.Errorf("Measurement = %q, want %q", id.Measurement, VerdictPass)
	}
	if id.ComposeHash != pidComposeHashHex {
		t.Errorf("ComposeHash = %q, want %q", id.ComposeHash, pidComposeHashHex)
	}
}

// The measurement verdict is three states, not a bool: an empty audited allowlist
// (every deployment today — trust-chain hop 3) must report no_baseline, NOT the
// no_match a provider running an unaudited image gets. Collapsing them would accuse
// every provider of running unaudited code because we have audited none.
func TestProviderIdentity_MeasurementVerdictIsThreeState(t *testing.T) {
	otherChain := attest.BootChainPolicy{Allowed: []attest.BootChain{attest.BootChainOf(qvMeasurement(0xbb))}}
	cases := []struct {
		name   string
		policy attest.BootChainPolicy
		mode   attest.MeasurementMode
		want   Verdict
	}{
		{"allowlisted", pidAllowAll(), attest.ModeEnforce, VerdictPass},
		{"empty allowlist", attest.BootChainPolicy{}, attest.ModeWarn, VerdictNoBaseline},
		{"not in a populated allowlist", otherChain, attest.ModeWarn, VerdictNoMatch},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := pidServer(t, pidQuote(t, qvMeasurement(0xaa), pidMRConfigID(t, 1, pidComposeHashHex)), nil)
			r := pidRouter(t, srv.URL, tc.policy, tc.mode, nil)
			pidResolve(t, r)

			id, ok := r.ProviderIdentity(testProviderAddr)
			if !ok {
				t.Fatal("expected a record")
			}
			if id.Measurement != tc.want {
				t.Errorf("Measurement = %q, want %q", id.Measurement, tc.want)
			}
			// Whatever the boot chain said, the quote itself was genuine — the two are
			// separate verdicts and must not bleed into each other.
			if id.QuoteDCAP != VerdictPass {
				t.Errorf("QuoteDCAP = %q, want %q", id.QuoteDCAP, VerdictPass)
			}
		})
	}
}

// The on-chain verdict distinguishes "no such acknowledged signer" (a finding about
// the provider) from "the chain was unreachable" (a finding about us) from "this
// deployment does not run the check at all".
func TestProviderIdentity_OnChainVerdicts(t *testing.T) {
	cases := []struct {
		name string
		reg  *stubRegistry
		want Verdict
	}{
		{"not configured", nil, VerdictNotChecked},
		{"match", &stubRegistry{signer: qvSignerStr, ack: true}, VerdictPass},
		{"unacknowledged", &stubRegistry{signer: qvSignerStr, ack: false}, VerdictNoMatch},
		{"mismatch", &stubRegistry{signer: "0x0000000000000000000000000000000000000001", ack: true}, VerdictNoMatch},
		{"rpc down", &stubRegistry{err: errors.New("rpc down")}, VerdictUnavailable},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := pidServer(t, pidQuote(t, qvMeasurement(0xaa), pidMRConfigID(t, 1, pidComposeHashHex)), nil)
			// Warn mode on the grounding check (WithOnChainVerification enforce=false), so a
			// negative still materializes the candidate and the verdict is recorded rather
			// than lost with the skipped candidate.
			r := pidRouter(t, srv.URL, pidAllowAll(), attest.ModeEnforce, tc.reg)
			pidResolve(t, r)

			id, ok := r.ProviderIdentity(testProviderAddr)
			if !ok {
				t.Fatal("expected a record")
			}
			if id.OnChainSigner != tc.want {
				t.Errorf("OnChainSigner = %q, want %q", id.OnChainSigner, tc.want)
			}
		})
	}
}

// A candidate the on-chain check REJECTS under enforce is still recorded, with the
// verdict that rejected it. The alternative is the one way this endpoint could state
// something the gateway no longer believes: an earlier "pass" standing for the rest
// of its TTL while every request is refusing that provider.
func TestProviderIdentity_RecordedEvenWhenTheVerdictRejects(t *testing.T) {
	srv := pidServer(t, pidQuote(t, qvMeasurement(0xaa), pidMRConfigID(t, 1, pidComposeHashHex)), nil)
	v := attest.New(pidAllowAll(),
		attest.WithQuoteParser(qvParser(qvMeasurement(0xaa), qvReportData(t))))
	// enforce=true on the grounding check: the chain names someone else, so the
	// candidate is skipped and core falls back.
	r := New(srv.URL,
		WithQuoteVerification(v, discardLogger()),
		WithOnChainVerification(&stubRegistry{signer: ocOther, ack: true}, true, discardLogger()))

	cands, err := r.Resolve(context.Background(), wire.Request{})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if _, err := cands.Provider(context.Background(), 0); err == nil {
		t.Fatal("enforce mode should have skipped the candidate")
	}

	id, ok := r.ProviderIdentity(testProviderAddr)
	if !ok {
		t.Fatal("a rejected candidate left no record; the panel would keep showing the previous verdict")
	}
	if id.OnChainSigner != VerdictNoMatch {
		t.Errorf("OnChainSigner = %q, want %q", id.OnChainSigner, VerdictNoMatch)
	}
	// The quote itself was genuine — that is why there is a record at all.
	if id.QuoteDCAP != VerdictPass {
		t.Errorf("QuoteDCAP = %q, want %q", id.QuoteDCAP, VerdictPass)
	}
}

// pidRotatedComposeHashHex is the compose hash of the POST-upgrade enclave —
// different from pidComposeHashHex, because a broker upgrade rotates the signer and
// the deployment together.
const pidRotatedComposeHashHex = "1c2d3e4f50617283940a1b2c3d4e5f60718293a4b5c6d7e8f90123456789abcd"

// The rotation recovery must carry the FRESH quote's facts into the record, not just
// its keys. This is the assertion that pins it: narrow `verified = fresh` back to
// taking encPub and signer alone and the record reports the pre-rotation
// compose_hash — describing an enclave the request was NOT sealed to, which is the
// one thing this whole design exists to rule out.
func TestProviderIdentity_RotationRecoveryRecordsTheFreshQuote(t *testing.T) {
	// The LIVE quote is the upgraded enclave: new signer, new compose hash.
	srv := pidServer(t, pidQuote(t, qvMeasurement(0xaa), pidMRConfigID(t, 1, pidRotatedComposeHashHex)), nil)
	v := attest.New(pidAllowAll(),
		attest.WithQuoteParser(qvParser(qvMeasurement(0xaa), mutableReportData(t, rotatedSignerHex))))
	// The chain names the rotated signer too — the upgrade is complete everywhere except
	// in our cache. enforce=true, so a mismatch that survived the recovery would skip
	// the candidate and fail this test loudly rather than quietly recording a warning.
	r := New(srv.URL,
		WithQuoteVerification(v, discardLogger()),
		WithOnChainVerification(&stubRegistry{signer: rotatedSignerStr, ack: true}, true, discardLogger()))

	// Seed the cache as a live gateway's would be for up to the quote TTL after a
	// rollout: the PRE-upgrade signer, and the pre-upgrade compose hash with it.
	quoteURL, err := deriveQuoteURL(srv.URL)
	if err != nil {
		t.Fatalf("deriveQuoteURL: %v", err)
	}
	r.quoteCache.put(quoteURL, quoteResult{
		encPub: mustHex(t, qvEncPubHex),
		signer: qvSignerStr,
		facts:  quoteFacts{measurement: VerdictPass, composeHash: pidComposeHashHex},
	})

	pidResolve(t, r)

	id, ok := r.ProviderIdentity(testProviderAddr)
	if !ok {
		t.Fatal("expected a record")
	}
	if id.ComposeHash == pidComposeHashHex {
		t.Errorf("ComposeHash = %q — the pre-rotation quote's; the request was sealed to the enclave at %q",
			id.ComposeHash, pidRotatedComposeHashHex)
	}
	if id.ComposeHash != pidRotatedComposeHashHex {
		t.Errorf("ComposeHash = %q, want the re-verified quote's %q", id.ComposeHash, pidRotatedComposeHashHex)
	}
	// And the verdict that stood is the one after the recovery: the rotation resolved
	// cleanly, so this is a pass rather than the mismatch the cached quote produced.
	if id.OnChainSigner != VerdictPass {
		t.Errorf("OnChainSigner = %q, want %q once the rotation is recognized", id.OnChainSigner, VerdictPass)
	}
}

// The verdict a panel reads and the outcome the metrics count are the same
// conclusion, so the mapping between them is worth pinning: the two negatives
// collapse (both are "no"), a match on a stale reading is still a match, and a
// lookup that failed must NOT arrive as an accusation against the provider.
func TestOnChainVerdictOf(t *testing.T) {
	for outcome, want := range map[groundingOutcome]Verdict{
		groundingOK:              VerdictPass,
		groundingOKStale:         VerdictPass,
		groundingMismatch:        VerdictNoMatch,
		groundingNotAcknowledged: VerdictNoMatch,
		groundingLookupFailed:    VerdictUnavailable,
		// An outcome this mapping has not been taught: unknown, never a pass.
		groundingOutcome("added_later"): VerdictUnavailable,
	} {
		if got := onchainVerdictOf(outcome); got != want {
			t.Errorf("onchainVerdictOf(%s) = %q, want %q", outcome, got, want)
		}
	}
}

// mr_config_id V2/V3 commit to the compose hash inside a digest, so there is
// nothing to extract. Report no hash rather than 32 bytes lifted out of a layout
// that does not mean what V1's does.
func TestProviderIdentity_ComposeHashOnlyFromAReadableLayout(t *testing.T) {
	for _, version := range []byte{2, 3} {
		t.Run(fmt.Sprintf("v%d", version), func(t *testing.T) {
			srv := pidServer(t, pidQuote(t, qvMeasurement(0xaa), pidMRConfigID(t, version, pidComposeHashHex)), nil)
			r := pidRouter(t, srv.URL, pidAllowAll(), attest.ModeEnforce, nil)
			pidResolve(t, r)

			id, _ := r.ProviderIdentity(testProviderAddr)
			if id.ComposeHash != "" {
				t.Errorf("ComposeHash = %q, want none for a v%d mr_config_id", id.ComposeHash, version)
			}
		})
	}
}

// The facts ride in the quote cache, so a request served from a warm cache records
// the same complete record — and the identity lookup itself never fetches anything,
// which is what keeps this surface from becoming a quote proxy for arbitrary
// addresses.
func TestProviderIdentity_SurvivesACacheHitAndFetchesNothing(t *testing.T) {
	var hits int32
	srv := pidServer(t, pidQuote(t, qvMeasurement(0xaa), pidMRConfigID(t, 1, pidComposeHashHex)), &hits)
	r := pidRouter(t, srv.URL, pidAllowAll(), attest.ModeEnforce, nil)

	pidResolve(t, r)
	// Drop the record but keep the warm quote cache, so the second request's record can
	// only have come from the cached facts.
	r.identities = newIdentityStore(providerIdentityTTL, maxProviderIdentities)
	pidResolve(t, r)

	id, ok := r.ProviderIdentity(testProviderAddr)
	if !ok {
		t.Fatal("a cache-hit request recorded nothing")
	}
	if id.ComposeHash != pidComposeHashHex || id.Measurement != VerdictPass {
		t.Errorf("record from a cache hit is incomplete: %+v", id)
	}
	if got := atomic.LoadInt32(&hits); got != 1 {
		t.Fatalf("quote fetched %d times, want 1 (the second request hit the cache)", got)
	}

	// Reading the record — including for an address nobody verified — must not fetch.
	for i := 0; i < 3; i++ {
		r.ProviderIdentity(testProviderAddr)
		r.ProviderIdentity("0x0000000000000000000000000000000000000009")
	}
	if got := atomic.LoadInt32(&hits); got != 1 {
		t.Errorf("quote fetched %d times after lookups, want 1: the lookup must never fetch a quote", got)
	}
}

// An address this gateway never verified has no record, and a known one is found
// whichever way its hex is cased (EIP-55 from one source, lowercase from another).
func TestProviderIdentity_LookupMisses(t *testing.T) {
	srv := pidServer(t, pidQuote(t, qvMeasurement(0xaa), pidMRConfigID(t, 1, pidComposeHashHex)), nil)
	r := pidRouter(t, srv.URL, pidAllowAll(), attest.ModeEnforce, nil)
	pidResolve(t, r)

	for _, spelling := range []string{
		testProviderAddr,
		strings.ToLower(testProviderAddr),
		strings.ToUpper(testProviderAddr),
		" " + testProviderAddr + " ",
	} {
		if _, ok := r.ProviderIdentity(spelling); !ok {
			t.Errorf("no record for %q; lookup must be case- and space-insensitive", spelling)
		}
	}
	for _, unknown := range []string{"", "0x0000000000000000000000000000000000000009", "not-an-address"} {
		if _, ok := r.ProviderIdentity(unknown); ok {
			t.Errorf("%q returned a record; only providers this process verified have one", unknown)
		}
	}
}

// With quote verification off nothing was verified, so there is no verdict to
// report and no record is kept. Reporting the router's word for a provider's
// identity would be worse than reporting nothing — it is the party the design does
// not trust to state it.
func TestProviderIdentity_NoRecordWithoutQuoteVerification(t *testing.T) {
	srv := pidServer(t, pidQuote(t, qvMeasurement(0xaa), pidMRConfigID(t, 1, pidComposeHashHex)), nil)
	r := New(srv.URL) // legacy pubkey path
	pidResolve(t, r)

	if _, ok := r.ProviderIdentity(testProviderAddr); ok {
		t.Error("a record exists without quote verification; nothing was verified to report")
	}
}

// --- the store ---

func pidRecord(addr string) ProviderIdentity {
	return ProviderIdentity{Address: addr, QuoteDCAP: VerdictPass, Measurement: VerdictNoBaseline}
}

// A verdict attests a point in time, so a record stops being reported once it
// expires rather than standing in for a verification no longer in force.
func TestIdentityStore_Expires(t *testing.T) {
	s := newIdentityStore(20*time.Millisecond, maxProviderIdentities)
	s.put(pidRecord(testProviderAddr))
	if _, ok := s.get(testProviderAddr); !ok {
		t.Fatal("a fresh record should be readable")
	}
	time.Sleep(40 * time.Millisecond)
	if _, ok := s.get(testProviderAddr); ok {
		t.Error("an expired record is still reported")
	}
	if len(s.m) != 0 {
		t.Errorf("expired record left behind: %d entries", len(s.m))
	}
}

// The address comes from the untrusted router, so the store must be bounded: a
// router inventing a new address per candidate turns into a fixed cost, not
// unbounded growth. The most recently used providers — the ones a panel asks about
// — are the ones kept.
func TestIdentityStore_IsBounded(t *testing.T) {
	const max = 8
	s := newIdentityStore(time.Minute, max)
	for i := 0; i < max*4; i++ {
		s.put(pidRecord(fmt.Sprintf("0x%040x", i)))
	}
	if len(s.m) > max {
		t.Errorf("store holds %d entries, want at most %d", len(s.m), max)
	}
	newest := fmt.Sprintf("0x%040x", max*4-1)
	if _, ok := s.get(newest); !ok {
		t.Errorf("the most recent record (%s) was evicted", newest)
	}
}

// A record with no address could never be looked up (direct-broker mode pins none),
// so it must not be stored and must not consume the cap.
func TestIdentityStore_IgnoresAddresslessRecords(t *testing.T) {
	s := newIdentityStore(time.Minute, maxProviderIdentities)
	s.put(pidRecord(""))
	s.put(pidRecord("   "))
	if len(s.m) != 0 {
		t.Errorf("stored %d addressless records, want 0", len(s.m))
	}
}
