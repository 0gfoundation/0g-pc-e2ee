package route

import (
	"context"
	"crypto/sha256"
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

	"github.com/0gfoundation/0g-pc-e2ee/client/chain"
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
	return pidServerWithAppCompose(t, raw, nil, hits)
}

// pidServerWithAppCompose is pidServer plus the app-compose the quote reply carries
// in tcb_info — the half that has to survive fetchQuote → verifyQuoteAt → the record
// for a container list to reach the wire. A nil appCompose serves the bare quote, so
// the two shapes exercise a provider that publishes tcb_info and one that does not.
func pidServerWithAppCompose(t *testing.T, raw, appCompose []byte, hits *int32) *httptest.Server {
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
	// The catalog the WARMER enumerates from, listing the same one provider the
	// preview offers. Both writers of the identity store can then be exercised against
	// one fixture, which is the point: the two paths must produce the same record, and
	// a test that gave them different servers could not tell.
	mux.HandleFunc("GET /v1/providers", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"object": "list",
			"data":   []map[string]string{{"address": testProviderAddr}},
		})
	})
	mux.HandleFunc("GET /v1/quote", func(w http.ResponseWriter, r *http.Request) {
		if hits != nil {
			atomic.AddInt32(hits, 1)
		}
		if appCompose == nil {
			_, _ = fmt.Fprintf(w, `{"quote":%q}`, hex.EncodeToString(raw))
			return
		}
		// tcb_info as a JSON string holding the document, the shape the real broker
		// serves. app_compose inside it stays a JSON string in every shape — those exact
		// bytes are the compose hash's preimage.
		tcb, err := json.Marshal(map[string]string{"app_compose": string(appCompose)})
		if err != nil {
			t.Errorf("marshal tcb_info: %v", err)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]string{
			"quote": hex.EncodeToString(raw), "tcb_info": string(tcb),
		})
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

// The wiring between the two halves this PR tests separately: fetchQuote pulling
// app_compose out of the reply, verifyQuoteAt gating it on the verified quote's
// compose_hash, and the result surviving into the record the endpoint reads.
//
// It earns its place because the failure mode is silent. Drop the assignment into
// facts, hand containersOf `raw` instead of `appCompose`, cache the facts without
// the list — every one of those yields `containers: null`, which is also what an
// honest "this provider publishes no tcb_info" looks like. No log, no error, no
// failing unit test at either end.
func TestProviderIdentity_RecordsContainersFromTheQuoteReply(t *testing.T) {
	appCompose := []byte(`{"docker_compose_file":"services:\n  broker:\n    image: ghcr.io/0gfoundation/0g-serving-broker@sha256:ec5df834\n  prometheus:\n    image: prom/prometheus:v2.45.2\n"}`)
	// The mr_config_id must commit to THIS app-compose, or the gate rejects it — which
	// is exactly the coupling being tested.
	sum := sha256.Sum256(appCompose)
	srv := pidServerWithAppCompose(t,
		pidQuote(t, qvMeasurement(0xaa), pidMRConfigID(t, 1, hex.EncodeToString(sum[:]))),
		appCompose, nil)
	r := pidRouter(t, srv.URL, pidAllowAll(), attest.ModeEnforce, &stubRegistry{signer: qvSignerStr, ack: true})
	pidResolve(t, r)

	id, ok := r.ProviderIdentity(testProviderAddr)
	if !ok {
		t.Fatal("no record for the provider this request sealed to")
	}
	if id.ComposeHash != hex.EncodeToString(sum[:]) {
		t.Fatalf("ComposeHash = %q, want the hash the quote binds %q", id.ComposeHash, hex.EncodeToString(sum[:]))
	}
	if len(id.Containers) != 2 {
		t.Fatalf("Containers = %+v, want the 2 services the authenticated compose lists", id.Containers)
	}
	if id.Containers[0].Name != "broker" || id.Containers[0].Digest != "sha256:ec5df834" {
		t.Errorf("Containers[0] = %+v, want the digest-pinned broker", id.Containers[0])
	}
	if id.Containers[1].Name != "prometheus" || id.Containers[1].Digest != "" {
		t.Errorf("Containers[1] = %+v, want prometheus with an empty digest (tag-only)", id.Containers[1])
	}
}

// The same path with a provider whose reply carries no tcb_info: everything else
// still records, and containers is absent rather than the request failing.
func TestProviderIdentity_NoAppComposeStillRecords(t *testing.T) {
	srv := pidServer(t, pidQuote(t, qvMeasurement(0xaa), pidMRConfigID(t, 1, pidComposeHashHex)), nil)
	r := pidRouter(t, srv.URL, pidAllowAll(), attest.ModeEnforce, &stubRegistry{signer: qvSignerStr, ack: true})
	pidResolve(t, r)

	id, ok := r.ProviderIdentity(testProviderAddr)
	if !ok {
		t.Fatal("no record for the provider this request sealed to")
	}
	if id.ComposeHash != pidComposeHashHex {
		t.Errorf("ComposeHash = %q, want it recorded even with no app-compose", id.ComposeHash)
	}
	if id.Containers != nil {
		t.Errorf("Containers = %+v, want nil when the reply carries no app-compose", id.Containers)
	}
}

// The warmer is the second writer, and the reason it exists as one: a panel asking
// "what would I be sealed to?" has to be answerable BEFORE the first request, which
// the request path alone can never do. A sweep must therefore leave a record as
// complete as a served request's — containers included, since those are derived from
// the quote reply and a sweep is the only place in a sweep that holds it.
func TestProviderIdentity_WarmerRecordsWithoutAnyRequest(t *testing.T) {
	appCompose := []byte(`{"docker_compose_file":"services:\n  broker:\n    image: ghcr.io/0gfoundation/0g-serving-broker@sha256:ec5df834\n"}`)
	sum := sha256.Sum256(appCompose)
	srv := pidServerWithAppCompose(t,
		pidQuote(t, qvMeasurement(0xaa), pidMRConfigID(t, 1, hex.EncodeToString(sum[:]))),
		appCompose, nil)
	r := pidRouter(t, srv.URL, pidAllowAll(), attest.ModeEnforce, &stubRegistry{signer: qvSignerStr, ack: true})

	// No Resolve, no Provider, no seal — only a sweep.
	r.WarmOnce(context.Background(), fakeResolver{url: srv.URL})

	id, ok := r.ProviderIdentity(testProviderAddr)
	if !ok {
		t.Fatal("a completed sweep left no record; the endpoint would 404 until the first request")
	}
	if id.Address != testProviderAddr {
		t.Errorf("Address = %q, want the catalog's spelling %q", id.Address, testProviderAddr)
	}
	if id.Endpoint != srv.URL {
		t.Errorf("Endpoint = %q, want the origin resolved from chain %q", id.Endpoint, srv.URL)
	}
	if id.QuoteURL == "" || !strings.HasPrefix(id.QuoteURL, srv.URL) {
		t.Errorf("QuoteURL = %q, want the URL the sweep actually verified", id.QuoteURL)
	}
	if id.QuoteDCAP != VerdictPass || id.OnChainSigner != VerdictPass || id.Measurement != VerdictPass {
		t.Errorf("verdicts = %q/%q/%q, want all pass", id.QuoteDCAP, id.OnChainSigner, id.Measurement)
	}
	if id.ComposeHash != hex.EncodeToString(sum[:]) {
		t.Errorf("ComposeHash = %q, want the hash the quote binds", id.ComposeHash)
	}
	// The whole point of the change: a panel can name the provider's containers with
	// no request having happened.
	if len(id.Containers) != 1 || id.Containers[0].Name != "broker" ||
		id.Containers[0].Digest != "sha256:ec5df834" {
		t.Errorf("Containers = %+v, want the one digest-pinned broker service", id.Containers)
	}
}

// QuoteDCAP is VerdictPass in every record that exists, and the warmer must not be
// the writer that breaks that: a provider whose quote does not verify leaves no
// record, so the endpoint 404s for it rather than reporting a failure it cannot
// describe. Without this the sweep would be the one path that records an unverified
// provider — and it sweeps EVERY provider, including the broken ones a request would
// simply have skipped.
func TestProviderIdentity_WarmerRecordsNothingWhenTheQuoteFails(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/providers", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"object": "list",
			"data":   []map[string]string{{"address": testProviderAddr}},
		})
	})
	mux.HandleFunc("GET /v1/quote", func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "boom", http.StatusServiceUnavailable)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	r := pidRouter(t, srv.URL, pidAllowAll(), attest.ModeEnforce, &stubRegistry{signer: qvSignerStr, ack: true})
	r.WarmOnce(context.Background(), fakeResolver{url: srv.URL})

	if id, ok := r.ProviderIdentity(testProviderAddr); ok {
		t.Errorf("recorded %+v for a provider whose quote never verified; QuoteDCAP would be a claim no check made", id)
	}
}

// A shutdown must not rewrite a verdict. The warmer's signer refresh reports OUR
// cancellation as a failed lookup, so without the context guard a sweep interrupted
// mid-provider would stamp "unavailable" over a `pass` it had just confirmed — the
// gateway accusing itself of being unable to check a provider it checked fine a
// moment earlier. Same reasoning as the sweep counters, applied to the record.
func TestProviderIdentity_CancelledSweepLeavesTheRecordAlone(t *testing.T) {
	srv := pidServer(t, pidQuote(t, qvMeasurement(0xaa), pidMRConfigID(t, 1, pidComposeHashHex)), nil)
	reg := &stubRegistry{signer: qvSignerStr, ack: true}
	r := pidRouter(t, srv.URL, pidAllowAll(), attest.ModeEnforce, reg)
	res := fakeResolver{url: srv.URL}

	r.WarmOnce(context.Background(), res)
	before, ok := r.ProviderIdentity(testProviderAddr)
	if !ok || before.OnChainSigner != VerdictPass {
		t.Fatalf("setup: record = %+v (found %v), want one with OnChainSigner pass", before, ok)
	}

	// Armed only now, so the priming sweep above completes normally: from here the
	// signer refresh cancels the sweep and then fails with ctx.Err(), which is what a
	// registry does when the process is going down mid-provider.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	cr := &cancellingRegistry{cancel: cancel, failWhenArmed: true}
	cr.arm()
	r.registry = cr
	r.WarmOnce(ctx, res)

	got, ok := r.ProviderIdentity(testProviderAddr)
	if !ok {
		t.Fatal("the record vanished on a cancelled sweep")
	}
	if got.OnChainSigner != VerdictPass {
		t.Errorf("OnChainSigner = %q after a cancelled sweep, want the confirmed %q left standing",
			got.OnChainSigner, VerdictPass)
	}
}

// A chain outage shorter than the cache's grace window must not make a sweep
// downgrade what a request confirmed. The two paths read the chain differently on
// purpose — a sweep forces RefreshSigner past the cache, grace window and cooldown
// because it feeds readiness; a request takes a grace-window reading as
// groundingOKStale, i.e. pass — so for the duration of the outage requests keep
// passing while the sweep's forced read fails. Same endpoint, so putWarmed has no
// conflict to defer on, and the sweep interval is under the record TTL: the sweep
// would own the steady state and the record would describe our own RPC's health
// rather than the provider's.
func TestProviderIdentity_SweepDoesNotDowngradeAPassDuringAChainOutage(t *testing.T) {
	srv := pidServer(t, pidQuote(t, qvMeasurement(0xaa), pidMRConfigID(t, 1, pidComposeHashHex)), nil)
	// The shape of an outage inside the grace window: the live re-read fails, while the
	// cached reading is stale-but-agreeing — which is what a request grounds on.
	reg := &stubRegistry{signer: qvSignerStr, ack: true, stale: true, refreshErr: errors.New("rpc down")}
	r := pidRouter(t, srv.URL, pidAllowAll(), attest.ModeEnforce, reg)

	pidResolve(t, r)
	if id, _ := r.ProviderIdentity(testProviderAddr); id.OnChainSigner != VerdictPass {
		t.Fatalf("setup: OnChainSigner = %q, want the request's pass on a stale-but-agreeing reading", id.OnChainSigner)
	}

	r.WarmOnce(context.Background(), fakeResolver{url: srv.URL})

	id, ok := r.ProviderIdentity(testProviderAddr)
	if !ok {
		t.Fatal("no record after the sweep")
	}
	if id.OnChainSigner != VerdictPass {
		t.Errorf("OnChainSigner = %q after a sweep during a chain outage, want %q — a request grounding right now still passes, so the record must not report our own RPC's failure as the provider's state",
			id.OnChainSigner, VerdictPass)
	}
}

// The fallback can only ever upgrade unavailable to pass, never accuse. A cached
// reading that DISAGREES is not a verdict in the request path either —
// groundSignerOnChain revalidates it live before ruling, and the live re-read is
// exactly what just failed — so a request meeting this state also lands on
// lookup_failed. Reporting no_match here would accuse a provider on evidence the rest
// of the package refuses to rule on.
func TestProviderIdentity_SweepFallbackNeverAccusesOnACachedReading(t *testing.T) {
	for _, tc := range []struct {
		name string
		reg  *stubRegistry
		want Verdict
	}{
		{"stale reading agrees",
			&stubRegistry{signer: qvSignerStr, ack: true, stale: true, refreshErr: errors.New("rpc down")},
			VerdictPass},
		{"stale reading names someone else",
			&stubRegistry{signer: "0xdead", ack: true, stale: true, refreshErr: errors.New("rpc down")},
			VerdictUnavailable},
		{"stale reading acknowledges nobody",
			&stubRegistry{ack: false, stale: true, refreshErr: errors.New("rpc down")},
			VerdictUnavailable},
		{"nothing cached to fall back on",
			&stubRegistry{err: errors.New("rpc down"), refreshErr: errors.New("rpc down")},
			VerdictUnavailable},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := pidServer(t, pidQuote(t, qvMeasurement(0xaa), pidMRConfigID(t, 1, pidComposeHashHex)), nil)
			r := pidRouter(t, srv.URL, pidAllowAll(), attest.ModeEnforce, tc.reg)
			r.WarmOnce(context.Background(), fakeResolver{url: srv.URL})

			id, ok := r.ProviderIdentity(testProviderAddr)
			if !ok {
				t.Fatal("no record; the quote verified, so the chain's state must not suppress it")
			}
			if id.OnChainSigner != tc.want {
				t.Errorf("OnChainSigner = %q, want %q", id.OnChainSigner, tc.want)
			}
		})
	}
}

// pidCatalogServer serves the provider catalog and a /v1/quote whose status is
// switchable, so a test can take a provider's quote endpoint down between sweeps.
func pidCatalogServer(t *testing.T, raw []byte, status *int32) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/providers", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"object": "list",
			"data":   []map[string]string{{"address": testProviderAddr}},
		})
	})
	mux.HandleFunc("GET /v1/quote", func(w http.ResponseWriter, r *http.Request) {
		if s := int(atomic.LoadInt32(status)); s != 0 {
			http.Error(w, "boom", s)
			return
		}
		_, _ = fmt.Fprintf(w, `{"quote":%q}`, hex.EncodeToString(raw))
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

// A sweep that can no longer verify a provider must WITHDRAW its record, not merely
// decline to write a new one. "A quote that fails DCAP leaves no record" holds
// trivially for a provider never seen before; with the warmer running, a record
// already exists for practically everyone, so declining to write leaves the previous
// sweep's `pass` standing for the rest of its TTL — reporting an enclave as verified
// minutes after this gateway established it cannot verify it at all. The quote cache
// is evicted on exactly this failure; the record has to be too.
func TestProviderIdentity_FailedSweepWithdrawsTheRecord(t *testing.T) {
	var status int32
	srv := pidCatalogServer(t, pidQuote(t, qvMeasurement(0xaa), pidMRConfigID(t, 1, pidComposeHashHex)), &status)
	r := pidRouter(t, srv.URL, pidAllowAll(), attest.ModeEnforce, &stubRegistry{signer: qvSignerStr, ack: true})
	res := fakeResolver{url: srv.URL}

	r.WarmOnce(context.Background(), res)
	if id, ok := r.ProviderIdentity(testProviderAddr); !ok || id.QuoteDCAP != VerdictPass {
		t.Fatalf("setup: record = %+v (found %v), want QuoteDCAP pass", id, ok)
	}

	// The provider's quote endpoint goes down. The sweep re-verifies, fails, and evicts
	// the quote cache; the record must go with it.
	atomic.StoreInt32(&status, http.StatusServiceUnavailable)
	r.WarmOnce(context.Background(), res)
	if id, ok := r.ProviderIdentity(testProviderAddr); ok {
		t.Errorf("record survived a failed sweep as %+v; the endpoint would report quote_dcap pass for an enclave it cannot verify", id)
	}

	// And it comes back on recovery: the withdrawal is re-established per sweep, not a
	// penalty a provider has to serve out.
	atomic.StoreInt32(&status, 0)
	r.WarmOnce(context.Background(), res)
	if id, ok := r.ProviderIdentity(testProviderAddr); !ok || id.QuoteDCAP != VerdictPass {
		t.Errorf("record = %+v (found %v), want it restored once the provider verifies again", id, ok)
	}
}

// cancellingResolver hands back an endpoint and cancels the sweep on the way out, so
// the quote fetch that follows fails because WE are going down. It is the shutdown
// shape for the quote half, as cancellingRegistry is for the chain half.
type cancellingResolver struct {
	url    string
	cancel context.CancelFunc
}

func (c cancellingResolver) ServiceInfo(context.Context, string) (chain.ServiceInfo, error) {
	c.cancel()
	return chain.ServiceInfo{URL: c.url, Signer: qvSignerStr, Acknowledged: true}, nil
}

// Shutdown is not a provider failure. A cancelled sweep's quote fetch fails like any
// other, and withdrawing a record on the strength of it would make a process delete
// what it knows on its way out — the same false-negative the quote-cache eviction and
// the sweep counters already guard against.
func TestProviderIdentity_CancelledSweepDoesNotWithdrawTheRecord(t *testing.T) {
	var status int32
	srv := pidCatalogServer(t, pidQuote(t, qvMeasurement(0xaa), pidMRConfigID(t, 1, pidComposeHashHex)), &status)
	r := pidRouter(t, srv.URL, pidAllowAll(), attest.ModeEnforce, &stubRegistry{signer: qvSignerStr, ack: true})

	r.WarmOnce(context.Background(), fakeResolver{url: srv.URL})
	if _, ok := r.ProviderIdentity(testProviderAddr); !ok {
		t.Fatal("setup: no record to preserve")
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	r.WarmOnce(ctx, cancellingResolver{url: srv.URL, cancel: cancel})

	if id, ok := r.ProviderIdentity(testProviderAddr); !ok {
		t.Errorf("record = %+v (found %v), want the confirmed record left standing through a shutdown", id, ok)
	}
}

// The withdrawal defers to a served record for another endpoint, symmetrically with
// the write. A sweep failing at the endpoint the chain names has established nothing
// about the endpoint a user's prompt actually went to, so it must not delete what that
// request verified.
func TestProviderIdentity_FailedSweepSparesAServedRecordForAnotherEndpoint(t *testing.T) {
	quote := pidQuote(t, qvMeasurement(0xaa), pidMRConfigID(t, 1, pidComposeHashHex))
	served := pidServerWithAppCompose(t, quote, nil, nil)
	var status int32 = http.StatusServiceUnavailable // the chain's endpoint is down
	onchain := pidCatalogServer(t, quote, &status)
	r := pidRouter(t, served.URL, pidAllowAll(), attest.ModeEnforce, &stubRegistry{signer: qvSignerStr, ack: true})

	pidResolve(t, r)
	r.WarmOnce(context.Background(), fakeResolver{url: onchain.URL})

	id, ok := r.ProviderIdentity(testProviderAddr)
	if !ok {
		t.Fatalf("the served record for %q was deleted by a sweep that failed at %q", served.URL, onchain.URL)
	}
	if id.Endpoint != served.URL {
		t.Errorf("Endpoint = %q, want the served %q", id.Endpoint, served.URL)
	}
}

// The two writers resolve a provider's endpoint from different places — the request
// path from the router's route preview, a sweep from the on-chain registry — so for
// one address they can verify two different enclaves. A sweep must not overwrite the
// served record then: under warn mode the request went through, and reporting the
// on-chain endpoint's verdicts for a prompt sealed to the router's endpoint would
// describe an enclave the user never talked to. Last-write-wins would decide this on
// sweep timing, which is the same "states something the gateway no longer believes"
// failure the request path records rejected candidates to avoid.
func TestProviderIdentity_SweepDoesNotOverwriteAServedRecordForAnotherEndpoint(t *testing.T) {
	quote := pidQuote(t, qvMeasurement(0xaa), pidMRConfigID(t, 1, pidComposeHashHex))
	// Two endpoints for one provider address: the one the preview names (and the
	// request verifies) and the one the chain names (and the sweep verifies).
	served := pidServerWithAppCompose(t, quote, nil, nil)
	onchain := pidServerWithAppCompose(t, quote, nil, nil)
	r := pidRouter(t, served.URL, pidAllowAll(), attest.ModeEnforce, &stubRegistry{signer: qvSignerStr, ack: true})

	pidResolve(t, r)
	r.WarmOnce(context.Background(), fakeResolver{url: onchain.URL})

	id, ok := r.ProviderIdentity(testProviderAddr)
	if !ok {
		t.Fatal("no record at all")
	}
	if id.Endpoint != served.URL {
		t.Errorf("Endpoint = %q, want the endpoint the request was actually sealed to %q (a sweep of %q must not displace it)",
			id.Endpoint, served.URL, onchain.URL)
	}

	// The deference is scoped to a CONFLICT. Sweeping the same endpoint the request
	// used has to keep refreshing the record, or a provider that served once would stop
	// being described the moment its served record expired.
	r.WarmOnce(context.Background(), fakeResolver{url: served.URL})
	if id, ok := r.ProviderIdentity(testProviderAddr); !ok || id.Endpoint != served.URL {
		t.Errorf("record = %+v (found %v), want the sweep to refresh a served record for the same endpoint", id, ok)
	}
}

// The sweep's on-chain verdict has to speak the same vocabulary the request path
// reports, or one panel would show two different answers for the same chain state.
// The distinction that matters most is the last case: our own RPC having a bad minute
// is `unavailable`, never a finding against the provider.
func TestProviderIdentity_WarmerOnChainVerdicts(t *testing.T) {
	for _, tc := range []struct {
		name string
		reg  *stubRegistry
		want Verdict
	}{
		{"acknowledged and agreeing", &stubRegistry{signer: qvSignerStr, ack: true}, VerdictPass},
		{"acknowledges nobody", &stubRegistry{ack: false}, VerdictNoMatch},
		{"acknowledges someone else", &stubRegistry{signer: "0xdead", ack: true}, VerdictNoMatch},
		{"chain unreadable", &stubRegistry{refreshErr: errors.New("rpc down")}, VerdictUnavailable},
		{"grounding not configured", nil, VerdictNotChecked},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := pidServer(t, pidQuote(t, qvMeasurement(0xaa), pidMRConfigID(t, 1, pidComposeHashHex)), nil)
			r := pidRouter(t, srv.URL, pidAllowAll(), attest.ModeEnforce, tc.reg)
			r.WarmOnce(context.Background(), fakeResolver{url: srv.URL})

			id, ok := r.ProviderIdentity(testProviderAddr)
			if !ok {
				t.Fatal("no record; the quote verified, so the on-chain outcome must not suppress it")
			}
			if id.OnChainSigner != tc.want {
				t.Errorf("OnChainSigner = %q, want %q", id.OnChainSigner, tc.want)
			}
			// Whatever the chain said, the quote's own verdict stands on its own evidence.
			if id.QuoteDCAP != VerdictPass {
				t.Errorf("QuoteDCAP = %q, want pass", id.QuoteDCAP)
			}
		})
	}
}

// A reply whose app-compose does NOT hash to the quote's compose_hash: the gate
// drops the list, and — the part worth pinning — the rest of the record survives.
// A substituted manifest must not cost the user the verdicts.
func TestProviderIdentity_MismatchedAppComposeDropsOnlyContainers(t *testing.T) {
	srv := pidServerWithAppCompose(t,
		pidQuote(t, qvMeasurement(0xaa), pidMRConfigID(t, 1, pidComposeHashHex)),
		[]byte(`{"docker_compose_file":"services:\n  evil:\n    image: attacker/x:latest\n"}`), nil)
	r := pidRouter(t, srv.URL, pidAllowAll(), attest.ModeEnforce, &stubRegistry{signer: qvSignerStr, ack: true})
	pidResolve(t, r)

	id, ok := r.ProviderIdentity(testProviderAddr)
	if !ok {
		t.Fatal("no record for the provider this request sealed to")
	}
	if id.Containers != nil {
		t.Fatalf("Containers = %+v, want nil for an app-compose that fails the hash gate", id.Containers)
	}
	if id.QuoteDCAP != VerdictPass || id.OnChainSigner != VerdictPass {
		t.Errorf("verdicts = %q/%q, want both pass: a failed container lookup must not cost the record its verdicts",
			id.QuoteDCAP, id.OnChainSigner)
	}
}
