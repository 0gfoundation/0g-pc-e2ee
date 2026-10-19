package route

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/0gfoundation/0g-pc-e2ee/client/endpoint"
	"github.com/0gfoundation/0g-pc-e2ee/client/evidence"
	"github.com/0gfoundation/0g-pc-e2ee/protocol/attest"
	"github.com/0gfoundation/0g-pc-e2ee/protocol/wire"
)

const (
	rtBrokerRepo = "ghcr.io/0gfoundation/0g-serving-broker"
	// rtV054 is broker v0.5.4, which the testnet vector runs.
	rtV054 = "sha256:951f4c7971f87377ab077639a5a84d2aed8945460494da076ff8466ea1ee90b5"
	// rtCN20 is the main-branch build cn-20 had swapped in on 2026-10-16.
	rtCN20 = "sha256:66ff49f0e1ffc9904c723b7d4ba71734bc541c478b38940f5b7c004c5a9a0698"
)

// stubReleases accepts the digests it lists and rejects the rest, counting calls. With
// gate set, every call waits on it — a registry that does not answer.
type stubReleases struct {
	accepted map[string]string // digest -> version
	gate     chan struct{}
	calls    atomic.Int32
}

func (s *stubReleases) Repository() string { return rtBrokerRepo }

func (s *stubReleases) Verify(repository, digest string) evidence.ReleaseVerdict {
	s.calls.Add(1)
	if s.gate != nil {
		<-s.gate
	}
	if v, ok := s.accepted[digest]; ok && repository == rtBrokerRepo {
		return evidence.ReleaseVerdict{Status: evidence.ReleaseAccepted,
			Release: evidence.BrokerRelease{Version: v, Digest: digest}}
	}
	return evidence.ReleaseVerdict{Reason: "it is signed by docker-publish.yml, not by build.yml on a release tag"}
}

func fleetStub() *stubReleases { return &stubReleases{accepted: map[string]string{rtV054: "v0.5.4"}} }

// rtVector is a real /v1/quote reply from evidence/testdata/rtmr3, with edit applied to
// its decoded fields when set.
func rtVector(t *testing.T, name string, edit func(map[string]any)) []byte {
	t.Helper()
	reply, err := os.ReadFile(filepath.Join("..", "evidence", "testdata", "rtmr3", name+".quote.json"))
	if err != nil {
		t.Fatal(err)
	}
	if edit == nil {
		return reply
	}
	var m map[string]any
	if err := json.Unmarshal(reply, &m); err != nil {
		t.Fatal(err)
	}
	edit(m)
	out, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// rtRouter serves reply as the one candidate's /v1/quote and returns a Router that
// verifies it. The quote parser is faked, as everywhere in this package, but it answers
// with the reply's OWN measurement and report_data: the event log has to replay to the
// RTMR3 that real quote carries, and the image record has to name its keys.
func rtRouter(t *testing.T, reply []byte, rels evidence.ReleaseVerifier, extra ...Option) (*Router, *httptest.Server) {
	t.Helper()
	return rtRouterAt(t, testProviderAddr, reply, rels, extra...)
}

// rtRouterAt is rtRouter with the candidate — and the one provider the catalog lists —
// at address.
func rtRouterAt(t *testing.T, address string, reply []byte, rels evidence.ReleaseVerifier,
	extra ...Option) (*Router, *httptest.Server) {
	t.Helper()
	raw, err := attest.DecodeQuoteResponse(reply)
	if err != nil {
		t.Fatal(err)
	}
	qb, err := attest.ParseTDXQuoteBody(raw)
	if err != nil {
		t.Fatal(err)
	}
	var srv *httptest.Server
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/routing/preview", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(previewResponse{
			Object: "routing.preview", ServiceType: "chatbot",
			Providers: []previewProvider{{Address: address, CanonicalID: "canon-1", Endpoint: srv.URL, ModelID: "m"}},
		})
	})
	mux.HandleFunc("GET /v1/providers", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"object": "list", "data": []map[string]string{{"address": address}}})
	})
	mux.HandleFunc("GET /v1/quote", func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write(reply) })
	srv = httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	bc := attest.BootChainOf(qb.Measurement)
	v := attest.New(attest.BootChainPolicy{Allowed: []attest.BootChain{bc}},
		attest.WithQuoteParser(qvParser(qb.Measurement, qb.ReportData)))
	opts := []Option{WithQuoteVerification(v, discardLogger())}
	if rels != nil {
		opts = append(opts, WithReleaseVerifier(rels, discardLogger()))
	}
	return New(srv.URL, append(opts, extra...)...), srv
}

// rtServe runs the checks a request runs before sealing and returns their error, for
// callers off the test goroutine.
func rtServe(r *Router) error {
	cands, err := r.Resolve(context.Background(), endpoint.Chat, wire.Request{})
	if err != nil {
		return err
	}
	_, err = cands.Provider(context.Background(), 0)
	return err
}

// rtSettled reads the record until its runtime verdict is not the one a check still in
// flight reports, or fails after a few seconds.
func rtSettled(t *testing.T, r *Router) ProviderIdentity {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		id, ok := r.ProviderIdentity(testProviderAddr)
		if !ok {
			t.Fatal("no record for the provider this request sealed to")
		}
		if id.RuntimeRelease != VerdictUnavailable || time.Now().After(deadline) {
			return id
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// The three live vectors, through the path a request takes: the verdict is the one
// pcverify reaches on the same reply (evidence.TestRuntime_LiveFleet).
func TestRuntimeRelease_LiveVectors(t *testing.T) {
	for _, tc := range []struct {
		name             string
		verdict          Verdict
		running, release string
	}{
		{"testnet-rehearsal-v0.5.4", VerdictPass, rtBrokerRepo + "@" + rtV054, "v0.5.4"},
		{"cn20-2026-10-16", VerdictNoMatch, rtBrokerRepo + "@" + rtCN20, ""},
		// No runtime image record: the manifest's pin runs, which the baseline judges.
		{"cn1-2026-10-16", VerdictNotChecked, "", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r, _ := rtRouter(t, rtVector(t, tc.name, nil), fleetStub())
			pidResolve(t, r)
			id := rtSettled(t, r)
			if id.RuntimeRelease != tc.verdict || id.RunningBroker != tc.running || id.RunningRelease != tc.release {
				t.Fatalf("got %q running %q release %q, want %q running %q release %q",
					id.RuntimeRelease, id.RunningBroker, id.RunningRelease, tc.verdict, tc.running, tc.release)
			}
		})
	}
}

// The log is believed only because it replays to the verified quote's RTMR3: one changed
// byte and it is a contradiction, not a record. A reply with no log is a check that did
// not run.
func TestRuntimeRelease_TheQuoteAnchorsTheLog(t *testing.T) {
	tampered := rtVector(t, "testnet-rehearsal-v0.5.4", func(m map[string]any) {
		// The zg-image-update record, naming a different digest: the payload is hex of
		// "repository@sha256:<digest> <signer> <enc_pub>", so its last digest byte moves.
		log := m["event_log"].([]any)
		last := log[len(log)-1].(map[string]any)
		if last["event"] != "zg-image-update" {
			t.Fatalf("the vector's last record is %v", last["event"])
		}
		p := last["event_payload"].(string)
		i := strings.Index(p, "203078") // " 0x", where the signer starts
		last["event_payload"] = p[:i-2] + "30" + p[i:]
	})
	r, _ := rtRouter(t, tampered, fleetStub())
	pidResolve(t, r)
	if id := rtSettled(t, r); id.RuntimeRelease != VerdictNoMatch {
		t.Fatalf("a log edited after the fact: %q", id.RuntimeRelease)
	}

	// Neither the top-level log nor tcb_info's copy.
	bare := rtVector(t, "testnet-rehearsal-v0.5.4", func(m map[string]any) {
		delete(m, "event_log")
		delete(m, "tcb_info")
	})
	r, _ = rtRouter(t, bare, fleetStub())
	pidResolve(t, r)
	if id, _ := r.ProviderIdentity(testProviderAddr); id.RuntimeRelease != VerdictUnavailable || id.RunningBroker != "" {
		t.Fatalf("a reply without a log: %q running %q", id.RuntimeRelease, id.RunningBroker)
	}
}

// OBSERVE ONLY, and off the request path: a release check that never answers neither
// delays nor refuses the request, and the record says the check has not run. A verdict
// that lands afterwards reaches the record with no second verification.
func TestRuntimeRelease_NeverOnTheRequestPath(t *testing.T) {
	rels := fleetStub()
	rels.gate = make(chan struct{})
	r, _ := rtRouter(t, rtVector(t, "cn20-2026-10-16", nil), rels)

	done := make(chan error, 1)
	go func() { done <- rtServe(r) }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("the request failed: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the request waited on the release check")
	}
	if id, _ := r.ProviderIdentity(testProviderAddr); id.RuntimeRelease != VerdictUnavailable ||
		id.RunningBroker != rtBrokerRepo+"@"+rtCN20 {
		t.Fatalf("while the check is in flight: %q running %q", id.RuntimeRelease, id.RunningBroker)
	}

	// A provider whose build is rejected is still served: nothing is enforced.
	pidResolve(t, r)
	close(rels.gate)
	if id := rtSettled(t, r); id.RuntimeRelease != VerdictNoMatch {
		t.Fatalf("after the check answered: %q", id.RuntimeRelease)
	}
	pidResolve(t, r)
	if n := rels.calls.Load(); n != 1 {
		t.Fatalf("the build was judged %d times, want once", n)
	}
}

// A Router without a release verifier still reports what runs, and says it judged none.
func TestRuntimeRelease_NotConfigured(t *testing.T) {
	r, _ := rtRouter(t, rtVector(t, "cn20-2026-10-16", nil), nil)
	pidResolve(t, r)
	if id, _ := r.ProviderIdentity(testProviderAddr); id.RuntimeRelease != VerdictNotChecked ||
		id.RunningBroker != rtBrokerRepo+"@"+rtCN20 {
		t.Fatalf("got %q running %q", id.RuntimeRelease, id.RunningBroker)
	}
}

// The judge's own rules: a read never starts a check, a verdict other than an acceptance
// is asked for again after releaseRecheck while an acceptance never is, and the work a
// provider can cause is bounded — maxReleaseChecks at once, maxJudgedReleases held.
func TestReleaseJudge(t *testing.T) {
	clock := time.Date(2026, 10, 19, 0, 0, 0, 0, time.UTC)
	var mu sync.Mutex
	now := func() time.Time { mu.Lock(); defer mu.Unlock(); return clock }
	advance := func(d time.Duration) { mu.Lock(); clock = clock.Add(d); mu.Unlock() }
	settle := func(j *releaseJudge, digest string) evidence.ReleaseVerdict {
		t.Helper()
		deadline := time.Now().Add(5 * time.Second)
		for {
			j.mu.Lock()
			e := j.m[rtBrokerRepo+"@"+digest]
			done := e != nil && e.have && !e.running
			var v evidence.ReleaseVerdict
			if done {
				v = e.verdict
			}
			j.mu.Unlock()
			if done {
				return v
			}
			if time.Now().After(deadline) {
				t.Fatalf("%s was never judged", digest)
			}
			time.Sleep(time.Millisecond)
		}
	}

	t.Run("reads never start a check", func(t *testing.T) {
		rels := fleetStub()
		j := newReleaseJudge(rels, discardLogger())
		if _, ok := j.verdict(rtBrokerRepo, rtV054, false); ok || rels.calls.Load() != 0 || len(j.m) != 0 {
			t.Fatalf("a read: ok %v, %d calls, %d entries", ok, rels.calls.Load(), len(j.m))
		}
	})

	t.Run("rechecks", func(t *testing.T) {
		rels := fleetStub()
		j := newReleaseJudge(rels, discardLogger())
		j.now = now
		j.verdict(rtBrokerRepo, rtV054, true)
		j.verdict(rtBrokerRepo, rtCN20, true)
		settle(j, rtV054)
		settle(j, rtCN20)
		advance(releaseRecheck - time.Second)
		j.verdict(rtBrokerRepo, rtCN20, true)
		if n := rels.calls.Load(); n != 2 {
			t.Fatalf("asked again within releaseRecheck (%d calls)", n)
		}
		advance(time.Hour)
		j.verdict(rtBrokerRepo, rtV054, true)
		if v, ok := j.verdict(rtBrokerRepo, rtCN20, true); !ok || v.Status != evidence.ReleaseRejected {
			t.Fatalf("a recheck in flight must still report what is held: %+v %v", v, ok)
		}
		settle(j, rtCN20)
		if n := rels.calls.Load(); n != 3 {
			t.Fatalf("want one recheck of the rejection and none of the acceptance, got %d calls", n)
		}
	})

	t.Run("bounded", func(t *testing.T) {
		rels := fleetStub()
		rels.gate = make(chan struct{})
		j := newReleaseJudge(rels, discardLogger())
		for i := 0; i < 3*maxReleaseChecks; i++ {
			j.verdict(rtBrokerRepo, fmt.Sprintf("sha256:%064x", i), true)
		}
		// Slots are released only when a check returns; give the scheduler a moment to
		// prove no extra one started.
		time.Sleep(20 * time.Millisecond)
		if n := rels.calls.Load(); n > maxReleaseChecks {
			t.Fatalf("%d checks at once, over %d", n, maxReleaseChecks)
		}
		close(rels.gate)

		j = newReleaseJudge(fleetStub(), discardLogger())
		j.verdict(rtBrokerRepo, rtV054, true)
		settle(j, rtV054)
		for i := 0; i < maxJudgedReleases+10; i++ {
			j.mu.Lock()
			if j.makeRoomLocked() {
				j.m[rtBrokerRepo+"@"+strings.Repeat("x", i+1)] = &judgedRelease{have: true}
			}
			j.mu.Unlock()
		}
		if len(j.m) > maxJudgedReleases {
			t.Fatalf("%d verdicts held, over %d", len(j.m), maxJudgedReleases)
		}
		if e := j.m[rtBrokerRepo+"@"+rtV054]; e == nil || e.verdict.Status != evidence.ReleaseAccepted {
			t.Fatal("rejections pushed an acceptance out")
		}
	})
}

// The judge is exercised from verifications and reads at once (run with -race).
func TestReleaseJudge_Concurrent(t *testing.T) {
	// No quote cache, so every request verifies and judges again.
	r, _ := rtRouter(t, rtVector(t, "testnet-rehearsal-v0.5.4", nil), fleetStub(), WithQuoteTTL(0))
	var wg sync.WaitGroup
	errs := make(chan error, 8)
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for k := 0; k < 10; k++ {
				if err := rtServe(r); err != nil {
					errs <- err
					return
				}
				r.ProviderIdentity(testProviderAddr)
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}
	if id := rtSettled(t, r); id.RuntimeRelease != VerdictPass {
		t.Fatalf("got %q", id.RuntimeRelease)
	}
}
