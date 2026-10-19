package route

import (
	"log/slog"
	"testing"

	"github.com/0gfoundation/0g-pc-e2ee/client/evidence"
	"github.com/0gfoundation/0g-pc-e2ee/client/evidence/compose"
	"github.com/0gfoundation/0g-pc-e2ee/protocol/attest"
)

// A provider whose manifest or event log makes a reader panic — no input is known to,
// so the panic is injected — is served, and reported as not checked. The readers run
// inside the quote singleflight, which re-panics on its caller's goroutine: without the
// boundary this test does not fail, it takes the test binary down, as it would the
// gateway.
func TestReaders_APanicIsACheckThatDidNotRun(t *testing.T) {
	savedReview, savedRuntime := reviewCompose, readRuntimeState
	t.Cleanup(func() { reviewCompose, readRuntimeState = savedReview, savedRuntime })
	reviewCompose = func([]byte, [attest.ComposeHashLen]byte, evidence.ReleaseVerifier) (compose.ComposeReview, error) {
		panic("index out of range [3] with length 3")
	}
	readRuntimeState = func([]byte, [evidence.RTMRLen]byte) (evidence.RuntimeState, error) {
		var m map[string]int
		m["x"]++ // assignment to entry in nil map
		return evidence.RuntimeState{}, nil
	}

	testnet := blManifest(t, "testnet-app-compose.json")
	logs := &logCounter{n: map[string]int{}}
	r, _ := blRouter(t, blTestnetProvider, blTestnetContract, testnet, testnet, fleetStub(),
		func(r *Router) { r.logger = slog.New(logs) })
	for i := 0; i < 2; i++ {
		if err := rtServe(r); err != nil {
			t.Fatalf("request %d: %v", i, err)
		}
	}
	id, ok := r.ProviderIdentity(blTestnetProvider)
	if !ok {
		t.Fatal("no record")
	}
	if id.ComposeBaseline != VerdictUnavailable || id.RuntimeRelease != VerdictUnavailable {
		t.Fatalf("compose_baseline %q, runtime_release %q; want both unavailable", id.ComposeBaseline,
			id.RuntimeRelease)
	}
	if got := logs.count("a reader of provider input panicked"); got != 2 {
		t.Fatalf("%d reader panics logged for one verification, want 2 (manifest, event log)", got)
	}
}
