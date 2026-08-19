package proxycli

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/0gfoundation/0g-pc-e2ee/client/chain"
	"github.com/0gfoundation/0g-pc-e2ee/client/route"
)

type stubEndpoints struct{}

func (stubEndpoints) ServiceInfo(context.Context, string) (chain.ServiceInfo, error) {
	return chain.ServiceInfo{}, nil
}

// Without a warmer there is no sweep data, so there is nothing to assert and
// Readiness must return nil — the caller reads that as "always ready" rather than
// failing a probe on a configuration that simply does not collect the signal.
func TestReadiness_NilWithoutWarmer(t *testing.T) {
	b := &Built{router: route.New("http://router.unused")}
	if b.Readiness() != nil {
		t.Error("Readiness should be nil when no warmer is configured")
	}
}

func TestReadiness_WiredWithWarmer(t *testing.T) {
	b := &Built{
		router:       route.New("http://router.unused"),
		resolver:     stubEndpoints{},
		warmInterval: time.Minute,
	}
	ready := b.Readiness()
	if ready == nil {
		t.Fatal("Readiness should be wired when a warmer is configured")
	}
	// No sweep has run against this router, so it must report not-ready rather than
	// defaulting to ready.
	if err := ready(); err == nil {
		t.Error("want not-ready before any sweep has completed")
	}
}

func TestReadinessFromWarmState(t *testing.T) {
	const interval = time.Minute
	now := time.Now()

	cases := []struct {
		name      string
		state     route.WarmState
		wantErr   bool
		wantInMsg string
	}{{
		// The state the blue/green probe spends most of its window waiting out: a cold
		// side that has not finished its first sweep must not read as ready.
		name:      "no sweep yet",
		state:     route.WarmState{},
		wantErr:   true,
		wantInMsg: "no warmer sweep",
	}, {
		// "Nobody is ready" and "there is nobody" are different operator actions, so
		// the reason carries both counts.
		name:      "nothing prepared",
		state:     route.WarmState{At: now, Ready: 0, Total: 7},
		wantErr:   true,
		wantInMsg: "0 of 7",
	}, {
		// One usable provider is enough: a request only needs somewhere to go.
		name:  "one prepared is enough",
		state: route.WarmState{At: now, Ready: 1, Total: 7},
	}, {
		// A slow or missed tick must not flap the answer.
		name:  "one missed sweep tolerated",
		state: route.WarmState{At: now.Add(-2 * interval), Ready: 1, Total: 1},
	}, {
		// But a warmer that has actually stalled must not leave a stale "ready"
		// standing indefinitely.
		name:      "stalled warmer",
		state:     route.WarmState{At: now.Add(-(warmStateMaxAge + 1) * interval), Ready: 3, Total: 3},
		wantErr:   true,
		wantInMsg: "no warmer sweep has finished or started",
	}, {
		// A sweep that is merely SLOW is not a warmer that has stalled. Sweep duration
		// scales with the provider count and gets worse exactly when the upstreams are
		// unwell, so judging on the finish time alone would report a process not-ready
		// for being busy re-confirming what it is still serving happily from cache.
		name: "slow sweep still running",
		state: route.WarmState{
			At:      now.Add(-(warmStateMaxAge + 5) * interval),
			Started: now.Add(-2 * interval),
			Ready:   3, Total: 3,
		},
	}, {
		// A sweep that hangs outright still ages out, because Started stops advancing
		// too — the guard above must not become a way to look ready forever.
		name: "sweep hung since long ago",
		state: route.WarmState{
			At:      now.Add(-(warmStateMaxAge + 5) * interval),
			Started: now.Add(-(warmStateMaxAge + 1) * interval),
			Ready:   3, Total: 3,
		},
		wantErr:   true,
		wantInMsg: "no warmer sweep has finished or started",
	}}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := readinessFromWarmState(tc.state, interval)
			if tc.wantErr && err == nil {
				t.Fatal("want not-ready, got ready")
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("want ready, got %v", err)
			}
			if tc.wantInMsg != "" && !strings.Contains(err.Error(), tc.wantInMsg) {
				t.Errorf("reason = %q, want it to mention %q", err, tc.wantInMsg)
			}
		})
	}
}
