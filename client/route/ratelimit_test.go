package route

import (
	"fmt"
	"testing"
	"time"
)

// Both of the limiter's keys — a provider address and a quote URL — come from the
// untrusted router, and a key is only ever added, never removed on its own. A
// router inventing them must not be able to grow the map without bound.
func TestRateLimiter_BoundsItsKeySpace(t *testing.T) {
	const window = time.Minute
	clock := time.Unix(1000, 0)
	l := &rateLimiter{now: func() time.Time { return clock }}

	// A modest overshoot past the cap: the claim is that the map stops growing, and
	// each refused key sweeps the full map, so a large overshoot only buys a slow test.
	for i := 0; i < maxLimiterKeys+64; i++ {
		l.allow(fmt.Sprintf("key-%d", i), window)
	}
	if got := len(l.next); got > maxLimiterKeys {
		t.Errorf("tracking %d keys, want at most %d", got, maxLimiterKeys)
	}

	// Refusing while full is not the same as wedging shut. Every key the limiter
	// holds goes inert at a known time, so once the windows lapse the sweep frees the
	// map and a genuine caller is due again.
	clock = clock.Add(window + time.Second)
	if !l.allow("a-real-provider", window) {
		t.Error("a new key was denied after every window had lapsed; the cap must not be permanent")
	}
}

// A key inside its window is refused whether or not the map is full — the cap is a
// backstop on memory, not a replacement for the limit itself.
func TestRateLimiter_HoldsTheWindow(t *testing.T) {
	clock := time.Unix(1000, 0)
	l := &rateLimiter{now: func() time.Time { return clock }}

	if !l.allow("k", time.Minute) {
		t.Fatal("first call: want allowed")
	}
	clock = clock.Add(59 * time.Second)
	if l.allow("k", time.Minute) {
		t.Error("inside the window: want denied")
	}
	clock = clock.Add(2 * time.Second)
	if !l.allow("k", time.Minute) {
		t.Error("past the window: want allowed")
	}
}

// reschedule shortens an outstanding window and never lengthens one, so an
// inconclusive attempt can be retried sooner without a later caller being able to
// push a due action further away.
func TestRateLimiter_RescheduleOnlyShortens(t *testing.T) {
	clock := time.Unix(1000, 0)
	l := &rateLimiter{now: func() time.Time { return clock }}

	l.allow("k", time.Hour)
	l.reschedule("k", time.Minute)
	clock = clock.Add(time.Minute + time.Second)
	if !l.allow("k", time.Hour) {
		t.Fatal("after reschedule: want allowed a minute in, not an hour")
	}
	l.reschedule("k", time.Hour) // now the stamp is already an hour out
	clock = clock.Add(time.Minute + time.Second)
	if l.allow("k", time.Hour) {
		t.Error("reschedule pushed the next allowed time OUT; it must only bring it in")
	}
}
