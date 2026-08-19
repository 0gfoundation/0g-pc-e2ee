package route

import (
	"sync"
	"time"
)

// rateLimiter bounds how often a keyed action may run. It stores the time each
// key is next ALLOWED rather than when it last ran, so a caller can shorten the
// wait after an inconclusive attempt (reschedule) without the limiter needing to
// know which window produced the current stamp.
//
// It exists for the two recovery paths — re-verifying a quote and re-reading a
// signer — which are both "do the expensive thing rather than reject a provider
// that may be innocent". Unbounded, either turns a persistently disagreeing
// provider into a per-request DCAP verify or a per-request chain RPC, so the
// bound is what makes "prefer evidence over a verdict" affordable rather than a
// lever an adversary can pull.
//
// Both of its keys — a provider address and a quote URL — are chosen by the
// untrusted router, so the map is bounded too; see allow.
type rateLimiter struct {
	mu   sync.Mutex
	next map[string]time.Time
	now  func() time.Time // nil uses time.Now; a test substitutes a clock
}

// maxLimiterKeys caps how many keys the limiter tracks at once. A key past its
// next-allowed time is indistinguishable from an absent one, so the sweep below
// costs nothing semantically and holds the map to the keys with a LIVE window —
// which is what a real deployment has, orders of magnitude under this cap. The
// hard refusal past it only ever fires on a router inventing addresses faster
// than the window expires, and refusing is the right side to fail on: a denied
// revalidation degrades to the cached verdict, where granting one costs an
// unbounded map.
const maxLimiterKeys = 4096

// allow reports whether key's action is due, stamping the next allowed time when
// it is. A key that has never run is always due.
func (l *rateLimiter) allow(key string, window time.Duration) bool {
	now := l.clock()
	l.mu.Lock()
	defer l.mu.Unlock()
	if next, ok := l.next[key]; ok {
		if now.Before(next) {
			return false
		}
	} else if len(l.next) >= maxLimiterKeys {
		sweepExpired(l.next, now, func(next time.Time) time.Time { return next })
		if len(l.next) >= maxLimiterKeys {
			return false
		}
	}
	if l.next == nil {
		l.next = make(map[string]time.Time)
	}
	l.next[key] = now.Add(window)
	return true
}

// reschedule brings key's next allowed time forward to d from now, for an attempt
// that concluded nothing — a fetch that failed says the provider might still be
// innocent, so holding the full window would reject it for that whole window over
// a problem on our side of the call.
func (l *rateLimiter) reschedule(key string, d time.Duration) {
	now := l.clock()
	l.mu.Lock()
	defer l.mu.Unlock()
	next, ok := l.next[key]
	if !ok && len(l.next) >= maxLimiterKeys {
		// Both call sites reschedule a key allow just stamped, so this is unreachable in
		// practice; skipping is the safe branch regardless, since an absent key is the
		// most permissive state a key can be in and reschedule only ever moves toward it.
		return
	}
	if l.next == nil {
		l.next = make(map[string]time.Time)
	}
	if !ok || next.After(now.Add(d)) {
		l.next[key] = now.Add(d)
	}
}

func (l *rateLimiter) clock() time.Time {
	if l.now != nil {
		return l.now()
	}
	return time.Now()
}

// sweepExpired deletes every entry whose deadline has passed. Callers use it on
// maps whose entries go inert at a known time, so a swept entry and a missing one
// mean the same thing to every reader.
func sweepExpired[V any](m map[string]V, now time.Time, deadline func(V) time.Time) {
	for k, v := range m {
		if !now.Before(deadline(v)) {
			delete(m, k)
		}
	}
}
