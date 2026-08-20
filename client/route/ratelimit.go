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

// Preview retry-suppression policy. Retrying an uncached dependency is a load
// multiplier exactly when the dependency is least able to take it: with the router
// fully down, every request makes previewAttempts calls instead of one, and each
// holds its gateway concurrency slot (openaiproxy.LimitInFlight) for the retry
// ceiling — budget plus one attempt — rather than for a single attempt. A local
// router outage would therefore turn into gateway-wide shedding, which is a worse
// failure than the one the retries were added to paper over.
//
// So the retries switch themselves off once the router stops looking like it is
// merely blipping. The FIRST attempt is never suppressed, so correctness does not
// depend on this at all — a request still reaches the router and still gets its
// real error; what is dropped is only the amplification.
const (
	// previewRetryTripAfter is how many consecutive calls must fail to get any
	// answer before retries are suppressed. Concurrent requests all count, so a
	// genuine outage trips this within one round of traffic, while an isolated blip
	// (which by definition is followed by a success) never does.
	previewRetryTripAfter = 5
	// previewRetryCooldown is how long retries stay off. Short on purpose: the next
	// single attempt after it is what discovers the recovery, so this is the longest
	// a recovered router waits to get its retries back.
	previewRetryCooldown = 10 * time.Second
)

// retryGate decides whether preview retries are currently worth making. It is the
// smallest thing that removes the amplification above: a consecutive-failure count
// and a cooldown, with any answer at all from the router clearing both.
//
// Deliberately NOT a general circuit breaker. It never blocks a request, never
// changes what a caller is told, and holds no per-route state — there is one
// router, so there is one counter. Safe for concurrent use.
type retryGate struct {
	mu sync.Mutex
	// consecutive counts calls that got no answer since the last one that did.
	consecutive int
	// openUntil is when retries resume; zero means they are on.
	openUntil time.Time
	now       func() time.Time // nil uses time.Now; a test substitutes a clock
}

// allow reports whether a retry may be made right now.
func (g *retryGate) allow() bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	return !g.clock().Before(g.openUntil)
}

// noAnswer records a call that never got an answer out of the router, tripping the
// gate once enough of them have piled up back to back.
func (g *retryGate) noAnswer() {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.consecutive++
	if g.consecutive >= previewRetryTripAfter {
		g.openUntil = g.clock().Add(previewRetryCooldown)
		// Reset the count with the window: it has done its job, and leaving it high
		// would re-trip the gate on the first failure after the window lapses,
		// before the traffic has had a chance to say anything new.
		g.consecutive = 0
	}
}

// answered records that the router replied — well or badly, but replied. That is
// proof of reachability, so it clears both the count and any open window: a
// recovered router should not keep serving requests with retries switched off.
func (g *retryGate) answered() {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.consecutive = 0
	g.openUntil = time.Time{}
}

func (g *retryGate) clock() time.Time {
	if g.now != nil {
		return g.now()
	}
	return time.Now()
}
