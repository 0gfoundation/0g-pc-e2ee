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
type rateLimiter struct {
	mu   sync.Mutex
	next map[string]time.Time
	now  func() time.Time // nil uses time.Now; a test substitutes a clock
}

// allow reports whether key's action is due, stamping the next allowed time when
// it is. A key that has never run is always due.
func (l *rateLimiter) allow(key string, window time.Duration) bool {
	now := l.clock()
	l.mu.Lock()
	defer l.mu.Unlock()
	if next, ok := l.next[key]; ok && now.Before(next) {
		return false
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
	if l.next == nil {
		l.next = make(map[string]time.Time)
	}
	if next, ok := l.next[key]; !ok || next.After(now.Add(d)) {
		l.next[key] = now.Add(d)
	}
}

func (l *rateLimiter) clock() time.Time {
	if l.now != nil {
		return l.now()
	}
	return time.Now()
}
