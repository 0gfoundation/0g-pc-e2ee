package openaiproxy

import (
	"net/http"

	"github.com/0gfoundation/0g-pc-e2ee/client/metrics"
)

// LimitInFlight bounds how many requests may be inside h at once, refusing the
// excess immediately (503) rather than admitting them.
//
// WHY A SERVER-SIDE CAP AT ALL, when every caller pays per token. Billing bounds
// what a caller SPENDS; it does not bound what they OCCUPY. The two come apart
// here in three ways, and each one is a way a paying user gets a worse gateway
// than they paid for:
//
//   - The gateway is shared and CPU-bound. Sealing a request and opening every
//     response frame is real HPKE work in this process, on the CVM's small vCPU
//     budget (loadtest/README.md). Past the knee, one caller's load is served out
//     of every other caller's latency — and they are paying too.
//   - Cost and occupancy are not the same shape. A stream is held open for its
//     whole token schedule, bounded only by providerTimeout (10m30s). A thousand
//     cheap, slow streams cost little and occupy everything.
//   - Not everything on the path is charged. The route-preview round trip and
//     the DCAP verify on a cold quote cache are gateway work that no token count
//     reflects.
//
// So this is deliberately NOT a per-caller quota — it is a ceiling on the whole
// process, and it exists to keep a pile-up from turning into a fleet-wide
// slowdown. Per-account fairness is a separate question that wants per-account
// data first; the router's own per-account limiter is what bounds a single
// account's request RATE today.
//
// SHED, DON'T QUEUE. Acquisition is non-blocking: over the limit the request is
// refused at once. Queueing would keep the promise of eventual service while
// converting the overload into latency every waiting caller pays — including the
// ones who would rather have been told to retry. A fast 503 is information; a
// slow 200 is not.
//
// 503, not 429. This says "the server is full", not "you sent too much" — the
// caller may have sent exactly one request. Retry-After: 1 marks it retryable,
// and OpenAI-compatible clients already back off on both codes.
//
// max <= 0 disables the cap and returns h unchanged, so a caller can wire this
// unconditionally (the load-test rig and local runs turn it off to measure the
// unbounded knee; see the -max-inflight flag).
//
// Mount it INSIDE the credential gate: a request with no credential, or a mgmt
// key, is rejected on shape alone and must not consume a slot that a real
// request could have had.
// Publishing the configured ceiling as a metric is the CALLER's job (see
// metrics.SetInFlightLimit), not this constructor's: a process has one ceiling
// but may build several handlers, and a gauge written from here would report
// whichever was built last.
func LimitInFlight(max int, h http.Handler) http.Handler {
	if max <= 0 {
		return h
	}
	// Buffered channel as a counting semaphore: a send takes a slot, a receive
	// returns one. Nothing is ever read out of it, so the values are irrelevant.
	slots := make(chan struct{}, max)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case slots <- struct{}{}:
		default:
			metrics.RequestShed()
			// Set before the status line, like every other header the proxy
			// emits on an error path.
			w.Header().Set("Retry-After", "1")
			WriteError(w, http.StatusServiceUnavailable, "gateway",
				"gateway at capacity; retry shortly")
			return
		}
		// Released on every exit, panic included — a leaked slot is permanent,
		// and enough of them silently strangle the gateway to zero capacity.
		defer func() { <-slots }()
		h.ServeHTTP(w, r)
	})
}
