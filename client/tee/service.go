package tee

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"sync"
	"time"
)

// fetchTimeout bounds a single attestor RPC, so a stalled backend cannot hold
// the lock (and thereby wedge every request) indefinitely.
const fetchTimeout = 15 * time.Second

// Handler serves an enclave quote as an http.Handler (mount it at GET /quote).
// The quote is stable for the life of the enclave — it binds a fixed
// report_data — so it is fetched once, lazily, and cached. Consequence: rotating
// the bound TLS cert to a new key changes the correct report_data, so a rotation
// requires a restart (the cache is not invalidated in-process).
type Handler struct {
	attestor   Attestor
	reportData []byte

	mu     sync.Mutex // one lock for a rarely-hit endpoint; cached after first success
	cached *Quote
}

// NewHandler returns a Handler that serves attestor's quote over reportData.
func NewHandler(attestor Attestor, reportData []byte) *Handler {
	return &Handler{attestor: attestor, reportData: reportData}
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	q, err := h.quote(r.Context())
	if err != nil {
		// Log the detail server-side; return a generic message so the public
		// endpoint does not leak internal error text (socket paths, backend bodies).
		log.Printf("attestation: serving quote failed: %v", err)
		http.Error(w, "attestation quote unavailable", http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(q); err != nil {
		// Status/headers are already sent; the body is truncated. Log so a broken
		// write is not silent (the client sees a short body and fails closed).
		log.Printf("attestation: writing quote response: %v", err)
	}
}

func (h *Handler) quote(ctx context.Context) (*Quote, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.cached != nil {
		return h.cached, nil
	}
	ctx, cancel := context.WithTimeout(ctx, fetchTimeout)
	defer cancel()
	q, err := h.attestor.Quote(ctx, h.reportData)
	if err != nil {
		return nil, err // not cached: a transient failure retries on the next request
	}
	h.cached = q
	return q, nil
}
