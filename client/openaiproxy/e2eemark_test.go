package openaiproxy

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// The marker reaches the wire on a real response — one with a status and a body,
// which is where a header set too late is silently dropped.
func TestMarkE2EEStampsTheResponse(t *testing.T) {
	for _, value := range []string{E2EEValueSealed, E2EEValueNone} {
		t.Run(value, func(t *testing.T) {
			h := MarkE2EE(value, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(`{"ok":true}`))
			}))
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/v1/models", nil))

			if got := rec.Header().Get(HeaderE2EE); got != value {
				t.Errorf("%s: got %q, want %q", HeaderE2EE, got, value)
			}
		})
	}
}

// It is on an ERROR response too. This is what makes the header a check rather
// than a hint: a client that refuses anything not marked sealed must be able to
// tell "the sealed path refused me" from "something answered in the clear", and
// an error whose marker is absent is indistinguishable from the latter.
func TestMarkE2EEStampsErrors(t *testing.T) {
	h := MarkE2EE(E2EEValueSealed, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		WriteError(w, http.StatusUnauthorized, "gateway", "missing API key")
	}))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/v1/chat/completions", nil))

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status: got %d, want 401", rec.Code)
	}
	if got := rec.Header().Get(HeaderE2EE); got != E2EEValueSealed {
		t.Errorf("%s: got %q, want %q", HeaderE2EE, got, E2EEValueSealed)
	}
}

// Exactly one value, never two. A client that has to disambiguate a
// comma-joined "sealed, none" has no answer at all, and Add rather than Set is
// the easy way to get there — which is why the reverse proxy strips the
// upstream's copy (newRouterProxy) instead of relying on this.
func TestMarkE2EESingleValue(t *testing.T) {
	h := MarkE2EE(E2EEValueNone, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/v1/models", nil))

	if got := rec.Header().Values(HeaderE2EE); len(got) != 1 {
		t.Errorf("%s has %d values (%v), want exactly 1", HeaderE2EE, len(got), got)
	}
}

// A handler that sets the marker itself wins: the specific path knows better
// than the wrapper. Nothing does this today; the precedence is pinned so that a
// path which needs to say something more precise can, without first having to
// discover that the wrapper would overwrite it.
func TestMarkE2EEHandlerOverrides(t *testing.T) {
	h := MarkE2EE(E2EEValueNone, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set(HeaderE2EE, E2EEValueSealed)
		w.WriteHeader(http.StatusOK)
	}))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/x", nil))

	if got := rec.Header().Get(HeaderE2EE); got != E2EEValueSealed {
		t.Errorf("%s: got %q, want the handler's own %q", HeaderE2EE, got, E2EEValueSealed)
	}
}
