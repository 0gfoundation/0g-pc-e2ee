package openaiproxy

import (
	"bytes"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// serveLogged runs h behind LogRequests and returns the response and the log.
func serveLogged(t *testing.T, h http.HandlerFunc) (*httptest.ResponseRecorder, string) {
	t.Helper()
	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, nil))
	rec := httptest.NewRecorder()
	LogRequests(logger, h).ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/v1/chat/completions", nil))
	return rec, buf.String()
}

// The response carries exactly one X-Request-Id. When the router answered it
// is the router's — the id usage history knows — however the relay added it
// (the passthrough and ReverseProxy both use Add) and whether the response is
// buffered or streamed. The access log keeps ours and records the router's.
func TestLogRequests_RouterRequestIDWins(t *testing.T) {
	const routerID = "9f1c2d3e-router-uuid"
	cases := map[string]http.HandlerFunc{
		"buffered": func(w http.ResponseWriter, r *http.Request) {
			setPassthrough(w, http.Header{"X-Request-Id": {routerID}})
			_, _ = w.Write([]byte("{}"))
		},
		"streamed": func(w http.ResponseWriter, r *http.Request) {
			w.Header().Add("X-Request-Id", routerID)
			w.Header().Set("Content-Type", "text/event-stream")
			w.(http.Flusher).Flush()
			_, _ = w.Write([]byte("data: {}\n\n"))
		},
		"router error": func(w http.ResponseWriter, r *http.Request) {
			setPassthrough(w, http.Header{"X-Request-Id": {routerID}})
			w.WriteHeader(http.StatusPaymentRequired)
		},
	}
	for name, h := range cases {
		t.Run(name, func(t *testing.T) {
			rec, log := serveLogged(t, h)
			if got := rec.Result().Header.Values("X-Request-Id"); len(got) != 1 || got[0] != routerID {
				t.Fatalf("X-Request-Id = %q, want exactly [%q]", got, routerID)
			}
			if !strings.Contains(log, `"router_request_id":"`+routerID+`"`) {
				t.Errorf("access log lacks router_request_id: %s", log)
			}
		})
	}
}

// Without a router answer — the proxy's own refusal, or a handler that writes
// nothing — the proxy's id is the one the caller gets.
func TestLogRequests_OwnRequestIDWhenRouterSilent(t *testing.T) {
	cases := map[string]http.HandlerFunc{
		"own error": func(w http.ResponseWriter, r *http.Request) {
			WriteError(w, http.StatusServiceUnavailable, "gateway", "busy")
		},
		"wrote nothing": func(w http.ResponseWriter, r *http.Request) {},
	}
	for name, h := range cases {
		t.Run(name, func(t *testing.T) {
			rec, log := serveLogged(t, h)
			got := rec.Result().Header.Values("X-Request-Id")
			if len(got) != 1 || got[0] == "" {
				t.Fatalf("X-Request-Id = %q, want the proxy's one id", got)
			}
			if !strings.Contains(log, `"request_id":"`+got[0]+`"`) || strings.Contains(log, "router_request_id") {
				t.Errorf("access log = %s, want request_id %q and no router_request_id", log, got[0])
			}
		})
	}
}
