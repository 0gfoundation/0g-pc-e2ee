package main

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/0gfoundation/0g-pc-e2ee/client/openaiproxy"
)

func TestGatewayRejectsSourceFileProbesBeforeRouter(t *testing.T) {
	for _, tc := range []struct {
		method string
		path   string
		block  bool
	}{
		{http.MethodGet, "/.git/HEAD", true},
		{http.MethodHead, "/backup/%2eGiT/config", true},
		{http.MethodGet, "/v1/.env", true},
		{http.MethodPost, "/.env", true},
		{http.MethodGet, "/v1/chat/completions/.env", true},
		{http.MethodGet, "/app/.ENV.local", true},
		{http.MethodGet, "/.git-credentials", true},
		{http.MethodGet, "/.github/workflows/check.yml", true},
		{http.MethodGet, "/.gitlab-ci.yml", true},
		{http.MethodGet, "/v1/models?filter=.env", false},
		{http.MethodGet, "/v1/models/vendor.git", false},
		{http.MethodGet, "/v1/account/usage/history", false},
	} {
		t.Run(tc.method+" "+tc.path, func(t *testing.T) {
			router := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("X-Test-Router", "reached")
				w.WriteHeader(http.StatusOK)
			}))
			defer router.Close()

			gateway := newHandler(sealedClients(routeClient(), nil), mustURL(t, router.URL), testOrigins(), "", "", noInFlightCap, nil, nil, nil, discardLogger())
			req := httptest.NewRequest(tc.method, tc.path, nil)
			res := httptest.NewRecorder()
			gateway.ServeHTTP(res, req)

			if tc.block {
				if got := res.Header().Get("X-Test-Router"); got != "" || res.Code != http.StatusNotFound {
					t.Fatalf("status = %d, upstream reached = %q, want local 404", res.Code, got)
				}
				if got := res.Header().Get("Cache-Control"); got != "no-store" {
					t.Errorf("Cache-Control = %q, want no-store", got)
				}
				if got := res.Header().Get(openaiproxy.HeaderE2EE); got != openaiproxy.E2EEValueNone {
					t.Errorf("X-0G-E2EE = %q, want none", got)
				}
			} else if got := res.Header().Get("X-Test-Router"); got != "reached" || res.Code != http.StatusOK {
				t.Fatalf("status = %d, upstream reached = %q, want upstream 200", res.Code, got)
			}
		})
	}
}
