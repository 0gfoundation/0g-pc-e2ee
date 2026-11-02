package main

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

// freshEvidenceGateway is a full gateway handler with /evidence wired to a fake
// quoter answering with quoterStatus, and a router that counts what reaches it.
func freshEvidenceGateway(t *testing.T, quoterStatus int) (gw *httptest.Server, quoterHits, routerHits *atomic.Int32, gotNonce *atomic.Value) {
	t.Helper()
	quoterHits, routerHits, gotNonce = new(atomic.Int32), new(atomic.Int32), new(atomic.Value)
	quoter := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		quoterHits.Add(1)
		if r.URL.Path != "/quote" {
			t.Errorf("quoter path = %q", r.URL.Path)
		}
		gotNonce.Store(r.URL.Query().Get("nonce"))
		w.WriteHeader(quoterStatus)
		_, _ = io.WriteString(w, `{"quote":"cXVvdGU=","e2e_pubkey":"cHVi"}`)
	}))
	t.Cleanup(quoter.Close)
	router := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		routerHits.Add(1)
		w.WriteHeader(http.StatusNotFound)
	}))
	t.Cleanup(router.Close)
	gw = httptest.NewServer(newHandler(sealedClients(routeClient(), nil), mustURL(t, router.URL), testOrigins(), "", "",
		noInFlightCap, nil, nil, nil, discardLogger(), withQuoter(mustURL(t, quoter.URL))))
	t.Cleanup(gw.Close)
	return gw, quoterHits, routerHits, gotNonce
}

func TestFreshEvidenceRelaysQuote(t *testing.T) {
	gw, _, routerHits, gotNonce := freshEvidenceGateway(t, http.StatusOK)
	req, _ := http.NewRequest(http.MethodGet, gw.URL+"/evidence?nonce="+strings.Repeat("AB", 32), nil)
	// An origin outside the sealed API's allowlist: this route answers every origin.
	req.Header.Set("Origin", "https://not-allowlisted.example")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d: %s", resp.StatusCode, body)
	}
	if string(body) != `{"quote":"cXVvdGU=","e2e_pubkey":"cHVi"}` {
		t.Errorf("body = %s, want the quoter's reply verbatim", body)
	}
	for k, want := range map[string]string{
		"Access-Control-Allow-Origin": "*",
		"Cache-Control":               "no-store",
		"Content-Type":                "application/json",
	} {
		if got := resp.Header.Get(k); got != want {
			t.Errorf("%s = %q, want %q", k, got, want)
		}
	}
	if got := gotNonce.Load(); got != strings.Repeat("ab", 32) {
		t.Errorf("quoter got nonce %q, want the canonical lowercase form", got)
	}
	if n := routerHits.Load(); n != 0 {
		t.Errorf("router saw %d requests; /evidence must never fall through to it", n)
	}
}

func TestFreshEvidenceRejectsBeforeQuoter(t *testing.T) {
	gw, quoterHits, routerHits, _ := freshEvidenceGateway(t, http.StatusOK)
	cases := []struct {
		method, query string
		want          int
	}{
		{http.MethodGet, "", http.StatusBadRequest},
		{http.MethodGet, "?nonce=abc", http.StatusBadRequest},
		{http.MethodPost, "?nonce=" + strings.Repeat("00", 32), http.StatusMethodNotAllowed},
		{http.MethodOptions, "", http.StatusNoContent},
	}
	for _, c := range cases {
		req, _ := http.NewRequest(c.method, gw.URL+"/evidence"+c.query, nil)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != c.want {
			t.Errorf("%s /evidence%s: status %d, want %d", c.method, c.query, resp.StatusCode, c.want)
		}
		if resp.Header.Get("Access-Control-Allow-Origin") != "*" {
			t.Errorf("%s /evidence%s: no wildcard CORS header", c.method, c.query)
		}
	}
	if quoterHits.Load() != 0 || routerHits.Load() != 0 {
		t.Errorf("quoter hits %d, router hits %d; want both 0", quoterHits.Load(), routerHits.Load())
	}
}

func TestFreshEvidenceMapsQuoterStatus(t *testing.T) {
	for quoterStatus, want := range map[int]int{
		http.StatusTooManyRequests:     http.StatusTooManyRequests,
		http.StatusServiceUnavailable:  http.StatusServiceUnavailable,
		http.StatusBadGateway:          http.StatusBadGateway,
		http.StatusInternalServerError: http.StatusBadGateway,
	} {
		gw, _, _, _ := freshEvidenceGateway(t, quoterStatus)
		resp, err := http.Get(gw.URL + "/evidence?nonce=" + strings.Repeat("00", 32))
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != want {
			t.Errorf("quoter %d: gateway answered %d, want %d", quoterStatus, resp.StatusCode, want)
		}
	}
}

func TestFreshEvidenceUnmountedWithoutQuoter(t *testing.T) {
	var routerHits atomic.Int32
	router := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		routerHits.Add(1)
		w.WriteHeader(http.StatusNotFound)
	}))
	defer router.Close()
	gw := httptest.NewServer(newHandler(sealedClients(routeClient(), nil), mustURL(t, router.URL), testOrigins(), "", "",
		noInFlightCap, nil, nil, nil, discardLogger()))
	defer gw.Close()
	resp, err := http.Get(gw.URL + "/evidence?nonce=" + strings.Repeat("00", 32))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if routerHits.Load() != 1 {
		t.Errorf("with no quoter, /evidence should fall through to the catch-all like any unknown path")
	}
}
