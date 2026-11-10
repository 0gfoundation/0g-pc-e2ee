package main

import (
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"testing"

	"github.com/0gfoundation/0g-pc-e2ee/client/clientip"
)

const testClientIPKey = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"

// headerRecordingRouter is a router stub that keeps the headers of the last request.
func headerRecordingRouter(t *testing.T) (*httptest.Server, func() http.Header) {
	t.Helper()
	var mu sync.Mutex
	var last http.Header
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		last = r.Header.Clone()
		mu.Unlock()
		_, _ = w.Write([]byte(`{"data":[]}`))
	}))
	t.Cleanup(srv.Close)
	return srv, func() http.Header {
		mu.Lock()
		defer mu.Unlock()
		return last
	}
}

// The catch-all passthrough (newRouterProxy) is the path most unauthenticated
// router traffic takes — the catalog, the auth endpoints. With a key configured, it
// must carry the client's address signed, and a forged set the client sent must not
// survive alongside it.
func TestPassthroughCarriesTheSignedClientIP(t *testing.T) {
	router, last := headerRecordingRouter(t)
	signer, err := clientip.NewSigner(testClientIPKey, mustURL(t, router.URL))
	if err != nil {
		t.Fatal(err)
	}
	h := withClientIP(signer, newHandler(sealedClients(routeClient(), nil), mustURL(t, router.URL), testOrigins(), "", "", noInFlightCap, nil, nil, nil, discardLogger()))

	req := httptest.NewRequest(http.MethodGet, "/v1/models", nil)
	req.RemoteAddr = "203.0.113.7:51000" // what proxyproto hands net/http
	req.Header.Set(clientip.HeaderIP, "6.6.6.6")
	req.Header.Set(clientip.HeaderTs, "1")
	req.Header.Set(clientip.HeaderSig, "forged")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rec.Code, rec.Body)
	}

	got := last()
	if ips := got.Values(clientip.HeaderIP); len(ips) != 1 || ips[0] != "203.0.113.7" {
		t.Fatalf("router saw X-0G-Client-IP = %v", ips)
	}
	ts, err := strconv.ParseInt(got.Get(clientip.HeaderTs), 10, 64)
	if err != nil {
		t.Fatalf("bad timestamp %q", got.Get(clientip.HeaderTs))
	}
	key, _ := hex.DecodeString(testClientIPKey)
	if want := clientip.Sign(key, "203.0.113.7", ts); got.Get(clientip.HeaderSig) != want {
		t.Fatalf("signature %q does not verify", got.Get(clientip.HeaderSig))
	}
}

// Without a key (the default), the router is told nothing — and a set the client
// sent is still dropped, not relayed.
func TestPassthroughWithoutKeySendsNoClientIP(t *testing.T) {
	router, last := headerRecordingRouter(t)
	h := withClientIP(nil, newHandler(sealedClients(routeClient(), nil), mustURL(t, router.URL), testOrigins(), "", "", noInFlightCap, nil, nil, nil, discardLogger()))

	req := httptest.NewRequest(http.MethodGet, "/v1/models", nil)
	req.RemoteAddr = "203.0.113.7:51000"
	req.Header.Set(clientip.HeaderIP, "6.6.6.6")
	req.Header.Set(clientip.HeaderSig, "forged")
	h.ServeHTTP(httptest.NewRecorder(), req)

	got := last()
	for _, k := range []string{clientip.HeaderIP, clientip.HeaderTs, clientip.HeaderSig} {
		if v := got.Get(k); v != "" {
			t.Errorf("router saw %s = %q", k, v)
		}
	}
}
