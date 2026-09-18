package main

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/0gfoundation/0g-pc-e2ee/client/core"
	"github.com/0gfoundation/0g-pc-e2ee/client/endpoint"
	"github.com/0gfoundation/0g-pc-e2ee/client/openaiproxy"
	"github.com/0gfoundation/0g-pc-e2ee/client/route"
)

// recordingRouter is a stand-in for the 0G router that remembers every request it
// was handed, so a case can assert on what the gateway FORWARDED rather than only
// on the status the caller saw. A 501 with the payload already forwarded is the
// same failure wearing a better answer, and the reverse — a 200 that never left
// the gateway — is the same mistake in the other direction.
type recordingRouter struct {
	mu    sync.Mutex
	paths []string
	auths []string
	seen  []string // request bodies, in the order they arrived
}

func (rr *recordingRouter) server(extra func(http.ResponseWriter)) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		rr.mu.Lock()
		rr.paths = append(rr.paths, r.Method+" "+r.URL.Path)
		rr.auths = append(rr.auths, r.Header.Get("Authorization"))
		rr.seen = append(rr.seen, string(body))
		rr.mu.Unlock()
		if extra != nil {
			extra(w)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"providers":[]}`))
	}))
}

func (rr *recordingRouter) snapshot() (paths, auths, bodies []string) {
	rr.mu.Lock()
	defer rr.mu.Unlock()
	return append([]string(nil), rr.paths...), append([]string(nil), rr.auths...), append([]string(nil), rr.seen...)
}

// allSealedClients gives the handler a client for every row, since whether this
// build seals a surface has no bearing on what its namespace answers.
func allSealedClients() map[string]*core.Client {
	clients := map[string]*core.Client{}
	for _, ep := range endpoint.All {
		clients[ep.Path] = routeClient()
	}
	return clients
}

// Under unsealedSubtreePassthrough a sealed surface's sub-resources are FORWARDED
// to the router, marked as unencrypted.
//
// This is the deliberate inverse of TestGatewayRefusesSubResourcesOfASealedSurface,
// which pins the default. Both behaviors are correct, for different topologies: the
// 501 is right while a caller who wants the router's own handling can call the
// router directly, and it is wrong once this gateway IS the router's hostname,
// where refusing is not pointing at another door but closing the only one.
//
// The marker is asserted alongside the forwarding because it is what keeps the
// forwarding honest. The payload really does reach the router in the clear here —
// that has not changed — so the caller has to be able to SEE that, on the response
// itself, rather than inferring it from a path.
func TestUnsealedSubtreePassthroughForwardsAndMarks(t *testing.T) {
	rr := &recordingRouter{}
	router := rr.server(nil)
	defer router.Close()

	gw := httptest.NewServer(newHandler(allSealedClients(), mustURL(t, router.URL), testOrigins(), "", "",
		noInFlightCap, nil, nil, nil, discardLogger(),
		withEntryPolicy(entryPolicy{unsealedSubtree: unsealedSubtreePassthrough})))
	defer gw.Close()

	for _, ep := range endpoint.All {
		for _, suffix := range []string{"count_tokens", "batches", "some/deeper/path"} {
			path := ep.Path + "/" + suffix
			t.Run(path, func(t *testing.T) {
				req, _ := http.NewRequest(http.MethodPost, gw.URL+path, strings.NewReader(`{"model":"m"}`))
				req.Header.Set("Content-Type", "application/json")
				req.Header.Set("Authorization", "Bearer sk-user-key")
				resp, err := http.DefaultClient.Do(req)
				if err != nil {
					t.Fatalf("post %s: %v", path, err)
				}
				defer resp.Body.Close()
				body, _ := io.ReadAll(resp.Body)

				if resp.StatusCode != http.StatusOK {
					t.Errorf("status = %d, want 200 — the router's own answer, not a gateway refusal (body %s)",
						resp.StatusCode, body)
				}
				if got := resp.Header.Get(openaiproxy.HeaderE2EE); got != openaiproxy.E2EEValueNone {
					t.Errorf("%s = %q, want %q: a cleartext passthrough must say so",
						openaiproxy.HeaderE2EE, got, openaiproxy.E2EEValueNone)
				}
			})
		}
	}

	paths, _, _ := rr.snapshot()
	if len(paths) != len(endpoint.All)*3 {
		t.Errorf("the router saw %d requests (%v), want one per sub-resource", len(paths), paths)
	}
}

// ...and the sealed POST is NOT forwarded, under either value.
//
// This is the invariant the whole flag has to preserve: passthrough widens what a
// sealed surface's NAMESPACE answers, and must not touch the one method that
// seals. If it did, turning the flag on for the global-entry topology would put
// every prompt on the cleartext path — the exact leak the refusal was written to
// prevent, reintroduced by the fix for it.
//
// The sealed client here points at a DIFFERENT (dead) router than the catch-all's
// target, so anything the recording router sees arrived through the passthrough
// and nothing else. Seeing no request for the surface's own path is therefore
// proof the POST went to the seal path.
func TestUnsealedSubtreePassthroughStillSealsThePost(t *testing.T) {
	rr := &recordingRouter{}
	router := rr.server(nil)
	defer router.Close()

	gw := httptest.NewServer(newHandler(allSealedClients(), mustURL(t, router.URL), testOrigins(), "", "",
		noInFlightCap, nil, nil, nil, discardLogger(),
		withEntryPolicy(entryPolicy{unsealedSubtree: unsealedSubtreePassthrough})))
	defer gw.Close()

	const secret = "my secret prompt"
	for _, ep := range endpoint.All {
		req, _ := http.NewRequest(http.MethodPost, gw.URL+ep.Path, strings.NewReader(
			`{"model":"m","prompt":"`+secret+`","messages":[{"role":"user","content":"`+secret+`"}]}`))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer sk-user-key")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("post %s: %v", ep.Path, err)
		}
		_ = resp.Body.Close()
		// The status is not the assertion: the sealed path fails here (its resolver
		// points at a dead host), and that is fine. What matters is where the body
		// went.
		if got := resp.Header.Get(openaiproxy.HeaderE2EE); got != openaiproxy.E2EEValueSealed {
			t.Errorf("POST %s: %s = %q, want %q — this is the sealed path even when it fails",
				ep.Path, openaiproxy.HeaderE2EE, got, openaiproxy.E2EEValueSealed)
		}
	}

	paths, _, bodies := rr.snapshot()
	if len(paths) != 0 {
		t.Fatalf("the sealed POST was forwarded to the router in the clear: %v", paths)
	}
	for i, b := range bodies {
		if strings.Contains(b, secret) {
			t.Errorf("the prompt reached the router in the clear at %s: %s", paths[i], b)
		}
	}
}

// Every response declares whether it was end-to-end encrypted — on the sealed
// path and on the cleartext catch-all alike.
//
// Stamping both is what makes the header a check rather than a hint. If only
// cleartext responses carried it, absence would be ambiguous between "sealed" and
// "a gateway that does not say", so a client could never assert sealing — only
// hope for it.
//
// The sealed row deliberately sends NO credential: a 401 from the sealed path is
// still an answer from the sealed path, and the marker has to survive the
// front-door refusals (gate 401/403, limiter 503) or a client keying on it reads
// every error as cleartext.
func TestEveryResponseDeclaresItsE2EEStatus(t *testing.T) {
	rr := &recordingRouter{}
	router := rr.server(nil)
	defer router.Close()

	gw := httptest.NewServer(newHandler(allSealedClients(), mustURL(t, router.URL), testOrigins(), "", "",
		noInFlightCap, nil, nil, nil, discardLogger()))
	defer gw.Close()

	tests := []struct {
		name, method, path string
		wantStatus         int
		wantMark           string
	}{
		{"sealed path, refused at the front door", http.MethodPost, endpoint.Chat.Path,
			http.StatusUnauthorized, openaiproxy.E2EEValueSealed},
		{"catch-all metadata", http.MethodGet, "/v1/models",
			http.StatusOK, openaiproxy.E2EEValueNone},
		{"catch-all discovery", http.MethodGet, "/v1/providers",
			http.StatusOK, openaiproxy.E2EEValueNone},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, _ := http.NewRequest(tt.method, gw.URL+tt.path, nil)
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatalf("%s %s: %v", tt.method, tt.path, err)
			}
			defer resp.Body.Close()
			if resp.StatusCode != tt.wantStatus {
				body, _ := io.ReadAll(resp.Body)
				t.Errorf("status = %d, want %d (body %s)", resp.StatusCode, tt.wantStatus, body)
			}
			if got := resp.Header.Get(openaiproxy.HeaderE2EE); got != tt.wantMark {
				t.Errorf("%s = %q, want %q", openaiproxy.HeaderE2EE, got, tt.wantMark)
			}
		})
	}
}

// An upstream that sends the marker itself must not end up appended to ours.
//
// ReverseProxy copies upstream headers with Add, so a router emitting this name
// would put two contradictory values on one response and leave a client with
// "sealed, none" to disambiguate — which is no answer. Same class of bug as the
// doubled Access-Control-Allow-Origin the proxy already strips for, and the
// router not sending it today is exactly why this needs a test rather than a
// comment.
func TestUpstreamE2EEMarkerIsStripped(t *testing.T) {
	rr := &recordingRouter{}
	router := rr.server(func(w http.ResponseWriter) {
		w.Header().Set(openaiproxy.HeaderE2EE, openaiproxy.E2EEValueSealed)
	})
	defer router.Close()

	gw := httptest.NewServer(newHandler(allSealedClients(), mustURL(t, router.URL), testOrigins(), "", "",
		noInFlightCap, nil, nil, nil, discardLogger()))
	defer gw.Close()

	resp, err := http.Get(gw.URL + "/v1/models")
	if err != nil {
		t.Fatalf("get /v1/models: %v", err)
	}
	defer resp.Body.Close()

	got := resp.Header.Values(openaiproxy.HeaderE2EE)
	if len(got) != 1 || got[0] != openaiproxy.E2EEValueNone {
		t.Errorf("%s = %v, want exactly [%q] — the upstream's claim must not survive",
			openaiproxy.HeaderE2EE, got, openaiproxy.E2EEValueNone)
	}
}

// The cookie credential is wired only when the deployment asks for it, and when
// it is, the converted credential reaches the router.
//
// The off row is the behavior the global-entry cutover would otherwise ship: the
// first-party web app authenticates with an HttpOnly cookie and no Authorization
// header, so every one of its chat requests 401s at the front door.
//
// The on row asserts the far end rather than the status, which is what makes it
// meaningful: the router's route-preview call must carry the cookie's value as a
// bearer token. That proves the gate admitted the request AND that the credential
// survived the conversion — a 200 from the gateway would prove neither, since the
// sealed path has plenty of other reasons to fail in a test.
func TestCookieCredentialWiring(t *testing.T) {
	tests := []struct {
		name   string
		policy entryPolicy
		// wantAuth is what the router's preview call should carry, or "" when the
		// request is expected never to get that far.
		wantAuth   string
		wantStatus int
	}{
		{"off by default: the cookie is not a credential", entryPolicy{}, "", http.StatusUnauthorized},
		{"on: the cookie becomes a bearer credential", entryPolicy{cookieCredential: true},
			"Bearer jwt-from-browser", 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rr := &recordingRouter{}
			router := rr.server(nil)
			defer router.Close()

			// The sealed client points at the recording router, so its route-preview
			// call is what this case observes.
			clients := map[string]*core.Client{endpoint.Chat.Path: core.NewWithResolver(route.New(router.URL))}
			gw := httptest.NewServer(newHandler(clients, mustURL(t, router.URL), testOrigins(), "", "",
				noInFlightCap, nil, nil, nil, discardLogger(), withEntryPolicy(tt.policy)))
			defer gw.Close()

			req, _ := http.NewRequest(http.MethodPost, gw.URL+endpoint.Chat.Path,
				strings.NewReader(`{"model":"m","messages":[{"role":"user","content":"hi"}]}`))
			req.Header.Set("Content-Type", "application/json")
			req.AddCookie(&http.Cookie{Name: "jwt", Value: "jwt-from-browser"})
			// A first-party browser origin, which is both what makes the cookie
			// admissible (CSRF) and what the real app sends.
			req.Header.Set("Origin", "https://chat.0g.ai")
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatalf("post: %v", err)
			}
			defer resp.Body.Close()
			body, _ := io.ReadAll(resp.Body)

			if tt.wantStatus != 0 && resp.StatusCode != tt.wantStatus {
				t.Errorf("status = %d, want %d (body %s)", resp.StatusCode, tt.wantStatus, body)
			}
			if tt.wantStatus == 0 && (resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden) {
				t.Errorf("status = %d: the front door rejected a cookie it was configured to accept (body %s)",
					resp.StatusCode, body)
			}

			paths, auths, _ := rr.snapshot()
			if tt.wantAuth == "" {
				if len(paths) != 0 {
					t.Errorf("the router was called for a request that should have been refused: %v", paths)
				}
				return
			}
			var found bool
			for i, p := range paths {
				if strings.HasPrefix(p, "POST ") && strings.HasSuffix(p, "/v1/routing/preview") {
					found = true
					if auths[i] != tt.wantAuth {
						t.Errorf("preview Authorization = %q, want %q", auths[i], tt.wantAuth)
					}
				}
			}
			if !found {
				t.Errorf("the router never saw a route-preview call; it saw %v", paths)
			}
		})
	}
}
