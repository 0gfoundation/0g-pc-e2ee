package main

import (
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"regexp"
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

// Every response from a CONTENT-CARRYING path declares whether it was end-to-end
// encrypted — on the sealed path and on the cleartext catch-all alike.
//
// Operational and evidence routes are deliberately outside that set (see
// openaiproxy.HeaderE2EE): they have no content to make a claim about.
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
func TestServedPathsDeclareTheirE2EEStatus(t *testing.T) {
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

// A default deployment answers browser calls with Access-Control-Allow-Credentials,
// on the catch-all as well as the sealed path.
//
// This is the assertion that stands between the cutover and a completely broken
// first-party app. Per the Fetch spec's CORS check, a request whose credentials mode
// is "include" fails as a NETWORK ERROR without this header — whether or not a cookie
// was actually sent — and the web app sets `credentials: 'include'` on EVERY router
// call, not just the authenticated ones. So losing this header does not degrade
// cookie auth, it takes out the model catalog and the balance read too, and it does
// so with a CORS error rather than a 401.
//
// The catch-all row is the one that would be missed by reasoning about auth: nothing
// on /v1/models is authenticated, and it still needs the header.
func TestDefaultDeploymentAnswersCredentialedCORS(t *testing.T) {
	rr := &recordingRouter{}
	router := rr.server(nil)
	defer router.Close()

	gw := httptest.NewServer(newHandler(allSealedClients(), mustURL(t, router.URL), testOrigins(), "", "",
		noInFlightCap, nil, nil, nil, discardLogger()))
	defer gw.Close()

	for _, path := range []string{endpoint.Chat.Path, "/v1/models"} {
		t.Run(path, func(t *testing.T) {
			req, _ := http.NewRequest(http.MethodGet, gw.URL+path, nil)
			req.Header.Set("Origin", "https://chat.0g.ai")
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatalf("get %s: %v", path, err)
			}
			defer resp.Body.Close()

			if got := resp.Header.Get("Access-Control-Allow-Credentials"); got != "true" {
				t.Errorf("Access-Control-Allow-Credentials = %q, want %q: without it every "+
					"`credentials: 'include'` call from the first-party app fails as a CORS network error",
					got, "true")
			}
			if got := resp.Header.Get("Access-Control-Allow-Origin"); got != "https://chat.0g.ai" {
				t.Errorf("Access-Control-Allow-Origin = %q, want the origin echoed (a literal \"*\" is "+
					"illegal with credentials)", got)
			}
		})
	}
}

// The cookie credential is wired by DEFAULT, and the converted credential reaches
// the router.
//
// The default row is the one that matters: a gateway with no options configured
// admits the router's cookie. That is the whole point of there being no flag — the
// first-party web app authenticates with an HttpOnly cookie and no Authorization
// header, and a deployment cannot detect whether it is the one serving the router's
// hostname, so "on unless the allowlist says otherwise" is the only setting that
// cannot be forgotten in the breaking direction.
//
// It asserts the far end rather than the status, which is what makes it meaningful:
// the router's route-preview call must carry the cookie's value as a bearer token.
// That proves the gate admitted the request AND that the credential survived the
// conversion — a 200 from the gateway would prove neither, since the sealed path has
// plenty of other reasons to fail in a test.
//
// The openOrigins row is the one exception, and it is a security property rather
// than a configuration preference: the origin allowlist is the entire CSRF defense
// for an ambient credential, so an allowlist of "*" — which makes that defense pass
// everything — turns cookie admission off and leaves the gateway keys-only.
func TestCookieCredentialWiring(t *testing.T) {
	tests := []struct {
		name   string
		policy entryPolicy
		// wantAuth is what the router's preview call should carry, or "" when the
		// request is expected never to get that far.
		wantAuth   string
		wantStatus int
	}{
		{"on by default: the cookie becomes a bearer credential", entryPolicy{},
			"Bearer jwt-from-browser", 0},
		{"off for an open allowlist: keys only", entryPolicy{openOrigins: true},
			"", http.StatusUnauthorized},
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

// The surface's own TRAILING-SLASH form is sealed, not proxied — under both values
// of -unsealed-subtree.
//
// This is the same invariant as TestUnsealedSubtreePassthroughStillSealsThePost,
// reached by the one spelling that slipped past it. To Go's ServeMux,
// `POST /v1/chat/completions/` matches the SUBTREE pattern, not `POST
// /v1/chat/completions` — so under `passthrough` the subtree handler was the
// reverse proxy, and the whole prompt went to the router in the clear with a 200.
// One character, and the caller could not tell: the router's gin 307s the retry
// onto the canonical path, so the request works and nothing looks wrong.
//
// The assertion is on what the ROUTER RECEIVED, for the reason the sibling test
// gives: a status code cannot distinguish "sealed" from "already forwarded".
func TestSealedSurfaceTrailingSlashIsNeverProxied(t *testing.T) {
	for _, mode := range []string{unsealedSubtreeRefuse, unsealedSubtreePassthrough} {
		t.Run(mode, func(t *testing.T) {
			rr := &recordingRouter{}
			router := rr.server(nil)
			defer router.Close()

			// The sealed client points at a DIFFERENT (dead) router, so anything the
			// recording router sees arrived through the passthrough and nothing else.
			gw := httptest.NewServer(newHandler(allSealedClients(), mustURL(t, router.URL), testOrigins(), "", "",
				noInFlightCap, nil, nil, nil, discardLogger(),
				withEntryPolicy(entryPolicy{unsealedSubtree: mode})))
			defer gw.Close()

			const secret = "my secret prompt"
			for _, ep := range endpoint.All {
				req, _ := http.NewRequest(http.MethodPost, gw.URL+ep.Path+"/", strings.NewReader(
					`{"model":"m","prompt":"`+secret+`","messages":[{"role":"user","content":"`+secret+`"}]}`))
				req.Header.Set("Content-Type", "application/json")
				req.Header.Set("Authorization", "Bearer sk-user-key")
				// Do not follow redirects: the point is what THIS gateway answered.
				client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error {
					return http.ErrUseLastResponse
				}}
				resp, err := client.Do(req)
				if err != nil {
					t.Fatalf("post %s/: %v", ep.Path, err)
				}
				_ = resp.Body.Close()
				if got := resp.Header.Get(openaiproxy.HeaderE2EE); got != openaiproxy.E2EEValueSealed {
					t.Errorf("POST %s/: %s = %q, want %q — the trailing-slash form belongs to the "+
						"sealed surface, not to its subtree", ep.Path, openaiproxy.HeaderE2EE, got,
						openaiproxy.E2EEValueSealed)
				}
			}

			paths, _, bodies := rr.snapshot()
			for i, b := range bodies {
				if strings.Contains(b, secret) {
					t.Fatalf("the prompt reached the router in the clear at %s: %s", paths[i], b)
				}
			}
			if len(paths) != 0 {
				t.Errorf("the trailing-slash form was forwarded to the router: %v", paths)
			}
		})
	}
}

// composeUnsealedSubtree reads the deployed default out of the compose manifest.
var composeUnsealedSubtree = regexp.MustCompile(
	`ZG_GATEWAY_UNSEALED_SUBTREE=\$\{ZG_GATEWAY_UNSEALED_SUBTREE:-([^}]*)\}`)

// The deployed default is pinned because it decides whether a sealed surface's
// sub-resources reach the untrusted router IN THE CLEAR, and because it
// deliberately disagrees with the binary's own default.
//
// The flag defaults to "refuse", which is right for a gateway beside a router a
// caller can still reach — a 501 there points at an open door. The deployment
// whose endpoint becomes the network's only entry needs "passthrough", because
// on the only entry a 501 deletes the feature instead of redirecting. Two
// correct answers for two topologies, and the file has to pick one.
//
// Neither direction of a wrong value announces itself: "refuse" on the sole
// entry looks like an endpoint that was never implemented, and "passthrough"
// beside a router forwards content nobody decided to forward. So this asserts
// the value rather than merely that it parses — changing it should mean editing
// this test and saying which topology changed.
func TestComposeUnsealedSubtreeIsPassthrough(t *testing.T) {
	compose, err := os.ReadFile(composePath)
	if err != nil {
		t.Fatalf("read %s: %v", composePath, err)
	}
	m := composeUnsealedSubtree.FindSubmatch(compose)
	if m == nil {
		t.Fatalf("no ZG_GATEWAY_UNSEALED_SUBTREE=${...:-<default>} entry in %s; if the entry was "+
			"reshaped deliberately, update this test rather than dropping it", composePath)
	}
	switch got := string(m[1]); got {
	case unsealedSubtreePassthrough:
		// The global-entry deployment's answer.
	case unsealedSubtreeRefuse:
		t.Errorf("the compose default is %q, the binary's default and the one for a gateway "+
			"running BESIDE a reachable router. On the sole entry it turns "+
			"POST /v1/messages/count_tokens and GET /v1/chat/completions into 501s that "+
			"look like endpoints nobody implemented. If this deployment is no longer the "+
			"sole entry, say so here", got)
	default:
		t.Errorf("the compose default is %q, which is neither %q nor %q — the gateway refuses "+
			"to start on it, so this would be a deploy that never comes up",
			got, unsealedSubtreeRefuse, unsealedSubtreePassthrough)
	}
}
