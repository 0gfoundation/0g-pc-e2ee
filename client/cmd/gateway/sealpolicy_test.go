package main

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/0gfoundation/0g-pc-e2ee/client/core"
	"github.com/0gfoundation/0g-pc-e2ee/client/endpoint"
	"github.com/0gfoundation/0g-pc-e2ee/client/openaiproxy"
)

// With -seal-policy=off the gateway is the plain router: every sealed surface's
// POST is FORWARDED, not sealed and not refused.
//
// This is what makes the DNS cutover a deploy rather than a release. Pointing
// router-api.0g.ai at a gateway that seals unconditionally would, in one DNS
// change, narrow the provider pool to sealable endpoints, break web search and
// file attachments by construction, and add a route-preview plus an HPKE seal to
// every request.
func TestSealPolicyOffForwardsThePromptInstead(t *testing.T) {
	rr := &recordingRouter{}
	router := rr.server(nil)
	defer router.Close()
	gw := catalogGateway(t, router, entryPolicy{sealPolicy: sealPolicyOff})

	const body = `{"model":"m","messages":[{"role":"user","content":"hello"}]}`
	for _, ep := range endpoint.All {
		t.Run(ep.Path, func(t *testing.T) {
			req, _ := http.NewRequest(http.MethodPost, gw.URL+ep.Path, strings.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Authorization", "Bearer sk-user-key")
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatalf("post %s: %v", ep.Path, err)
			}
			defer resp.Body.Close()
			got, _ := io.ReadAll(resp.Body)

			if resp.StatusCode != http.StatusOK {
				t.Errorf("status = %d, want 200 — the router's own answer (body %s)", resp.StatusCode, got)
			}
			// The caller must be able to SEE that this was not encrypted. With
			// sealing off that is the only signal there is.
			if got := resp.Header.Get(openaiproxy.HeaderE2EE); got != openaiproxy.E2EEValueNone {
				t.Errorf("%s = %q, want %q", openaiproxy.HeaderE2EE, got, openaiproxy.E2EEValueNone)
			}
		})
	}

	paths, _, bodies := rr.snapshot()
	if len(bodies) != len(endpoint.All) {
		t.Fatalf("router saw %d requests, want %d (one per sealed surface): with sealing off "+
			"these must reach the router, not be sealed or refused", len(bodies), len(endpoint.All))
	}
	for i, b := range bodies {
		if b != body {
			t.Errorf("router request %d (%s) body = %q, want the caller's verbatim %q",
				i, paths[i], b, body)
		}
	}
}

// The default seals. A deployment that says nothing about seal policy — every
// gateway running today, and every test that is about something else — must keep
// sealing rather than silently becoming a cleartext proxy.
func TestSealPolicyDefaultsToSealing(t *testing.T) {
	if !(entryPolicy{}).sealingOn() {
		t.Error("the zero entryPolicy does not seal; the zero value must be the ordinary deployment")
	}
	if !(entryPolicy{sealPolicy: sealPolicyAlways}).sealingOn() {
		t.Error(`sealPolicy "always" must seal`)
	}
	if (entryPolicy{sealPolicy: sealPolicyOff}).sealingOn() {
		t.Error(`sealPolicy "off" must not seal`)
	}
	// Only the exact "off" turns it off. Anything else — a value startup
	// validation somehow let through — lands on sealing, which is the direction
	// that cannot put a prompt the caller expected encrypted onto the clear path.
	if !(entryPolicy{sealPolicy: "OFF"}).sealingOn() {
		t.Error("an unrecognised seal policy must fall back to SEALING, not to cleartext")
	}

	rr := &recordingRouter{}
	router := rr.server(nil)
	defer router.Close()
	gw := catalogGateway(t, router, entryPolicy{}) // no seal policy stated

	req, _ := http.NewRequest(http.MethodPost, gw.URL+endpoint.Chat.Path,
		strings.NewReader(`{"model":"m","messages":[{"role":"user","content":"secret"}]}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer sk-user-key")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer resp.Body.Close()

	if got := resp.Header.Get(openaiproxy.HeaderE2EE); got != openaiproxy.E2EEValueSealed {
		t.Errorf("%s = %q, want %q on the default policy", openaiproxy.HeaderE2EE, got, openaiproxy.E2EEValueSealed)
	}
	if _, _, bodies := rr.snapshot(); len(bodies) != 0 {
		t.Errorf("the router saw %d requests under the default policy, want 0: the prompt must "+
			"not reach it in the clear", len(bodies))
	}
}

// -unsealed-subtree is inert while sealing is off. It only ever decided what a
// SEALED surface's namespace answers, and with nothing sealed every one of those
// paths is proxied — so `refuse` must not still be refusing sub-resources.
func TestSealPolicyOffMakesUnsealedSubtreeInert(t *testing.T) {
	for _, subtree := range []string{unsealedSubtreeRefuse, unsealedSubtreePassthrough} {
		t.Run(subtree, func(t *testing.T) {
			rr := &recordingRouter{}
			router := rr.server(nil)
			defer router.Close()
			gw := catalogGateway(t, router, entryPolicy{
				sealPolicy:      sealPolicyOff,
				unsealedSubtree: subtree,
			})

			for _, path := range []string{
				endpoint.Chat.Path + "/count_tokens",
				endpoint.Chat.Path + "/batches",
				endpoint.Chat.Path, // GET on the surface itself
			} {
				req, _ := http.NewRequest(http.MethodGet, gw.URL+path, nil)
				resp, err := http.DefaultClient.Do(req)
				if err != nil {
					t.Fatalf("get %s: %v", path, err)
				}
				resp.Body.Close()
				if resp.StatusCode != http.StatusOK {
					t.Errorf("%s = %d, want 200: with sealing off there is no sealed namespace "+
						"left to refuse", path, resp.StatusCode)
				}
			}
		})
	}
}

// Even with sealing off, the sealed surfaces must not be served from the catalog
// cache — they are POSTs carrying prompts, and one caller's completion must
// never be replayed to another. Guarded twice over (the cache is GET-only and
// allowlisted, and these mount the uncached passthrough), so this pins the
// outcome rather than either mechanism.
func TestSealPolicyOffStillNeverCachesAPrompt(t *testing.T) {
	rr := &recordingRouter{}
	router := rr.server(nil)
	defer router.Close()
	gw := catalogGateway(t, router, entryPolicy{sealPolicy: sealPolicyOff})

	var sent []string
	for _, body := range []string{`{"prompt":"first"}`, `{"prompt":"second"}`, `{"prompt":"third"}`} {
		req, _ := http.NewRequest(http.MethodPost, gw.URL+endpoint.Chat.Path, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("post: %v", err)
		}
		resp.Body.Close()
		sent = append(sent, body)
	}
	_, _, bodies := rr.snapshot()
	if len(bodies) != len(sent) {
		t.Fatalf("router saw %d prompts, want %d", len(bodies), len(sent))
	}
	for i := range sent {
		if bodies[i] != sent[i] {
			t.Errorf("router request %d = %q, want %q", i, bodies[i], sent[i])
		}
	}
}

// A build with no client for a row still refuses its sealed POST while sealing
// is ON — `off` is the only thing that turns a sealed surface into a proxy, and
// a build that cannot seal must not become one by accident.
func TestUnservedRowStillRefusesWhileSealingIsOn(t *testing.T) {
	rr := &recordingRouter{}
	router := rr.server(nil)
	defer router.Close()
	gw := httptest.NewServer(newHandler(map[string]*core.Client{}, mustURL(t, router.URL),
		testOrigins(), "", "", noInFlightCap, nil, nil, nil, discardLogger(),
		withEntryPolicy(entryPolicy{})))
	defer gw.Close()

	req, _ := http.NewRequest(http.MethodPost, gw.URL+endpoint.Chat.Path,
		strings.NewReader(`{"model":"m"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer sk-user-key")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotImplemented {
		t.Errorf("status = %d, want 501: a build that cannot seal must refuse, not forward",
			resp.StatusCode)
	}
	if _, _, bodies := rr.snapshot(); len(bodies) != 0 {
		t.Errorf("the router saw %d requests, want 0", len(bodies))
	}
}
