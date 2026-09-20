package main

import (
	"bufio"
	"fmt"
	"net"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/0gfoundation/0g-pc-e2ee/client/endpoint"
	"github.com/0gfoundation/0g-pc-e2ee/client/openaiproxy"
)

// rawPOST writes the request line VERBATIM over a socket and returns the status
// line plus headers.
//
// net/http's client is not usable for these cases: it normalises the URL it is
// given, so `%2F` and an odd-cased path never survive to the wire and the test
// would assert against a spelling the gateway never sees. A raw socket is the only
// way to send what an attacker (or a sloppy SDK) actually sends.
func rawPOST(t *testing.T, addr, target, body string) (status string, header map[string]string) {
	t.Helper()
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	fmt.Fprintf(conn, "POST %s HTTP/1.1\r\nHost: gw\r\nAuthorization: Bearer sk-user-key\r\n"+
		"Content-Type: application/json\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s",
		target, len(body), body)

	br := bufio.NewReader(conn)
	line, err := br.ReadString('\n')
	if err != nil {
		t.Fatalf("read status: %v", err)
	}
	status = strings.TrimSpace(line)
	header = map[string]string{}
	for {
		line, err := br.ReadString('\n')
		if err != nil || strings.TrimSpace(line) == "" {
			break
		}
		if k, v, ok := strings.Cut(line, ":"); ok {
			header[strings.ToLower(strings.TrimSpace(k))] = strings.TrimSpace(v)
		}
	}
	return status, header
}

// A sealed surface's own POST must never reach the cleartext proxy — in ANY
// spelling of its path, not just the canonical one.
//
// Three spellings were confirmed leaking against the real handler before this
// guard existed, each answering 200 with the whole prompt in the router's log:
//
//	POST /v1/chat/completions%2F     ServeMux matches the ESCAPED path segment by
//	                                 segment, so %2F is an ordinary character and
//	                                 this matches neither the exact path nor the
//	                                 subtree — it fell to the catch-all.
//	POST /V1/chat/completions        ServeMux is case-sensitive. Same fall-through.
//	POST /v1/Chat/completions        Likewise.
//
// All three are invisible to the caller: the router's gin answers the decoded path
// with a 307 onto the canonical one, the retry is sealed and served, and only the
// first request leaked. That is why this asserts on what the ROUTER RECEIVED
// rather than on the status the caller saw — the caller's view is exactly what
// makes the defect survivable in production.
//
// Driven off endpoint.All so a row added later is covered the day it lands.
func TestSealedSurfaceSpellingsNeverReachTheRouter(t *testing.T) {
	// spell returns an alternative spelling of path, or "" when the transform does
	// not apply to it.
	spellings := map[string]func(path string) string{
		"percent-encoded trailing slash": func(p string) string { return p + "%2F" },
		"upper-cased first segment": func(p string) string {
			seg := strings.SplitN(strings.TrimPrefix(p, "/"), "/", 2)
			return "/" + strings.ToUpper(seg[0]) + "/" + seg[1]
		},
		"upper-cased last segment": func(p string) string {
			i := strings.LastIndex(p, "/")
			return p[:i+1] + strings.ToUpper(p[i+1:])
		},
	}

	for _, mode := range []string{unsealedSubtreeRefuse, unsealedSubtreePassthrough} {
		t.Run(mode, func(t *testing.T) {
			rr := &recordingRouter{}
			router := rr.server(nil)
			defer router.Close()

			// The sealed client points at a DIFFERENT (dead) router, so anything the
			// recording router sees arrived through the cleartext passthrough.
			gw := httptest.NewServer(newHandler(allSealedClients(), mustURL(t, router.URL), testOrigins(), "", "",
				noInFlightCap, nil, nil, nil, discardLogger(),
				withEntryPolicy(entryPolicy{unsealedSubtree: mode})))
			defer gw.Close()
			addr := strings.TrimPrefix(gw.URL, "http://")

			const secret = "my secret prompt"
			body := `{"model":"m","prompt":"` + secret + `","messages":[{"role":"user","content":"` + secret + `"}]}`
			for _, ep := range endpoint.All {
				for name, spell := range spellings {
					target := spell(ep.Path)
					t.Run(ep.Path+" / "+name, func(t *testing.T) {
						_, hdr := rawPOST(t, addr, target, body)
						if got := hdr[strings.ToLower(openaiproxy.HeaderE2EE)]; got != openaiproxy.E2EEValueSealed {
							t.Errorf("POST %s: %s = %q, want %q — every spelling of a sealed "+
								"surface belongs to the sealed path", target,
								openaiproxy.HeaderE2EE, got, openaiproxy.E2EEValueSealed)
						}
					})
				}
			}

			paths, _, bodies := rr.snapshot()
			for i, b := range bodies {
				if strings.Contains(b, secret) {
					t.Fatalf("the prompt reached the router in the clear at %s: %s", paths[i], b)
				}
			}
			if len(paths) != 0 {
				t.Errorf("a sealed surface was forwarded to the router: %v", paths)
			}
		})
	}
}

// A sub-resource spelled with %2F is answered exactly as the literal spelling is —
// refused under `refuse`, forwarded and marked under `passthrough`.
//
// The point is that the guard FOLDS spellings rather than inventing a third
// behaviour for them: `/v1/messages%2Fcount_tokens` and
// `/v1/messages/count_tokens` are the same request, so whatever policy governs one
// governs the other. Under `refuse` that means the 501 covers the encoded form too,
// which is what stops it being a way around the refusal.
func TestSubResourceSpellingFollowsThePolicy(t *testing.T) {
	tests := []struct {
		mode       string
		wantMark   string
		wantRouter int
	}{
		{unsealedSubtreeRefuse, "", 0},
		{unsealedSubtreePassthrough, openaiproxy.E2EEValueNone, 1},
	}
	for _, tt := range tests {
		t.Run(tt.mode, func(t *testing.T) {
			rr := &recordingRouter{}
			router := rr.server(nil)
			defer router.Close()

			gw := httptest.NewServer(newHandler(allSealedClients(), mustURL(t, router.URL), testOrigins(), "", "",
				noInFlightCap, nil, nil, nil, discardLogger(),
				withEntryPolicy(entryPolicy{unsealedSubtree: tt.mode})))
			defer gw.Close()

			status, hdr := rawPOST(t, strings.TrimPrefix(gw.URL, "http://"),
				endpoint.Anthropic.Path+"%2Fcount_tokens", `{"model":"m"}`)

			if tt.wantRouter == 0 && !strings.Contains(status, "501") {
				t.Errorf("status = %q, want 501: the encoded spelling must be refused like the literal one", status)
			}
			if tt.wantMark != "" {
				if got := hdr[strings.ToLower(openaiproxy.HeaderE2EE)]; got != tt.wantMark {
					t.Errorf("%s = %q, want %q", openaiproxy.HeaderE2EE, got, tt.wantMark)
				}
			}
			paths, _, _ := rr.snapshot()
			if len(paths) != tt.wantRouter {
				t.Errorf("the router saw %v, want %d request(s) — the encoded spelling must follow "+
					"the same policy as the literal one", paths, tt.wantRouter)
			}
			// And when it IS forwarded, it goes with the canonical spelling: the guard
			// folds the surface prefix, so the router is not handed a path whose
			// escaping it would have to re-interpret.
			if len(paths) == 1 && !strings.HasSuffix(paths[0], endpoint.Anthropic.Path+"/count_tokens") {
				t.Errorf("forwarded as %q, want the canonical %q", paths[0],
					endpoint.Anthropic.Path+"/count_tokens")
			}
		})
	}
}
