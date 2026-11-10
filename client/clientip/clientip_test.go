package clientip

import (
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

// The cross-implementation vector. The router's verifier test carries the same
// three inputs and expected signature (0g-router backend/internal/middleware
// client_ip_header_test.go); change both or neither.
const (
	vectorKeyHex = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
	vectorIP     = "203.0.113.7"
	vectorTs     = int64(1762790000)
	// knownVectorSig was computed independently with
	//   printf '0g-client-ip/v1\n203.0.113.7\n1762790000' | openssl dgst -sha256 -mac HMAC -macopt hexkey:<vectorKeyHex>
	knownVectorSig = "028032077f0bb4a63592a1578122a808205a8e4b91958443d0a54666f12f7a58"
)

func TestMessageFormat(t *testing.T) {
	if got := string(Message(vectorIP, vectorTs)); got != "0g-client-ip/v1\n203.0.113.7\n1762790000" {
		t.Fatalf("Message = %q", got)
	}
}

func TestSignVector(t *testing.T) {
	key, _ := hex.DecodeString(vectorKeyHex)
	got := Sign(key, vectorIP, vectorTs)
	if got != knownVectorSig {
		t.Fatalf("Sign(vector) = %s, want %s — the router's copy of this vector must change too", got, knownVectorSig)
	}
}

func mustSigner(t *testing.T, router string) *Signer {
	t.Helper()
	u, _ := url.Parse(router)
	s, err := NewSigner(vectorKeyHex, u)
	if err != nil {
		t.Fatal(err)
	}
	s.now = func() time.Time { return time.Unix(vectorTs, 0) }
	return s
}

func TestNewSignerRejectsBadKeys(t *testing.T) {
	u, _ := url.Parse("https://router.example")
	for _, k := range []string{"", "zz", strings.Repeat("ab", MinKeyBytes-1)} {
		if _, err := NewSigner(k, u); err == nil {
			t.Errorf("NewSigner(%q) accepted", k)
		}
	}
	if _, err := NewSigner(vectorKeyHex, &url.URL{}); err == nil {
		t.Error("NewSigner accepted an empty router URL")
	}
}

// stampVia runs a request with RemoteAddr through the Middleware and returns the
// outbound request a handler would build to target, after Stamp.
func stampVia(t *testing.T, s *Signer, remoteAddr, target string, inbound http.Header) *http.Request {
	t.Helper()
	var out *http.Request
	h := s.Middleware(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		req, err := http.NewRequestWithContext(r.Context(), http.MethodGet, target, nil)
		if err != nil {
			t.Fatal(err)
		}
		for k, vs := range inbound {
			req.Header[k] = vs
		}
		Stamp(req)
		out = req
	}))
	in := httptest.NewRequest(http.MethodGet, "/v1/models", nil)
	in.RemoteAddr = remoteAddr
	h.ServeHTTP(httptest.NewRecorder(), in)
	return out
}

func TestStampSignsRouterBoundRequests(t *testing.T) {
	s := mustSigner(t, "https://router-api-cloud.0g.ai")
	for _, target := range []string{
		"https://router-api-cloud.0g.ai/v1/chat/completions",
		"https://ROUTER-API-CLOUD.0g.ai:443/v1/routing/preview",
	} {
		req := stampVia(t, s, "203.0.113.7:51000", target, nil)
		if req.Header.Get(HeaderIP) != vectorIP || req.Header.Get(HeaderTs) != "1762790000" || req.Header.Get(HeaderSig) != knownVectorSig {
			t.Errorf("%s: headers %v", target, req.Header)
		}
	}
}

func TestStampCanonicalisesIPv6AndMappedIPv4(t *testing.T) {
	s := mustSigner(t, "https://router.example")
	if got := stampVia(t, s, "[2001:DB8::7]:1", "https://router.example/x", nil).Header.Get(HeaderIP); got != "2001:db8::7" {
		t.Errorf("IPv6 = %q", got)
	}
	if got := stampVia(t, s, "[::ffff:203.0.113.7]:1", "https://router.example/x", nil).Header.Get(HeaderIP); got != "203.0.113.7" {
		t.Errorf("mapped IPv4 = %q", got)
	}
}

// A provider's broker is a third party: it must never receive the address, and a
// client-forged set must not ride along either.
func TestStampNeverSendsTheAddressElsewhere(t *testing.T) {
	s := mustSigner(t, "https://router.example")
	forged := http.Header{HeaderIP: {"6.6.6.6"}, HeaderTs: {"1"}, HeaderSig: {"ff"}}
	for _, target := range []string{
		"https://broker.provider.example/v1/quote",
		"https://router.example.evil.com/x",
		"http://router.example/x", // same host, other default port (80 vs 443)
		"https://router.example:8443/x",
	} {
		req := stampVia(t, s, "203.0.113.7:51000", target, forged)
		for _, h := range []string{HeaderIP, HeaderTs, HeaderSig} {
			if v := req.Header.Get(h); v != "" {
				t.Errorf("%s: %s = %q leaked", target, h, v)
			}
		}
	}
}

// A client that sends the headers itself to the gateway: they are replaced by ours.
func TestStampReplacesForgedHeaders(t *testing.T) {
	s := mustSigner(t, "https://router.example")
	forged := http.Header{HeaderIP: {"6.6.6.6"}, HeaderTs: {"1"}, HeaderSig: {"ff"}}
	req := stampVia(t, s, "203.0.113.7:51000", "https://router.example/x", forged)
	if got := req.Header.Values(HeaderIP); len(got) != 1 || got[0] != vectorIP {
		t.Fatalf("X-0G-Client-IP = %v", got)
	}
}

// The -health probe and a local run come from loopback: nothing is signed, and a
// forged set is still stripped.
func TestLoopbackPeerIsNotSigned(t *testing.T) {
	s := mustSigner(t, "https://router.example")
	req := stampVia(t, s, "127.0.0.1:40000", "https://router.example/x", http.Header{HeaderIP: {"6.6.6.6"}})
	if v := req.Header.Get(HeaderIP); v != "" {
		t.Fatalf("loopback peer stamped/leaked %q", v)
	}
}

// Without the Middleware (no signer configured, or a background request), Stamp
// only strips.
func TestStampWithoutContextOnlyStrips(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "https://router.example/x", nil)
	req.Header.Set(HeaderIP, "6.6.6.6")
	req.Header.Set(HeaderSig, "ff")
	Stamp(req)
	if req.Header.Get(HeaderIP) != "" || req.Header.Get(HeaderSig) != "" {
		t.Fatalf("headers survived: %v", req.Header)
	}
}
