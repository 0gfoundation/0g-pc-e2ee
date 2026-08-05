package route

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/0gfoundation/0g-pc-e2ee/client/core"
)

func TestDeriveSignatureURL(t *testing.T) {
	cases := []struct {
		endpoint, key, want string
		wantErr             bool
	}{
		{"https://p.example.com", "ck-1", "https://p.example.com/v1/proxy/signature/ck-1", false},
		{"https://p.example.com/v1", "ck-1", "https://p.example.com/v1/proxy/signature/ck-1", false},
		{"https://p.example.com/v1/chat/completions", "ck_1", "https://p.example.com/v1/proxy/signature/ck_1", false},
		{"https://p.example.com", "../etc/passwd", "", true}, // path traversal rejected
		{"https://p.example.com", "", "", true},
		{"not-a-url", "ck-1", "", true},
	}
	for _, tc := range cases {
		got, err := deriveSignatureURL(tc.endpoint, tc.key)
		if tc.wantErr {
			if err == nil {
				t.Errorf("deriveSignatureURL(%q,%q) = %q, want error", tc.endpoint, tc.key, got)
			}
			continue
		}
		if err != nil || got != tc.want {
			t.Errorf("deriveSignatureURL(%q,%q) = %q,%v, want %q", tc.endpoint, tc.key, got, err, tc.want)
		}
	}
}

func TestFetchSignature_RoundTrip(t *testing.T) {
	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"text":"zg-sig-v1/e2ee-ct:aa:bb","signature":"0x1c","signing_address":"0xabc","signing_algo":"ecdsa"}`))
	}))
	defer srv.Close()

	f := NewSignatureFetcher(srv.Client())
	sig, err := f.FetchSignature(context.Background(), core.Provider{Endpoint: srv.URL}, "ck-9")
	if err != nil {
		t.Fatalf("FetchSignature: %v", err)
	}
	if gotPath != "/v1/proxy/signature/ck-9" {
		t.Fatalf("server saw path %q", gotPath)
	}
	if sig.Text != "zg-sig-v1/e2ee-ct:aa:bb" || sig.SigningAddress != "0xabc" {
		t.Fatalf("decoded unexpected signature: %+v", sig)
	}
}

func TestFetchSignature_Errors(t *testing.T) {
	f := NewSignatureFetcher(nil)
	if _, err := f.FetchSignature(context.Background(), core.Provider{}, "ck-1"); err == nil {
		t.Fatal("want error for empty endpoint")
	}

	notFound := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `{"error":"chat_id_not_found"}`, http.StatusNotFound)
	}))
	defer notFound.Close()
	_, err := NewSignatureFetcher(notFound.Client()).FetchSignature(context.Background(), core.Provider{Endpoint: notFound.URL}, "ck-1")
	if err == nil || !strings.Contains(err.Error(), "404") {
		t.Fatalf("want 404 error, got %v", err)
	}
}

func TestFetchSignature_RetriesThenSucceeds(t *testing.T) {
	var n int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if atomic.AddInt32(&n, 1) < 3 { // 404 twice (broker not-yet-cached), then serve
			http.Error(w, `{"error":"chat_id_not_found"}`, http.StatusNotFound)
			return
		}
		_, _ = w.Write([]byte(`{"text":"zg-sig-v1/e2ee-ct:aa:bb","signature":"0x1c","signing_address":"0xabc","signing_algo":"ecdsa"}`))
	}))
	defer srv.Close()

	sig, err := NewSignatureFetcher(srv.Client()).FetchSignature(context.Background(), core.Provider{Endpoint: srv.URL}, "ck-1")
	if err != nil {
		t.Fatalf("expected success after transient 404s: %v", err)
	}
	if sig.Text == "" {
		t.Fatal("empty signature after retry")
	}
	if got := atomic.LoadInt32(&n); got != 3 {
		t.Fatalf("expected 3 attempts, got %d", got)
	}
}

func TestFetchSignature_NoRetryOn4xx(t *testing.T) {
	var n int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&n, 1)
		http.Error(w, `{"error":"bad request"}`, http.StatusBadRequest)
	}))
	defer srv.Close()

	_, err := NewSignatureFetcher(srv.Client()).FetchSignature(context.Background(), core.Provider{Endpoint: srv.URL}, "ck-1")
	if err == nil {
		t.Fatal("want error for 400")
	}
	if got := atomic.LoadInt32(&n); got != 1 {
		t.Fatalf("a 400 must not be retried, got %d attempts", got)
	}
}
