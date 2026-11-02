package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/0gfoundation/0g-pc-e2ee/client/freshquote"
)

func writeCert(t *testing.T) (path, spkiB64 string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "gw"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	path = filepath.Join(t.TempDir(), "cert-gw.pem")
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644); err != nil {
		t.Fatal(err)
	}
	return path, base64.StdEncoding.EncodeToString(cert.RawSubjectPublicKeyInfo)
}

var discard = slog.New(slog.NewTextHandler(io.Discard, nil))

func get(h http.Handler, target string) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, target, nil))
	return rec
}

func TestQuoteBindsNonceAndServedCert(t *testing.T) {
	certPath, spki := writeCert(t)
	var gotRD [64]byte
	h := newHandler(certPath, func(_ context.Context, rd [64]byte) ([]byte, error) {
		gotRD = rd
		return []byte("QUOTE"), nil
	}, 1, discard)

	nonce := strings.Repeat("AB", 32) // upper case is folded before hashing
	rec := get(h, "/quote?nonce="+nonce)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rec.Code, rec.Body)
	}
	var resp freshquote.Response
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.E2EPubkey != spki {
		t.Errorf("e2e_pubkey is not the certificate's SPKI")
	}
	if resp.Quote != base64.StdEncoding.EncodeToString([]byte("QUOTE")) {
		t.Errorf("quote = %q", resp.Quote)
	}
	if gotRD != freshquote.ReportData(strings.ToLower(nonce), spki) {
		t.Errorf("report_data does not commit to (lowercase nonce, served SPKI)")
	}
}

func TestQuoteErrors(t *testing.T) {
	certPath, _ := writeCert(t)
	ok := func(context.Context, [64]byte) ([]byte, error) { return []byte("q"), nil }
	nonce := strings.Repeat("00", 32)

	if rec := get(newHandler(certPath, ok, 1, discard), "/quote?nonce=abc"); rec.Code != http.StatusBadRequest {
		t.Errorf("bad nonce: status %d, want 400", rec.Code)
	}
	missing := filepath.Join(t.TempDir(), "absent.pem")
	if rec := get(newHandler(missing, ok, 1, discard), "/quote?nonce="+nonce); rec.Code != http.StatusServiceUnavailable {
		t.Errorf("no certificate yet: status %d, want 503", rec.Code)
	}
	fail := func(context.Context, [64]byte) ([]byte, error) { return nil, errors.New("agent down") }
	if rec := get(newHandler(certPath, fail, 1, discard), "/quote?nonce="+nonce); rec.Code != http.StatusBadGateway {
		t.Errorf("agent failure: status %d, want 502", rec.Code)
	}
	rec := httptest.NewRecorder()
	newHandler(certPath, ok, 1, discard).ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/quote?nonce="+nonce, nil))
	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("POST: status %d, want 405", rec.Code)
	}
}

func TestQuoteRejectsWhenFull(t *testing.T) {
	certPath, _ := writeCert(t)
	entered, release := make(chan struct{}), make(chan struct{})
	h := newHandler(certPath, func(context.Context, [64]byte) ([]byte, error) {
		close(entered)
		<-release
		return []byte("q"), nil
	}, 1, discard)
	nonce := strings.Repeat("00", 32)

	done := make(chan int)
	go func() { done <- get(h, "/quote?nonce="+nonce).Code }()
	<-entered
	if rec := get(h, "/quote?nonce="+nonce); rec.Code != http.StatusTooManyRequests {
		t.Errorf("second request while full: status %d, want 429", rec.Code)
	}
	close(release)
	if code := <-done; code != http.StatusOK {
		t.Errorf("first request: status %d", code)
	}
}
