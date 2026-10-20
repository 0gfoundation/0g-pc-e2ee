package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/0gfoundation/0g-pc-e2ee/client/evidence"
)

type stubChain struct {
	report chainReport
	err    error
	// leaf records the pin the step asked for.
	leaf *[sha256.Size]byte
}

func (s stubChain) ReadChain(_ context.Context, _ string, leaf [sha256.Size]byte) (chainReport, error) {
	if s.leaf != nil {
		*s.leaf = leaf
	}
	return s.report, s.err
}

func named(n string) chainReport {
	return chainReport{Network: &n, RPCURL: "https://rpc.test", ServingContract: "0xc0ffee"}
}

func TestReportGatewayChain(t *testing.T) {
	for _, tc := range []struct {
		name     string
		want     string
		read     chainReader
		unbound  bool
		wantCode int
		says     string
	}{
		{name: "mainnet as expected", want: "mainnet", read: stubChain{report: named("mainnet")},
			wantCode: 0, says: "✓ chain              mainnet, as the gateway reports it"},
		{name: "testnet as expected", want: "testnet", read: stubChain{report: named("testnet")},
			wantCode: 0, says: "✓ chain              testnet"},
		{name: "testnet where mainnet was expected", want: "mainnet", read: stubChain{report: named("testnet")},
			wantCode: 1, says: "✗ chain              testnet, as the gateway reports it (want mainnet)"},
		{name: "a root nobody named", want: "mainnet", read: stubChain{report: chainReport{RPCURL: "http://node"}},
			wantCode: 1, says: "✗ chain              custom"},
		{name: "older build is mainnet", want: "mainnet", read: stubChain{err: errNoChainReport},
			wantCode: 0, says: "✓ chain              mainnet, the only network"},
		{name: "older build is not testnet", want: "testnet", read: stubChain{err: errNoChainReport},
			wantCode: 1, says: "✗ chain              mainnet, the only network"},
		{name: "unreadable", want: "mainnet", read: stubChain{err: errors.New("connection refused")},
			wantCode: 3, says: "- chain              not checked: connection refused"},
		{name: "turned off", want: "", read: stubChain{report: named("mainnet")},
			wantCode: 3, says: "not checked (-network is empty)"},
		{name: "not asked", want: "mainnet", read: nil, wantCode: 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var out bytes.Buffer
			code := reportGateway(context.Background(), &out, stubEvidence{rep: passing()}, "pc-gateway.test",
				false, false, expectSource{Label: "newest 5 release(s)"}, chainCheck{want: tc.want, read: tc.read})
			if code != tc.wantCode {
				t.Errorf("exit %d, want %d:\n%s", code, tc.wantCode, out.String())
			}
			if tc.says != "" && !strings.Contains(out.String(), tc.says) {
				t.Errorf("output does not say %q:\n%s", tc.says, out.String())
			}
			if tc.read == nil && strings.Contains(out.String(), "chain  ") {
				t.Errorf("a run that never asked printed a chain line:\n%s", out.String())
			}
		})
	}
}

// The network is read only over the connection step 4 bound to the quote: without
// that, whatever answers is not known to be the attested code.
func TestReportGatewayChainNeedsEndpointBinding(t *testing.T) {
	rep := passing()
	rep.CertMatch = evidence.CertMismatch
	var leaf [sha256.Size]byte
	var out bytes.Buffer
	reportGateway(context.Background(), &out, stubEvidence{rep: rep}, "pc-gateway.test", false, false,
		expectSource{Label: "newest 5 release(s)"}, chainCheck{want: "mainnet", read: stubChain{report: named("mainnet"), leaf: &leaf}})
	if !strings.Contains(out.String(), "not checked (needs the endpoint binding above)") {
		t.Errorf("read the network over an unbound connection:\n%s", out.String())
	}
	if leaf != ([sha256.Size]byte{}) {
		t.Error("the reader was called")
	}

	rep = passing()
	rep.ServedCertSHA256 = sha256.Sum256([]byte("leaf"))
	out.Reset()
	reportGateway(context.Background(), &out, stubEvidence{rep: rep}, "pc-gateway.test", false, false,
		expectSource{Label: "newest 5 release(s)"}, chainCheck{want: "mainnet", read: stubChain{report: named("mainnet"), leaf: &leaf}})
	if leaf != rep.ServedCertSHA256 {
		t.Errorf("pinned %x, want the served certificate %x", leaf, rep.ServedCertSHA256)
	}
}

func TestParseChainReport(t *testing.T) {
	c, err := parseChainReport([]byte(`{"instance_id":"a","chain":{"network":"testnet","rpc_url":"https://r","serving_contract":"0x1"}}`))
	if err != nil || c.Network == nil || *c.Network != "testnet" || c.RPCURL != "https://r" || c.ServingContract != "0x1" {
		t.Fatalf("parsed %+v, %v", c, err)
	}
	c, err = parseChainReport([]byte(`{"chain":{"network":null,"rpc_url":"http://node","serving_contract":"0x1"}}`))
	if err != nil || c.Network != nil {
		t.Fatalf("a null network parsed as %+v, %v", c, err)
	}
	for _, body := range []string{`{"instance_id":"a"}`, `{"chain":null}`} {
		if _, err := parseChainReport([]byte(body)); !errors.Is(err, errNoChainReport) {
			t.Errorf("%s: err = %v, want errNoChainReport", body, err)
		}
	}
	if _, err := parseChainReport([]byte(`not json`)); err == nil || errors.Is(err, errNoChainReport) {
		t.Errorf("garbage: err = %v", err)
	}
}

// The reader talks only to the certificate it was given, whatever else would
// validate: a different one is refused before a byte of the document is read.
func TestHTTPChainReaderPinsTheCertificate(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != gatewayIdentityPath {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write([]byte(`{"chain":{"network":"mainnet","rpc_url":"https://r","serving_contract":"0x1"}}`))
	}))
	defer srv.Close()
	host := strings.TrimPrefix(srv.URL, "https://")
	leaf := sha256.Sum256(srv.Certificate().Raw)
	// The test certificate is self-signed, which is what -allow-untrusted-cert is for;
	// the pin is checked either way.
	r := httpChainReader{timeout: 5 * time.Second, allowUntrustedCert: true}

	c, err := r.ReadChain(context.Background(), host, leaf)
	if err != nil || c.Network == nil || *c.Network != "mainnet" {
		t.Fatalf("pinned read: %+v, %v", c, err)
	}
	if _, err := r.ReadChain(context.Background(), host, sha256.Sum256([]byte("another"))); err == nil ||
		!strings.Contains(err.Error(), "not the one the quote binds") {
		t.Fatalf("a different certificate was accepted: %v", err)
	}
	// Without the waiver ordinary validation runs too, and a self-signed certificate
	// fails it even when pinned.
	strict := httpChainReader{timeout: 5 * time.Second}
	if _, err := strict.ReadChain(context.Background(), host, leaf); err == nil {
		t.Fatal("an untrusted certificate passed without -allow-untrusted-cert")
	}
}
