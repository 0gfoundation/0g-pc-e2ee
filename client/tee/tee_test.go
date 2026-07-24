package tee

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"net"
	"net/http"
	"path/filepath"
	"testing"
)

func TestMockEchoesReportData(t *testing.T) {
	rd := []byte{1, 2, 3, 4}
	q, err := Mock{}.Quote(context.Background(), rd)
	if err != nil {
		t.Fatal(err)
	}
	if string(q.ReportData) != string(rd) {
		t.Fatalf("report_data not echoed: got %x want %x", q.ReportData, rd)
	}
	if q.Quote != "mock-quote:"+hex.EncodeToString(rd) {
		t.Fatalf("unexpected mock quote %q", q.Quote)
	}
}

func TestReportDataRejectsOversize(t *testing.T) {
	big := make([]byte, MaxReportData+1)
	if _, err := (Mock{}).Quote(context.Background(), big); err == nil {
		t.Fatal("mock accepted oversize report_data")
	}
	if _, err := (&Dstack{}).Quote(context.Background(), big); err == nil {
		t.Fatal("dstack accepted oversize report_data")
	}
}

func TestReportDataForCertIsPubKeyDigest(t *testing.T) {
	cert := selfSignedCert(t)
	rd := ReportDataForCert(cert)
	if len(rd) != MaxReportData {
		t.Fatalf("report_data is %d bytes, want %d (the full TDX field)", len(rd), MaxReportData)
	}
	// Digest in the leading 32 bytes, the rest zero (so a verifier extracting the
	// 64-byte field matches byte-for-byte).
	for i := 32; i < MaxReportData; i++ {
		if rd[i] != 0 {
			t.Fatalf("report_data byte %d is %#x, want zero padding", i, rd[i])
		}
	}
	if [32]byte(rd[:32]) == [32]byte{} {
		t.Fatal("report_data digest is all zero")
	}
	if string(rd) != string(ReportDataForCert(cert)) {
		t.Fatal("report_data not deterministic")
	}
	// Bound to the public key, not the whole cert: a distinct cert with the SAME
	// key yields the same binding.
	if string(rd) != string(ReportDataForCert(reissueWithSameKey(t, cert))) {
		t.Fatal("report_data changed for a cert with the same public key")
	}
}

// TestDstackRPC drives the real Dstack RPC path against a fake tappd server on a
// unix socket, so the request/response marshaling is verified without a TEE.
func TestDstackRPC(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "tappd.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	mux := http.NewServeMux()
	mux.HandleFunc("/GetQuote", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			ReportData string `json:"report_data"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		// Echo the report_data hex back inside the quote so the test can assert it
		// round-tripped through the RPC correctly.
		_ = json.NewEncoder(w).Encode(map[string]string{
			"quote":     "tdxquote-" + req.ReportData,
			"event_log": "log",
			"vm_config": "cfg",
			"tcb_info":  `{"status":"UpToDate"}`,
		})
	})
	srv := &http.Server{Handler: mux}
	go srv.Serve(ln)
	defer srv.Close()

	rd := []byte{0xde, 0xad, 0xbe, 0xef}
	q, err := (&Dstack{Socket: sock}).Quote(context.Background(), rd)
	if err != nil {
		t.Fatal(err)
	}
	if q.Quote != "tdxquote-"+hex.EncodeToString(rd) {
		t.Fatalf("quote did not round-trip report_data: %q", q.Quote)
	}
	if string(q.ReportData) != string(rd) {
		t.Fatalf("report_data not preserved: %x", q.ReportData)
	}
	if q.TcbInfo != `{"status":"UpToDate"}` {
		t.Fatalf("tcb_info not carried: %q", q.TcbInfo)
	}
}

// TestDstackRejectsEmptyQuote: a 200 with an empty quote body must be an error,
// not a cached "success" that serves an attestation binding nothing.
func TestDstackRejectsEmptyQuote(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "tappd.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	mux := http.NewServeMux()
	mux.HandleFunc("/GetQuote", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{"quote": "", "event_log": "log"})
	})
	srv := &http.Server{Handler: mux}
	go srv.Serve(ln)
	defer srv.Close()

	if _, err := (&Dstack{Socket: sock}).Quote(context.Background(), []byte{1}); err == nil {
		t.Fatal("Dstack accepted an empty quote as success")
	}
}

func selfSignedCert(t *testing.T) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return certForKey(t, key, big.NewInt(1))
}

func reissueWithSameKey(t *testing.T, orig *x509.Certificate) *x509.Certificate {
	t.Helper()
	key, ok := orig.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		t.Fatal("unexpected key type")
	}
	// A fresh cert (different serial) over the same public key.
	return certForKeyPub(t, key, big.NewInt(2))
}

func certForKey(t *testing.T, key *ecdsa.PrivateKey, serial *big.Int) *x509.Certificate {
	t.Helper()
	tmpl := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: "gw"}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

// certForKeyPub signs a new cert with a throwaway key but embeds pub as the
// certificate subject public key, so RawSubjectPublicKeyInfo matches the original.
func certForKeyPub(t *testing.T, pub *ecdsa.PublicKey, serial *big.Int) *x509.Certificate {
	t.Helper()
	signer, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: "gw2"}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, signer)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}
