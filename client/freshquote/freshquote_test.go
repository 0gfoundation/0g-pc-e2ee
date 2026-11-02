package freshquote

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"
	"time"
)

// TestReportDataVector pins the byte layout against a value computed with AntSeed's
// own builder (antseed-verifier src/report-data.ts, noncePubkeySha256V1.build):
//
//	createHash('sha256').update(nonceHex,'utf8').update(pubkeyB64,'utf8').digest('hex')
//
// A drift here fails their verifier for every quote, so it is a fixed vector rather
// than a re-implementation of the formula.
func TestReportDataVector(t *testing.T) {
	nonce := strings.Repeat("11", 32)
	pub := "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE"
	rd := ReportData(nonce, pub)
	if got, want := hex.EncodeToString(rd[:32]), "58314413bcfba5f38af88d24a9d109819fa3a227a2ca46b014237bd838610ae5"; got != want {
		t.Errorf("report_data[0:32] = %s, want %s", got, want)
	}
	for i, b := range rd[32:] {
		if b != 0 {
			t.Fatalf("report_data[%d] = %#x, want zero", 32+i, b)
		}
	}
}

func TestParseNonce(t *testing.T) {
	upper := strings.Repeat("AB", 32)
	got, err := ParseNonce(upper)
	if err != nil || got != strings.Repeat("ab", 32) {
		t.Errorf("ParseNonce(upper) = %q, %v; want lowercase", got, err)
	}
	for _, bad := range []string{"", strings.Repeat("a", 63), strings.Repeat("a", 66), strings.Repeat("zz", 32)} {
		if _, err := ParseNonce(bad); err == nil {
			t.Errorf("ParseNonce(%q) succeeded", bad)
		}
	}
}

func TestSPKIBase64TakesLeaf(t *testing.T) {
	leaf, leafDER := selfSigned(t, "leaf")
	_, caDER := selfSigned(t, "ca")
	fullchain := append(pemCert(leafDER), pemCert(caDER)...)
	got, err := SPKIBase64(fullchain)
	if err != nil {
		t.Fatal(err)
	}
	if want := base64.StdEncoding.EncodeToString(leaf.RawSubjectPublicKeyInfo); got != want {
		t.Errorf("SPKI is not the first certificate's")
	}
	if _, err := SPKIBase64([]byte("not a pem")); err == nil {
		t.Error("SPKIBase64 accepted a non-PEM input")
	}
}

func selfSigned(t *testing.T, cn string) (*x509.Certificate, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert, der
}

func pemCert(der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}
