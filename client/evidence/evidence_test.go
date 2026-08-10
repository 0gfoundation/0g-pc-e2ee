package evidence

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/0gfoundation/0g-pc-e2ee/protocol/attest"
)

const testDomain = "pc-gateway.test"

// TDX v4 quote geometry, mirrored here so the fixture can synthesize a
// structurally valid quote prefix. The DCAP *verification* is the injected
// QuoteParser's job (as in production, where client/dcap fills that seam), but the
// Checker re-reads mr_config_id structurally from the verified bytes, so those
// bytes have to be the right shape and carry the right fields.
const (
	fxQuoteLen      = 632 // 48-byte header + 584-byte TD report body
	fxMRConfigOff   = 232
	fxReportDataOff = 568
)

// mkMRConfigID builds a dstack mr_config_id: a version byte, then the compose hash,
// then zero padding.
func mkMRConfigID(version byte, composeHash [attest.ComposeHashLen]byte) [48]byte {
	var r [48]byte
	r[0] = version
	copy(r[1:], composeHash[:])
	return r
}

// mkRawQuote synthesizes the quote prefix the fixture publishes: the right length,
// with mr_config_id and report_data at their real offsets.
func mkRawQuote(mrConfigID [48]byte, reportData [64]byte) []byte {
	raw := make([]byte, fxQuoteLen)
	copy(raw[fxMRConfigOff:], mrConfigID[:])
	copy(raw[fxReportDataOff:], reportData[:])
	return raw
}

// certPair is a certificate plus the key that signs for it.
type certPair struct {
	cert *x509.Certificate
	der  []byte
	key  *ecdsa.PrivateKey
}

func (c certPair) pemBytes() []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.der})
}

// newCA makes a self-signed CA, standing in for Let's Encrypt.
func newCA(t *testing.T) certPair {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ca key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test Evidence CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("ca cert: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse ca cert: %v", err)
	}
	return certPair{cert: cert, der: der, key: key}
}

// newLeaf issues a serving certificate for testDomain under ca. Passing a non-nil
// key reuses it, which is how the same-key/different-bytes (stale evidence) case
// is built.
func newLeaf(t *testing.T, ca certPair, serial int64, key *ecdsa.PrivateKey) certPair {
	t.Helper()
	if key == nil {
		var err error
		key, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatalf("leaf key: %v", err)
		}
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(serial),
		Subject:      pkix.Name{CommonName: testDomain},
		DNSNames:     []string{testDomain},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatalf("leaf cert: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse leaf cert: %v", err)
	}
	return certPair{cert: cert, der: der, key: key}
}

// rotateCert is a newFixture option: see fixture.rotateCert.
func rotateCert(f *fixture) { f.rotateCert = true }

// fixture is a running stand-in for a dstack-ingress CVM: an HTTPS endpoint
// serving an evidence bundle under /evidences/ and presenting a certificate.
type fixture struct {
	domain string
	files  map[string][]byte
	server *httptest.Server
	ca     certPair
	served certPair
	// reportData is what the fixture's quote parser returns, set by bindQuote so a
	// test can bind the quote to something other than the served manifest.
	reportData [64]byte
	// rotateCert makes the server present a DIFFERENT certificate on every handshake
	// after the first — what a domain backed by several CVMs looks like, since dstack
	// picks a replica per TCP connection and each generates its own key inside itself.
	// handshakes counts them, guarded because the TLS callback may run off the test
	// goroutine.
	rotateCert  bool
	handshakeMu sync.Mutex
	handshakes  int
	// wantDNSDiscovery opts a test into the DNS-derived base-domain path; checker()
	// otherwise disables it, since testDomain does not resolve.
	wantDNSDiscovery bool
	// mrConfigID is what the published quote carries at the mr_config_id offset.
	// Defaults to a valid dstack V1 register; a test overrides it (before Check) to
	// exercise the unsupported-layout paths.
	mrConfigID [48]byte
}

// newFixture builds the happy path: the bundle names the same certificate the
// endpoint serves, and the quote binds the manifest. Mutators run after the
// bundle's files are laid out but before the manifest and quote are computed, so a
// test can change what the bundle *claims*; mutate f.files afterwards to change
// what it *serves*.
func newFixture(t *testing.T, opts ...func(*fixture)) *fixture {
	t.Helper()
	ca := newCA(t)
	leaf := newLeaf(t, ca, 100, nil)

	f := &fixture{domain: testDomain, ca: ca, served: leaf, files: map[string][]byte{}}
	// A valid dstack V1 register by default, committing to the test app-compose, so
	// the code-identity hop works without every test setting it up.
	f.mrConfigID = mkMRConfigID(1, composeHashOf(testAppCompose))
	// lego publishes the fullchain, leaf first (dstack-ingress evidence_collect_cert).
	f.files[accountName] = []byte(`{"status":"valid","uri":"https://acme.test/acct/1"}`)
	f.files[certName(testDomain)] = append(leaf.pemBytes(), ca.pemBytes()...)
	for _, o := range opts {
		o(f)
	}
	f.finalize(t, nil)

	mux := http.NewServeMux()
	mux.HandleFunc("/evidences/", func(w http.ResponseWriter, r *http.Request) {
		name := strings.TrimPrefix(r.URL.Path, "/evidences/")
		body, ok := f.files[name]
		if !ok {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write(body)
	})
	primary := &tls.Certificate{
		Certificate: [][]byte{f.served.der, ca.der},
		PrivateKey:  f.served.key,
	}
	srv := httptest.NewUnstartedServer(mux)
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{*primary}}
	if f.rotateCert {
		// A second replica's certificate, minted up front so the callback needs no *testing.T.
		alt := newLeaf(t, ca, 101, nil)
		altPair := &tls.Certificate{Certificate: [][]byte{alt.der, ca.der}, PrivateKey: alt.key}
		srv.TLS = &tls.Config{GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
			f.handshakeMu.Lock()
			defer f.handshakeMu.Unlock()
			f.handshakes++
			if f.handshakes == 1 {
				return primary, nil
			}
			return altPair, nil
		}}
	}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	f.server = srv
	return f
}

// finalize writes sha256sum.txt over the collected files and the quote.json bound
// to it, mirroring dstack-ingress's evidence_finalize. bindTo overrides the bytes
// the quote's report_data commits to, for the "quote binds a different bundle" case.
func (f *fixture) finalize(t *testing.T, bindTo []byte) {
	t.Helper()
	// sha256sum's argument order in evidence_finalize: the account document, then
	// the certificates.
	var manifest strings.Builder
	for _, name := range []string{accountName, certName(f.domain)} {
		body, ok := f.files[name]
		if !ok {
			continue
		}
		sum := sha256.Sum256(body)
		fmt.Fprintf(&manifest, "%x  %s\n", sum, name)
	}
	f.files[manifestName] = []byte(manifest.String())
	if bindTo == nil {
		bindTo = f.files[manifestName]
	}
	f.bindQuote(bindTo)
}

func (f *fixture) bindQuote(manifest []byte) {
	f.reportData = attest.EvidenceReportData(manifest)
	f.publishQuote()
}

// publishQuote (re)writes quote.json from the fixture's current report_data and
// mr_config_id. Called by bindQuote, and again by checker() so a test that
// overrode mrConfigID after construction is reflected in the published bytes.
func (f *fixture) publishQuote() {
	raw := mkRawQuote(f.mrConfigID, f.reportData)
	f.files[quoteName] = []byte(`{"quote":"` + hex.EncodeToString(raw) + `"}`)
}

// parser is the injected DCAP seam. It stands in for the real verifier: it checks
// the bytes are the ones the fixture published and returns the measurement and
// report_data, exactly as client/dcap does after a successful DCAP verify.
func (f *fixture) parser() QuoteParser {
	return func(raw []byte) (attest.Measurement, [64]byte, error) {
		want := mkRawQuote(f.mrConfigID, f.reportData)
		if string(raw) != string(want) {
			return attest.Measurement{}, [64]byte{}, fmt.Errorf("unexpected quote bytes %x", raw)
		}
		return attest.Measurement{MRTD: [48]byte{0x11}}, f.reportData, nil
	}
}

// dialPlain returns a DialContext that ignores the requested address and connects
// to the fixture, so a client can keep its own TLS configuration while reaching a
// server that testDomain does not actually resolve to.
func (f *fixture) dialPlain() func(context.Context, string, string) (net.Conn, error) {
	addr := f.server.Listener.Addr().String()
	return func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "tcp", addr)
	}
}

// dialTLS is the Config.DialTLS equivalent: the caller's tls.Config, the fixture's
// address.
func (f *fixture) dialTLS() func(context.Context, string, *tls.Config) (*tls.Conn, error) {
	addr := f.server.Listener.Addr().String()
	return func(ctx context.Context, _ string, tc *tls.Config) (*tls.Conn, error) {
		conn, err := (&tls.Dialer{Config: tc}).DialContext(ctx, "tcp", addr)
		if err != nil {
			return nil, err
		}
		return conn.(*tls.Conn), nil
	}
}

// checker wires a Checker at the fixture: HTTP and TLS both dial the test server
// while keeping testDomain as the name, so URLs, SNI and the certificate's DNS
// name all line up without touching the resolver.
func (f *fixture) checker(t *testing.T, cfg Config) *Checker {
	t.Helper()
	// Reflect any post-construction mrConfigID override in the published bytes, so
	// the parser and the Checker's structural re-read see the same quote.
	f.publishQuote()
	pool := x509.NewCertPool()
	pool.AddCert(f.ca.cert)

	if cfg.QuoteParser == nil {
		cfg.QuoteParser = f.parser()
	}
	// Deliberately no HTTPClient: leaving it nil is what makes Check build its own
	// pinned session, so the tests exercise the production transport — one connection
	// for the whole run, which is the property step 4 depends on. Only DialTLS is
	// redirected, since testDomain does not resolve.
	if cfg.DialTLS == nil {
		cfg.DialTLS = f.dialTLS()
	}
	if cfg.Roots == nil {
		cfg.Roots = pool
	}
	// testDomain does not resolve, so leave DNS discovery off unless a test asks for
	// it: otherwise every case would pay a failing lookup and depend on the resolver.
	if cfg.AppCompose == nil && cfg.BaseDomain == "" && !f.wantDNSDiscovery {
		cfg.NoDNSDiscovery = true
	}
	c, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return c
}

func TestNew_RequiresQuoteParser(t *testing.T) {
	if _, err := New(Config{}); err == nil {
		t.Error("New with no QuoteParser: want an error (fail-closed)")
	}
}

func TestCheck_HappyPath(t *testing.T) {
	f := newFixture(t)
	rep, err := f.checker(t, Config{}).Check(context.Background(), testDomain)
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if !rep.Pass() {
		t.Fatalf("Pass = false, want true: %+v", rep)
	}
	if rep.CertMatch != CertExact {
		t.Errorf("CertMatch = %v, want CertExact", rep.CertMatch)
	}
	if rep.ChainTrustErr != nil {
		t.Errorf("ChainTrustErr = %v, want nil", rep.ChainTrustErr)
	}
	if len(rep.Files) != 2 {
		t.Errorf("checked %d files, want 2 (%s, %s)", len(rep.Files), accountName, certName(testDomain))
	}
	for _, fc := range rep.Files {
		if !fc.OK() {
			t.Errorf("file %s: not OK (%v)", fc.Name, fc.Err)
		}
	}
	if rep.ServedCertSHA256 != sha256.Sum256(f.served.der) {
		t.Error("ServedCertSHA256 is not the served leaf's digest")
	}
	if rep.Note == "" {
		t.Error("Note is empty; a pass must still say that code identity is unchecked")
	}
}

// A file whose bytes changed after the manifest was written: the classic
// swap-the-evidence-after-the-fact attempt, and what `sha256sum -c` catches.
func TestCheck_TamperedFileFailsManifest(t *testing.T) {
	f := newFixture(t)
	f.files[accountName] = []byte(`{"status":"valid","tampered":true}`)

	rep, err := f.checker(t, Config{}).Check(context.Background(), testDomain)
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if rep.Pass() {
		t.Error("Pass = true, want false for a file that does not match the manifest")
	}
	var found bool
	for _, fc := range rep.Files {
		if fc.Name == accountName {
			found = true
			if fc.OK() {
				t.Error("tampered file reported OK")
			}
			if fc.Got == fc.Want {
				t.Error("digests compared equal on a tampered file")
			}
		}
	}
	if !found {
		t.Errorf("no FileCheck for %s", accountName)
	}
}

// The bundle verifies against its own manifest, but the quote commits to a
// different manifest — an old quote republished beside a regenerated bundle. Only
// the report_data check catches this.
func TestCheck_QuoteBindsDifferentBundle(t *testing.T) {
	f := newFixture(t)
	f.bindQuote([]byte("some other bundle's sha256sum.txt\n"))

	rep, err := f.checker(t, Config{}).Check(context.Background(), testDomain)
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if rep.BindingErr == nil {
		t.Error("BindingErr = nil, want a mismatch")
	}
	if rep.Pass() {
		t.Error("Pass = true, want false when the quote binds another bundle")
	}
	// Everything else must still have been checked, so the operator sees where it broke.
	if rep.QuoteErr != nil {
		t.Errorf("QuoteErr = %v, want nil (the quote itself verified)", rep.QuoteErr)
	}
	if rep.CertMatch != CertExact {
		t.Errorf("CertMatch = %v, want CertExact (the cert comparison is independent)", rep.CertMatch)
	}
}

// A quote that fails DCAP verification must fail the run, and must not leave the
// binding looking checked.
func TestCheck_QuoteVerificationFailure(t *testing.T) {
	f := newFixture(t)
	sentinel := errors.New("not a genuine TDX quote")
	c := f.checker(t, Config{QuoteParser: func([]byte) (attest.Measurement, [64]byte, error) {
		return attest.Measurement{}, [64]byte{}, sentinel
	}})

	rep, err := c.Check(context.Background(), testDomain)
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if !errors.Is(rep.QuoteErr, sentinel) {
		t.Errorf("QuoteErr = %v, want %v", rep.QuoteErr, sentinel)
	}
	if rep.BindingErr == nil {
		t.Error("BindingErr = nil; with no verified quote the binding cannot be checked")
	}
	if rep.Pass() {
		t.Error("Pass = true, want false when the quote does not verify")
	}
}

// The load-bearing check: a genuine, correctly-bound bundle that belongs to a
// DIFFERENT certificate than the endpoint serves. Skipping this step is exactly
// what deploy/phala/README.md warns leaves the quote proving nothing about the
// endpoint you are talking to.
func TestCheck_ServedCertNotInBundle(t *testing.T) {
	f := newFixture(t)
	// Re-issue a wholly separate certificate and publish THAT in the bundle, then
	// re-hash so the bundle is internally consistent and correctly bound.
	other := newLeaf(t, f.ca, 200, nil)
	f.files[certName(testDomain)] = append(other.pemBytes(), f.ca.pemBytes()...)
	f.finalize(t, nil)

	rep, err := f.checker(t, Config{}).Check(context.Background(), testDomain)
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if rep.ManifestErr != nil || rep.QuoteErr != nil || rep.BindingErr != nil {
		t.Fatalf("bundle should verify internally: manifest=%v quote=%v binding=%v",
			rep.ManifestErr, rep.QuoteErr, rep.BindingErr)
	}
	if rep.CertMatch != CertMismatch {
		t.Errorf("CertMatch = %v, want CertMismatch", rep.CertMatch)
	}
	if rep.Pass() {
		t.Error("Pass = true although the endpoint serves a certificate the quote never bound")
	}
}

// Same key, different bytes: a renewal the evidence has not caught up with. Still
// a failure, but reported distinctly so an operator regenerates evidence instead
// of hunting an attack.
func TestCheck_StaleEvidenceSameKey(t *testing.T) {
	f := newFixture(t)
	renewed := newLeaf(t, f.ca, 300, f.served.key)
	f.files[certName(testDomain)] = append(renewed.pemBytes(), f.ca.pemBytes()...)
	f.finalize(t, nil)

	rep, err := f.checker(t, Config{}).Check(context.Background(), testDomain)
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if rep.CertMatch != CertSameKeyDifferentCert {
		t.Errorf("CertMatch = %v, want CertSameKeyDifferentCert", rep.CertMatch)
	}
	if rep.Pass() {
		t.Error("Pass = true on stale evidence")
	}
}

// Chain trust is reported but NOT part of Pass: an ACME-staging deployment has a
// correctly-bound certificate signed by an untrusted CA on purpose.
func TestCheck_UntrustedChainStillBinds(t *testing.T) {
	f := newFixture(t)
	// An empty trust store: the served cert chains to nothing known.
	rep, err := f.checker(t, Config{Roots: x509.NewCertPool()}).Check(context.Background(), testDomain)
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if rep.ChainTrustErr == nil {
		t.Error("ChainTrustErr = nil, want a verification failure against an empty trust store")
	}
	if rep.CertMatch != CertExact {
		t.Errorf("CertMatch = %v, want CertExact", rep.CertMatch)
	}
	if !rep.Pass() {
		t.Errorf("Pass = false; chain trust must not gate the attestation result: %+v", rep)
	}
}

// Asking about a domain the bundle does not cover must fail loudly rather than
// verify some other domain's certificate and report a pass.
func TestCheck_WrongDomainForBundle(t *testing.T) {
	f := newFixture(t)
	// Publish the cert under a different name and re-hash: the bundle is valid, it
	// just is not this domain's.
	f.files["cert-other.example.pem"] = f.files[certName(testDomain)]
	delete(f.files, certName(testDomain))
	f.files[manifestName] = []byte(fmt.Sprintf("%x  %s\n%x  %s\n",
		sha256.Sum256(f.files[accountName]), accountName,
		sha256.Sum256(f.files["cert-other.example.pem"]), "cert-other.example.pem"))
	f.bindQuote(f.files[manifestName])

	rep, err := f.checker(t, Config{}).Check(context.Background(), testDomain)
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if rep.ManifestErr == nil {
		t.Error("ManifestErr = nil, want a complaint that the bundle has no entry for this domain")
	}
	if !strings.Contains(fmt.Sprint(rep.ManifestErr), certName(testDomain)) {
		t.Errorf("ManifestErr should name the missing file, got: %v", rep.ManifestErr)
	}
	if rep.Pass() {
		t.Error("Pass = true for a bundle that does not cover this domain")
	}
}

// A missing evidence file is a fetch failure on that entry, not a digest mismatch:
// an HTML 404 body must never be hashed and reported as "wrong contents".
func TestCheck_MissingFile(t *testing.T) {
	f := newFixture(t)
	delete(f.files, accountName)

	rep, err := f.checker(t, Config{}).Check(context.Background(), testDomain)
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	for _, fc := range rep.Files {
		if fc.Name == accountName {
			if fc.Err == nil {
				t.Error("missing file: Err = nil, want a fetch error")
			}
			if fc.Got != ([sha256.Size]byte{}) {
				t.Error("missing file: a digest was computed over the error body")
			}
		}
	}
	if rep.Pass() {
		t.Error("Pass = true with an unfetchable evidence file")
	}
}

func TestCheck_NoBundleAtAll(t *testing.T) {
	f := newFixture(t)
	delete(f.files, manifestName)

	rep, err := f.checker(t, Config{}).Check(context.Background(), testDomain)
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if rep.ManifestErr == nil {
		t.Error("ManifestErr = nil, want a fetch failure")
	}
	if len(rep.Files) != 0 {
		t.Error("files were checked without a manifest")
	}
	if rep.Pass() {
		t.Error("Pass = true with no manifest")
	}
}

// A bundle whose certificate file is not a certificate: the comparison cannot be
// made, which must be reported as such rather than as a mismatch (a mismatch would
// point an operator at the endpoint instead of at the bundle).
func TestCheck_UnparseableCertInBundle(t *testing.T) {
	f := newFixture(t)
	f.files[certName(testDomain)] = []byte("-----BEGIN CERTIFICATE-----\nnot base64\n-----END CERTIFICATE-----\n")
	f.finalize(t, nil)

	rep, err := f.checker(t, Config{}).Check(context.Background(), testDomain)
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if rep.CertErr == nil {
		t.Error("CertErr = nil, want a parse failure")
	}
	if rep.CertMatch != CertMismatch {
		t.Errorf("CertMatch = %v; with no comparable certificate it must not claim a match", rep.CertMatch)
	}
	if rep.Pass() {
		t.Error("Pass = true with an unparseable certificate in the bundle")
	}
}

// The endpoint does not complete a handshake, so there is no run: the bundle and the
// certificate come over the SAME connection now, and without it neither exists. The
// error must name the dial rather than surfacing as some downstream mismatch, and the
// run must not pass.
func TestCheck_HandshakeFailure(t *testing.T) {
	f := newFixture(t)
	sentinel := errors.New("connection reset by peer")
	c := f.checker(t, Config{DialTLS: func(context.Context, string, *tls.Config) (*tls.Conn, error) {
		return nil, sentinel
	}})

	rep, err := c.Check(context.Background(), testDomain)
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if !errors.Is(rep.ManifestErr, sentinel) {
		t.Errorf("ManifestErr = %v, want it to wrap %v", rep.ManifestErr, sentinel)
	}
	if rep.Pass() {
		t.Error("Pass = true with no connection to the endpoint at all")
	}
}

// A deployment on an ACME-staging certificate must be fully checkable with no flag
// and no trust store: the fetch rides the same unverified connection whose
// certificate step 4 compares, so PKI never gates the evidence. Chain trust is still
// evaluated and REPORTED — that is the caller's decision to weigh, not this
// package's.
//
// This replaces an earlier contract in which the fetch verified PKI and a flag had to
// relax it. That shape put the same decision in two places and made a staging
// endpoint unverifiable until the flag reached both.
func TestCheck_UntrustedCertIsCheckableAndReported(t *testing.T) {
	f := newFixture(t)
	// No CA pool anywhere: the fixture's certificate chains to nothing trusted,
	// exactly like an ACME-staging deployment.
	c, err := New(Config{
		QuoteParser:    f.parser(),
		Roots:          x509.NewCertPool(),
		DialTLS:        f.dialTLS(),
		NoDNSDiscovery: true,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	f.publishQuote()

	rep, err := c.Check(context.Background(), testDomain)
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if rep.ManifestErr != nil {
		t.Fatalf("ManifestErr = %v; an untrusted certificate must not block the fetch", rep.ManifestErr)
	}
	if rep.QuoteErr != nil || rep.BindingErr != nil || rep.CertErr != nil {
		t.Errorf("attestation checks did not run cleanly: quote=%v binding=%v cert=%v",
			rep.QuoteErr, rep.BindingErr, rep.CertErr)
	}
	if rep.CertMatch != CertExact {
		t.Errorf("CertMatch = %v, want CertExact", rep.CertMatch)
	}
	if rep.ChainTrustErr == nil {
		t.Error("ChainTrustErr = nil; an untrusted chain must still be reported as untrusted")
	}
}

// Code identity end to end: the fixture's quote parser reports an mr_config_id
// committing to a compose hash, the app-compose is supplied, and its
// docker_compose_file is compared against the expected manifest.
func TestCheck_CodeIdentity(t *testing.T) {
	composeHash := composeHashOf(testAppCompose)
	expected := []byte("services:\n  gateway:\n    image: ghcr.io/x/gateway@sha256:abc\n")

	cases := []struct {
		name            string
		appCompose      []byte
		expectCompose   []byte
		mrConfigVersion byte
		wantPass        bool
		check           func(*testing.T, CodeIdentity)
	}{
		{
			name: "hash only, nothing requested", mrConfigVersion: 1, wantPass: true,
			check: func(t *testing.T, c CodeIdentity) {
				if c.Requested {
					t.Error("Requested = true with no material supplied")
				}
				if c.ComposeHash != composeHash {
					t.Errorf("compose_hash = %x, want %x", c.ComposeHash, composeHash)
				}
				// app_id must be the leading bytes of the hash, hex.
				if want := attest.AppIDFromComposeHash(composeHash); c.AppID != want {
					t.Errorf("app_id = %q, want %q", c.AppID, want)
				}
			},
		},
		{
			name: "app-compose bound", mrConfigVersion: 1, appCompose: []byte(testAppCompose), wantPass: true,
			check: func(t *testing.T, c CodeIdentity) {
				if c.BoundErr != nil {
					t.Fatalf("BoundErr = %v", c.BoundErr)
				}
				if c.Source != "supplied" {
					t.Errorf("Source = %q", c.Source)
				}
				if c.Name != "0g-pc-gateway-staging-a" {
					t.Errorf("Name = %q", c.Name)
				}
				if !strings.Contains(string(c.ComposeFile), "gateway@sha256:abc") {
					t.Errorf("ComposeFile did not carry the image line:\n%s", c.ComposeFile)
				}
			},
		},
		{
			// The wrong app's compose — exactly what happens when an operator picks an
			// app_id by hand while blue/green sides run side by side.
			name: "app-compose for another app", mrConfigVersion: 1,
			appCompose: []byte(`{"name":"other","docker_compose_file":"services: {}"}`), wantPass: false,
			check: func(t *testing.T, c CodeIdentity) {
				if c.BoundErr == nil {
					t.Error("BoundErr = nil for an app-compose the quote does not commit to")
				}
				if len(c.ComposeFile) != 0 {
					t.Error("an unbound app-compose must not yield a ComposeFile")
				}
			},
		},
		{
			name: "compose file matches", mrConfigVersion: 1,
			appCompose: []byte(testAppCompose), expectCompose: expected, wantPass: true,
			check: func(t *testing.T, c CodeIdentity) {
				if c.ExpectErr != nil {
					t.Errorf("ExpectErr = %v", c.ExpectErr)
				}
			},
		},
		{
			name: "compose file differs", mrConfigVersion: 1,
			appCompose:    []byte(testAppCompose),
			expectCompose: []byte("services:\n  gateway:\n    image: ghcr.io/x/gateway@sha256:DIFFERENT\n"),
			wantPass:      false,
			check: func(t *testing.T, c CodeIdentity) {
				if c.ExpectErr == nil {
					t.Error("ExpectErr = nil although the image digest differs")
				}
			},
		},
		{
			// V2 commits to the compose hash inside a digest, so it cannot be read out.
			// Requested checks must fail rather than proceed on a guess.
			name: "unsupported mr_config_id", mrConfigVersion: 2,
			appCompose: []byte(testAppCompose), wantPass: false,
			check: func(t *testing.T, c CodeIdentity) {
				if c.HashErr == nil {
					t.Error("HashErr = nil for a V2 mr_config_id")
				}
			},
		},
		{
			// …but with nothing requested, an unreadable mr_config_id is only reported.
			name: "unsupported mr_config_id, nothing requested", mrConfigVersion: 2, wantPass: true,
			check: func(t *testing.T, c CodeIdentity) {
				if c.HashErr == nil {
					t.Error("HashErr = nil for a V2 mr_config_id")
				}
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t)
			f.mrConfigID = mkMRConfigID(tc.mrConfigVersion, composeHash)
			c := f.checker(t, Config{
				AppCompose:         tc.appCompose,
				ExpectComposeFiles: expectCandidates(tc.expectCompose),
			})
			rep, err := c.Check(context.Background(), testDomain)
			if err != nil {
				t.Fatalf("Check: %v", err)
			}
			if got := rep.Pass(); got != tc.wantPass {
				t.Errorf("Pass = %v, want %v (code: %+v)", got, tc.wantPass, rep.Code)
			}
			if tc.check != nil {
				tc.check(t, rep.Code)
			}
		})
	}
}

// A requested fetch that cannot be made must fail the run, not be skipped.
func TestCheck_CodeIdentity_FetchFailure(t *testing.T) {
	f := newFixture(t)
	f.mrConfigID = mkMRConfigID(1, composeHashOf(testAppCompose))
	// A base domain that does not resolve: the fetch is attempted and fails.
	rep, err := f.checker(t, Config{BaseDomain: "gateway.invalid"}).Check(context.Background(), testDomain)
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if rep.Code.FetchErr == nil {
		t.Error("FetchErr = nil although the guest agent is unreachable")
	}
	if rep.Pass() {
		t.Error("Pass = true although a requested code-identity check could not run")
	}
}

func TestCheck_RejectsUnusableDomain(t *testing.T) {
	f := newFixture(t)
	if _, err := f.checker(t, Config{}).Check(context.Background(), "http://pc-gateway.test"); err == nil {
		t.Error("Check with a non-https URL: want an error return (a caller mistake, not a failed check)")
	}
}

func TestParseManifest_Accepts(t *testing.T) {
	digest := strings.Repeat("ab", 32)
	cases := map[string]string{
		"text mode":      digest + "  acme-account.json\n",
		"binary mode":    digest + " *acme-account.json\n",
		"crlf":           digest + "  acme-account.json\r\n",
		"no trailing nl": digest + "  acme-account.json",
		"blank lines":    "\n" + digest + "  acme-account.json\n\n",
		"spaces inside":  digest + "  cert-my host.pem\n",
	}
	for name, in := range cases {
		t.Run(name, func(t *testing.T) {
			entries, err := parseManifest([]byte(in))
			if err != nil {
				t.Fatalf("parseManifest: %v", err)
			}
			if len(entries) != 1 {
				t.Fatalf("got %d entries, want 1", len(entries))
			}
			want, _ := hex.DecodeString(digest)
			if string(entries[0].Digest[:]) != string(want) {
				t.Errorf("digest = %x, want %x", entries[0].Digest, want)
			}
		})
	}
}

func TestParseManifest_Rejects(t *testing.T) {
	digest := strings.Repeat("ab", 32)
	cases := map[string]string{
		"empty":             "",
		"only blank lines":  "\n\n",
		"no separator":      digest + "acme-account.json\n",
		"single space":      digest + " acme-account.json\n",
		"short digest":      "abcd  acme-account.json\n",
		"non-hex digest":    strings.Repeat("zz", 32) + "  acme-account.json\n",
		"escaped filename":  "\\" + digest + "  weird\\nname\n",
		"path traversal":    digest + "  ../../etc/passwd\n",
		"absolute path":     digest + "  /etc/passwd\n",
		"backslash path":    digest + "  ..\\secrets\n",
		"dot":               digest + "  .\n",
		"dotdot":            digest + "  ..\n",
		"leading dash":      digest + "  -oh-no\n",
		"empty filename":    digest + "  \n",
		"duplicate entries": digest + "  a.json\n" + digest + "  a.json\n",
	}
	for name, in := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := parseManifest([]byte(in)); err == nil {
				t.Errorf("parseManifest(%q): want an error, got nil", in)
			}
		})
	}
}

func TestNormalizeDomain(t *testing.T) {
	ok := map[string]string{
		"pc-gateway.test":          "pc-gateway.test",
		"  pc-gateway.test  ":      "pc-gateway.test",
		"https://pc-gateway.test":  "pc-gateway.test",
		"https://pc-gateway.test/": "pc-gateway.test",
		"pc-gateway.test:8443":     "pc-gateway.test:8443",
		// Folded, so a mixed-case argument still finds cert-<domain>.pem.
		"PC-Gateway.TEST":         "pc-gateway.test",
		"https://PC-Gateway.TEST": "pc-gateway.test",
	}
	for in, want := range ok {
		got, err := normalizeDomain(in)
		if err != nil {
			t.Errorf("normalizeDomain(%q): %v", in, err)
			continue
		}
		if got != want {
			t.Errorf("normalizeDomain(%q) = %q, want %q", in, got, want)
		}
	}
	for _, bad := range []string{
		"",
		"   ",
		"http://pc-gateway.test",            // the whole check is TLS
		"https://pc-gateway.test/evidences", // a path means the caller is confused
		"pc-gateway.test/evidences",
		"pc-gateway.test?x=1",
	} {
		if _, err := normalizeDomain(bad); err == nil {
			t.Errorf("normalizeDomain(%q): want an error, got nil", bad)
		}
	}
}

func TestParseCertChain(t *testing.T) {
	ca := newCA(t)
	leaf := newLeaf(t, ca, 1, nil)

	chain, err := parseCertChain(append(leaf.pemBytes(), ca.pemBytes()...))
	if err != nil {
		t.Fatalf("parseCertChain: %v", err)
	}
	if len(chain) != 2 {
		t.Fatalf("got %d certs, want 2", len(chain))
	}
	if !chain[0].Equal(leaf.cert) {
		t.Error("first certificate is not the leaf; the bundle order carries meaning")
	}

	// A non-CERTIFICATE block is skipped, not an error — but a bundle with no
	// certificate at all is.
	keyOnly := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: []byte{1, 2, 3}})
	if _, err := parseCertChain(keyOnly); err == nil {
		t.Error("parseCertChain on a PEM with no certificate: want an error")
	}
	if _, err := parseCertChain(nil); err == nil {
		t.Error("parseCertChain(nil): want an error")
	}
	bad := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("not a cert")})
	if _, err := parseCertChain(bad); err == nil {
		t.Error("parseCertChain on an unparseable certificate: want an error")
	}
}

// CertInChain: the served leaf is in the bundle but not first. The bundle is a
// fullchain, so this means its order is not what the check relies on.
func TestCompareCert_InChainButNotLeaf(t *testing.T) {
	ca := newCA(t)
	leaf := newLeaf(t, ca, 1, nil)
	// A bundle written CA-first: the served leaf is present, just not the leaf.
	got := compareCert(leaf.cert, []*x509.Certificate{ca.cert, leaf.cert})
	if got != CertInChain {
		t.Errorf("compareCert = %v, want CertInChain", got)
	}
	if got.OK() {
		t.Error("CertInChain must not be a pass")
	}
}

func TestCertMatch_Strings(t *testing.T) {
	for _, m := range []CertMatch{CertMismatch, CertExact, CertInChain, CertSameKeyDifferentCert} {
		if m.String() == "" {
			t.Errorf("CertMatch(%d) has no description", m)
		}
	}
	if !CertExact.OK() {
		t.Error("CertExact must be the pass condition")
	}
	for _, m := range []CertMatch{CertMismatch, CertInChain, CertSameKeyDifferentCert} {
		if m.OK() {
			t.Errorf("%v must not pass", m)
		}
	}
}

// expectCandidates wraps a single expected compose text as the one-candidate set,
// which is the pinned-manifest form. nil means "no comparison requested".
func expectCandidates(b []byte) []ExpectedCompose {
	if b == nil {
		return nil
	}
	return []ExpectedCompose{{Label: "expected", Content: b}}
}

// The bundle and the served certificate must come over ONE connection.
//
// dstack picks a CVM per TCP connection and each CVM generates its own TLS key inside
// itself, so a second connection can legitimately land on a replica presenting a
// different certificate. While the fetch and the comparison used separate
// connections, an N-replica deployment reported "served certificate is not in the
// bundle" — a healthy deployment described in the shape of an attack — roughly
// (N-1)/N of the time.
//
// The fixture models exactly that: one address that hands out a different certificate
// to every handshake after the first. Only a run that stays on connection 1 can match
// the bundle, so this fails for ANY second connection, wherever it is opened from.
func TestCheck_RunUsesOneConnection(t *testing.T) {
	f := newFixture(t, rotateCert)
	c := f.checker(t, Config{})

	rep, err := c.Check(context.Background(), testDomain)
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	f.handshakeMu.Lock()
	handshakes := f.handshakes
	f.handshakeMu.Unlock()
	if handshakes != 1 {
		t.Errorf("handshakes = %d, want 1: the bundle and the certificate must come "+
			"from the same connection, or replicas get compared against each other", handshakes)
	}
	if rep.CertErr != nil {
		t.Fatalf("CertErr = %v", rep.CertErr)
	}
	if rep.CertMatch != CertExact {
		t.Errorf("CertMatch = %v, want CertExact", rep.CertMatch)
	}
	if !rep.Pass() {
		t.Error("Pass = false on a healthy multi-replica deployment")
	}
}

// If the run does end up spanning connections with different certificates — a
// connection recycled mid-run onto another replica — the report must say THAT, not
// hand back a mismatch verdict. Both leaves may be legitimate, so there is no
// comparison to make, and "not in the bundle" would send the reader hunting an attack.
func TestSession_ServedChainDetectsAReplicaChange(t *testing.T) {
	a := newFixture(t)
	b := newFixture(t)

	same := &session{chains: [][]*x509.Certificate{{a.served.cert}, {a.served.cert}}}
	if chain, changed := same.servedChain(); changed || len(chain) == 0 {
		t.Errorf("two connections to the same replica: changed = %v, chain len = %d; want false, >0",
			changed, len(chain))
	}

	differing := &session{chains: [][]*x509.Certificate{{a.served.cert}, {b.served.cert}}}
	if chain, changed := differing.servedChain(); !changed || chain != nil {
		t.Errorf("two connections to different replicas: changed = %v, chain = %v; want true, nil",
			changed, chain)
	}

	empty := &session{}
	if chain, changed := empty.servedChain(); changed || chain != nil {
		t.Errorf("no connection recorded: changed = %v, chain = %v; want false, nil", changed, chain)
	}
}

// An invariant, asserted independently of the state table above because it is the
// shape a whole CLASS of bug takes: any early return in checkCodeIdentity leaves
// ExpectErr nil and MatchedExpect empty, and the old OK() read exactly that as
// "compared, matched". Nothing may ever count a comparison as passed without naming
// what it matched.
func TestCodeIdentity_ComparisonNeedsALabelToPass(t *testing.T) {
	for _, c := range []CodeIdentity{
		{Requested: true, ExpectRequested: true},
		{Requested: true, ExpectRequested: true, ExpectExplicit: true},
		{ExpectRequested: true},
		{Discovered: true, ExpectRequested: true},
		{NoSource: true, ExpectRequested: true, ExpectExplicit: true},
	} {
		if c.ExpectErr != nil || c.MatchedExpect != "" {
			t.Fatalf("test bug: case is not the no-result shape: %+v", c)
		}
		if c.OK() {
			t.Errorf("OK() = true for %+v — a comparison with neither a result nor an error "+
				"must never pass", c)
		}
	}
}

// -no-dns-discovery with no -app-compose / -base-domain, which deploy/phala/README.md
// documents for a DNS-less environment. The app-compose stage cannot run. Before the
// fix this returned with every field zero while ExpectRequested was already true from
// the default -releases lookup, so the run reported an authenticated app-compose and a
// byte-for-byte compose match — two ✓ and exit 0 — having fetched nothing.
func TestCheck_NoDNSDiscoveryCannotFabricateACodeIdentityPass(t *testing.T) {
	f := newFixture(t)
	c := f.checker(t, Config{
		NoDNSDiscovery: true,
		// What the default -releases 5 produces: candidates exist, but nothing asked for them.
		ExpectComposeFiles: []ExpectedCompose{{Label: "release-1", Content: []byte("services: {}\n")}},
	})

	rep, err := c.Check(context.Background(), testDomain)
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	code := rep.Code
	if !code.NoSource {
		t.Error("NoSource = false; the stage did not run and must say so")
	}
	if code.ComposeFile != nil || code.MatchedExpect != "" || code.Source != "" {
		t.Errorf("state claims work that never happened: ComposeFile=%q MatchedExpect=%q Source=%q",
			code.ComposeFile, code.MatchedExpect, code.Source)
	}
	// Endpoint identity is untouched by any of this, and opting out of a check is not a
	// failure — so the run still passes. What must NOT happen is claiming code identity.
	if !rep.Pass() {
		t.Error("Pass = false: declining code identity is not a verification failure")
	}
	if rep.Note == "" {
		t.Error("Note is empty; a partial result must carry its caveat")
	}
}
