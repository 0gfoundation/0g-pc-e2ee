// Package evidence verifies the cloud-TEE gateway's own attestation: the
// dstack-ingress evidence bundle published at `https://<domain>/evidences/`.
//
// It answers the one question the gateway's trust story rests on and that the
// provider-side trust chain (docs/design/trust-chain.md) does not cover:
// **is the endpoint I am talking to a genuine TEE, and is its TLS certificate
// one that was minted inside that enclave?** The gateway emits no quote of its
// own — its identity comes from the ingress's cert-binding quote, whose
// `report_data` commits to the bundle manifest and whose RTMR chain commits to
// `app_id` (docs/design/cloud-gateway.md §6.1).
//
// The checks, in the order Check runs them:
//
//  1. **Bundle integrity** — fetch `sha256sum.txt`, then every file it names, and
//     confirm each digest. This is `sha256sum -c` over the published bundle.
//  2. **Quote authenticity** — DCAP-verify `quote.json` (genuine Intel TDX, TCB
//     status, signature chain to the Intel root) via the QuoteParser seam.
//  3. **Bundle binding** — the verified quote's `report_data` must equal
//     SHA-256(manifest) ‖ zero padding (protocol/attest.VerifyEvidenceReportData).
//     Steps 1+3 together mean the enclave chose these exact bytes.
//  4. **Endpoint binding** — the certificate the domain actually serves, obtained
//     by our own TLS handshake, must be the one in the bundle. This is the
//     load-bearing step: without it the quote proves only that *some* CVM
//     obtained *some* certificate, saying nothing about the endpoint in front of
//     you (deploy/phala/README.md "Verify").
//  5. **Chain trust** — whether that certificate also validates for the domain
//     against the system roots, reported separately so an ACME-staging smoke test
//     can be told apart from a real trust failure. Separate does not mean optional:
//     it is what rules out an interceptor presenting its own attested CVM (see
//     Report.ChainTrustErr).
//
// # What this does NOT establish
//
// **Code identity.** Proving *which code* the CVM runs means recovering `app_id`
// by replaying the quote's event log against the verified RTMRs, then checking
// the CVM's `app-compose.json` against the digest-pinned
// `docker-compose.release.yml` from the Release that was deployed. Neither half
// is done here: the replay is unimplemented, and the compose comparison needs the
// Phala Cloud API. So a PASS means "a genuine TEE minted the certificate this
// endpoint serves" — not "that TEE runs the audited gateway image". Report.Note
// says so, and the measurement registers are printed for manual comparison.
// Until that lands this is docs/design/cloud-gateway.md §10 phase 2 for the cert
// binding only.
//
// Everything here is read-only: HTTP GETs of public evidence files, one TLS
// handshake, plus whatever collateral the DCAP verifier fetches.
package evidence

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/0gfoundation/0g-pc-e2ee/protocol/attest"
)

// maxFileBytes bounds each evidence-file read. The bundle is a handful of small
// text files (a cert chain, a JSON account document, a manifest, a hex quote);
// 1 MiB is far above any of them and keeps a hostile origin from streaming
// unbounded data into the tool.
const maxFileBytes = 1 << 20

// QuoteParser is the DCAP seam: it must verify that raw is a genuine, signed
// Intel TDX quote and return its measurement and raw 64-byte report_data, failing
// closed otherwise. It is the same shape protocol/attest.WithQuoteParser takes,
// so production passes dcap.NewQuoteParser(...) unchanged and tests inject a fake.
//
// The evidence quote cannot go through attest.Verifier: that path ends in
// ParseReportData, which is the *provider's* §4.2 key layout and correctly fails
// closed on the ingress's cert-binding layout. So this package takes the parser
// directly and applies attest.VerifyEvidenceReportData itself.
type QuoteParser func(raw []byte) (attest.Measurement, [64]byte, error)

// Config configures a Checker. The zero value is not usable — QuoteParser is
// required, since without it nothing verifies the quote.
type Config struct {
	// QuoteParser DCAP-verifies quote.json. Required.
	QuoteParser QuoteParser
	// HTTPClient fetches the evidence files. Nil uses a client with Timeout.
	HTTPClient *http.Client
	// DialTLS opens the TLS connection whose served certificate is compared
	// against the bundle. Nil dials <domain>:443. Injected by tests; also the seam
	// for pointing the handshake at a specific address while keeping the SNI name.
	DialTLS func(ctx context.Context, domain string, cfg *tls.Config) (*tls.Conn, error)
	// Timeout bounds the default HTTP client and the TLS handshake. Zero uses
	// defaultTimeout.
	Timeout time.Duration
	// Roots overrides the trust store used for the *reported* chain-trust check
	// (step 5). Nil uses the system roots. It never affects steps 1–4: the
	// certificate comparison is an identity check against the quote, not a PKI
	// decision, so the handshake deliberately does not depend on this.
	Roots *x509.CertPool
	// AllowUntrustedCert lets the evidence FETCH proceed over a TLS connection whose
	// certificate does not chain to a trusted root, for a deployment brought up
	// against the ACME staging CA (deploy/phala/README.md). Without it the fetch
	// fails on ordinary PKI verification and no check runs at all, which makes a
	// staging endpoint unverifiable.
	//
	// It does not weaken steps 1–3: the bundle is untrusted input either way, and
	// its authenticity comes from the report_data binding to a DCAP-verified quote,
	// never from TLS. What it DOES give up is the guarantee that the connection
	// reaches the name that was asked for — see Report.ChainTrustErr for the
	// consequence, which is why chain trust is still evaluated and reported.
	//
	// It applies only to the client this package builds; a caller supplying
	// HTTPClient controls its own TLS configuration.
	AllowUntrustedCert bool
}

const defaultTimeout = 30 * time.Second

// Checker verifies evidence bundles. It is immutable after New and safe for
// concurrent use.
type Checker struct {
	cfg   Config
	http  *http.Client
	dial  func(ctx context.Context, domain string, cfg *tls.Config) (*tls.Conn, error)
	limit time.Duration
}

// New returns a Checker. It errors when QuoteParser is nil rather than defaulting
// to a permissive parser: a Checker that cannot verify a quote must not exist.
func New(cfg Config) (*Checker, error) {
	if cfg.QuoteParser == nil {
		return nil, errors.New("evidence: QuoteParser is required (fail-closed)")
	}
	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = defaultTimeout
	}
	c := &Checker{cfg: cfg, http: cfg.HTTPClient, dial: cfg.DialTLS, limit: timeout}
	if c.http == nil {
		c.http = &http.Client{Timeout: timeout, Transport: &http.Transport{
			// Verification is on by default and only AllowUntrustedCert turns it off;
			// see that field for why doing so does not weaken the bundle checks, and
			// what it does cost.
			TLSClientConfig: &tls.Config{
				MinVersion:         tls.VersionTLS12,
				InsecureSkipVerify: cfg.AllowUntrustedCert, //nolint:gosec // opt-in, see Config.AllowUntrustedCert
			},
		}}
	}
	if c.dial == nil {
		c.dial = dialTLS
	}
	return c, nil
}

// FileCheck is one manifest entry and how the fetched file compared to it.
type FileCheck struct {
	Name string
	Want [sha256.Size]byte
	Got  [sha256.Size]byte
	// Err is set when the file could not be fetched at all; Got is then zero.
	Err error
}

// OK reports whether the file was fetched and its digest matched.
func (f FileCheck) OK() bool { return f.Err == nil && f.Got == f.Want }

// CertMatch classifies how the served certificate compared to the bundle's.
type CertMatch int

const (
	// CertMismatch: the served certificate is not in the bundle at all — the
	// quote says nothing about the endpoint being talked to.
	CertMismatch CertMatch = iota
	// CertExact: the served leaf is byte-identical to the bundle's leaf. This is
	// the pass condition.
	CertExact
	// CertInChain: the served leaf appears in the bundle file but is not its first
	// certificate. The bundle is a full chain, so a leaf found deeper in it means
	// the file is ordered unexpectedly; treated as a failure because the identity
	// the quote commits to is then not the one being served as the leaf.
	CertInChain
	// CertSameKeyDifferentCert: the served certificate carries the same public key
	// as the bundle's leaf but different bytes — the signature of a *stale bundle*,
	// e.g. the certificate was renewed (same key) and the evidence has not been
	// regenerated, or was regenerated without a fresh quote. A failure, but an
	// operational one, distinct from being served a foreign certificate.
	CertSameKeyDifferentCert
)

func (m CertMatch) String() string {
	switch m {
	case CertExact:
		return "served certificate is the one the quote binds"
	case CertInChain:
		return "served certificate is in the bundle chain but is not its leaf"
	case CertSameKeyDifferentCert:
		return "served certificate has the bundle key but different bytes (stale evidence?)"
	default:
		return "served certificate is not in the bundle"
	}
}

// OK reports whether the match is the pass condition.
func (m CertMatch) OK() bool { return m == CertExact }

// Report is the outcome of Check: one field per verified property, plus the
// values an operator needs for the manual code-identity step. Every field is
// filled in as far as the run got, so a partial Report is still useful for
// diagnosis; Pass is the single answer.
type Report struct {
	Domain string

	// Files is the per-entry result of the manifest check (step 1), in manifest
	// order. ManifestErr is set instead when the manifest itself could not be
	// fetched or parsed, in which case no later step ran.
	Files       []FileCheck
	ManifestErr error

	// QuoteErr is set when quote.json could not be fetched or failed DCAP
	// verification (step 2). Measurement is only meaningful when it is nil.
	QuoteErr    error
	Measurement attest.Measurement
	// ReportData is the verified quote's raw report_data, surfaced for diagnosis.
	ReportData [64]byte
	// BindingErr is set when report_data does not bind this manifest (step 3).
	BindingErr error

	// CertMatch is how the served certificate compared to the bundle's (step 4). It
	// is meaningful ONLY when CertErr is nil — CertErr means the comparison could
	// not be made at all (handshake failure, the cert file missing or unparseable),
	// and CertMatch then holds its zero value rather than a verdict.
	CertMatch CertMatch
	CertErr   error
	// ServedCertSHA256 and BundleCertSHA256 are the two leaf DER digests compared,
	// so a mismatch can be reported concretely. Zero when unavailable.
	ServedCertSHA256 [sha256.Size]byte
	BundleCertSHA256 [sha256.Size]byte
	// CertSubject, CertIssuer and CertNotAfter describe the served leaf, for the
	// human reading the report (issuer in particular distinguishes an ACME-staging
	// certificate from a real one).
	CertSubject  string
	CertIssuer   string
	CertNotAfter time.Time

	// ChainTrustErr is set when the served certificate does not validate for Domain
	// against the trust store (step 5). It is reported separately from CertMatch
	// because an untrusted-but-correctly-bound certificate is an ACME-staging
	// deployment rather than an attestation failure — but it is NOT cosmetic.
	//
	// Chain trust is what ties "the certificate on this connection" to "the DNS name
	// I asked for". Without it, an attacker who can intercept the connection and
	// runs its OWN dstack CVM can satisfy every other check: it serves its own
	// genuine quote, its own consistent bundle, and its own certificate — which then
	// matches the bundle, because it controls both. So treating a chain-trust failure
	// as acceptable narrows the claim to "some genuine TEE minted the certificate
	// being served on this connection", dropping "and this connection reaches the
	// host I named". Acceptable for an operator smoke-testing their own staging
	// deployment; not acceptable when auditing an endpoint you do not control.
	ChainTrustErr error

	// Note records what a pass does NOT cover, so a caller cannot present this as
	// full attestation. See the package doc.
	Note string
}

// codeIdentityNote is Report.Note: the one gap a caller must not paper over.
const codeIdentityNote = "code identity (app_id) is NOT checked here — replay the event log against " +
	"the verified quote and compare the CVM's app-compose.json with the deployed " +
	"docker-compose.release.yml (see deploy/phala/README.md \"Verify\")"

// Pass reports whether every enforced check succeeded. Chain trust is deliberately
// excluded — callers decide whether an untrusted chain is acceptable (it is, for an
// ACME-staging smoke test) by consulting ChainTrustErr.
func (r Report) Pass() bool {
	if r.ManifestErr != nil || r.QuoteErr != nil || r.BindingErr != nil || r.CertErr != nil {
		return false
	}
	if !r.CertMatch.OK() {
		return false
	}
	if len(r.Files) == 0 {
		return false
	}
	for _, f := range r.Files {
		if !f.OK() {
			return false
		}
	}
	return true
}

// Check runs the full verification against domain (a bare hostname, optionally
// with a port). It returns a Report even on failure — the error return is
// reserved for a caller mistake (an unusable domain), not for a failed check, so
// a caller reports per-step results rather than a single opaque error.
func (c *Checker) Check(ctx context.Context, domain string) (Report, error) {
	host, err := normalizeDomain(domain)
	if err != nil {
		return Report{}, err
	}
	// certName and the SNI want the hostname without any port; the URLs and the
	// dial want the authority as given.
	name := host
	if h, _, splitErr := net.SplitHostPort(host); splitErr == nil {
		name = h
	}
	rep := Report{Domain: host, Note: codeIdentityNote}

	// Step 1 — the manifest, then every file it names. The manifest bytes are kept
	// verbatim: the binding in step 3 is a hash over exactly these bytes.
	manifest, err := c.fetch(ctx, host, manifestName)
	if err != nil {
		rep.ManifestErr = err
		return rep, nil
	}
	entries, err := parseManifest(manifest)
	if err != nil {
		rep.ManifestErr = err
		return rep, nil
	}
	if err := requireEntries(entries, name); err != nil {
		rep.ManifestErr = err
		return rep, nil
	}
	var certPEM []byte
	for _, e := range entries {
		body, ferr := c.fetch(ctx, host, e.Name)
		fc := FileCheck{Name: e.Name, Want: e.Digest, Err: ferr}
		if ferr == nil {
			fc.Got = sha256.Sum256(body)
			if e.Name == certName(name) {
				certPEM = body
			}
		}
		rep.Files = append(rep.Files, fc)
	}

	// Step 2 — the quote. Fetched separately: it is generated from the manifest's
	// digest, so it is not (and cannot be) a manifest entry.
	quoteBody, err := c.fetch(ctx, host, quoteName)
	if err != nil {
		rep.QuoteErr = err
	} else {
		raw, derr := attest.DecodeQuoteResponse(quoteBody)
		if derr != nil {
			rep.QuoteErr = derr
		} else if m, rd, verr := c.cfg.QuoteParser(raw); verr != nil {
			rep.QuoteErr = verr
		} else {
			rep.Measurement, rep.ReportData = m, rd
			// Step 3 — the verified quote must bind this exact manifest.
			rep.BindingErr = attest.VerifyEvidenceReportData(rd, manifest)
		}
	}
	if rep.QuoteErr != nil {
		// Without a verified quote there is nothing for the manifest to be bound to.
		rep.BindingErr = errors.New("not checked: the quote did not verify")
	}

	// Steps 4 and 5 — what the endpoint actually serves, versus what the bundle
	// says. Run even when the quote failed: knowing whether the served certificate
	// matches is useful either way, and Pass already requires both.
	c.checkServedCert(ctx, host, name, certPEM, &rep)
	return rep, nil
}

// requireEntries confirms the manifest covers the files this check depends on. A
// bundle missing cert-<domain>.pem cannot bind the endpoint at all; a bundle
// missing the ACME account document is not the shape dstack-ingress produces, so
// treat it as malformed rather than verify a subset and report a pass.
func requireEntries(entries []ManifestEntry, name string) error {
	have := make(map[string]struct{}, len(entries))
	for _, e := range entries {
		have[e.Name] = struct{}{}
	}
	if _, ok := have[certName(name)]; !ok {
		names := make([]string, 0, len(entries))
		for _, e := range entries {
			names = append(names, e.Name)
		}
		return fmt.Errorf("%s has no entry for %s (bundle covers: %s) — wrong domain, or the ingress does not serve it",
			manifestName, certName(name), strings.Join(names, ", "))
	}
	if _, ok := have[accountName]; !ok {
		return fmt.Errorf("%s has no entry for %s", manifestName, accountName)
	}
	return nil
}

// checkServedCert performs the TLS handshake, compares the served leaf against
// the bundle's certificate, and records chain trust. It fills rep in place and
// never returns an error: every outcome is a reported field.
func (c *Checker) checkServedCert(ctx context.Context, host, name string, certPEM []byte, rep *Report) {
	if certPEM == nil {
		// requireEntries guarantees the manifest names it, so getting here means the
		// fetch failed — already recorded as that entry's FileCheck.Err.
		rep.CertErr = fmt.Errorf("%s was not fetched; cannot compare the served certificate", certName(name))
		return
	}
	bundle, err := parseCertChain(certPEM)
	if err != nil {
		rep.CertErr = fmt.Errorf("%s: %w", certName(name), err)
		return
	}

	handshakeCtx, cancel := context.WithTimeout(ctx, c.limit)
	defer cancel()
	// InsecureSkipVerify on purpose: this handshake exists to OBTAIN the served
	// certificate so it can be compared against the quote-bound one, which is an
	// identity check that does not depend on PKI. Verifying here instead would make
	// the tool useless exactly when it is most needed — an ACME-staging deployment,
	// or a misissued-but-trusted certificate. Chain trust is checked explicitly
	// below and reported as its own property.
	conn, err := c.dial(handshakeCtx, host, &tls.Config{
		ServerName:         name,
		InsecureSkipVerify: true, //nolint:gosec // see comment: identity check, trust verified separately below
		MinVersion:         tls.VersionTLS12,
	})
	if err != nil {
		rep.CertErr = fmt.Errorf("TLS handshake with %s: %w", host, err)
		return
	}
	defer conn.Close()
	served := conn.ConnectionState().PeerCertificates
	if len(served) == 0 {
		rep.CertErr = fmt.Errorf("%s presented no certificate", host)
		return
	}
	leaf := served[0]
	rep.ServedCertSHA256 = sha256.Sum256(leaf.Raw)
	rep.BundleCertSHA256 = sha256.Sum256(bundle[0].Raw)
	rep.CertSubject = leaf.Subject.String()
	rep.CertIssuer = leaf.Issuer.String()
	rep.CertNotAfter = leaf.NotAfter
	rep.CertMatch = compareCert(leaf, bundle)
	rep.ChainTrustErr = verifyChainTrust(leaf, served[1:], name, c.cfg.Roots)
}

// compareCert classifies the served leaf against the bundle chain. See CertMatch
// for what each outcome means operationally.
func compareCert(leaf *x509.Certificate, bundle []*x509.Certificate) CertMatch {
	if leaf.Equal(bundle[0]) {
		return CertExact
	}
	for _, c := range bundle[1:] {
		if leaf.Equal(c) {
			return CertInChain
		}
	}
	// Same key, different bytes: almost always a renewal the evidence has not
	// caught up with. Worth naming, because "not in the bundle" would send an
	// operator hunting for an attack instead of regenerating the evidence.
	if leaf.PublicKeyAlgorithm == bundle[0].PublicKeyAlgorithm && samePublicKey(leaf, bundle[0]) {
		return CertSameKeyDifferentCert
	}
	return CertMismatch
}

// samePublicKey compares two certificates' SubjectPublicKeyInfo bytes, which is
// an algorithm-agnostic key comparison (x509 exposes no generic key equality).
func samePublicKey(a, b *x509.Certificate) bool {
	return len(a.RawSubjectPublicKeyInfo) > 0 &&
		string(a.RawSubjectPublicKeyInfo) == string(b.RawSubjectPublicKeyInfo)
}

// verifyChainTrust validates leaf for name against roots (system roots when nil),
// using the certificates the handshake supplied as intermediates. This is the
// ordinary PKI check a browser would do, reported separately from the
// attestation checks.
func verifyChainTrust(leaf *x509.Certificate, intermediates []*x509.Certificate, name string, roots *x509.CertPool) error {
	pool := x509.NewCertPool()
	for _, c := range intermediates {
		pool.AddCert(c)
	}
	_, err := leaf.Verify(x509.VerifyOptions{
		DNSName:       name,
		Roots:         roots, // nil = system roots
		Intermediates: pool,
	})
	return err
}

// parseCertChain decodes every CERTIFICATE block in a PEM bundle, in file order.
// dstack-ingress publishes lego's fullchain, so the first block is the leaf — the
// one the endpoint must be serving.
func parseCertChain(pemBytes []byte) ([]*x509.Certificate, error) {
	var out []*x509.Certificate
	rest := pemBytes
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse certificate %d: %w", len(out)+1, err)
		}
		out = append(out, cert)
	}
	if len(out) == 0 {
		return nil, errors.New("no CERTIFICATE block found")
	}
	return out, nil
}

// fetch GETs one evidence file and returns its bytes. The read is bounded and a
// non-200 is an error: a bundle served as an HTML error page must not be hashed
// and reported as a digest mismatch.
func (c *Checker) fetch(ctx context.Context, host, name string) ([]byte, error) {
	u := "https://" + host + "/evidences/" + url.PathEscape(name)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch %s: %w", name, err)
	}
	defer resp.Body.Close()
	// Read one byte past the cap so an oversized file is reported as such. Silently
	// truncating instead would surface as a digest mismatch — or, for the manifest,
	// as a wrong report_data binding — sending the reader after an attack that is
	// really just an unexpectedly large file.
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxFileBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", name, err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GET /evidences/%s returned %s", name, resp.Status)
	}
	if len(body) > maxFileBytes {
		return nil, fmt.Errorf("%s is larger than %d bytes; not an evidence file", name, maxFileBytes)
	}
	return body, nil
}

// dialTLS is the default DialTLS: a plain TLS dial to domain, defaulting to port
// 443. It honors the context deadline for both the TCP connect and the handshake.
func dialTLS(ctx context.Context, domain string, cfg *tls.Config) (*tls.Conn, error) {
	addr := domain
	if _, _, err := net.SplitHostPort(addr); err != nil {
		addr = net.JoinHostPort(domain, "443")
	}
	d := &tls.Dialer{Config: cfg}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	return conn.(*tls.Conn), nil
}

// normalizeDomain accepts what an operator is likely to paste — a bare hostname,
// a host:port, or a full URL — and returns the authority to use. It rejects
// anything with a path or scheme other than https, because the evidence path is
// fixed and a caller passing a URL with a path is confused about what this checks.
func normalizeDomain(domain string) (string, error) {
	d := strings.TrimSpace(domain)
	if d == "" {
		return "", errors.New("evidence: empty domain")
	}
	if strings.Contains(d, "://") {
		u, err := url.Parse(d)
		if err != nil {
			return "", fmt.Errorf("evidence: %q is not a valid URL: %w", domain, err)
		}
		if u.Scheme != "https" {
			return "", fmt.Errorf("evidence: %q must be https (the evidence bundle and the cert comparison are both TLS)", domain)
		}
		if p := strings.Trim(u.Path, "/"); p != "" {
			return "", fmt.Errorf("evidence: pass the domain only, not a path (%q)", domain)
		}
		d = u.Host
	}
	if strings.ContainsAny(d, "/?#") {
		return "", fmt.Errorf("evidence: %q is not a bare domain", domain)
	}
	if d == "" {
		return "", fmt.Errorf("evidence: %q has no host", domain)
	}
	// Lowercase: hostnames are case-insensitive in DNS, SNI and URLs, but the
	// bundle's `cert-<domain>.pem` is a filename and is not. dstack-ingress names it
	// from $DOMAIN, which is lowercase by convention, so folding here turns a
	// mixed-case argument into a match instead of a confusing "no entry for
	// cert-<domain>.pem". If a deployment really did use uppercase, requireEntries
	// lists the names the bundle does carry.
	return strings.ToLower(d), nil
}
