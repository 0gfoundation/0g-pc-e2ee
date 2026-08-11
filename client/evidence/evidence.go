// Package evidence verifies the cloud-TEE gateway's own attestation: the
// dstack-ingress evidence bundle published at `https://<domain>/evidences/`.
//
// It answers the two questions the gateway's trust story rests on and that the
// provider-side trust chain (docs/design/trust-chain.md) does not cover: **is the
// endpoint I am talking to a genuine TEE whose TLS certificate was minted inside
// it, and which code is it running?** The gateway emits no quote of its own — both
// answers come from the ingress's cert-binding quote, whose `report_data` commits to
// the bundle manifest and whose `mr_config_id` commits to the deployment's compose
// hash (docs/design/cloud-gateway.md §6.1).
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
//  6. **Code identity** — *which* configuration, and therefore which container
//     images, the CVM booted. The verified quote's `mr_config_id` carries the
//     dstack `compose_hash` (SHA-256 over the bytes of the CVM's
//     `app-compose.json`), so this needs no event-log replay: the register is
//     inside the signed TD report. Given the app-compose bytes,
//     `sha256 == compose_hash` authenticates them, and the `docker_compose_file`
//     they carry is then compared against the manifest that was published. See
//     CodeIdentity.
//  7. **OS image** — `mr_config_id` is chosen by the untrusted host, so step 6
//     stands up only because the guest OS refuses to boot when that register
//     disagrees with the app-compose actually delivered. Trusting that means
//     trusting the OS doing it, so the quote's image registers (MRTD, RTMR1, RTMR2)
//     must be ones this verifier accepts. RTMR0 is excluded: it records the VM shape,
//     which this check does not depend on. See OSImageCheck and Config.OSImages.
//
// # What a pass means
//
// Steps 1–5 are self-contained: point Check at a domain and it answers "is a
// genuine TEE serving the certificate its own quote committed to".
//
// Step 6 needs material, because a hash has no preimage of its own: the app-compose
// bytes (Config.AppCompose, or fetched — Config.BaseDomain, or derived from DNS) and
// the compose text to compare against (Config.ExpectComposeFiles). Their source need
// not be trusted, since the compose_hash from the quote anchors them; but without
// them compose_hash and app_id are only opaque values to eyeball — enough to notice
// that a deployment changed, not enough to say what it runs.
//
// Step 7 needs an allowlist, which ships embedded (see Config.OSImages) so a caller
// supplies nothing. While it is empty the step reports "not pinned" rather than
// failing, and code identity is evidence rather than proof: nothing then establishes
// that the guest enforced step 6's binding at all.
//
// Report.Note carries whichever of these caveats apply, so a partial result cannot be
// presented as a full one. One survives even a complete run: an image referenced by a
// floating tag instead of a digest keeps `compose_hash` stable while the code behind
// the tag changes. Code identity is only ever as strong as the pinning in the compose
// text it authenticates.
//
// Everything here is read-only: HTTP GETs of the public evidence files and (for
// step 6) the platform's guest-agent Info endpoint, one TLS handshake, plus
// whatever collateral the DCAP verifier fetches.
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
	"sync"
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
	// HTTPClient overrides BOTH HTTP paths: the evidence-bundle fetch and the
	// app-compose lookup. Nil is the normal case and the one production uses — the
	// bundle then rides a per-run pinned connection (see the session type) whose
	// certificate is what step 4 compares, which a caller-supplied client cannot
	// provide. Set it only when the transport itself is what you are controlling.
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
	// AppCompose, when non-nil, is the app-compose.json bytes to check the quote's
	// compose_hash against — an operator's deploy record, a release asset, or a copy
	// pulled from the platform by hand. It takes precedence over BaseDomain.
	//
	// Its source does not need to be trusted (see VerifyAppCompose); what matters is
	// that the bytes are verbatim, since the digest is over them.
	AppCompose []byte
	// BaseDomain, when set and AppCompose is nil, is the platform base domain to
	// fetch app-compose from — e.g. "in1.phala.network", giving
	// `<app_id>-8090.in1.phala.network` (see FetchAppCompose). Leave it empty to let
	// Check derive it from the served domain's DNS (see DeriveBaseDomain), which is
	// what makes `Check(domain)` alone able to do code identity.
	//
	// The app_id in that hostname always comes from the quote, never from a caller.
	// That is deliberate: picking one by hand is how an operator ends up verifying
	// the standby side of a blue/green pair while the other one serves traffic.
	BaseDomain string
	// NoDNSDiscovery disables deriving BaseDomain from DNS. Set it to keep the run
	// to the endpoint and the inputs given.
	NoDNSDiscovery bool
	// OSImages is the allowlist of acceptable OS-image boot chains (step 7). Nil loads
	// the embedded builtin, which is what makes the check need no configuration; pass
	// an explicitly empty slice to disable it, or your own entries to override.
	//
	// This is what grounds code identity: mr_config_id is host-chosen, and it is the
	// guest OS that refuses to boot when it disagrees with the real app-compose, so the
	// compose hash means what it says only if the OS is the audited one.
	OSImages []OSImage
	// ExpectComposeFiles are candidate docker-compose texts, any one of which the
	// authenticated docker_compose_file may equal — normally the digest-pinned
	// manifest(s) from the release(s) that could be deployed. This is the step that
	// turns "we know which configuration booted" into "it is one we published".
	//
	// With one candidate this is a gate: it must be exactly that. With several it is
	// discovery — which published release is live — and the answer "none of them" is
	// the finding that matters.
	ExpectComposeFiles []ExpectedCompose
	// ExpectComposeExplicit says the caller ASKED for the compose comparison, as
	// opposed to it happening by default. It must not be inferred from
	// ExpectComposeFiles being non-empty: a default lookup that happens to succeed
	// would then harden an unrelated discovered lookup (see CodeIdentity.OK), making
	// the verdict depend on whether an unrelated network call worked.
	ExpectComposeExplicit bool
}

// ExpectedCompose is one candidate compose text and the name to report it by (a
// release tag, a file path).
type ExpectedCompose struct {
	Label   string
	Content []byte
}

const defaultTimeout = 30 * time.Second

// Checker verifies evidence bundles. It is immutable after New and safe for
// concurrent use.
type Checker struct {
	cfg      Config
	http     *http.Client
	dial     func(ctx context.Context, domain string, cfg *tls.Config) (*tls.Conn, error)
	limit    time.Duration
	osImages []OSImage
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
	// A malformed embedded allowlist is a mistake in this repository, not a fact about
	// any deployment, so it fails construction rather than quietly leaving the OS-image
	// check unconfigured — which would drop it without anyone noticing.
	osImages := cfg.OSImages
	if osImages == nil {
		var err error
		if osImages, err = BuiltinOSImages(); err != nil {
			return nil, err
		}
	}
	c := &Checker{cfg: cfg, http: cfg.HTTPClient, dial: cfg.DialTLS, limit: timeout, osImages: osImages}
	if c.http == nil {
		// Used for the app-compose lookup only (a DIFFERENT host from the endpoint, so
		// it shares nothing with the pinned bundle connection). Ordinary PKI
		// verification: it is the platform's own public hostname, and the bytes it
		// returns are authenticated against the quote's compose_hash regardless, so a
		// TLS failure here is an advisory dead end rather than something to work around.
		c.http = &http.Client{Timeout: timeout, Transport: &http.Transport{
			TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12},
		}}
	}
	if c.dial == nil {
		c.dial = dialTLS
	}
	return c, nil
}

// session is one Check's transport. Everything a single run fetches goes over ONE
// TLS connection, and that connection's certificate chain is what step 4 compares
// against the bundle.
//
// That has to be the same connection, not merely the same host. dstack selects a
// CVM **per TCP connection** (a connect race over the instances of one app_id — see
// deploy/phala/blue-green.md), and every CVM generates its own TLS key inside itself.
// So a deployment with N replicas would, on separate connections, hand the fetch one
// replica's bundle and the handshake another replica's certificate: a healthy
// deployment reported as "served certificate is not in the bundle", which is the
// shape of an attack. Pinning removes that whole class of false negative.
//
// The handshake does not verify PKI. It cannot: an ACME-staging deployment's
// certificate is correctly quote-bound and deliberately untrusted, and refusing to
// connect would make the tool useless exactly where it is needed. Nothing is lost —
// the bundle is untrusted input either way (its authenticity comes from the
// report_data binding to a DCAP-verified quote, never from TLS), and chain trust is
// verified explicitly afterwards against Config.Roots and reported as its own
// property for the caller's verdict to require.
type session struct {
	client *http.Client
	mu     sync.Mutex
	// chains is one entry per connection this session dialed. More than one means
	// the run may have spanned replicas; see servedChain.
	chains [][]*x509.Certificate
}

// newSession builds the pinned transport for one run. name is the SNI to present,
// which is the hostname without any port.
func (c *Checker) newSession(name string) *session {
	s := &session{}
	if c.cfg.HTTPClient != nil {
		// A caller supplying its own client owns its transport, so nothing can be
		// pinned or recorded; checkServedCert falls back to its own handshake.
		s.client = c.cfg.HTTPClient
		return s
	}
	s.client = &http.Client{Timeout: c.limit, Transport: &http.Transport{
		// MaxConnsPerHost pins the run to one connection so the recorded chain is the
		// one the evidence came over. DisableKeepAlives must stay false or every
		// request would dial afresh, which is the behaviour being fixed.
		MaxConnsPerHost: 1,
		DialTLSContext: func(ctx context.Context, _, addr string) (net.Conn, error) {
			conn, err := c.dial(ctx, addr, &tls.Config{
				ServerName:         name,
				InsecureSkipVerify: true, //nolint:gosec // identity check; chain trust verified separately, see session
				MinVersion:         tls.VersionTLS12,
			})
			if err != nil {
				return nil, err
			}
			s.mu.Lock()
			s.chains = append(s.chains, conn.ConnectionState().PeerCertificates)
			s.mu.Unlock()
			return conn, nil
		},
	}}
	return s
}

// servedChain returns the certificate chain the run's connection presented.
//
// It reports changed=true when the session dialed more than once and the leaves
// disagree — a replica change mid-run. The caller must then say so rather than
// compare, because either leaf may be legitimate and a mismatch verdict would name
// the wrong problem.
func (s *session) servedChain() (chain []*x509.Certificate, changed bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.chains) == 0 {
		return nil, false
	}
	first := s.chains[0]
	for _, other := range s.chains[1:] {
		if len(other) == 0 || len(first) == 0 || !other[0].Equal(first[0]) {
			return nil, true
		}
	}
	return first, false
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
	// CertSameKeyDifferentCert: the served certificate carries the same public key as
	// the bundle's leaf but different bytes. Operationally this is a renewal caught
	// mid-apply, and note which side is stale: dstack-ingress regenerates the evidence
	// BEFORE it reloads HAProxy (dstack-examples custom-domain scripts/dns01.sh,
	// run_pass), so the SERVED certificate is normally the one lagging, not the bundle.
	// A failure either way, but an operational one, distinct from being served a foreign
	// certificate.
	//
	// It is not a reliable *detector* of that state: whether a renewal reuses the key
	// depends on the certbot default in the ingress image, which the image does not pin,
	// so a renewal can equally land in the default CertMismatch bucket.
	CertSameKeyDifferentCert
)

func (m CertMatch) String() string {
	switch m {
	case CertExact:
		return "served certificate is the one the quote binds"
	case CertInChain:
		return "served certificate is in the bundle chain but is not its leaf"
	case CertSameKeyDifferentCert:
		return "served certificate has the bundle key but different bytes (renewal mid-apply?)"
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
	// MRConfigID is the verified quote's mr_config_id, which carries the dstack
	// compose_hash (step 6). MRConfigIDErr is set if it could not be re-read from
	// the verified quote bytes.
	MRConfigID    [48]byte
	MRConfigIDErr error
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

	// Code is the code-identity result: which configuration — and therefore which
	// container images — the CVM booted (step 6). Only the checks the caller asked
	// for are performed; see CodeIdentity.
	Code CodeIdentity

	// OSImage is the OS-image check (step 7): whether MRTD/RTMR1/RTMR2 are an
	// OS image this verifier accepts. It is what makes Code meaningful rather than
	// self-reported — see Config.OSImages.
	OSImage OSImageCheck

	// Note records what a pass does NOT cover, so a caller cannot present this as
	// full attestation. See the package doc.
	Note string
}

// CodeIdentity is the chain from the verified quote to the container images:
// mr_config_id → compose_hash → app-compose.json → docker_compose_file.
//
// The first hop always runs (it is a read of the already-verified quote). The rest
// run only when the caller supplies the material for them, because a hash has no
// preimage of its own: without an app-compose there is nothing to learn from
// compose_hash but "it changed", and without an expected compose file there is
// nothing to compare the authenticated one to.
type CodeIdentity struct {
	// ComposeHash is SHA-256 of the CVM's app-compose.json, read from the verified
	// quote's mr_config_id. AppID is its first bytes, hex — the platform's label.
	ComposeHash [attest.ComposeHashLen]byte
	AppID       string
	// HashErr is set when mr_config_id does not expose a compose hash (an
	// unsupported dstack layout, or no quote to read it from). Everything below is
	// then unavailable.
	HashErr error

	// Requested reports whether the caller asked for the app-compose checks at all.
	// When false, the fields below are unset and none of this affects Report.Pass.
	Requested bool
	// Source names where the app-compose bytes came from, for the report.
	Source string
	// FetchErr is set when the app-compose could not be obtained.
	FetchErr error
	// BoundErr is set when the app-compose's digest is not the quote's compose_hash
	// — i.e. it is not the manifest this CVM booted. Until it is nil, nothing the
	// app-compose says may be believed.
	BoundErr error

	// Name and AllowedEnvs come from the authenticated app-compose (only meaningful
	// once BoundErr is nil). AllowedEnvs is names only — the platform never puts
	// values in the measured manifest.
	Name        string
	AllowedEnvs []string
	// ComposeFile is the authenticated docker_compose_file: the text that actually
	// booted, proven by the quote. Empty unless the binding succeeded.
	ComposeFile []byte

	// ExpectRequested reports whether a compose-file comparison happened at all, and
	// ExpectErr the result — nil meaning the deployed text equals one of the
	// candidates, whose label is then MatchedExpect.
	ExpectRequested bool
	ExpectErr       error
	MatchedExpect   string
	// ExpectExplicit reports that the comparison was ASKED for rather than run by
	// default (Config.ExpectComposeExplicit). Only this may harden an otherwise
	// advisory lookup — see OK.
	ExpectExplicit bool

	// Discovered reports that BaseDomain was derived from DNS rather than supplied.
	// A failure of a discovered lookup is informational: the caller did not ask for
	// it, so it does not fail the run (see OK).
	Discovered bool
	// NoSource reports that the app-compose stage never ran because there was nothing
	// to run it with: DNS discovery is off and neither AppCompose nor BaseDomain was
	// given. Deliberately distinct from FetchErr — nothing was attempted, so nothing
	// failed — and it exists so that no later step can read the resulting zero
	// ComposeFile / nil ExpectErr as a success.
	NoSource bool
}

// OK reports whether every code-identity check the caller requested succeeded.
//
// The line it draws: an **availability** failure is advisory, a **fact about the
// deployment** is fatal. DNS or the platform endpoint being unreachable says nothing
// about what is running, and the caller did not ask for that lookup. A compose_hash
// the register does not expose, bytes that do not hash to it, or a compose text
// matching no published release are all statements about the deployment itself.
//
// Requested and ExpectExplicit are the only two ways a caller says "this must work".
// ExpectRequested is NOT one of them: it can be true purely because -releases has a
// nonzero default, and treating it as a demand made the verdict depend on whether an
// unrelated network call happened to succeed.
func (c CodeIdentity) OK() bool {
	// Nothing to run the stage with. That is a configuration the caller chose, so it is
	// not a failure — unless they also explicitly asked for a comparison, which cannot
	// be performed without an app-compose to compare.
	if c.NoSource {
		return !c.ExpectExplicit
	}
	if c.HashErr != nil {
		return !c.Requested && !c.ExpectRequested
	}
	// Bytes that claim to be this CVM's manifest and do not hash to the quote's
	// compose_hash are a finding however they were obtained, so this never degrades to
	// advisory the way an unreachable endpoint does.
	if c.BoundErr != nil {
		return false
	}
	if c.FetchErr != nil {
		return c.Discovered && !c.ExpectExplicit
	}
	if !c.ExpectRequested {
		return true
	}
	// A comparison counts as passed only if it names what it matched. Without this,
	// any path that returns early with ExpectErr still nil — having compared nothing —
	// reads as a match.
	return c.ExpectErr == nil && c.MatchedExpect != ""
}

// Report.Note strings: what a given run did NOT cover, so a caller cannot present
// a partial result as a full one. Which one applies depends on how far the
// code-identity checks were asked to go.
// Report.Note caveats. Each names one thing a pass does NOT cover; note() composes
// the ones that apply, so a partial result can never be read as a full one.
const (
	noteNoCodeIdentity = "code identity was NOT checked — app-compose discovery is off, so " +
		"compose_hash could not be resolved to an actual configuration; it is only a value " +
		"to compare by eye"
	noteNoComposeFileCheck = "the app-compose is authenticated, but its docker_compose_file was " +
		"NOT compared against a published manifest — pass the deployed " +
		"docker-compose.release.yml (or a set of releases) to close that step"
	noteFloatingTag = "code identity is only as strong as the image pinning inside the compose " +
		"text — a floating tag keeps compose_hash stable while the code changes"
	// The one caveat that undercuts code identity rather than qualifying it: without a
	// pinned OS image, nothing establishes that the guest enforced the compose binding
	// at all, so the compose hash is evidence rather than proof.
	noteNoOSImage = "the OS image is NOT pinned (the allowlist is empty), so nothing establishes " +
		"that the guest enforced the compose-hash binding — treat code identity as strong " +
		"evidence, not proof. Endpoint identity is unaffected"
	// When the app-compose never got authenticated, the caveats that QUALIFY code
	// identity (floating tags, an uncompared compose file) presume something that does
	// not exist. Saying them anyway is worse than silence: the closing note would
	// discuss the strength of a conclusion the run never reached.
	noteNoComposeAuthenticated = "code identity was NOT established on this run — the app-compose " +
		"was not obtained or did not match compose_hash, so nothing above resolved compose_hash " +
		"to a configuration. Endpoint identity is unaffected"
)

// note is the Report.Note for this run: the caveats that apply, joined.
//
// rep may be nil, which gives the configuration-only note — what was never in scope,
// available before any check has run so an early return still carries it. Passing the
// report refines it with what actually happened, which matters in one case the
// configuration cannot predict: a lookup that was in scope and failed. Check does both,
// the second via defer, so every return path ends up with the refined form.
func (c *Checker) note(rep *Report) string {
	var notes []string
	cfg := c.cfg
	noAppCompose := cfg.AppCompose == nil && strings.TrimSpace(cfg.BaseDomain) == "" && cfg.NoDNSDiscovery
	// Attempted but unauthenticated: the app-compose stage was in scope and did not
	// produce compose text. Not the same as never asking (noteNoCodeIdentity), and not
	// something the config knows.
	unauthenticated := rep != nil && !noAppCompose && rep.Code.ComposeFile == nil
	switch {
	case noAppCompose:
		notes = append(notes, noteNoCodeIdentity)
	case unauthenticated:
		notes = append(notes, noteNoComposeAuthenticated)
	case len(cfg.ExpectComposeFiles) == 0:
		notes = append(notes, noteNoComposeFileCheck, noteFloatingTag)
	default:
		notes = append(notes, noteFloatingTag)
	}
	if len(c.osImages) == 0 {
		notes = append(notes, noteNoOSImage)
	}
	return strings.Join(notes, "; ")
}

// Pass reports whether every enforced check succeeded. Chain trust is deliberately
// excluded — callers decide whether an untrusted chain is acceptable (it is, for an
// ACME-staging smoke test) by consulting ChainTrustErr.
func (r Report) Pass() bool {
	if r.ManifestErr != nil || r.QuoteErr != nil || r.BindingErr != nil || r.CertErr != nil {
		return false
	}
	if !r.CertMatch.OK() || !r.Code.OK() || !r.OSImage.OK() {
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
func (c *Checker) Check(ctx context.Context, domain string) (rep Report, err error) {
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
	rep = Report{Domain: host, Note: c.note(nil)}
	// Refine the note with the outcome on the way out, however this returns: the
	// configuration cannot know that an in-scope lookup failed, and the qualifying
	// caveats presume it did not.
	defer func() { rep.Note = c.note(&rep) }()
	sess := c.newSession(name)

	// Step 1 — the manifest, then every file it names. The manifest bytes are kept
	// verbatim: the binding in step 3 is a hash over exactly these bytes.
	manifest, err := c.fetch(ctx, sess, host, manifestName)
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
		body, ferr := c.fetch(ctx, sess, host, e.Name)
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
	quoteBody, err := c.fetch(ctx, sess, host, quoteName)
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
			// mr_config_id (for step 6) is not on the QuoteParser seam, which carries only
			// what SPEC §4.4 needs. Re-read it structurally from the same bytes — safe
			// ONLY here, after the parser above has verified the signature, and over
			// exactly the bytes it verified. A structural parse of unverified bytes would
			// be attacker-chosen; a structural parse of verified bytes is a field read.
			if body, perr := attest.ParseTDXQuoteBody(raw); perr == nil {
				rep.MRConfigID = body.MRConfigID
			} else {
				// The parser accepted the quote but its layout will not re-read: report it
				// against code identity rather than silently leaving mr_config_id zero.
				rep.MRConfigIDErr = perr
			}
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
	c.checkServedCert(ctx, sess, host, name, certPEM, &rep)

	// Step 6 — code identity, from the same verified quote.
	c.checkCodeIdentity(ctx, &rep)

	// Step 7 — is the OS that enforced step 6's binding one we accept? Only meaningful
	// once the quote verified; before that there is no measurement to compare.
	if rep.QuoteErr == nil {
		rep.OSImage = checkOSImage(c.osImages, rep.Measurement)
	} else {
		rep.OSImage = OSImageCheck{Configured: len(c.osImages) > 0,
			Err: errors.New("not checked: the quote did not verify")}
	}
	return rep, nil
}

// checkCodeIdentity walks mr_config_id → compose_hash → app-compose →
// docker_compose_file, filling rep.Code. The first hop always runs; the rest only
// when the caller supplied the material (see CodeIdentity).
func (c *Checker) checkCodeIdentity(ctx context.Context, rep *Report) {
	code := &rep.Code
	code.Requested = c.cfg.AppCompose != nil || strings.TrimSpace(c.cfg.BaseDomain) != ""
	code.ExpectRequested = len(c.cfg.ExpectComposeFiles) > 0
	code.ExpectExplicit = c.cfg.ExpectComposeExplicit

	if rep.QuoteErr != nil {
		code.HashErr = errors.New("not checked: the quote did not verify")
		return
	}
	if rep.MRConfigIDErr != nil {
		code.HashErr = rep.MRConfigIDErr
		return
	}
	composeHash, err := attest.ComposeHashFromMRConfigID(rep.MRConfigID)
	if err != nil {
		code.HashErr = err
		return
	}
	code.ComposeHash = composeHash
	code.AppID = attest.AppIDFromComposeHash(composeHash)

	// Obtain the app-compose. A caller-supplied copy wins over fetching: it is what
	// an operator uses to assert "this is the release I deployed", and it works when
	// the platform endpoint is unreachable or public_tcbinfo is off.
	var raw []byte
	switch {
	case c.cfg.AppCompose != nil:
		raw, code.Source = c.cfg.AppCompose, "supplied"
	default:
		baseDomain := strings.TrimSpace(c.cfg.BaseDomain)
		if baseDomain == "" {
			// Nothing supplied: derive the platform base domain from the served domain's
			// DNS so `Check(domain)` alone can do code identity. Marked Discovered, so a
			// lookup the caller never asked for cannot fail the run on its own.
			if c.cfg.NoDNSDiscovery {
				// Say so explicitly. Returning with every field at its zero value left
				// ComposeFile empty and ExpectErr nil, which downstream read as "compared,
				// matched" — two ✓ for work that never happened.
				code.NoSource = true
				return
			}
			code.Discovered = true
			baseDomain, err = DeriveBaseDomain(ctx, rep.Domain)
			if err != nil {
				code.FetchErr = err
				return
			}
		}
		// The app_id comes from the quote, never from the caller or from DNS, so this
		// cannot be pointed at a different app's compose.
		code.Source = appIDHost(code.AppID, baseDomain)
		raw, err = FetchAppCompose(ctx, c.http, code.AppID, baseDomain)
		if err != nil {
			code.FetchErr = err
			return
		}
	}

	ac, err := VerifyAppCompose(raw, composeHash)
	if err != nil {
		code.BoundErr = err
		return
	}
	code.Name, code.AllowedEnvs = ac.Name, ac.AllowedEnvs
	code.ComposeFile = []byte(ac.DockerComposeFile)

	if code.ExpectRequested {
		code.MatchedExpect, code.ExpectErr = matchExpected(code.ComposeFile, c.cfg.ExpectComposeFiles)
	}
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
func (c *Checker) checkServedCert(ctx context.Context, sess *session, host, name string, certPEM []byte, rep *Report) {
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

	// The chain the run's own connection presented — the one the bundle above came
	// over, which is what makes this a comparison of one replica against itself
	// rather than of two replicas against each other (see session).
	served, changed := sess.servedChain()
	switch {
	case changed:
		// Two connections, two different leaves. Both may be legitimate replicas, so
		// there is no comparison to report: say what happened and let the caller re-run.
		rep.CertErr = fmt.Errorf("the connection to %s changed mid-run and the two certificates differ "+
			"(a deployment can be several CVMs, each with its own key); re-run to check one of them", host)
		return
	case served == nil:
		// No connection was recorded: either the caller supplied its own HTTP client
		// (nothing to record) or every fetch failed before a handshake completed. Fall
		// back to a handshake of our own so the report can still name the certificate.
		handshakeCtx, cancel := context.WithTimeout(ctx, c.limit)
		defer cancel()
		conn, derr := c.dial(handshakeCtx, host, &tls.Config{
			ServerName:         name,
			InsecureSkipVerify: true, //nolint:gosec // identity check; chain trust verified separately, see session
			MinVersion:         tls.VersionTLS12,
		})
		if derr != nil {
			rep.CertErr = fmt.Errorf("TLS handshake with %s: %w", host, derr)
			return
		}
		defer conn.Close()
		served = conn.ConnectionState().PeerCertificates
	}
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
	// Same key, different bytes: almost always a renewal caught between the evidence
	// being regenerated and HAProxy being reloaded. Worth naming, because "not in the
	// bundle" would send an operator hunting for an attack instead of re-running.
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
func (c *Checker) fetch(ctx context.Context, sess *session, host, name string) ([]byte, error) {
	u := "https://" + host + "/evidences/" + url.PathEscape(name)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	resp, err := sess.client.Do(req)
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
