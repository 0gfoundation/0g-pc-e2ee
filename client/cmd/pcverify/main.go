// Command pcverify is a read-only diagnostic for the two halves of the 0G Private
// Computer trust story. It has two modes, exactly one of which must be selected.
//
// # -provider: the provider trust chain
//
// Checks a provider against docs/design/trust-chain.md in one shot: it
// DCAP-verifies the provider's TDX quote (hops 2–4 — genuine TDX, measurement,
// report_data) and grounds the quote-bound signer in the on-chain
// InferenceServing registry (hop 5 — SPEC §4.4 step 3). It is the pre-enable gate
// for the sidecar/gateway -onchain / -attest modes: run it against the chain and
// provider you will point them at to confirm the whole chain lines up before
// flipping on enforcement.
//
//	pcverify -provider 0x... [-chain-rpc-url ...] [-serving-contract 0x...]
//	         [-endpoint https://...] [-expect-signer 0x...] [-no-quote]
//	         [-pccs-url https://...]
//
// The provider's serving endpoint is read from the chain (Service.url), so
// -endpoint is only needed to override it. -no-quote restricts the run to the
// on-chain hop (no provider contact), matching the earlier on-chain-only tool.
//
// # -gateway: the cloud-TEE gateway's own attestation
//
// Checks the gateway endpoint itself — a hop the provider chain does not cover.
// The gateway emits no quote of its own; its identity rests on the dstack-ingress
// cert-binding quote published at https://<domain>/evidences/
// (docs/design/cloud-gateway.md §6.1). This mode automates what
// deploy/phala/README.md "Verify" describes by hand: verify the bundle against its
// own sha256sum.txt, DCAP-verify quote.json, confirm its report_data binds that
// manifest, and — the load-bearing step — confirm the certificate the domain
// actually serves is the one the quote committed to.
//
//	pcverify -gateway pc-gateway.example.com [-pccs-url https://...]
//	         [-allow-untrusted-cert]
//	         [-expect-compose-file docker-compose.release.yml | -releases N]
//	         [-app-compose app-compose.json | -base-domain <cluster>.phala.network]
//	         [-no-dns-discovery]
//
// Code identity — which configuration, and so which images, the CVM booted — comes
// from the same verified quote: its mr_config_id carries
// compose_hash = SHA-256(app-compose.json), so no event-log replay is involved. It
// needs no extra arguments: the platform base domain is derived from the served
// domain's CNAME chain, the app_id comes from the QUOTE (never from the caller or
// from DNS), and the app-compose is fetched from the platform guest agent and checked
// against compose_hash before anything in it is believed. -app-compose supplies those
// bytes from a file instead; -base-domain overrides the derived domain;
// -no-dns-discovery keeps the run to the endpoint and the inputs given.
//
// The last step is naming what SHOULD be running, which only the caller knows:
// -expect-compose-file pins one manifest (a gate), while -releases N accepts any of
// the newest N published releases and reports which one is live (discovery, whose
// interesting answer is "none of them"). Without either, the compose hash and app_id
// are still printed, but nothing says whether the configuration is the intended one.
//
// -allow-untrusted-cert proceeds when the served certificate does not chain to a
// public root, for ACME-staging deployments. It relaxes no attestation check — and
// it is needed on the evidence FETCH too, not just the comparison, since that fetch
// is itself an HTTPS GET. But chain trust is what ties the connection to the domain
// asked for, so waiving it lets an interceptor running its OWN attested CVM satisfy
// every other check with its own quote, bundle and certificate. A run that uses the
// flag prints that caveat. Use it to smoke-test a deployment you operate, never to
// audit an endpoint you do not control.
//
// A pass is only ever as strong as the image pinning inside the compose text it
// authenticates: a floating tag keeps compose_hash identical while the code behind
// the tag changes. The report states which checks were skipped on every run, so a
// partial result cannot be read as a full one.
//
// # Shared
//
// -pccs-url applies to whichever mode verifies a quote: it points DCAP collateral
// fetches at a PCCS mirror instead of Intel PCS. It defaults to empty (Intel PCS,
// the authority) rather than to a mirror, because a mirror can serve
// older-but-still-valid CRL / TCB Info — a bounded freshness delegation this tool
// should not take on by default. Pass it when Intel PCS rate-limits a repeated or
// CI run, or to check against the collateral source a deployment actually uses
// (ZG_GATEWAY_PCCS_URL).
//
// Both modes make NO changes and send NOTHING beyond reads: the chain RPC and the
// provider's public /quote, or the public evidence files and one TLS handshake,
// plus whatever DCAP collateral the verifier fetches. Exit code is non-zero on any
// failed check, so either drops into CI or a deploy gate.
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/0gfoundation/0g-pc-e2ee/client/chain"
	"github.com/0gfoundation/0g-pc-e2ee/client/dcap"
	"github.com/0gfoundation/0g-pc-e2ee/protocol/attest"
)

// maxQuoteBodyBytes bounds the provider /quote response read.
const maxQuoteBodyBytes = 1 << 20

func main() {
	os.Exit(run(context.Background(), os.Stdout, os.Args[1:]))
}

// serviceReader reads a provider's on-chain Service info (URL + signer + ack).
type serviceReader interface {
	ServiceInfo(ctx context.Context, provider string) (chain.ServiceInfo, error)
}

// quoteChecker fetches a provider's TDX quote from its endpoint and DCAP-verifies
// it. nil disables the quote hops (on-chain only).
type quoteChecker interface {
	FetchAndVerify(ctx context.Context, endpoint string) (attest.Verified, error)
}

func run(ctx context.Context, out io.Writer, args []string) int {
	fs := flag.NewFlagSet("pcverify", flag.ContinueOnError)
	fs.SetOutput(out)
	provider := fs.String("provider", "", "provider on-chain account address (0x + 40 hex); selects provider mode")
	chainRPCURL := fs.String("chain-rpc-url", chain.DefaultChainRPCURL, "0G chain JSON-RPC endpoint; a source trusted independently of the router (defaults to 0G mainnet)")
	servingContract := fs.String("serving-contract", chain.DefaultInferenceServingAddress, "InferenceServing contract address")
	endpoint := fs.String("endpoint", "", "provider serving endpoint for the quote fetch (default: read from chain, Service.url)")
	expectSigner := fs.String("expect-signer", "", "if set, require the on-chain teeSignerAddress to equal this")
	noQuote := fs.Bool("no-quote", false, "skip the TDX quote hops; check only the on-chain signer (no provider contact)")
	gateway := fs.String("gateway", "", "cloud-TEE gateway domain (e.g. pc-gateway.example.com); selects gateway mode — verify its /evidences bundle and compare the served certificate")
	pccsURL := fs.String("pccs-url", "", "fetch DCAP collateral (TCB Info, QE Identity, PCK CRL) from this PCCS mirror instead of api.trustedservices.intel.com (e.g. https://pccs.phala.network); the root-CA CRL still comes from Intel. Applies to whichever mode verifies a quote")
	allowUntrustedCert := fs.Bool("allow-untrusted-cert", false, "gateway mode: proceed when the served certificate does not chain to a public root (ACME staging). Relaxes no attestation check, but drops the link between the connection and the domain asked for, so an interceptor running its own attested CVM would still pass — smoke-test your own deployment only")
	appCompose := fs.String("app-compose", "", "gateway mode: path to the CVM's app-compose.json, checked against the compose_hash the quote binds. Its source need not be trusted — the hash anchors it. Takes precedence over the guest-agent fetch")
	baseDomain := fs.String("base-domain", "", "gateway mode: platform base domain (e.g. in1.phala.network) to fetch app-compose.json from the guest agent of the app_id the QUOTE names. Default: derived from the served domain's CNAME chain")
	noDNSDiscovery := fs.Bool("no-dns-discovery", false, "gateway mode: do not derive the platform base domain from DNS; check only what was passed in")
	expectComposeFile := fs.String("expect-compose-file", "", "gateway mode: path to the docker-compose manifest this deployment should be running (a digest-pinned docker-compose.release.yml), compared against the authenticated app-compose's docker_compose_file. Mutually exclusive with -releases")
	releases := fs.Int("releases", 0, "gateway mode: instead of -expect-compose-file, accept the deployment if its compose text matches any of the newest N published releases, and report which one")
	releaseRepo := fs.String("repo", defaultReleaseRepo, "gateway mode: owner/name to read releases from, with -releases")
	releaseAsset := fs.String("release-asset", defaultReleaseAsset, "gateway mode: release asset holding the deployment manifest, with -releases")
	timeout := fs.Duration("timeout", 30*time.Second, "overall timeout")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	// Exactly one mode. They verify unrelated things (a provider's trust chain vs
	// the gateway endpoint's own attestation) and share no flags, so combining them
	// would only hide which one the exit code refers to.
	wantProvider := strings.TrimSpace(*provider) != ""
	wantGateway := strings.TrimSpace(*gateway) != ""
	switch {
	case wantProvider && wantGateway:
		fmt.Fprintln(out, "pcverify: -provider and -gateway are separate modes; pass exactly one")
		return 2
	case !wantProvider && !wantGateway:
		fmt.Fprintln(out, "pcverify: one of -provider (provider trust chain) or -gateway (gateway attestation) is required")
		fs.Usage()
		return 2
	}

	if wantGateway {
		gcfg := gatewayConfig{
			pccsURL:            *pccsURL,
			timeout:            *timeout,
			allowUntrustedCert: *allowUntrustedCert,
			appComposePath:     *appCompose,
			baseDomain:         *baseDomain,
			noDNSDiscovery:     *noDNSDiscovery,
			expectComposePath:  *expectComposeFile,
			releases:           *releases,
			releaseRepo:        *releaseRepo,
			releaseAsset:       *releaseAsset,
		}
		// The release lookup happens inside Build, so it shares the run's deadline.
		ctx, cancel := context.WithTimeout(ctx, *timeout)
		defer cancel()
		ec, err := newEvidenceChecker(ctx, out, gcfg)
		if err != nil {
			fmt.Fprintf(out, "pcverify: %v\n", err)
			return 2
		}
		return reportGateway(ctx, out, ec, *gateway, *allowUntrustedCert)
	}

	reg, err := chain.NewOnChainRegistry(chain.Config{RPCURL: *chainRPCURL, ContractAddress: *servingContract})
	if err != nil {
		fmt.Fprintf(out, "pcverify: %v\n", err)
		return 2
	}

	var qc quoteChecker
	if !*noQuote {
		qc = newDCAPChecker(*pccsURL)
	}

	ctx, cancel := context.WithTimeout(ctx, *timeout)
	defer cancel()
	return report(ctx, out, reg, qc, *provider, *servingContract, *endpoint, *expectSigner)
}

// report runs the checks and prints a per-hop result, returning the process exit
// code (0 pass, 1 failed check). It takes interfaces so tests drive it without a
// live chain or provider.
func report(ctx context.Context, out io.Writer, sr serviceReader, qc quoteChecker, provider, contract, endpointOverride, expectSigner string) int {
	fmt.Fprintf(out, "provider           %s\n", provider)
	fmt.Fprintf(out, "contract           %s\n", contract)

	info, err := sr.ServiceInfo(ctx, provider)
	if err != nil {
		fmt.Fprintf(out, "%s on-chain lookup    %v\n", mark(false), err)
		return fail(out)
	}
	fmt.Fprintf(out, "  teeSignerAddress %s\n", info.Signer)
	fmt.Fprintf(out, "%s acknowledged     %v\n", mark(info.Acknowledged), info.Acknowledged)
	ok := info.Acknowledged

	if strings.TrimSpace(expectSigner) != "" {
		match := strings.EqualFold(strings.TrimSpace(info.Signer), strings.TrimSpace(expectSigner))
		fmt.Fprintf(out, "%s matches expected %s\n", mark(match), expectSigner)
		ok = ok && match
	}

	if qc != nil {
		endpoint, src := endpointOverride, "from -endpoint"
		if strings.TrimSpace(endpoint) == "" {
			endpoint, src = info.URL, "from chain (Service.url)"
		}
		if strings.TrimSpace(endpoint) == "" {
			fmt.Fprintf(out, "%s quote            no endpoint (not on chain; pass -endpoint or -no-quote)\n", mark(false))
			return fail(out)
		}
		fmt.Fprintf(out, "endpoint           %s (%s)\n", endpoint, src)

		v, err := qc.FetchAndVerify(ctx, endpoint)
		if err != nil {
			fmt.Fprintf(out, "%s quote            %v\n", mark(false), err)
			return fail(out)
		}
		fmt.Fprintf(out, "%s quote            genuine TDX (DCAP verified)\n", mark(true))
		fmt.Fprintf(out, "  measurement MRTD %x\n", v.Measurement.MRTD[:])
		if !v.MeasurementTrusted {
			fmt.Fprintf(out, "  note             measurement not in allowlist (none configured)\n")
		}
		fmt.Fprintf(out, "  report_data enc  %x\n", v.EncPub)
		fmt.Fprintf(out, "  report_data sgnr %s\n", v.SignerAddr)

		// hop 5: the signer bound in the (genuine) quote must equal the on-chain one.
		match := strings.EqualFold(strings.TrimSpace(v.SignerAddr), strings.TrimSpace(info.Signer))
		fmt.Fprintf(out, "%s quote signer == on-chain signer\n", mark(match))
		ok = ok && match
	}

	if ok {
		fmt.Fprintln(out, "\nPASS")
		return 0
	}
	return fail(out)
}

func fail(out io.Writer) int {
	fmt.Fprintln(out, "\nFAIL")
	return 1
}

func mark(ok bool) string {
	if ok {
		return "✓"
	}
	return "✗"
}

// dcapChecker is the real quoteChecker: it GETs the provider's /quote and
// DCAP-verifies it (genuine TDX + TCB + report_data binding). Measurement runs in
// warn mode so the tool reports an out-of-allowlist measurement rather than
// erroring — the allowlist is not yet populated (see proxycli/newVerifier).
type dcapChecker struct {
	http     *http.Client
	verifier *attest.Verifier
}

// newDCAPChecker builds the provider-mode verifier. pccsURL (when non-empty)
// points collateral fetches at a PCCS mirror instead of Intel PCS — the same knob
// the gateway mode and the sidecar/gateway binaries take, so a run of either mode
// can be aimed at the collateral source the deployment actually uses.
func newDCAPChecker(pccsURL string) *dcapChecker {
	return &dcapChecker{
		http: &http.Client{Timeout: 20 * time.Second},
		verifier: attest.New(
			attest.Policy{},
			attest.WithQuoteParser(dcap.NewQuoteParser(dcap.Config{PCCSBaseURL: pccsURL})),
			attest.WithMeasurementMode(attest.ModeWarn),
		),
	}
}

func (c *dcapChecker) FetchAndVerify(ctx context.Context, endpoint string) (attest.Verified, error) {
	raw, err := c.fetchQuote(ctx, endpoint)
	if err != nil {
		return attest.Verified{}, err
	}
	return c.verifier.Verify(raw)
}

func (c *dcapChecker) fetchQuote(ctx context.Context, endpoint string) ([]byte, error) {
	quoteURL, err := quoteURLFromEndpoint(endpoint)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, quoteURL, nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch quote: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxQuoteBodyBytes))
	if err != nil {
		return nil, fmt.Errorf("read quote: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("quote endpoint returned %d", resp.StatusCode)
	}
	return attest.DecodeQuoteResponse(body)
}

// quoteURLFromEndpoint turns a provider endpoint into its DCAP quote URL,
// mirroring client/route: normalize to the /v1 base, then /quote?legacy=false.
func quoteURLFromEndpoint(endpoint string) (string, error) {
	u, err := url.Parse(strings.TrimSpace(endpoint))
	if err != nil {
		return "", fmt.Errorf("%q is not a valid URL: %w", endpoint, err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return "", fmt.Errorf("%q is not an http(s) URL", endpoint)
	}
	if u.Host == "" {
		return "", fmt.Errorf("%q has no host", endpoint)
	}
	base := strings.TrimSuffix(u.Path, "/")
	switch {
	case strings.HasSuffix(base, "/chat/completions"):
		base = strings.TrimSuffix(base, "/chat/completions")
	case strings.HasSuffix(base, "/v1"):
		// already the /v1 base
	default:
		base += "/v1"
	}
	return u.Scheme + "://" + u.Host + base + "/quote?legacy=false", nil
}
