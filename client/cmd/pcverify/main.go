// Command pcverify is a read-only diagnostic for the two halves of the 0G Private
// Computer trust story. It has two modes, exactly one of which must be selected.
//
// # -provider: the provider trust chain
//
// Checks a provider against docs/design/trust-chain.md in one shot: it
// DCAP-verifies the provider's TDX quote (hops 2–4 — genuine TDX, boot chain,
// report_data) and grounds the quote-bound signer in the on-chain
// InferenceServing registry (hop 5 — SPEC §4.4 step 3). It is the pre-enable gate
// for the sidecar/gateway -onchain / -attest modes: run it against the chain and
// provider you will point them at to confirm the whole chain lines up before
// flipping on enforcement.
//
// Hop 3 compares, against the same embedded allowlist the sealing path enforces
// (client/evidence/brokerimages.json). An image that is not listed FAILS the run. When
// that file has no entries the comparison cannot run at all, and the report says so
// and returns 3 rather than passing — so a run can never read as "audited" on the
// strength of an allowlist that was never consulted. Either way the observed boot
// chain is printed in the shape an entry wants — MRTD, RTMR1, RTMR2, the three
// registers attest.BootChain pins — because that is how the next entry gets recorded.
// RTMR3 is not offered as a candidate value: it carries per-instance events, so
// pinning it would pin one CVM. RTMR0 is shown, labelled as not compared.
//
// Hop 3 pins the OS and stops there, so the run then reads WHAT RUNS INSIDE it. Two
// providers on one allowlisted image can run entirely different containers, because
// mr_config_id commits to the app-compose the operator chose. The reply's app-compose
// is checked against the compose_hash that register carries — a mismatch means the
// provider served a manifest its own enclave did not boot, and fails the run — and
// what it authenticated is then printed: every service with its image reference,
// whether that reference is digest-pinned, whether it comes from our namespace or
// upstream, and a structural review of the manifest (client/evidence's
// composereview.go). The review REPORTS and never gates: its rules are heuristics
// about a manifest we did not write, and a heuristic wired to an exit code refuses a
// provider for being unusual. It is there so a per-service baseline can be written
// from a real deployment; the baseline, once it exists, is what will adjudicate. A
// provider that publishes no app_compose at all is a 3, not a pass.
//
// Beside each service the run prints its CANONICAL BLOCK fingerprint — two of them,
// because a baseline will pin them separately: `block` covers everything the deployment
// decided, and `block-no-image` is the half that must not move when the broker ships a
// new image digest (see client/evidence/composeblock.go). The fingerprints make a sweep
// across providers able to say which services are already identical fleet-wide, which is
// the fact a first baseline has to be written against. -blocks prints the canonical text
// itself, which is what a baseline entry will hold; it is a comparison form, not
// deployable YAML.
//
// Those blocks are then COMPARED against the recorded per-service baseline
// (client/evidence/brokercompose.json) — the check that adjudicates, and the only part of
// the manifest section that can fail a run. Every direction is checked: a recorded
// service missing from the manifest, a manifest service the baseline does not record (an
// unlisted container runs in the same guest as the reviewed ones), a service declared
// twice, a block that differs, and an image outside its rule. The baseline ships EMPTY,
// because recording cn-20's manifest as it stands would bless the ten blocking findings
// the review reports on it — so provider mode returns 3 until it is filled, saying the
// containers were not compared against anything. -app-baseline reads a candidate file
// instead, which is how the first one gets written and checked against a live provider
// before it is committed.
//
//	pcverify -provider 0x... [-chain-rpc-url ...] [-serving-contract 0x...]
//	         [-endpoint https://...] [-expect-signer 0x...] [-no-quote]
//	         [-pccs-url https://...] [-blocks] [-app-baseline brokercompose.json]
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
//	         [-no-dns-discovery] [-os-image-allowlist osimages.json]
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
// The last step — what SHOULD be running — defaults to -releases 5: the deployment
// matches if its compose text equals any of the newest 5 published releases, and the
// report names which one (its interesting answer is "none of them").
// -expect-compose-file overrides that with a single pinned manifest, a stricter gate;
// -releases 0 skips the comparison entirely. Passing -expect-compose-file and an
// explicit -releases together is rejected — they answer different questions.
//
// Because -releases has a default, its failure mode depends on whether it was asked
// for: a GitHub lookup that fails on a DEFAULT run is advisory and does not fail the
// run (an unreachable or rate-limited API says nothing about the deployment), while an
// explicit -releases N that cannot be satisfied is fatal. Same rule as DNS discovery.
//
// -strict ends that degradation for every optional lookup at once. It is the flag for
// a gate: without it the only way to make a lookup mandatory is to also supply its
// input (-releases N, -base-domain …), which conflates "I require this check" with
// "here is where to look" and leaves a CI author who does not know the platform base
// domain unable to harden the run at all. -strict requires the checks and lets
// discovery keep finding the values. It is rejected together with -releases 0, which
// asks to skip the one comparison whose failure is the finding that matters.
//
// -allow-untrusted-cert accepts a served certificate that does not chain to a public
// root, for ACME-staging deployments. It is purely a verdict decision: the evidence
// fetch never verifies PKI in the first place (it rides the same connection whose
// certificate is being compared), so every check still runs without the flag — what
// the flag changes is whether the reported chain-trust failure blocks the result. It
// relaxes no attestation check, but chain trust is what ties the connection to the
// domain asked for, so waiving it lets an interceptor running its OWN attested CVM
// satisfy every other check with its own quote, bundle and certificate. A run that
// uses the flag prints that caveat. Use it to smoke-test a deployment you operate,
// never to audit an endpoint you do not control.
//
// Underneath all of that sits the OS image. mr_config_id is chosen by the untrusted
// host, so the compose hash means what it says only because the guest OS refuses to
// boot when that register disagrees with the app-compose actually delivered — which
// makes the OS itself part of the chain. The quote's image registers (MRTD, RTMR1,
// RTMR2) are therefore compared against an allowlist embedded in the binary, so
// nothing has to be supplied; -os-image-allowlist overrides it for testing or for
// pinning an image before it is committed. An image that is not listed FAILS the run.
// (An allowlist with no entries at all would instead report "not pinned" and pass, but
// the embedded one has entries and -os-image-allowlist rejects an empty file.)
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
// plus whatever DCAP collateral the verifier fetches.
//
// # Exit codes
//
//	0  every check ran and passed
//	1  a check failed — including a lookup the caller DEMANDED (-strict, or an
//	   explicit -releases N) that could not be completed: the flags were usable, the
//	   claim just could not be made
//	2  caller mistake (bad flags, an unusable domain, an unreadable file)
//	3  nothing failed, but a check did not RUN
//
// 3 exists because "nothing I checked was wrong" is a weaker claim than "I checked
// everything", and a gate reading only zero/non-zero cannot tell them apart — which
// would let a GitHub outage read as a full pass on the one check that catches a
// deployment running unpublished code. A run that skips something says so on screen
// and returns 3; -strict turns that into 1 instead. Treat 3 as failure in a gate
// unless a partial verification is genuinely acceptable there.
//
// Both modes use it. In provider mode a 3 means one of four things, and the verdict line
// names every one that applies rather than the first: the embedded broker-image allowlist
// has no entry to compare against, so the code root did not run; the provider published
// no app-compose (or a quote whose mr_config_id exposes no compose_hash to gate one
// against), so what runs inside the audited image was not read; no per-service baseline
// is recorded, so the containers were not compared against anything; or -no-quote skipped
// hops 2–4 by request. As shipped the third always applies, since brokercompose.json is
// deliberately empty — pass -app-baseline with a candidate to reach a clean 0.
package main

import (
	"context"
	"errors"
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
	"github.com/0gfoundation/0g-pc-e2ee/client/evidence"
	"github.com/0gfoundation/0g-pc-e2ee/protocol/attest"
)

// maxQuoteBodyBytes bounds the provider /quote response read. It matches
// evidence's guest-agent cap, because the reply carries the same nested documents: the
// quote hex plus a tcb_info holding the whole app-compose (which holds the whole
// docker-compose text) and the RTMR3 event log. A limit that merely fitted the quote
// would truncate the manifest, and the JSON error that followed would be reported as a
// malformed quote — a false accusation against the provider for a bound of ours.
const maxQuoteBodyBytes = 4 << 20

func main() {
	os.Exit(run(context.Background(), os.Stdout, os.Args[1:]))
}

// serviceReader reads a provider's on-chain Service info (URL + signer + ack).
type serviceReader interface {
	ServiceInfo(ctx context.Context, provider string) (chain.ServiceInfo, error)
}

// providerQuote is everything one /v1/quote fetch established, in the order it
// becomes trustworthy.
//
// The three fields are NOT equally believable and the type keeps them apart on
// purpose. Verified is signed by Intel. ComposeHash comes out of the signed report's
// mr_config_id, so it is as good as Verified — but only because it was re-parsed from
// the same authenticated bytes under the measurement-equality guard (see
// FetchAndVerify). AppCompose is the reply's own text: nothing signs it, and it means
// nothing until sha256 over it equals ComposeHash. Collapsing them into one struct
// with one comment is how a caller ends up reading the third as if it were the first.
type providerQuote struct {
	Verified attest.Verified
	// ComposeHash is the compose_hash the verified quote commits to, and HaveComposeHash
	// says whether there is one to read — a V2/V3 mr_config_id folds it into a digest
	// instead of carrying it in the clear, which is not a fault in the quote.
	ComposeHash     [attest.ComposeHashLen]byte
	HaveComposeHash bool
	// ComposeHashErr says why there is no hash, for the report. Distinct from
	// HaveComposeHash because "this layout does not expose one" and "the re-parse
	// disagreed with the verified measurement" are very different findings.
	ComposeHashErr error
	// AppCompose is the reply's app-compose text, UNAUTHENTICATED. It exists to be fed
	// to evidence.ReviewCompose together with ComposeHash, which is the only sanctioned
	// use: that call performs the gate, so there is no path here that reads this text
	// without one.
	AppCompose []byte
	// AppComposeErr says why the reply carried none.
	AppComposeErr error
}

// quoteChecker fetches a provider's TDX quote from its endpoint and DCAP-verifies
// it. nil disables the quote hops (on-chain only).
type quoteChecker interface {
	FetchAndVerify(ctx context.Context, endpoint string) (providerQuote, error)
	// BaselineConfigured reports whether the verifier holds any expected boot chain,
	// so the report can separate "this image is not in the allowlist" (a finding about
	// the provider) from "there is no allowlist" (a finding about this build). Under
	// warn mode Verified.MeasurementTrusted is false for both, which is why the
	// distinction has to come from here — see attest.Verifier.MeasurementBaselineConfigured,
	// which exists for exactly this caller shape.
	BaselineConfigured() bool
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
	appBaseline := fs.String("app-baseline", "", "provider mode: read the per-service compose baseline from this file instead of the one built into the binary (see client/evidence/brokercompose.json). For writing and checking a candidate baseline against a live provider before committing it")
	blocks := fs.Bool("blocks", false, "provider mode: print each service's canonical block text, not just its fingerprint. This is the text a per-service baseline is written from (client/evidence/composeblock.go); it is a COMPARISON form, not deployable YAML")
	gateway := fs.String("gateway", "", "cloud-TEE gateway domain (e.g. pc-gateway.example.com); selects gateway mode — verify its /evidences bundle and compare the served certificate")
	pccsURL := fs.String("pccs-url", "", "fetch DCAP collateral (TCB Info, QE Identity, PCK CRL) from this PCCS mirror instead of api.trustedservices.intel.com (e.g. https://pccs.phala.network); the root-CA CRL still comes from Intel. Applies to whichever mode verifies a quote")
	allowUntrustedCert := fs.Bool("allow-untrusted-cert", false, "gateway mode: proceed when the served certificate does not chain to a public root (ACME staging). Relaxes no attestation check, but drops the link between the connection and the domain asked for, so an interceptor running its own attested CVM would still pass — smoke-test your own deployment only")
	appCompose := fs.String("app-compose", "", "gateway mode: path to the CVM's app-compose.json, checked against the compose_hash the quote binds. Its source need not be trusted — the hash anchors it. Takes precedence over the guest-agent fetch")
	baseDomain := fs.String("base-domain", "", "gateway mode: platform base domain (e.g. in1.phala.network) to fetch app-compose.json from the guest agent of the app_id the QUOTE names. Default: derived from the served domain's CNAME chain")
	osImages := fs.String("os-image-allowlist", "", "gateway mode: read the expected OS-image boot-chain measurements from this file instead of the ones built into the binary (see client/evidence/osimages.json). For testing and for pinning an image before it is committed")
	noDNSDiscovery := fs.Bool("no-dns-discovery", false, "gateway mode: do not derive the platform base domain from DNS; check only what was passed in")
	expectComposeFile := fs.String("expect-compose-file", "", "gateway mode: path to the docker-compose manifest this deployment should be running (a digest-pinned docker-compose.release.yml), compared against the authenticated app-compose's docker_compose_file. Overrides the default -releases lookup")
	releases := fs.Int("releases", defaultReleases, "gateway mode: accept the deployment if its compose text matches any of the newest N published releases, and report which one. 0 disables the lookup")
	strict := fs.Bool("strict", false, "require every check to RUN, not merely to not fail: anything that would report an advisory \"-\" (exit 3) fails the run instead (exit 1). Gateway mode — a releases or app-compose lookup that cannot be completed; it demands the checks without demanding their inputs, so discovery still supplies them. Provider mode — hop 3, which cannot pass when the audited allowlist has no entry to compare against, and the app-compose read, which cannot happen when the provider publishes none")
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
			osImagesPath:       *osImages,
			expectComposePath:  *expectComposeFile,
			releases:           *releases,
			releaseRepo:        *releaseRepo,
			releaseAsset:       *releaseAsset,
			// Whether a flag was PASSED, not just what it holds: -releases has a nonzero
			// default, so "the operator asked for this" and "this is what the default does"
			// have to be told apart — it decides both which expectation wins and whether a
			// failed release lookup is fatal.
			releasesSet:      flagSet(fs, "releases"),
			expectComposeSet: flagSet(fs, "expect-compose-file"),
			strict:           *strict,
		}
		// The release lookup happens during construction, so it shares the run's deadline.
		ctx, cancel := context.WithTimeout(ctx, *timeout)
		defer cancel()
		ec, expect, err := newEvidenceChecker(ctx, out, gcfg)
		if err != nil {
			fmt.Fprintf(out, "pcverify: %v\n", err)
			// A lookup the caller demanded and did not get is a failed check, not a
			// caller mistake: the run could not make a claim it was told to make. Every
			// other setup failure here really is exit 2.
			var required errLookupRequired
			if errors.As(err, &required) {
				return fail(out)
			}
			return 2
		}
		return reportGateway(ctx, out, ec, *gateway, *allowUntrustedCert, *strict, expect)
	}

	reg, err := chain.NewOnChainRegistry(chain.Config{RPCURL: *chainRPCURL, ContractAddress: *servingContract})
	if err != nil {
		fmt.Fprintf(out, "pcverify: %v\n", err)
		return 2
	}

	// -strict demands every check; -no-quote switches off hops 2–4. Same contradiction
	// as -strict with -releases 0, and rejected the same way rather than by silently
	// honouring one of the two.
	if *strict && *noQuote {
		fmt.Fprintln(out, "pcverify: -strict requires the quote hops; drop -no-quote")
		return 2
	}

	// Loaded here rather than inside report so a malformed file is a caller/build error
	// (exit 2) before any claim is made about the provider, matching how the broker-image
	// allowlist is handled. An unreadable -app-baseline is the caller's mistake; a
	// malformed EMBEDDED one is a defect in this build, and both are worth exiting on
	// rather than degrading to "not configured", which would silently drop the check.
	baseline, err := loadComposeBaseline(*appBaseline)
	if err != nil {
		fmt.Fprintf(out, "pcverify: %v\n", err)
		return 2
	}

	var qc quoteChecker
	if !*noQuote {
		// Usage-class exit (2), not a check failure (1): a malformed embedded allowlist
		// is a defect in this build, and no statement has been made about the provider.
		checker, err := newDCAPChecker(*pccsURL)
		if err != nil {
			fmt.Fprintf(out, "pcverify: %v\n", err)
			return 2
		}
		qc = checker
	}

	ctx, cancel := context.WithTimeout(ctx, *timeout)
	defer cancel()
	return report(ctx, out, reg, qc, *provider, *servingContract, *endpoint, *expectSigner,
		providerOpts{strict: *strict, blocks: *blocks, baseline: baseline})
}

// providerOpts are provider-mode knobs that change what the run REPORTS, not what it
// checks. Grouped rather than added as more trailing booleans: report already takes
// eight parameters, and a caller passing `..., false, true)` says nothing about which
// knob is which.
type providerOpts struct {
	// strict turns every "did not run" into a failure (see verdict).
	strict bool
	// blocks prints each service's canonical block text, not just its fingerprint. It is
	// off by default because the text is long and only one reader needs it: whoever is
	// writing the per-service baseline the fingerprints are for.
	blocks bool
	// baseline is the per-service baseline to compare the manifest against. Passed in
	// rather than loaded inside report so a test can drive the comparison, and so
	// -app-baseline can substitute a candidate file for the embedded one.
	baseline []evidence.BaselineService
}

// report runs the checks and prints a per-hop result, returning the process exit code
// on the same contract as gateway mode: 0 every check ran and passed, 1 a check
// failed, 3 nothing failed but a check did not run (see verdict). It takes interfaces
// so tests drive it without a live chain or provider.
//
// Provider mode reaches "did not run" through its own door: an allowlist with no
// entry means the boot-chain comparison cannot happen, and the run is incomplete
// however well every other hop went. With entries — the shipped state — a matching
// provider reaches a clean 0. The distinction matters for a CI gate, which would
// otherwise read an unconsulted allowlist as a pass.
func report(ctx context.Context, out io.Writer, sr serviceReader, qc quoteChecker, provider, contract, endpointOverride, expectSigner string, opts providerOpts) int {
	fmt.Fprintf(out, "provider           %s\n", provider)
	fmt.Fprintf(out, "contract           %s\n", contract)

	// What this run did not cover, for the verdict. -no-quote is a deliberate skip of
	// hops 2–4, which is still a skip: the run says nothing about the enclave.
	//
	// A slice rather than a string because more than one thing can go unchecked in a
	// single run — an unconfigured allowlist AND a provider that publishes no manifest —
	// and reporting only the first would have the verdict line understate the gap it
	// exists to disclose.
	var skipped []string
	if qc == nil {
		skipped = append(skipped, "the quote hops (2-4) did not run (-no-quote), so nothing here is about the enclave")
	}

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

		pq, err := qc.FetchAndVerify(ctx, endpoint)
		if err != nil {
			fmt.Fprintf(out, "%s quote            %v\n", mark(false), err)
			return fail(out)
		}
		v := pq.Verified
		fmt.Fprintf(out, "%s quote            genuine TDX (DCAP verified)\n", mark(true))
		// The boot chain, in the shape an allowlist entry wants — MRTD + RTMR1 + RTMR2,
		// the registers attest.BootChain pins. Printing MRTD alone was enough to see
		// that a check did not happen and not enough to do anything about it: nobody
		// could derive an entry from this tool's output, which is the only way the
		// values get recorded in the first place. Gateway mode has printed all three
		// for that reason (reportBootChain), and this is the same need on the hop that
		// still has no allowlist.
		switch {
		case v.MeasurementTrusted:
			// A clean match needs only to say so; the registers are the reader's next
			// action only when there is one.
			fmt.Fprintf(out, "%s boot chain       in the audited allowlist\n", mark(true))
		case !qc.BaselineConfigured():
			fmt.Fprintf(out, "- boot chain       not compared (no allowlist configured)\n")
			reportBootChain(out, attest.BootChainOf(v.Measurement))
			reportShapeRegister(out, v.Measurement)
			// The code root did not run. Reported, so the verdict cannot be 0 — this is
			// exactly the "- read as ✓" mistake the exit codes exist to prevent, and here
			// it fires on every run rather than on a bad day.
			skipped = append(skipped, "the boot chain was not compared (hop 3: no audited allowlist configured)")
		default:
			fmt.Fprintf(out, "%s boot chain       matches no audited image\n", mark(false))
			reportBootChain(out, attest.BootChainOf(v.Measurement))
			reportShapeRegister(out, v.Measurement)
			ok = false
		}
		fmt.Fprintf(out, "  report_data enc  %x\n", v.EncPub)
		fmt.Fprintf(out, "  report_data sgnr %s\n", v.SignerAddr)

		// hop 5: the signer bound in the (genuine) quote must equal the on-chain one.
		match := strings.EqualFold(strings.TrimSpace(v.SignerAddr), strings.TrimSpace(info.Signer))
		fmt.Fprintf(out, "%s quote signer == on-chain signer\n", mark(match))
		ok = ok && match

		// What runs INSIDE the audited image. Hop 3 pins the OS; two providers on one
		// allowlisted image can still run entirely different containers, because
		// mr_config_id commits to the manifest the OPERATOR chose. This is the only place
		// in the tool that reads it.
		failed, skip := reportManifest(out, pq, opts.baseline, opts.blocks)
		if failed {
			ok = false
		}
		if skip != "" {
			skipped = append(skipped, skip)
		}
	}

	return verdict(out, !ok, strings.Join(skipped, "; "), opts.strict)
}

// reportManifest prints the provider's app-compose, hash-gated, and the structural
// review of it. It returns whether a check FAILED and, separately, what went unchecked.
//
// The split between those two return values is the whole design of this section:
//
//   - The gate is a real check with a real verdict. sha256 over the reply's app-compose
//     must equal the compose_hash the verified quote binds. A mismatch means the
//     provider served a manifest that is not the one its own enclave booted, which is a
//     finding about the provider and fails the run.
//   - Absence is a SKIP, not a pass. A provider whose reply carries no app_compose
//     (public_tcbinfo off, an older broker) or whose mr_config_id does not expose a
//     compose_hash has not been checked here, and a gate reading exit 0 must not be
//     told otherwise.
//   - The review itself gates NOTHING. Its rules are heuristics about a manifest we did
//     not write, and a heuristic wired to an exit code refuses a provider for being
//     unusual. It is printed so a human can turn it into a baseline; the baseline is
//     what will adjudicate. See evidence/composereview.go's header.
func reportManifest(out io.Writer, pq providerQuote, baseline []evidence.BaselineService, dumpBlocks bool) (failed bool, skipped string) {
	switch {
	case !pq.HaveComposeHash:
		fmt.Fprintf(out, "- app-compose      not read (%s)\n", reason(pq.ComposeHashErr,
			"the quote's mr_config_id exposes no compose_hash"))
		return false, "the provider's manifest was not read (the quote exposes no compose_hash to gate it against)"
	case len(pq.AppCompose) == 0:
		fmt.Fprintf(out, "  compose_hash     %x\n", pq.ComposeHash)
		fmt.Fprintf(out, "- app-compose      not served (%s)\n", reason(pq.AppComposeErr,
			"the /v1/quote reply carries no app_compose"))
		return false, "the provider's manifest was not read (its /v1/quote reply carries no app_compose)"
	}

	review, err := evidence.ReviewCompose(pq.AppCompose, pq.ComposeHash)
	if err != nil {
		// The gate, or bytes that are not JSON. Either way nothing below it may be
		// believed, so nothing below it is printed.
		fmt.Fprintf(out, "%s app-compose      %v\n", mark(false), err)
		return true, ""
	}
	fmt.Fprintf(out, "%s app-compose      authenticated: sha256 equals the compose_hash the quote binds\n", mark(true))
	fmt.Fprintf(out, "  compose_hash     %x\n", pq.ComposeHash)
	fmt.Fprintf(out, "  app_id           %s\n", attest.AppIDFromComposeHash(pq.ComposeHash))
	// "none" is a claim, so it is only printed when the manifest actually made it. An
	// unreadable features field renders as such — see ComposeReview.FeaturesUnreadable.
	features := "none"
	switch {
	case review.FeaturesUnreadable:
		features = "<unreadable>"
	case len(review.Features) > 0:
		features = strings.Join(review.Features, ",")
	}
	fmt.Fprintf(out, "  manifest         name=%q runner=%q features=%s\n", review.Name, review.Runner, features)
	// The manifest's WHOLE key surface, not the subset the reviewer has rules for. The
	// two diverge as dstack adds fields, and printing only the checked half is how a
	// review goes quietly stale — the unrecognised ones also appear as findings, but the
	// list is what lets a reader see the shape of the document at a glance.
	fmt.Fprintf(out, "  fields           %s\n", strings.Join(review.Fields, ", "))

	pinned, firstParty := 0, 0
	for _, s := range review.Services {
		if s.Pinned() {
			pinned++
		}
		if s.Origin == evidence.OriginFirstParty {
			firstParty++
		}
	}
	fmt.Fprintf(out, "  services         %d (%d pinned by digest, %d first-party)\n",
		len(review.Services), pinned, firstParty)
	for i, s := range review.Services {
		ref := s.Ref
		if ref == "" {
			ref = "(no image)"
		}
		fmt.Fprintf(out, "    %-24s %-18s %s\n", s.Name, s.Origin, ref)
		// The block's canonical fingerprint, indented under the service it belongs to.
		// Two values, because a baseline pins them separately: `block` covers everything
		// the deployment decided, `block-no-image` is the half that must NOT move when
		// the broker ships a new digest. Printing both is what makes a fleet sweep able
		// to say "eleven providers run the same broker block" without printing eleven
		// blocks — and, for the operator writing the first baseline, which services are
		// already identical across the fleet.
		if i < len(review.Blocks) {
			b := review.Blocks[i]
			if !b.Pinnable() {
				fmt.Fprintf(out, "      block          cannot be pinned: %v\n", b.Err)
				continue
			}
			fmt.Fprintf(out, "      block          %s\n", b.Digest)
			if b.DigestNoImage != b.Digest {
				fmt.Fprintf(out, "      block-no-image %s\n", b.DigestNoImage)
			}
			if dumpBlocks {
				// BOTH forms, because a broker service's baseline entry holds the
				// image-held-out one — that is the whole reason the split exists — and
				// printing only the full form left exactly those entries unobtainable from
				// the tool. Deriving them by hand is the transcription that makes the two
				// sides drift, which is what CanonicalizeServiceBlock exists to prevent.
				// Skipped when the two are identical, matching the fingerprint lines.
				dumpBlock(out, "", b.Canonical)
				if b.DigestNoImage != b.Digest {
					dumpBlock(out, "no-image: ", b.CanonicalNoImage)
				}
			}
		}
	}

	// Never a mark: a ✓ or ✗ here would read as a verdict, and this is the one section
	// of the report that deliberately has none.
	// The baseline comparison, which is the check that ADJUDICATES — printed before the
	// review so a reader meets the verdict before the advice. It is also the only part of
	// this section that can fail the run.
	failed = reportBaseline(out, review.Blocks, baseline)

	fmt.Fprintf(out, "  compose review   %s — reported, never a gate\n", review.Summary())
	for _, f := range review.Findings {
		where := f.Service
		if where == "" {
			where = "app-compose"
		}
		if f.Key != "" {
			where += "." + f.Key
		}
		fmt.Fprintf(out, "    [%s] %s: %s\n", f.Severity, where, f.Detail)
	}
	return failed, baselineSkip(baseline)
}

// baselineSkip names the gap when no baseline is recorded. An empty baseline is not a
// pass: the comparison that would say "these are the containers we approved" did not
// run, and exit 3 is what keeps a gate from reading that as a full verification —
// exactly the contract an unconfigured boot-chain allowlist has one layer up.
func baselineSkip(baseline []evidence.BaselineService) string {
	if len(baseline) > 0 {
		return ""
	}
	return "the manifest was not compared against a per-service baseline (none is recorded yet)"
}

// reportBaseline prints the baseline comparison and reports whether it FAILED.
//
// This is the adjudicating half of the manifest section, and the only part of it that
// can fail a run. Its vocabulary is deliberately not the review's: a mismatch carries no
// severity, because there is nothing to rank — either the deployment is the one that was
// reviewed and recorded, or it is not.
func reportBaseline(out io.Writer, blocks []evidence.ServiceBlock, baseline []evidence.BaselineService) bool {
	check := evidence.CheckCompose(baseline, blocks)
	if !check.Configured {
		fmt.Fprintf(out, "- baseline         not compared (no per-service baseline recorded; see "+
			"client/evidence/brokercompose.json)\n")
		return false
	}
	if check.OK() {
		fmt.Fprintf(out, "%s baseline         all %d service(s) match the recorded baseline\n",
			mark(true), check.Matched)
		return false
	}
	fmt.Fprintf(out, "%s baseline         %d of %d service(s) match; %d mismatch(es)\n",
		mark(false), check.Matched, len(baseline), len(check.Mismatches))
	for _, m := range check.Mismatches {
		where := m.Service
		if where == "" {
			where = "manifest"
		}
		fmt.Fprintf(out, "    %s: %s\n", where, m.Reason)
		if m.Diff != "" {
			fmt.Fprintf(out, "      %s\n", m.Diff)
		}
	}
	return true
}

// dumpBlock prints one canonical block, line-prefixed so it cannot be mistaken for the
// report's own structure. label names which form it is, and is empty for the full one.
func dumpBlock(out io.Writer, label, canonical string) {
	for i, line := range strings.Split(strings.TrimRight(canonical, "\n"), "\n") {
		prefix := ""
		if i == 0 {
			prefix = label
		}
		fmt.Fprintf(out, "      | %s%s\n", prefix, line)
	}
}

// reason renders err, falling back to a description when there is none. A "-" line
// whose parenthetical reads "(<nil>)" tells a reader nothing about what to do, and the
// fallback keeps that out of the report even if a future caller forgets to set the
// error alongside the flag.
func reason(err error, fallback string) string {
	if err == nil {
		return fallback
	}
	return err.Error()
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

// providerBootChains loads the audited broker OS-image allowlist for -provider mode:
// one entry per image, as attest.BootChain (MRTD + RTMR1 + RTMR2) rather than a full
// Measurement, so an entry pins a version rather than a single CVM.
//
// It reads the SAME embedded client/evidence/brokerimages.json the gateway and the
// sidecar enforce against, deliberately: a diagnostic that answered from its own copy
// of the allowlist could report a provider as acceptable while the sealing path
// refuses it, which is worse than having no diagnostic. Where those values come from
// is that file's header; trust-chain.md hop 3's open question — where the expected
// values are PUBLISHED — is answered by embedding them here beside the gateway's own.
//
// A malformed file is returned as an error for main to report, not swallowed into an
// empty allowlist: an empty one silently turns the boot-chain comparison into "not
// configured", and a diagnostic that hides its own broken input is misleading in the
// direction that matters.
func providerBootChains() (attest.BootChainPolicy, error) {
	images, err := evidence.BuiltinBrokerImages()
	if err != nil {
		return attest.BootChainPolicy{}, err
	}
	return evidence.BootChainPolicyOf(images), nil
}

// loadComposeBaseline reads the per-service baseline, from path when given and from the
// embedded file otherwise.
//
// A file given explicitly may legitimately be EMPTY — that is how an operator checks a
// candidate baseline one service at a time — so unlike -os-image-allowlist this does not
// reject an empty one. What it does reject is an unreadable or malformed one, in either
// source: a baseline that failed to load and a baseline with no entries reach the report
// as the same "not configured" state, and only one of them should be silent.
func loadComposeBaseline(path string) ([]evidence.BaselineService, error) {
	if strings.TrimSpace(path) == "" {
		return evidence.BuiltinComposeBaseline()
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read -app-baseline: %w", err)
	}
	svcs, err := evidence.ParseComposeBaseline(raw)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return svcs, nil
}

// dcapChecker is the real quoteChecker: it GETs the provider's /quote and
// DCAP-verifies it (genuine TDX + TCB + report_data binding). Measurement runs in
// warn mode so the tool REPORTS an out-of-allowlist boot chain rather than erroring:
// a read-only diagnostic should print what it saw, and erroring would say nothing
// about the provider beyond "not in the list", which the report states more usefully.
type dcapChecker struct {
	http     *http.Client
	verifier *attest.Verifier
}

// newDCAPChecker builds the provider-mode verifier. pccsURL (when non-empty)
// points collateral fetches at a PCCS mirror instead of Intel PCS — the same knob
// the gateway mode and the sidecar/gateway binaries take, so a run of either mode
// can be aimed at the collateral source the deployment actually uses.
func newDCAPChecker(pccsURL string) (*dcapChecker, error) {
	policy, err := providerBootChains()
	if err != nil {
		return nil, err
	}
	return &dcapChecker{
		http: &http.Client{Timeout: 20 * time.Second},
		verifier: attest.New(
			policy,
			attest.WithQuoteParser(dcap.NewQuoteParser(dcap.Config{PCCSBaseURL: pccsURL})),
			attest.WithMeasurementMode(attest.ModeWarn),
		),
	}, nil
}

// BaselineConfigured delegates to the verifier rather than re-reading the embedded
// file: one source, so the report cannot disagree with what the comparison used.
func (c *dcapChecker) BaselineConfigured() bool {
	return c.verifier.MeasurementBaselineConfigured()
}

// FetchAndVerify runs the whole quote fetch: verify first, then read the two
// application-identity values out of what was verified.
//
// Order is the security argument, not a style choice. The reply's app-compose is read
// only after c.verifier.Verify has succeeded, and it is returned UNGATED for
// reportManifest to hash — so no code path here can act on provider-chosen text. The
// compose hash is taken from a structural re-parse of the same raw quote, admitted
// only when its measurement equals the verified one: that guard is what makes
// mr_config_id "in the signed report" rather than "read from bytes nobody checked".
// route.composeHashOf carries the long form of the argument; this is the same shape,
// which is deliberate — a diagnostic that derived compose_hash differently from the
// sealing path could report a manifest the gateway never authenticated.
func (c *dcapChecker) FetchAndVerify(ctx context.Context, endpoint string) (providerQuote, error) {
	reply, err := c.fetchQuoteReply(ctx, endpoint)
	if err != nil {
		return providerQuote{}, err
	}
	raw, err := attest.DecodeQuoteResponse(reply)
	if err != nil {
		return providerQuote{}, err
	}
	verified, err := c.verifier.Verify(raw)
	if err != nil {
		return providerQuote{}, err
	}
	pq := providerQuote{Verified: verified}

	switch qb, err := attest.ParseTDXQuoteBody(raw); {
	case err != nil:
		pq.ComposeHashErr = fmt.Errorf("cannot structurally re-parse the verified quote: %w", err)
	case qb.Measurement != verified.Measurement:
		// Unreachable with the wired parser, which extracts through this same function —
		// and that is exactly why it is checked rather than assumed. It earns its place
		// against a future decoder that derives the measurement some other way, where "the
		// bytes I read describe the TD you verified" stops being self-evident.
		pq.ComposeHashErr = errors.New("the structural re-parse disagrees with the verified measurement")
	default:
		hash, err := attest.ComposeHashFromMRConfigID(qb.MRConfigID)
		if err != nil {
			pq.ComposeHashErr = err
		} else {
			pq.ComposeHash, pq.HaveComposeHash = hash, true
		}
	}

	if ac, err := attest.AppComposeFromQuoteResponse(reply); err != nil {
		pq.AppComposeErr = err
	} else {
		pq.AppCompose = ac
	}
	return pq, nil
}

// fetchQuoteReply GETs the provider's /quote and returns the raw JSON reply. The reply
// rather than just the decoded quote: the app-compose rides in the same body, and
// fetching twice would let a provider serve a manifest belonging to a different quote.
func (c *dcapChecker) fetchQuoteReply(ctx context.Context, endpoint string) ([]byte, error) {
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
	// One byte past the cap, so hitting it is DETECTED rather than delivered as a
	// truncated document: silent truncation would surface downstream as invalid JSON and
	// be reported as a bad quote.
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxQuoteBodyBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read quote: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("quote endpoint returned %d", resp.StatusCode)
	}
	if len(body) > maxQuoteBodyBytes {
		return nil, fmt.Errorf("quote reply from %s is larger than %d bytes", quoteURL, maxQuoteBodyBytes)
	}
	return body, nil
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
