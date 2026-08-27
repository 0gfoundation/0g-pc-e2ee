package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/0gfoundation/0g-pc-e2ee/client/chain"
	"github.com/0gfoundation/0g-pc-e2ee/protocol/attest"
)

type stubService struct {
	info chain.ServiceInfo
	err  error
}

func (s stubService) ServiceInfo(context.Context, string) (chain.ServiceInfo, error) {
	return s.info, s.err
}

type stubQuote struct {
	v   attest.Verified
	err error
	// noBaseline makes the stub report an unconfigured allowlist, the state that
	// separates "not in the list" from "there is no list". Default false, i.e. a
	// baseline IS configured, matching the shipped brokerimages.json.
	noBaseline bool
	// The manifest half. Zero value means "the quote exposes no compose_hash", which is
	// the state a V2/V3 mr_config_id is in — deliberately the default, so a test that
	// does not care about the manifest still exercises the skip path rather than
	// silently getting a pass. withManifest builds the populated shape.
	appCompose      []byte
	composeHash     [attest.ComposeHashLen]byte
	haveComposeHash bool
	composeHashErr  error
	appComposeErr   error
}

func (s stubQuote) FetchAndVerify(context.Context, string) (providerQuote, error) {
	if s.err != nil {
		return providerQuote{}, s.err
	}
	hashErr := s.composeHashErr
	if !s.haveComposeHash && hashErr == nil {
		hashErr = errors.New("mr_config_id does not expose compose_hash")
	}
	acErr := s.appComposeErr
	if len(s.appCompose) == 0 && acErr == nil {
		acErr = attest.ErrNoAppCompose
	}
	return providerQuote{
		Verified:        s.v,
		ComposeHash:     s.composeHash,
		HaveComposeHash: s.haveComposeHash,
		ComposeHashErr:  hashErr,
		AppCompose:      s.appCompose,
		AppComposeErr:   acErr,
	}, nil
}

func (s stubQuote) BaselineConfigured() bool { return !s.noBaseline }

// withManifest gives the stub an app-compose and the compose_hash a genuine quote
// would bind to it, so the manifest section runs its real gate rather than being
// stubbed past it. That is the point: the gate is the check, and a fake that returned
// "authenticated" would test nothing.
func (s stubQuote) withManifest(t *testing.T, composeText string, extra map[string]any) stubQuote {
	t.Helper()
	fields := map[string]any{
		"manifest_version":    2,
		"name":                "broker",
		"runner":              "docker-compose",
		"docker_compose_file": composeText,
	}
	for k, v := range extra {
		fields[k] = v
	}
	raw, err := json.Marshal(fields)
	if err != nil {
		t.Fatalf("marshal app-compose: %v", err)
	}
	s.appCompose = raw
	s.composeHash = sha256.Sum256(raw)
	s.haveComposeHash = true
	return s
}

// cleanCompose trips no rule in the reviewer, so a test asserting a verdict is not
// quietly asserting the shape of a finding list.
const cleanCompose = "services:\n  broker:\n    image: ghcr.io/0gfoundation/broker@sha256:" +
	"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n    restart: always\n"

const (
	prov   = "0xaabbccddeeff00112233445566778899aabbccdd"
	signer = "0x99887766554433221100ffeeddccbbaa99887766"
)

// On-chain-only (qc == nil, i.e. -no-quote): the on-chain hop passes, but hops 2–4
// never ran, so the best available verdict is 3. A clean 0 here would be the tool
// claiming an enclave was checked when no quote was even fetched.
func TestReport_OnChainOnly(t *testing.T) {
	cases := []struct {
		name         string
		svc          stubService
		expectSigner string
		wantCode     int
	}{
		{"acknowledged", stubService{info: chain.ServiceInfo{Signer: signer, Acknowledged: true}}, "", 3},
		{"expected matches", stubService{info: chain.ServiceInfo{Signer: signer, Acknowledged: true}}, strings.ToUpper(signer), 3},
		{"expected mismatch", stubService{info: chain.ServiceInfo{Signer: signer, Acknowledged: true}}, "0x0000000000000000000000000000000000000001", 1},
		{"unacknowledged", stubService{info: chain.ServiceInfo{Signer: signer, Acknowledged: false}}, "", 1},
		{"lookup error", stubService{err: errors.New("rpc down")}, "", 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var out bytes.Buffer
			code := report(context.Background(), &out, tc.svc, nil, prov, "0xcontract", "", tc.expectSigner, providerOpts{})
			if code != tc.wantCode {
				t.Errorf("code = %d, want %d\n%s", code, tc.wantCode, out.String())
			}
		})
	}
}

// With a quote checker: full chain including hop-5 cross-check.
func TestReport_WithQuote(t *testing.T) {
	acked := chain.ServiceInfo{URL: "https://prov.example/v1", Signer: signer, Acknowledged: true}
	cases := []struct {
		name     string
		svc      stubService
		qc       stubQuote
		wantCode int
		contains string
	}{
		// 3, not 0: this stub reports no baseline, so the boot chain was never compared.
		// A build whose embedded allowlist has no entries cannot compare, so the run is
		// incomplete however well every other hop went.
		{"hops pass, hop 3 never ran", stubService{info: acked},
			stubQuote{v: attest.Verified{SignerAddr: signer}, noBaseline: true}, 3, "PASS (INCOMPLETE)"},
		{"quote signer mismatch", stubService{info: acked},
			stubQuote{v: attest.Verified{SignerAddr: "0x0000000000000000000000000000000000000002"}}, 1, "FAIL"},
		{"quote fetch/verify error", stubService{info: acked}, stubQuote{err: errors.New("not a genuine TDX quote")}, 1, "FAIL"},
		{"no endpoint on chain", stubService{info: chain.ServiceInfo{Signer: signer, Acknowledged: true}},
			stubQuote{v: attest.Verified{SignerAddr: signer}}, 1, "no endpoint"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var out bytes.Buffer
			code := report(context.Background(), &out, tc.svc, tc.qc, prov, "0xcontract", "", "", providerOpts{})
			if code != tc.wantCode {
				t.Errorf("code = %d, want %d\n%s", code, tc.wantCode, out.String())
			}
			if !strings.Contains(out.String(), tc.contains) {
				t.Errorf("output missing %q:\n%s", tc.contains, out.String())
			}
		})
	}
}

// Provider mode is where the audited boot chains have to come FROM: the allowlist is
// empty, so the only way a first entry ever gets recorded is by reading it off a run
// against a provider. That makes printing all three pinned registers the point of the
// step, not decoration — MRTD alone said a check had not happened without letting
// anyone do something about it.
func TestReport_PrintsTheBootChainInAllowlistShape(t *testing.T) {
	var m attest.Measurement
	for i := range m.MRTD {
		m.MRTD[i], m.RTMR1[i], m.RTMR2[i] = 0x3f, 0xaa, 0x5d
		m.RTMR0[i], m.RTMR3[i] = 0x01, 0x77
	}
	acked := chain.ServiceInfo{URL: "https://prov.example/v1", Signer: signer, Acknowledged: true}

	var out bytes.Buffer
	code := report(context.Background(), &out, stubService{info: acked},
		stubQuote{v: attest.Verified{SignerAddr: signer, Measurement: m}, noBaseline: true},
		prov, "0xcontract", "", "", providerOpts{})
	// An unconfigured allowlist is not a verdict on the provider — nothing FAILED — but
	// it is a check that did not run, which is exit 3.
	if code != 3 {
		t.Fatalf("code = %d, want 3\n%s", code, out.String())
	}
	got := out.String()

	for _, want := range []string{
		"- boot chain",                 // not compared, and not dressed up as a ✓
		"no allowlist configured",      // says why, so nobody reads it as a pass
		strings.Repeat("3f", 48),       // mrtd
		strings.Repeat("aa", 48),       // rtmr1
		strings.Repeat("5d", 48),       // rtmr2
		"rtmr0 (vm shape, not pinned)", // shown, labelled as not compared
	} {
		if !strings.Contains(got, want) {
			t.Errorf("output missing %q:\n%s", want, got)
		}
	}
	// RTMR3 must NOT be offered: it carries per-instance events, so pasting it into an
	// entry is exactly the mistake that kept this allowlist unfillable.
	if strings.Contains(got, strings.Repeat("77", 48)) {
		t.Errorf("RTMR3 must not be printed as an allowlist value:\n%s", got)
	}
}

// A configured allowlist that the provider misses is a finding, and must fail the run
// rather than print observed registers and pass. This is the shipped state — the stub
// reports a configured baseline by default — so it guards the ordinary path, not a
// hypothetical one.
func TestReport_BootChainMismatchFails(t *testing.T) {
	acked := chain.ServiceInfo{URL: "https://prov.example/v1", Signer: signer, Acknowledged: true}
	var out bytes.Buffer
	// MeasurementTrusted false with a non-empty allowlist: the provider's image is not
	// one that was audited.
	code := report(context.Background(), &out, stubService{info: acked},
		stubQuote{v: attest.Verified{SignerAddr: signer}}, prov, "0xcontract", "", "", providerOpts{})
	if code != 1 {
		t.Errorf("code = %d, want 1\n%s", code, out.String())
	}
	if !strings.Contains(out.String(), "matches no audited image") {
		t.Errorf("output must name the mismatch:\n%s", out.String())
	}
}

// Provider mode must carry the same verdict contract as gateway mode. It is the mode
// where the gap is easiest to miss: gateway mode needs a GitHub outage to skip
// something, while here hop 3 is skipped on EVERY run, so a gate that trusts exit 0
// would be told "verified" by a run that never checked the code root at all.
func TestReport_ProviderVerdicts(t *testing.T) {
	acked := chain.ServiceInfo{URL: "https://prov.example/v1", Signer: signer, Acknowledged: true}
	// Unconfigured on purpose: this is the input the "no allowlist" verdicts describe.
	good := stubQuote{v: attest.Verified{SignerAddr: signer}, noBaseline: true}

	t.Run("allowlist populated and matched is a clean 0", func(t *testing.T) {
		var out bytes.Buffer
		// A manifest too: the run is only complete when the provider's app-compose was
		// read AND gated, so a stub without one belongs in the skip cases below.
		trusted := stubQuote{v: attest.Verified{SignerAddr: signer, MeasurementTrusted: true}}.
			withManifest(t, cleanCompose, nil)
		if code := report(context.Background(), &out, stubService{info: acked}, trusted,
			prov, "0xcontract", "", "", providerOpts{}); code != 0 {
			t.Errorf("code = %d, want 0 — every hop ran and passed\n%s", code, out.String())
		}
		if strings.Contains(out.String(), "INCOMPLETE") {
			t.Errorf("a fully-checked run must not be marked incomplete:\n%s", out.String())
		}
	})

	t.Run("two gaps are both named, not just the first", func(t *testing.T) {
		var out bytes.Buffer
		// No allowlist AND no manifest. The verdict line exists to disclose what went
		// unchecked, so reporting one of two gaps is the failure mode to guard against.
		code := report(context.Background(), &out, stubService{info: acked}, good,
			prov, "0xcontract", "", "", providerOpts{})
		if code != 3 {
			t.Fatalf("code = %d, want 3\n%s", code, out.String())
		}
		for _, want := range []string{"hop 3", "manifest was not read"} {
			if !strings.Contains(out.String(), want) {
				t.Errorf("verdict does not name %q:\n%s", want, out.String())
			}
		}
	})

	t.Run("strict turns an unconfigured allowlist into a failure", func(t *testing.T) {
		var out bytes.Buffer
		code := report(context.Background(), &out, stubService{info: acked}, good,
			prov, "0xcontract", "", "", providerOpts{strict: true})
		if code != 1 {
			t.Errorf("code = %d, want 1 under -strict\n%s", code, out.String())
		}
		if !strings.Contains(out.String(), "hop 3") {
			t.Errorf("the failure must name the gap:\n%s", out.String())
		}
	})

	t.Run("a real failure stays 1, not 3", func(t *testing.T) {
		var out bytes.Buffer
		bad := stubQuote{v: attest.Verified{SignerAddr: "0x0000000000000000000000000000000000000002"}}
		if code := report(context.Background(), &out, stubService{info: acked}, bad,
			prov, "0xcontract", "", "", providerOpts{}); code != 1 {
			t.Errorf("code = %d, want 1\n%s", code, out.String())
		}
		if strings.Contains(out.String(), "INCOMPLETE") {
			t.Errorf("a failed check must not be reported as merely incomplete:\n%s", out.String())
		}
	})
}

// The manifest section has three outcomes and they must stay distinguishable, because
// the whole reason it exists is that hop 3 pins the OS and says nothing about what
// runs inside it. Its gate is the check; its review is not.
func TestReport_Manifest(t *testing.T) {
	acked := chain.ServiceInfo{URL: "https://prov.example/v1", Signer: signer, Acknowledged: true}
	base := stubQuote{v: attest.Verified{SignerAddr: signer, MeasurementTrusted: true}}
	runReport := func(t *testing.T, qc stubQuote, strict bool) (int, string) {
		t.Helper()
		var out bytes.Buffer
		code := report(context.Background(), &out, stubService{info: acked}, qc,
			prov, "0xcontract", "", "", providerOpts{strict: strict})
		return code, out.String()
	}

	t.Run("authenticated manifest is read and reviewed", func(t *testing.T) {
		code, got := runReport(t, base.withManifest(t, cleanCompose, nil), false)
		if code != 0 {
			t.Fatalf("code = %d, want 0\n%s", code, got)
		}
		for _, want := range []string{
			"✓ app-compose",
			"authenticated: sha256 equals the compose_hash the quote binds",
			"compose_hash     ",
			"app_id           ",
			"services         1 (1 pinned by digest, 1 first-party)",
			"broker",
			"first-party",
			"0 blocking, 0 to justify, 0 notes — reported, never a gate",
		} {
			if !strings.Contains(got, want) {
				t.Errorf("output missing %q:\n%s", want, got)
			}
		}
	})

	// The gate. A provider serving a manifest that is not the one its own quote binds
	// is a finding about the provider, so it FAILS — and nothing from inside those
	// bytes may be printed, since none of it is authenticated.
	t.Run("a manifest the quote does not bind fails the run", func(t *testing.T) {
		qc := base.withManifest(t, cleanCompose, nil)
		qc.composeHash[0] ^= 0xff
		code, got := runReport(t, qc, false)
		if code != 1 {
			t.Fatalf("code = %d, want 1\n%s", code, got)
		}
		if !strings.Contains(got, "✗ app-compose") {
			t.Errorf("the mismatch is not marked as a failure:\n%s", got)
		}
		if strings.Contains(got, "compose review") || strings.Contains(got, "services ") {
			t.Errorf("unauthenticated manifest contents were printed:\n%s", got)
		}
	})

	// Absence is a skip, never a pass: a gate reading exit 0 must not be told the
	// manifest was checked when the provider published nothing to check.
	t.Run("skips", func(t *testing.T) {
		for _, tc := range []struct {
			name string
			qc   stubQuote
			says string
		}{
			{"no compose_hash in mr_config_id", base, "exposes no compose_hash"},
			{
				"reply carries no app_compose",
				func() stubQuote {
					q := base.withManifest(t, cleanCompose, nil)
					q.appCompose = nil
					return q
				}(),
				"carries no app_compose",
			},
		} {
			t.Run(tc.name, func(t *testing.T) {
				code, got := runReport(t, tc.qc, false)
				if code != 3 {
					t.Fatalf("code = %d, want 3\n%s", code, got)
				}
				if !strings.Contains(got, "- app-compose") {
					t.Errorf("the skip is not marked as one:\n%s", got)
				}
				if !strings.Contains(got, tc.says) {
					t.Errorf("output does not say why it was skipped (%q):\n%s", tc.says, got)
				}
				if code, got := runReport(t, tc.qc, true); code != 1 {
					t.Errorf("-strict: code = %d, want 1\n%s", code, got)
				}
			})
		}
	})

	// The block fingerprints are what a per-service baseline will be written from, so
	// the report has to carry them — and has to carry BOTH, because a baseline pins the
	// block and the image separately (a broker release moves the image and nothing else).
	t.Run("block fingerprints", func(t *testing.T) {
		_, got := runReport(t, base.withManifest(t, cleanCompose, nil), false)
		if !strings.Contains(got, "block          ") {
			t.Errorf("no block fingerprint in the report:\n%s", got)
		}
		if !strings.Contains(got, "block-no-image ") {
			t.Errorf("no image-held-out fingerprint in the report:\n%s", got)
		}
		// Off by default: the canonical text is long, and only a baseline author needs it.
		if strings.Contains(got, "      | ") {
			t.Errorf("canonical block text printed without -blocks:\n%s", got)
		}
	})

	t.Run("-blocks prints the canonical text", func(t *testing.T) {
		var out bytes.Buffer
		code := report(context.Background(), &out, stubService{info: acked},
			base.withManifest(t, cleanCompose, nil), prov, "0xcontract", "", "",
			providerOpts{blocks: true})
		if code != 0 {
			t.Fatalf("code = %d, want 0\n%s", code, out.String())
		}
		got := out.String()
		for _, want := range []string{"      | image:", "      | restart: always"} {
			if !strings.Contains(got, want) {
				t.Errorf("output missing %q:\n%s", want, got)
			}
		}
		// cleanCompose's block has nothing outside the image, so the two forms differ only
		// by the image key and the no-image text is worth printing; what must NOT happen is
		// the label appearing when the forms are identical (asserted below).
	})

	// The image-held-out form is the one a broker service's baseline entry holds — that is
	// the whole reason the split exists. Printing only the full form left exactly those
	// entries unobtainable from the tool, and deriving them by hand is the transcription
	// CanonicalizeServiceBlock exists to prevent.
	t.Run("-blocks prints the image-held-out form too", func(t *testing.T) {
		// The cn-20 shape: the digest is copied into an environment variable, so the two
		// forms differ in more than the image line.
		digest := strings.Repeat("e", 64)
		doc := "services:\n  0g-controller:\n    image: ghcr.io/0gfoundation/0g-serving-broker@sha256:" +
			digest + "\n    environment:\n      - IMAGE_DIGEST=sha256:" + digest + "\n"
		var out bytes.Buffer
		report(context.Background(), &out, stubService{info: acked},
			base.withManifest(t, doc, nil), prov, "0xcontract", "", "", providerOpts{blocks: true})
		got := out.String()
		if !strings.Contains(got, "      | no-image: ") {
			t.Fatalf("the image-held-out text was not printed:\n%s", got)
		}
		// It must be the reduced text, not a second copy of the full one.
		noImagePart := got[strings.Index(got, "| no-image: "):]
		if strings.Contains(noImagePart, digest) {
			t.Errorf("the held-out form still carries the digest:\n%s", noImagePart)
		}

		// And when the two forms are identical there is nothing to label — matching the
		// fingerprint lines, which already skip block-no-image in that case.
		var plain bytes.Buffer
		report(context.Background(), &plain, stubService{info: acked},
			base.withManifest(t, "services:\n  a:\n    restart: always\n", nil),
			prov, "0xcontract", "", "", providerOpts{blocks: true})
		if strings.Contains(plain.String(), "no-image: ") {
			t.Errorf("a service with no image printed a held-out form:\n%s", plain.String())
		}
	})

	// A block with no canonical form must say so where its fingerprint would be, not go
	// blank — a missing line reads as "nothing to report".
	t.Run("a block that cannot be pinned says so", func(t *testing.T) {
		doc := "x-base: &base\n  privileged: true\nservices:\n  broker:\n    <<: *base\n    image: mysql:8.0\n"
		_, got := runReport(t, base.withManifest(t, doc, nil), false)
		if !strings.Contains(got, "cannot be pinned") {
			t.Errorf("an unpinnable block printed no reason:\n%s", got)
		}
	})

	// The review reports and does not adjudicate. A manifest full of blocking findings
	// still exits 0 — deliberately: these rules are heuristics about a manifest we did
	// not write, and wiring them to an exit code refuses a provider for being unusual.
	// The byte-exact baseline comparison is what will decide; this is how it gets
	// written.
	t.Run("findings are printed and gate nothing", func(t *testing.T) {
		dirty := "services:\n  broker:\n    image: mysql:8.0\n    privileged: true\n"
		code, got := runReport(t, base.withManifest(t, dirty, map[string]any{
			"allowed_envs": []string{"DSTACK_AUTHORIZED_KEYS"},
		}), false)
		if code != 0 {
			t.Fatalf("code = %d, want 0 — the review must not gate\n%s", code, got)
		}
		for _, want := range []string{
			"[blocking] broker.privileged",
			"[blocking] broker.image",
			"[blocking] app-compose.allowed_envs",
			"blocking,",
			"reported, never a gate",
			"third-party",
		} {
			if !strings.Contains(got, want) {
				t.Errorf("output missing %q:\n%s", want, got)
			}
		}
		// A ✓/✗ on the review line would read as a verdict on findings that carry none.
		for _, line := range strings.Split(got, "\n") {
			if strings.Contains(line, "compose review") && (strings.Contains(line, "✓") || strings.Contains(line, "✗")) {
				t.Errorf("the review line carries a verdict mark: %q", line)
			}
		}
	})
}

// -strict demands every check; -no-quote switches hops 2-4 off. Rejected as a caller
// mistake, the same way -strict with -releases 0 is.
func TestRun_StrictRejectsNoQuote(t *testing.T) {
	var out bytes.Buffer
	code := run(context.Background(), &out, []string{"-provider", prov, "-strict", "-no-quote"})
	if code != 2 {
		t.Errorf("exit = %d, want 2\n%s", code, out.String())
	}
	if !strings.Contains(out.String(), "-no-quote") {
		t.Errorf("the rejection must name the conflicting flag:\n%s", out.String())
	}
}

// -endpoint overrides the on-chain URL.
func TestReport_EndpointOverride(t *testing.T) {
	var out bytes.Buffer
	svc := stubService{info: chain.ServiceInfo{URL: "https://from-chain/v1", Signer: signer, Acknowledged: true}}
	code := report(context.Background(), &out, svc,
		stubQuote{v: attest.Verified{SignerAddr: signer}, noBaseline: true},
		prov, "0xc", "https://override/v1", "", providerOpts{})
	// 3 because hop 3 never ran; this test is about the endpoint line, not the verdict.
	if code != 3 {
		t.Fatalf("code = %d, want 3\n%s", code, out.String())
	}
	if !strings.Contains(out.String(), "https://override/v1 (from -endpoint)") {
		t.Errorf("expected endpoint override in output:\n%s", out.String())
	}
}

func TestRun_MissingProvider(t *testing.T) {
	var out bytes.Buffer
	if code := run(context.Background(), &out, []string{"-no-quote", "-chain-rpc-url", "http://127.0.0.1:0"}); code != 2 {
		t.Errorf("missing -provider: exit = %d, want 2", code)
	}
}

func TestQuoteURLFromEndpoint(t *testing.T) {
	cases := map[string]string{
		"https://h/v1":                  "https://h/v1/quote?legacy=false",
		"https://h":                     "https://h/v1/quote?legacy=false",
		"https://h/v1/chat/completions": "https://h/v1/quote?legacy=false",
		"http://h:8080/":                "http://h:8080/v1/quote?legacy=false",
	}
	for in, want := range cases {
		got, err := quoteURLFromEndpoint(in)
		if err != nil {
			t.Errorf("%q: %v", in, err)
			continue
		}
		if got != want {
			t.Errorf("%q: got %q, want %q", in, got, want)
		}
	}
	for _, bad := range []string{"", "ftp://h", "not a url", "https://"} {
		if _, err := quoteURLFromEndpoint(bad); err == nil {
			t.Errorf("%q: want error", bad)
		}
	}
}
