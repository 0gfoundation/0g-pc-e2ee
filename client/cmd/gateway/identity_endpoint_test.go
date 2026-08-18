package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/0gfoundation/0g-pc-e2ee/client/evidence"
	"github.com/0gfoundation/0g-pc-e2ee/client/openaiproxy"
	"github.com/0gfoundation/0g-pc-e2ee/protocol/attest"
)

// TDX v4 quote geometry, mirrored here (as client/evidence's fixtures do) so a
// test can synthesize a structurally valid quote prefix. The identity endpoint
// reads mr_config_id and the boot-chain registers straight out of these bytes —
// see identity.go on why it parses rather than DCAP-verifies — so the fixture has
// to put them at their real offsets.
const (
	fxQuoteLen    = 632 // 48-byte header + 584-byte TD report body
	fxMRTDOff     = 184
	fxMRConfigOff = 232
	fxRTMR1Off    = 424
	fxRTMR2Off    = 472
)

// deployedComposeText is the docker-compose text the fixture's app-compose embeds:
// the real deployment's four containers, two of them ours and two third-party.
const deployedComposeText = `services:
  cvm-identity:
    image: ghcr.io/0gfoundation/0g-pc-e2ee-gateway@sha256:9c41ab7e
  dstack-ingress:
    image: dstacktee/dstack-ingress:2.3@sha256:527c5352
  gateway:
    image: ghcr.io/0gfoundation/0g-pc-e2ee-gateway@sha256:9c41ab7e
  prometheus-agent:
    image: prom/prometheus:v2.55.1@sha256:2659f4c2
`

// testOSImage is the allowlist entry the fixture's quote matches.
func testOSImage() evidence.OSImage {
	img := evidence.OSImage{Name: "dstack-test-1.0"}
	for i := range img.BootChain.MRTD {
		img.BootChain.MRTD[i] = 0x11
		img.BootChain.RTMR1[i] = 0x22
		img.BootChain.RTMR2[i] = 0x33
	}
	return img
}

// identityFixture is a CVM's worth of on-disk state: the evidence bundle's quote
// and the app-compose cmd/cvmid published, consistent with each other.
type identityFixture struct {
	dir            string
	quotePath      string
	appComposePath string
	composeHash    [attest.ComposeHashLen]byte
	appID          string
}

// newIdentityFixture writes a quote committing to composeText's app-compose, and
// the app-compose itself. A test that wants the two to disagree rewrites one of
// them afterwards.
func newIdentityFixture(t *testing.T, composeText string) *identityFixture {
	t.Helper()
	dir := t.TempDir()

	// The authenticated artifact is the RAW app-compose bytes, so build them once
	// and hash exactly what is written — a re-marshal here would silently break the
	// binding the endpoint checks.
	appCompose, err := json.Marshal(map[string]any{
		"name":                "0g-pc-gateway",
		"docker_compose_file": composeText,
	})
	if err != nil {
		t.Fatal(err)
	}
	f := &identityFixture{
		dir:            dir,
		quotePath:      filepath.Join(dir, evidenceQuoteFile),
		appComposePath: filepath.Join(dir, "app-compose.json"),
		composeHash:    sha256.Sum256(appCompose),
	}
	f.appID = attest.AppIDFromComposeHash(f.composeHash)
	writeFile(t, f.appComposePath, appCompose)
	f.writeQuote(t, f.composeHash)
	return f
}

// writeQuote publishes a quote prefix committing to composeHash, with boot-chain
// registers matching testOSImage.
func (f *identityFixture) writeQuote(t *testing.T, composeHash [attest.ComposeHashLen]byte) {
	t.Helper()
	raw := make([]byte, fxQuoteLen)
	// dstack's mr_config_id v1 layout: version byte, compose hash, zero padding.
	raw[fxMRConfigOff] = 1
	copy(raw[fxMRConfigOff+1:], composeHash[:])
	img := testOSImage()
	copy(raw[fxMRTDOff:], img.BootChain.MRTD[:])
	copy(raw[fxRTMR1Off:], img.BootChain.RTMR1[:])
	copy(raw[fxRTMR2Off:], img.BootChain.RTMR2[:])

	body, err := json.Marshal(map[string]string{"quote": hex.EncodeToString(raw)})
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, f.quotePath, body)
}

// config is the assembly config for this fixture, with the release lookup off.
// Tests that want it point ReleaseAPIBase at a stub and set Releases.
func (f *identityFixture) config() identityConfig {
	return identityConfig{
		InstanceID:     "aa11bb22",
		QuotePath:      f.quotePath,
		AppComposePath: f.appComposePath,
		OSImages:       []evidence.OSImage{testOSImage()},
		Timeout:        5 * time.Second,
	}
}

func writeFile(t *testing.T, path string, body []byte) {
	t.Helper()
	if err := os.WriteFile(path, body, 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

// stubReleaseAPI serves a GitHub releases API publishing one release whose
// docker-compose.release.yml asset is assetBody.
func stubReleaseAPI(t *testing.T, tag, assetBody string) string {
	t.Helper()
	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	mux.HandleFunc("/repos/", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode([]map[string]any{{
			"tag_name": tag,
			"html_url": "https://github.com/0gfoundation/0g-pc-e2ee/releases/tag/" + tag,
			"assets": []map[string]string{
				{"name": "docker-compose.release.yml", "browser_download_url": srv.URL + "/asset"},
			},
		}})
	})
	mux.HandleFunc("/asset", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(assetBody))
	})
	return srv.URL
}

func buildFixture(t *testing.T, cfg identityConfig) buildResult {
	t.Helper()
	return buildIdentity(context.Background(), cfg, discardLogger())
}

// The whole chain, with every source available: quote → compose_hash/app_id, boot
// chain → os_image, authenticated manifest → containers, release asset →
// matched_release. This is the acceptance criterion that the endpoint's values are
// the ones pcverify derives on the same replica.
func TestBuildIdentity_FullAssembly(t *testing.T) {
	f := newIdentityFixture(t, deployedComposeText)
	cfg := f.config()
	cfg.Releases = 3
	cfg.ReleaseAPIBase = stubReleaseAPI(t, "release-2026.08.07.1", deployedComposeText)

	res := buildFixture(t, cfg)
	if len(res.pending) != 0 {
		t.Errorf("pending = %v, want a settled assembly", res.pending)
	}
	doc := res.doc
	if doc.InstanceID != "aa11bb22" {
		t.Errorf("instance_id = %q", doc.InstanceID)
	}
	if doc.AppID == nil || *doc.AppID != f.appID {
		t.Errorf("app_id = %v, want %q", doc.AppID, f.appID)
	}
	if want := hex.EncodeToString(f.composeHash[:]); doc.ComposeHash == nil || *doc.ComposeHash != want {
		t.Errorf("compose_hash = %v, want %q", doc.ComposeHash, want)
	}
	if doc.OSImage == nil || *doc.OSImage != "dstack-test-1.0" {
		t.Errorf("os_image = %v, want the matched allowlist entry", doc.OSImage)
	}
	if doc.MatchedRelease == nil {
		t.Fatal("matched_release = null, want the release whose asset equals the deployed text")
	}
	if doc.MatchedRelease.Tag != "release-2026.08.07.1" ||
		!strings.HasSuffix(doc.MatchedRelease.URL, "/releases/tag/release-2026.08.07.1") {
		t.Errorf("matched_release = %+v", *doc.MatchedRelease)
	}
	// Four containers, in file order, with sources told apart correctly.
	want := []containerRef{
		{Name: "cvm-identity", Image: "ghcr.io/0gfoundation/0g-pc-e2ee-gateway", Digest: "sha256:9c41ab7e", Source: sourceOwn},
		{Name: "dstack-ingress", Image: "dstacktee/dstack-ingress", Digest: "sha256:527c5352", Source: sourceThirdParty},
		{Name: "gateway", Image: "ghcr.io/0gfoundation/0g-pc-e2ee-gateway", Digest: "sha256:9c41ab7e", Source: sourceOwn},
		{Name: "prometheus-agent", Image: "prom/prometheus", Digest: "sha256:2659f4c2", Source: sourceThirdParty},
	}
	if len(doc.Containers) != len(want) {
		t.Fatalf("containers = %+v, want %d", doc.Containers, len(want))
	}
	for i := range want {
		if doc.Containers[i] != want[i] {
			t.Errorf("container %d = %+v, want %+v", i, doc.Containers[i], want[i])
		}
	}
	// The endpoint must never claim to have verified anything.
	if strings.Contains(strings.ToLower(marshal(t, doc)), `"verified"`) {
		t.Error("the response carries a \"verified\" field; this endpoint is self-description, not evidence")
	}
}

// realGatewayQuote is a genuine `/evidences/quote.json` captured from a deployed
// 0G-PC gateway CVM, shared with protocol/attest's known-answer test. Reached by
// relative path rather than copied: a second copy of a capture is a second thing to
// keep honest, and both modules live in one checkout.
const realGatewayQuote = "../../../protocol/attest/testdata/dstack_gateway_quote_prefix.json"

// The synthetic fixtures above prove the logic; this proves the FILE FORMAT and the
// SHIPPED ALLOWLIST. It runs the endpoint's quote path over a real capture, with
// evidence.BuiltinOSImages() rather than a test allowlist, and pins the values a
// panel would display for that deployment.
//
// It is the check that would have caught a hex-prefix assumption, a wrong register
// offset, or an allowlist entry that drifted away from the image actually deployed —
// none of which a hand-built quote can fail on, because the same code writes it.
func TestBuildIdentity_RealCapturedQuote(t *testing.T) {
	body, err := os.ReadFile(realGatewayQuote)
	if err != nil {
		t.Fatalf("read the shared quote capture: %v", err)
	}
	dir := t.TempDir()
	quotePath := filepath.Join(dir, evidenceQuoteFile)
	writeFile(t, quotePath, body)

	osImages, err := evidence.BuiltinOSImages()
	if err != nil {
		t.Fatalf("BuiltinOSImages: %v", err)
	}
	res := buildFixture(t, identityConfig{QuotePath: quotePath, OSImages: osImages})

	// The app_id this deployment is known by, and the compose hash it is the prefix of.
	const wantAppID = "55d872aaa9c0b148228ebcf89302a52e7cd3d252"
	if res.doc.AppID == nil || *res.doc.AppID != wantAppID {
		t.Errorf("app_id = %v, want %q", res.doc.AppID, wantAppID)
	}
	if res.doc.ComposeHash == nil || !strings.HasPrefix(*res.doc.ComposeHash, wantAppID) {
		t.Errorf("compose_hash = %v, want app_id as its prefix", res.doc.ComposeHash)
	}
	// The boot chain of a real CVM against the allowlist this repository ships. A
	// null here means the deployment is running an image we no longer recognize —
	// which is exactly the finding the field exists to surface.
	if res.doc.OSImage == nil || *res.doc.OSImage != "dstack-nvidia-0.5.4.1" {
		t.Errorf("os_image = %v, want the shipped allowlist entry this capture matches", res.doc.OSImage)
	}
}

// An empty allowlist must not produce an OS image. The check did not run, and a
// name would read as one that passed.
func TestBuildIdentity_EmptyAllowlistReportsNoOSImage(t *testing.T) {
	f := newIdentityFixture(t, deployedComposeText)
	cfg := f.config()
	cfg.OSImages = nil

	if got := buildFixture(t, cfg).doc.OSImage; got != nil {
		t.Errorf("os_image = %q with an empty allowlist, want null — an unchecked image must not look checked", *got)
	}
}

// A boot chain matching nothing in a configured allowlist is a real finding, and
// it too reports null rather than a name.
func TestBuildIdentity_UnrecognizedOSImageReportsNull(t *testing.T) {
	f := newIdentityFixture(t, deployedComposeText)
	cfg := f.config()
	other := testOSImage()
	other.Name = "some-other-image"
	for i := range other.BootChain.MRTD {
		other.BootChain.MRTD[i] = 0xEE
	}
	cfg.OSImages = []evidence.OSImage{other}

	if got := buildFixture(t, cfg).doc.OSImage; got != nil {
		t.Errorf("os_image = %q for an unallowlisted boot chain, want null", *got)
	}
}

// The load-bearing rule for the container list: bytes that do not hash to the
// quote's compose_hash are NOT this deployment's manifest, and publishing a
// container list out of them would be the gateway vouching for itself.
func TestBuildIdentity_UnauthenticatedComposeIsRefused(t *testing.T) {
	f := newIdentityFixture(t, deployedComposeText)
	// Rewrite the manifest so its digest no longer matches the quote, exactly as a
	// stale volume or a redeploy without a re-run init container would.
	writeFile(t, f.appComposePath, []byte(`{"name":"other","docker_compose_file":"services:\n  evil:\n    image: evil\n"}`))

	res := buildFixture(t, f.config())
	if res.doc.Containers != nil {
		t.Errorf("containers = %+v, want null for a manifest that fails the compose_hash check", res.doc.Containers)
	}
	// Settled, not pending: re-reading the same file will never make it match, and a
	// retry loop that never converges is worse than an honest null.
	if len(res.pending) != 0 {
		t.Errorf("pending = %v, want a settled result", res.pending)
	}
	// The quote's own values are unaffected — they came from a different source.
	if res.doc.AppID == nil {
		t.Error("app_id = null; a bad manifest must not cost the values the quote carries")
	}
}

// No quote means no app_id, no compose_hash and no os_image — they all come out of
// it — and no container list either, because there is nothing to authenticate the
// manifest against. The endpoint still answers; it just knows very little.
func TestBuildIdentity_NoQuote(t *testing.T) {
	f := newIdentityFixture(t, deployedComposeText)
	cfg := f.config()
	cfg.QuotePath = filepath.Join(f.dir, "absent-quote.json")

	res := buildFixture(t, cfg)
	if res.doc.AppID != nil || res.doc.ComposeHash != nil || res.doc.OSImage != nil || res.doc.Containers != nil {
		t.Errorf("doc = %+v, want every quote-derived field null", res.doc)
	}
	if res.doc.InstanceID != "aa11bb22" {
		t.Error("the instance id must survive; it does not come from the quote")
	}
	// The bundle appears only after dstack-ingress's first ACME run, so this is a
	// state to retry out of, not to settle on.
	if len(res.pending) == 0 {
		t.Error("pending is empty; a quote that is not written yet must be retried")
	}
}

// GitHub being unreachable says nothing about the deployment: matched_release goes
// null, everything else stands, and the lookup is retried.
func TestBuildIdentity_ReleaseLookupFailureDegrades(t *testing.T) {
	f := newIdentityFixture(t, deployedComposeText)
	cfg := f.config()
	cfg.Releases = 3
	cfg.ReleaseAPIBase = "http://127.0.0.1:0" // nothing listening

	res := buildFixture(t, cfg)
	if res.doc.MatchedRelease != nil {
		t.Errorf("matched_release = %+v, want null", *res.doc.MatchedRelease)
	}
	if res.doc.Containers == nil {
		t.Error("containers = null; a failed GitHub lookup must not cost the container list")
	}
	if len(res.pending) == 0 {
		t.Error("pending is empty; an unreachable GitHub is worth retrying")
	}
}

// "This deployment is not any published release" is an ANSWER, not a failure — the
// checked-in compose carries :latest and is expected not to match. It reports null
// and stops retrying.
func TestBuildIdentity_NoMatchingReleaseIsSettled(t *testing.T) {
	f := newIdentityFixture(t, deployedComposeText)
	cfg := f.config()
	cfg.Releases = 3
	cfg.ReleaseAPIBase = stubReleaseAPI(t, "release-old", "services:\n  gateway:\n    image: something-else\n")

	res := buildFixture(t, cfg)
	if res.doc.MatchedRelease != nil {
		t.Errorf("matched_release = %+v, want null — no approximate matching", *res.doc.MatchedRelease)
	}
	if len(res.pending) != 0 {
		t.Errorf("pending = %v; a definite 'matches nothing' must not be retried forever", res.pending)
	}
}

// A release lookup that was never asked for is not a gap to retry.
func TestBuildIdentity_ReleasesZeroIsSettled(t *testing.T) {
	f := newIdentityFixture(t, deployedComposeText)
	cfg := f.config() // Releases stays 0

	res := buildFixture(t, cfg)
	if res.doc.MatchedRelease != nil || len(res.pending) != 0 {
		t.Errorf("matched_release = %v, pending = %v; want null and settled", res.doc.MatchedRelease, res.pending)
	}
}

// A deployment that configures no manifest source has ANSWERED: containers is null
// and the assembly is done. Recording it as pending would leave the background
// builder retrying an unsatisfiable lookup for the life of the process — both paths
// are fixed at startup — and would keep the document permanently incomplete, and so
// permanently uncacheable, over a deliberate configuration choice.
func TestBuildIdentity_NoAppComposeSourceIsSettled(t *testing.T) {
	f := newIdentityFixture(t, deployedComposeText)
	cfg := f.config()
	cfg.AppComposePath = "" // and BaseDomain was never set

	res := buildFixture(t, cfg)
	if res.doc.Containers != nil {
		t.Errorf("containers = %+v, want null", res.doc.Containers)
	}
	if len(res.pending) != 0 {
		t.Errorf("pending = %v; an unconfigured source can never become configured, so retrying it never ends", res.pending)
	}
	// A configured-but-missing file is the opposite case, and must still be retried:
	// nothing orders cvm-identity ahead of the gateway.
	cfg.AppComposePath = filepath.Join(f.dir, "not-written-yet.json")
	if res := buildFixture(t, cfg); len(res.pending) == 0 {
		t.Error("pending is empty for a configured file that is not there yet; cvm-identity may still be writing it")
	}
}

func TestLoadAppCompose_ReportsEverySourceItTried(t *testing.T) {
	cfg := identityConfig{AppComposePath: filepath.Join(t.TempDir(), "absent.json")}
	_, _, err := loadAppCompose(context.Background(), cfg, "")
	if err == nil || !strings.Contains(err.Error(), "absent.json") {
		t.Errorf("err = %v, want the attempted path named", err)
	}
	// Nothing configured at all is still an error, not a silent empty manifest.
	if _, _, err := loadAppCompose(context.Background(), identityConfig{}, ""); err == nil {
		t.Error("expected an error when no source is configured")
	}
}

// The image-to-source rule, stated on its own: it keys off the registry namespace
// in the authenticated compose text, so it holds whether or not a release lookup
// succeeded — and a third-party image can never be labelled as ours.
func TestClassifySource(t *testing.T) {
	for image, want := range map[string]string{
		"ghcr.io/0gfoundation/0g-pc-e2ee-gateway": sourceOwn,
		"ghcr.io/0gfoundation/0g-pc-e2ee":         sourceOwn,
		"GHCR.IO/0gfoundation/0g-pc-e2ee-gateway": sourceOwn,
		"dstacktee/dstack-ingress":                sourceThirdParty,
		"prom/prometheus":                         sourceThirdParty,
		// A different repo under the same owner is not this repository's release.
		"ghcr.io/0gfoundation/something-else": sourceThirdParty,
		// Nor is a lookalike registry.
		"evil.io/0gfoundation/0g-pc-e2ee-gateway": sourceThirdParty,
		"": sourceThirdParty,
	} {
		if got := classifySource(image, ""); got != want {
			t.Errorf("classifySource(%q) = %q, want %q", image, got, want)
		}
	}
}

// --- the route ---

// identityGateway stands up a gateway with the identity route mounted from a
// pre-assembled document, and a router that fails the test if the catch-all is
// reached.
func identityGateway(t *testing.T, cache *identityCache) *httptest.Server {
	t.Helper()
	router := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("router catch-all reached for %s %s", r.Method, r.URL.Path)
		w.WriteHeader(http.StatusNotFound)
	}))
	t.Cleanup(router.Close)
	gw := httptest.NewServer(newHandler(routeClient(), mustURL(t, router.URL), testOrigins(), "", "", noInFlightCap, cache, discardLogger()))
	t.Cleanup(gw.Close)
	return gw
}

// assembledCache is a cache holding a finished document.
func assembledCache(t *testing.T) *identityCache {
	t.Helper()
	f := newIdentityFixture(t, deployedComposeText)
	c := &identityCache{}
	c.store(buildFixture(t, f.config()))
	return c
}

func TestIdentityRoute_ServesTheDocument(t *testing.T) {
	gw := identityGateway(t, assembledCache(t))

	resp, err := http.Get(gw.URL + identityPath)
	if err != nil {
		t.Fatalf("GET %s: %v", identityPath, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type = %q", ct)
	}
	// A session should fetch this once, not per request — the values cannot change
	// without a redeploy replacing the process.
	if cc := resp.Header.Get("Cache-Control"); cc != identityCompleteMaxAge {
		t.Errorf("Cache-Control = %q, want %q", cc, identityCompleteMaxAge)
	}
	var doc identityDoc
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if doc.AppID == nil || doc.Containers == nil {
		t.Errorf("doc = %+v, want the assembled values", doc)
	}
	if doc.EvidenceURL != evidencePrefix {
		t.Errorf("evidence_url = %q, want the relative bundle path", doc.EvidenceURL)
	}
	if doc.Verify == "" {
		t.Error("the response must carry the caveat that these values are self-reported")
	}
}

// The response is cacheable AND its Access-Control-Allow-Origin is reflected from
// the request, so it has to declare that it varies by Origin — including on the
// requests that carry none. Without this a shared cache stores the header-less
// variant a curl or an uptime probe fetched and replays it to the browser panel,
// which blocks it for the whole max-age.
func TestIdentityRoute_VariesByOrigin(t *testing.T) {
	gw := identityGateway(t, assembledCache(t))

	for _, origin := range []string{"", "https://0g.ai"} {
		t.Run("origin="+origin, func(t *testing.T) {
			var resp *http.Response
			if origin == "" {
				r, err := http.Get(gw.URL + identityPath)
				if err != nil {
					t.Fatalf("GET: %v", err)
				}
				resp = r
			} else {
				resp = getWithOrigin(t, gw.URL+identityPath, origin)
			}
			defer resp.Body.Close()
			if !strings.Contains(strings.ToLower(strings.Join(resp.Header.Values("Vary"), ",")), "origin") {
				t.Errorf("Vary = %v, want it to name Origin — this response is cacheable and its CORS header is per-origin",
					resp.Header.Values("Vary"))
			}
		})
	}
}

// A half-assembled document must not be cached: the finished one is seconds away,
// and a max-age would pin the partial answer in front of it.
func TestIdentityRoute_IncompleteIsNotCached(t *testing.T) {
	c := &identityCache{}
	c.store(buildResult{doc: identityDoc{InstanceID: "aa11"}, pending: []string{"quote: not written yet"}})
	gw := identityGateway(t, c)

	resp, err := http.Get(gw.URL + identityPath)
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200 — an incomplete document is still an answer", resp.StatusCode)
	}
	if cc := resp.Header.Get("Cache-Control"); cc != "no-cache" {
		t.Errorf("Cache-Control = %q, want no-cache", cc)
	}
}

// The route is public: a verification panel has to load before anyone signs in,
// and everything it reports is already published under /evidences/.
func TestIdentityRoute_NeedsNoCredential(t *testing.T) {
	gw := identityGateway(t, assembledCache(t))

	resp, err := http.Get(gw.URL + identityPath) // no Authorization at all
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d without a credential, want 200", resp.StatusCode)
	}
}

// Unlike /evidences/, this route rides the gateway's ORIGIN ALLOWLIST: it is a
// convenience for the first-party panel, and a verifier that wants these values
// without an allowlisted origin reads the bundle instead.
func TestIdentityRoute_UsesTheOriginAllowlist(t *testing.T) {
	gw := identityGateway(t, assembledCache(t))

	t.Run("allowed origin", func(t *testing.T) {
		resp := getWithOrigin(t, gw.URL+identityPath, "https://0g.ai")
		defer resp.Body.Close()
		if got := resp.Header.Get("Access-Control-Allow-Origin"); got != "https://0g.ai" {
			t.Errorf("Access-Control-Allow-Origin = %q, want the requesting origin", got)
		}
	})
	t.Run("disallowed origin", func(t *testing.T) {
		resp := getWithOrigin(t, gw.URL+identityPath, "https://evil.example")
		defer resp.Body.Close()
		got := resp.Header.Get("Access-Control-Allow-Origin")
		if got != "" {
			t.Errorf("Access-Control-Allow-Origin = %q for an unlisted origin, want none", got)
		}
		if got == "*" {
			t.Error("this route must not answer every origin the way /evidences/ does")
		}
	})
}

func getWithOrigin(t *testing.T, url, origin string) *http.Response {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Origin", origin)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	return resp
}

// The endpoint is a constant served from memory, so it must not compete with
// sealed inference for the concurrency cap's slots.
func TestIdentityRoute_DoesNotConsumeAnInFlightSlot(t *testing.T) {
	cache := assembledCache(t)
	gw, entered := blockedGateway(t, 1, cache)

	go func() { _ = postAsync(gw, "Bearer sk-holder") }()
	select {
	case <-entered:
	case <-time.After(10 * time.Second):
		t.Fatal("the holding request never reached the router; the cap is not occupied")
	}

	resp, err := http.Get(gw.URL + identityPath)
	if err != nil {
		t.Fatalf("identity at capacity: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("identity at capacity = %d, want 200 — a static read must not be shed with the sealed path",
			resp.StatusCode)
	}
}

// With the endpoint switched off the path is not mounted at all, and falls through
// to the catch-all like any other unknown path.
func TestIdentityRoute_NotMountedWhenDisabled(t *testing.T) {
	reached := make(chan string, 1)
	router := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached <- r.URL.Path
		w.WriteHeader(http.StatusNotFound)
	}))
	t.Cleanup(router.Close)
	gw := httptest.NewServer(newHandler(routeClient(), mustURL(t, router.URL), testOrigins(), "", "", noInFlightCap, nil, discardLogger()))
	t.Cleanup(gw.Close)

	resp, err := http.Get(gw.URL + identityPath)
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	select {
	case got := <-reached:
		if got != identityPath {
			t.Errorf("router saw %q, want the unmounted path forwarded", got)
		}
	default:
		t.Error("the disabled route answered locally; it must fall through to the catch-all")
	}
}

// Absent fields marshal to JSON null, never to "" or []. A panel that cannot tell
// "no release matched" from "we never asked" will state the wrong one.
func TestIdentityDoc_AbsentFieldsAreNull(t *testing.T) {
	body := marshal(t, identityDoc{InstanceID: "aa11"})
	for _, want := range []string{
		`"app_id": null`, `"compose_hash": null`, `"os_image": null`,
		`"matched_release": null`, `"containers": null`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("body is missing %s:\n%s", want, body)
		}
	}
}

func marshal(t *testing.T, doc identityDoc) string {
	t.Helper()
	b, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// The cache answers from the moment it exists, so a request that beats the first
// assembly gets the instance id rather than a 503 or an empty body.
func TestStartIdentity_AnswersBeforeAssembly(t *testing.T) {
	f := newIdentityFixture(t, deployedComposeText)
	cache, stop := startIdentity(f.config(), discardLogger())
	t.Cleanup(stop)

	body, _ := cache.Doc()
	if body == nil {
		t.Fatal("the cache is empty immediately after startup; a request arriving now would 503")
	}
	if !strings.Contains(string(body), "aa11bb22") {
		t.Errorf("the pre-assembly document does not carry the instance id:\n%s", body)
	}

	// And it converges: every source here is local, so the background pass settles.
	deadline := time.Now().Add(5 * time.Second)
	for {
		if _, complete := cache.Doc(); complete {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("the assembly never completed with every source available locally")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// A HEAD is what a cache or a link checker sends; Go's ServeMux answers it from
// the GET registration, and it must not fall through to the router.
func TestIdentityRoute_HeadIsAnswered(t *testing.T) {
	gw := identityGateway(t, assembledCache(t))
	resp, err := http.Head(gw.URL + identityPath)
	if err != nil {
		t.Fatalf("HEAD: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("HEAD status = %d, want 200", resp.StatusCode)
	}
}

// A browser preflight for the panel's fetch is answered by the gateway's CORS
// middleware, not forwarded to the router.
func TestIdentityRoute_PreflightIsAnswered(t *testing.T) {
	gw := identityGateway(t, assembledCache(t))

	req, err := http.NewRequest(http.MethodOptions, gw.URL+identityPath, nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Origin", "https://0g.ai")
	req.Header.Set("Access-Control-Request-Method", http.MethodGet)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("preflight: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Errorf("preflight status = %d, want 204", resp.StatusCode)
	}
	if got := resp.Header.Get("Access-Control-Allow-Origin"); got != "https://0g.ai" {
		t.Errorf("Access-Control-Allow-Origin = %q", got)
	}
	if got := resp.Header.Get(openaiproxy.HeaderGatewayInstance); got != "" && got != "aa11bb22" {
		t.Errorf("unexpected instance header %q", got)
	}
}
