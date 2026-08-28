package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/0gfoundation/0g-pc-e2ee/client/compose"
	"github.com/0gfoundation/0g-pc-e2ee/client/route"
)

// pidAddr is the provider address the panel would have read out of the X-Provider
// response header; pidPath is the route it then asks about.
const pidAddr = "0xC0FFEE0000000000000000000000000000000001"

var pidPath = "/v1/providers/" + pidAddr + "/identity"

// stubIdentities is a route.ProviderIdentitySource holding one record, plus a
// counter so a test can prove the handler consults it exactly once per request (and
// that nothing else in the mux reaches it).
type stubIdentities struct {
	record route.ProviderIdentity
	have   bool
	// lookups records the addresses asked for, in order.
	lookups []string
}

func (s *stubIdentities) ProviderIdentity(address string) (route.ProviderIdentity, bool) {
	s.lookups = append(s.lookups, address)
	if !s.have {
		return route.ProviderIdentity{}, false
	}
	return s.record, true
}

// pidFullRecord is a record with every check made and positive — the shape a
// deployment with -attest and -onchain produces.
func pidFullRecord() route.ProviderIdentity {
	return route.ProviderIdentity{
		Address:       pidAddr,
		Endpoint:      "https://broker-07.0g.ai",
		QuoteURL:      "https://broker-07.0g.ai/v1/quote?legacy=false",
		QuoteDCAP:     route.VerdictPass,
		OnChainSigner: route.VerdictPass,
		// The no-entry case: nothing was compared, so no image was named.
		Measurement: route.VerdictNoBaseline,
		ComposeHash: "8779f38c1b2d4e5a6071829304a5b6c7d8e9f00112233445566778899aabbccd",
	}
}

// pidGateway stands up a gateway with the provider-identity route mounted from src,
// and a router catch-all that records what fell through to it.
func pidGateway(t *testing.T, src route.ProviderIdentitySource) (*httptest.Server, <-chan string) {
	t.Helper()
	fellThrough := make(chan string, 4)
	router := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fellThrough <- r.URL.Path
		w.WriteHeader(http.StatusNotFound)
	}))
	t.Cleanup(router.Close)
	gw := httptest.NewServer(newHandler(routeClient(), mustURL(t, router.URL), testOrigins(), "", "",
		noInFlightCap, nil, src, nil, discardLogger()))
	t.Cleanup(gw.Close)
	return gw, fellThrough
}

func pidGet(t *testing.T, url string) (*http.Response, string) {
	t.Helper()
	resp, err := http.Get(url)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	t.Cleanup(func() { resp.Body.Close() })
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	return resp, string(body)
}

// The endpoint reports the verdicts the gateway reached, keyed by the address a
// panel already holds, with no credential — the same public posture as the
// self-description, since every value is obtainable from the provider's own quote.
func TestProviderIdentityRoute_ReportsTheVerdicts(t *testing.T) {
	src := &stubIdentities{record: pidFullRecord(), have: true}
	gw, fellThrough := pidGateway(t, src)

	resp, body := pidGet(t, gw.URL+pidPath)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200; body: %s", resp.StatusCode, body)
	}
	select {
	case p := <-fellThrough:
		t.Fatalf("the request reached the router catch-all (%s); the answer must come from the party that verified", p)
	default:
	}
	if ct := resp.Header.Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type = %q", ct)
	}
	// A verdict must not outlive the record it came from: a shared cache replaying one
	// would be showing a verification no longer in force.
	if cc := resp.Header.Get("Cache-Control"); cc != "no-store" {
		t.Errorf("Cache-Control = %q, want no-store", cc)
	}
	if v := resp.Header.Get("Vary"); !strings.Contains(v, "Origin") {
		t.Errorf("Vary = %q, want it to name Origin", v)
	}

	var doc providerIdentityDoc
	if err := json.Unmarshal([]byte(body), &doc); err != nil {
		t.Fatalf("decode: %v\n%s", err, body)
	}
	want := pidFullRecord()
	if doc.Address != want.Address || doc.Endpoint != want.Endpoint {
		t.Errorf("address/endpoint = %q/%q, want %q/%q", doc.Address, doc.Endpoint, want.Address, want.Endpoint)
	}
	if doc.Verdicts.QuoteDCAP != route.VerdictPass ||
		doc.Verdicts.OnChainSigner != route.VerdictPass ||
		doc.Verdicts.Measurement != route.VerdictNoBaseline {
		t.Errorf("verdicts = %+v, want the ones the gateway reached", doc.Verdicts)
	}
	if doc.ComposeHash == nil || *doc.ComposeHash != want.ComposeHash {
		t.Errorf("compose_hash = %v, want %q", doc.ComposeHash, want.ComposeHash)
	}
	// os_image is null and NOT ambiguous: verdicts.measurement says which case it is.
	if doc.OSImage != nil {
		t.Errorf("os_image = %q, want null: the policy carries no entry labels", *doc.OSImage)
	}
	// The caveat rides with the value, and it names where to go to check for yourself:
	// the provider direct, not this gateway.
	if !strings.Contains(doc.Verify, want.QuoteURL) {
		t.Errorf("verify = %q, want it to name the provider's own quote URL", doc.Verify)
	}
	if !strings.Contains(doc.Verify, "pcverify -gateway") {
		t.Errorf("verify = %q, want it to name how to verify this gateway itself", doc.Verify)
	}
	if len(src.lookups) != 1 || src.lookups[0] != pidAddr {
		t.Errorf("lookups = %v, want exactly one for %s", src.lookups, pidAddr)
	}
}

// Acceptance rule from the issue: no raw quote and no raw boot-chain registers. A
// reader who wants those goes to the provider (or runs pcverify); relaying them
// through the party under examination lengthens the trust path for nothing.
func TestProviderIdentityRoute_ReturnsNoRawEvidence(t *testing.T) {
	gw, _ := pidGateway(t, &stubIdentities{record: pidFullRecord(), have: true})

	_, body := pidGet(t, gw.URL+pidPath)
	var raw map[string]any
	if err := json.Unmarshal([]byte(body), &raw); err != nil {
		t.Fatalf("decode: %v", err)
	}
	for _, forbidden := range []string{"quote", "raw_quote", "measurement", "mrtd", "rtmr0", "rtmr1", "rtmr2", "rtmr3", "boot_chain", "report_data"} {
		if _, present := raw[forbidden]; present {
			t.Errorf("response carries %q; this endpoint publishes verdicts, not evidence:\n%s", forbidden, body)
		}
	}
	if strings.Contains(strings.ToLower(body), "rtmr") {
		t.Errorf("response mentions a measurement register:\n%s", body)
	}
}

// An address the gateway has not verified is a 404 — including a malformed one.
// Both mean "no verdict here", and answering anything else would invite a caller to
// keep asking about addresses hoping for a different result.
func TestProviderIdentityRoute_UnknownAddressIs404(t *testing.T) {
	gw, _ := pidGateway(t, &stubIdentities{have: false})

	for _, addr := range []string{pidAddr, "0x0000000000000000000000000000000000000009", "not-an-address"} {
		resp, body := pidGet(t, gw.URL+"/v1/providers/"+addr+"/identity")
		if resp.StatusCode != http.StatusNotFound {
			t.Errorf("%s: status = %d, want 404", addr, resp.StatusCode)
		}
		// The gateway's own error envelope, attributed to the gateway rather than dressed
		// up as an upstream failure.
		if !strings.Contains(body, "gateway_error") {
			t.Errorf("%s: body = %s, want the gateway error envelope", addr, body)
		}
	}
}

// The route is a browser surface, so it must answer a cross-origin GET from an
// allowed origin — and, unlike /evidences/, only from an allowed one: everything
// here is also obtainable from the provider's own quote, so widening the policy
// would buy nothing.
func TestProviderIdentityRoute_CORSUsesTheAllowlist(t *testing.T) {
	gw, _ := pidGateway(t, &stubIdentities{record: pidFullRecord(), have: true})

	allowed := getWithOrigin(t, gw.URL+pidPath, "https://0g.ai")
	defer allowed.Body.Close()
	if got := allowed.Header.Get("Access-Control-Allow-Origin"); got != "https://0g.ai" {
		t.Errorf("Access-Control-Allow-Origin = %q for an allowed origin, want it reflected", got)
	}

	blocked := getWithOrigin(t, gw.URL+pidPath, "https://evil.example")
	defer blocked.Body.Close()
	if got := blocked.Header.Get("Access-Control-Allow-Origin"); got != "" {
		t.Errorf("Access-Control-Allow-Origin = %q for an unlisted origin, want none", got)
	}
}

// A map lookup must not be priced against sealed inference, so the route sits
// outside the concurrency cap — a gateway at capacity still answers the panel.
func TestProviderIdentityRoute_DoesNotConsumeAnInFlightSlot(t *testing.T) {
	src := &stubIdentities{record: pidFullRecord(), have: true}
	gw, entered := blockedGatewayWith(t, 1, nil, src)

	go func() { _ = postAsync(gw, "Bearer sk-holder") }()
	select {
	case <-entered:
	case <-time.After(10 * time.Second):
		t.Fatal("the holding request never reached the router; the cap is not occupied")
	}

	resp, _ := pidGet(t, gw.URL+pidPath)
	if resp.StatusCode != http.StatusOK {
		t.Errorf("provider identity at capacity = %d, want 200", resp.StatusCode)
	}
}

// With no source — a build that verifies no provider quotes (-attest off) or
// direct-broker mode — the route is not mounted and the path falls through to the
// catch-all like any other unknown path. A route that could only ever 404 is worse
// than an absent one.
func TestProviderIdentityRoute_NotMountedWithoutASource(t *testing.T) {
	gw, fellThrough := pidGateway(t, nil)

	resp, _ := pidGet(t, gw.URL+pidPath)
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("status = %d, want the catch-all's 404", resp.StatusCode)
	}
	select {
	case got := <-fellThrough:
		if got != pidPath {
			t.Errorf("router saw %q, want %q", got, pidPath)
		}
	default:
		t.Error("the unmounted route answered locally")
	}
}

// The provider CATALOG is a less specific pattern and must keep reaching the
// router: this change shadows one path, not the whole /v1/providers space.
func TestProviderIdentityRoute_LeavesTheCatalogAlone(t *testing.T) {
	gw, fellThrough := pidGateway(t, &stubIdentities{record: pidFullRecord(), have: true})

	pidGet(t, gw.URL+"/v1/providers?service_type=chatbot")
	select {
	case got := <-fellThrough:
		if got != "/v1/providers" {
			t.Errorf("router saw %q, want the catalog forwarded", got)
		}
	default:
		t.Error("the provider catalog was answered locally; it belongs to the router")
	}
}

// pidRecordWithContainers is pidFullRecord plus the service list its compose_hash
// commits to — one 0G image pinned by digest, one third-party image pinned, and one
// pinned only by a tag.
func pidRecordWithContainers() route.ProviderIdentity {
	rec := pidFullRecord()
	rec.Containers = []compose.Service{
		{Name: "broker", Ref: "ghcr.io/0gfoundation/0g-serving-broker@sha256:ec5df834",
			Image: "ghcr.io/0gfoundation/0g-serving-broker", Digest: "sha256:ec5df834"},
		{Name: "sglang", Ref: "lmsysorg/sglang:v0.5.17@sha256:220bb1a1",
			Image: "lmsysorg/sglang", Tag: "v0.5.17", Digest: "sha256:220bb1a1"},
		{Name: "prometheus", Ref: "prom/prometheus:v2.45.2",
			Image: "prom/prometheus", Tag: "v2.45.2"},
	}
	return rec
}

func TestProviderIdentityRoute_ReportsContainers(t *testing.T) {
	gw, _ := pidGateway(t, &stubIdentities{record: pidRecordWithContainers(), have: true})

	_, body := pidGet(t, gw.URL+pidPath)
	var doc providerIdentityDoc
	if err := json.Unmarshal([]byte(body), &doc); err != nil {
		t.Fatalf("decode: %v\n%s", err, body)
	}
	if len(doc.Containers) != 3 {
		t.Fatalf("containers = %+v, want 3", doc.Containers)
	}
	// File order is part of the answer — see compose.ParseServices.
	if doc.Containers[0].Name != "broker" || doc.Containers[2].Name != "prometheus" {
		t.Errorf("containers out of file order: %+v", doc.Containers)
	}
	if doc.Containers[0].Digest != "sha256:ec5df834" {
		t.Errorf("broker digest = %q", doc.Containers[0].Digest)
	}
	// An unpinned image is the one finding this list carries unaided, so the empty
	// digest must reach the wire rather than be hidden.
	if doc.Containers[2].Digest != "" {
		t.Errorf("prometheus digest = %q, want empty for a tag-only reference", doc.Containers[2].Digest)
	}
	// The `source` label, in the same vocabulary as /v1/gateway/identity. The broker is
	// the case that decides the classifier: it is 0G's, and it ships from a DIFFERENT
	// repository, so a repo-scoped rule would stamp it third-party.
	for i, want := range []string{sourceOwn, sourceThirdParty, sourceThirdParty} {
		if got := doc.Containers[i].Source; got != want {
			t.Errorf("containers[%d] (%s) source = %q, want %q",
				i, doc.Containers[i].Image, got, want)
		}
	}
}

// The label describes the image's publisher and nothing else. In particular it must not
// be read as — or quietly become — a claim that the image is pinned, since the two are
// independent and a reader who conflates them reads "0g-release" as "and it is the
// build we published".
func TestProviderIdentityRoute_SourceIsIndependentOfPinning(t *testing.T) {
	rec := pidFullRecord()
	rec.Containers = []compose.Service{
		// Ours, pinned by nothing but a tag.
		{Name: "broker", Ref: "ghcr.io/0gfoundation/0g-serving-broker:v1.2.3",
			Image: "ghcr.io/0gfoundation/0g-serving-broker", Tag: "v1.2.3"},
		// Our namespace on a registry we do not publish through, pinned by digest. The
		// digest makes it no more ours than the tag made the first one less.
		{Name: "mirror", Ref: "evil.example.com/0gfoundation/0g-serving-broker@sha256:aa11",
			Image: "evil.example.com/0gfoundation/0g-serving-broker", Digest: "sha256:aa11"},
	}
	gw, _ := pidGateway(t, &stubIdentities{record: rec, have: true})

	_, body := pidGet(t, gw.URL+pidPath)
	var doc providerIdentityDoc
	if err := json.Unmarshal([]byte(body), &doc); err != nil {
		t.Fatalf("decode: %v\n%s", err, body)
	}
	if got := doc.Containers[0].Source; got != sourceOwn {
		t.Errorf("an unpinned image of ours = %q, want %q — pinning is reported by digest, not by source", got, sourceOwn)
	}
	if doc.Containers[0].Digest != "" {
		t.Errorf("digest = %q, want empty — the tag-only reference must still read as unpinned", doc.Containers[0].Digest)
	}
	if got := doc.Containers[1].Source; got != sourceThirdParty {
		t.Errorf("our namespace on a foreign registry = %q, want %q — a digest does not make it ours", got, sourceThirdParty)
	}
}

// Null, never []. An empty array would state that the enclave runs no containers,
// which is never true — the honest report of "nothing to show" is the absence.
func TestProviderIdentityRoute_ContainersNullWhenUnavailable(t *testing.T) {
	gw, _ := pidGateway(t, &stubIdentities{record: pidFullRecord(), have: true})

	_, body := pidGet(t, gw.URL+pidPath)
	if !strings.Contains(body, `"containers": null`) {
		t.Errorf("want containers to marshal as null when there are none; body:\n%s", body)
	}
}
