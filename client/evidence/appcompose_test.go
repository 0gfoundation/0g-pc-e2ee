package evidence

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/0gfoundation/0g-pc-e2ee/protocol/attest"
)

// A small but structurally faithful app-compose: the docker-compose text is a
// string FIELD, which is what makes the compose hash cover it.
const testAppCompose = `{"manifest_version":2,"name":"0g-pc-gateway-staging-a","runner":"docker-compose",` +
	`"docker_compose_file":"services:\n  gateway:\n    image: ghcr.io/x/gateway@sha256:abc\n",` +
	`"allowed_envs":["ZG_GATEWAY_ROUTER_URL","ACME_STAGING"]}`

func composeHashOf(s string) [attest.ComposeHashLen]byte { return sha256.Sum256([]byte(s)) }

func TestVerifyAppCompose_Accepts(t *testing.T) {
	ac, err := VerifyAppCompose([]byte(testAppCompose), composeHashOf(testAppCompose))
	if err != nil {
		t.Fatalf("VerifyAppCompose: %v", err)
	}
	if ac.Name != "0g-pc-gateway-staging-a" {
		t.Errorf("Name = %q", ac.Name)
	}
	if !strings.Contains(ac.DockerComposeFile, "image: ghcr.io/x/gateway@sha256:abc") {
		t.Errorf("docker_compose_file did not round-trip:\n%s", ac.DockerComposeFile)
	}
	if len(ac.AllowedEnvs) != 2 {
		t.Errorf("AllowedEnvs = %v, want 2 entries", ac.AllowedEnvs)
	}
}

func TestVerifyAppCompose_Rejects(t *testing.T) {
	right := composeHashOf(testAppCompose)

	// The bytes are semantically identical JSON but reformatted, so the digest moves.
	// This is the mistake most likely to be made by hand, so it must be caught.
	var reformatted map[string]any
	if err := json.Unmarshal([]byte(testAppCompose), &reformatted); err != nil {
		t.Fatalf("fixture: %v", err)
	}
	pretty, err := json.MarshalIndent(reformatted, "", "  ")
	if err != nil {
		t.Fatalf("fixture: %v", err)
	}

	cases := map[string]struct {
		raw  []byte
		hash [attest.ComposeHashLen]byte
	}{
		"different app-compose": {[]byte(`{"name":"other","docker_compose_file":"services: {}"}`), right},
		"reformatted bytes":     {pretty, right},
		"one byte changed":      {[]byte(testAppCompose + " "), right},
		"zero hash":             {[]byte(testAppCompose), [attest.ComposeHashLen]byte{}},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := VerifyAppCompose(tc.raw, tc.hash); err == nil {
				t.Error("expected an error, got nil")
			}
		})
	}
}

// Authenticated but with no compose text: must not report an empty match.
func TestVerifyAppCompose_NoDockerComposeFile(t *testing.T) {
	raw := `{"manifest_version":2,"name":"x","docker_compose_file":""}`
	if _, err := VerifyAppCompose([]byte(raw), composeHashOf(raw)); err == nil {
		t.Error("expected an error for an app-compose with no docker_compose_file")
	}
}

// A guest-agent Info fixture with the real double-nesting: tcb_info is a JSON
// string, and app_compose inside it is another JSON string.
func infoBody(t *testing.T, appCompose string, publicTCBInfo bool) []byte {
	t.Helper()
	tcb := map[string]string{
		"compose_hash": fmt.Sprintf("%x", composeHashOf(appCompose)),
		"app_compose":  appCompose,
	}
	tcbJSON, err := json.Marshal(tcb)
	if err != nil {
		t.Fatalf("fixture: %v", err)
	}
	info := map[string]string{"app_id": "deadbeef"}
	if publicTCBInfo {
		info["tcb_info"] = string(tcbJSON)
	} else {
		info["tcb_info"] = "" // what the guest agent returns when public_tcbinfo is off
	}
	b, err := json.Marshal(info)
	if err != nil {
		t.Fatalf("fixture: %v", err)
	}
	return b
}

// guestAgent serves /prpc/Info over TLS (FetchAppCompose builds an https URL) and
// records the host+path it was asked for, so a test can assert the URL is derived
// from the app_id.
func guestAgent(t *testing.T, body []byte, status int) (*httptest.Server, *string) {
	t.Helper()
	var gotHost string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotHost = r.Host + r.URL.Path
		w.WriteHeader(status)
		_, _ = w.Write(body)
	}))
	t.Cleanup(srv.Close)
	return srv, &gotHost
}

// httpTo returns a client whose requests all land on srv whatever host they name,
// so the URL under test can be the real platform hostname (which does not resolve).
//
// It skips certificate verification because these tests exercise the fetch and the
// double JSON unwrap, not TLS: httptest's certificate is issued for example.com,
// never for the platform hostname the URL under test uses. That is sound here for
// the same reason the endpoint's own TLS is not load-bearing in production — the
// bytes are authenticated afterwards by VerifyAppCompose against the quote.
func httpTo(srv *httptest.Server) *http.Client {
	return &http.Client{Transport: &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "tcp", srv.Listener.Addr().String())
		},
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // see comment
	}}
}

func TestFetchAppCompose(t *testing.T) {
	srv, gotHost := guestAgent(t, infoBody(t, testAppCompose, true), http.StatusOK)

	raw, err := FetchAppCompose(context.Background(), httpTo(srv), "f45d6de2b96e7f4a1b5dc093e9d5bc4db8ba5f66", "in1.phala.network")
	if err != nil {
		t.Fatalf("FetchAppCompose: %v", err)
	}
	if string(raw) != testAppCompose {
		t.Errorf("app-compose bytes did not survive the double unwrap:\n got %q\nwant %q", raw, testAppCompose)
	}
	// The digest of what we fetched must be usable directly — i.e. no reformatting
	// happened anywhere in the path.
	if _, err := VerifyAppCompose(raw, composeHashOf(testAppCompose)); err != nil {
		t.Errorf("fetched bytes do not hash to the expected compose_hash: %v", err)
	}
	// The URL must be built from the app_id and the guest-agent port.
	if want := "f45d6de2b96e7f4a1b5dc093e9d5bc4db8ba5f66-8090.in1.phala.network/prpc/Info"; *gotHost != want {
		t.Errorf("requested %q, want %q", *gotHost, want)
	}
}

func TestFetchAppCompose_Errors(t *testing.T) {
	t.Run("public_tcbinfo off", func(t *testing.T) {
		srv, _ := guestAgent(t, infoBody(t, testAppCompose, false), http.StatusOK)
		_, err := FetchAppCompose(context.Background(), httpTo(srv), "abc", "in1.phala.network")
		if err == nil || !strings.Contains(err.Error(), "public_tcbinfo") {
			t.Errorf("err = %v, want it to name public_tcbinfo", err)
		}
	})
	t.Run("non-200", func(t *testing.T) {
		srv, _ := guestAgent(t, []byte("nope"), http.StatusNotFound)
		if _, err := FetchAppCompose(context.Background(), httpTo(srv), "abc", "in1.phala.network"); err == nil {
			t.Error("expected an error on 404")
		}
	})
	t.Run("no app_id", func(t *testing.T) {
		srv, _ := guestAgent(t, infoBody(t, testAppCompose, true), http.StatusOK)
		if _, err := FetchAppCompose(context.Background(), httpTo(srv), "", "in1.phala.network"); err == nil {
			t.Error("expected an error with no app_id")
		}
	})
	t.Run("no base domain", func(t *testing.T) {
		srv, _ := guestAgent(t, infoBody(t, testAppCompose, true), http.StatusOK)
		if _, err := FetchAppCompose(context.Background(), httpTo(srv), "abc", ""); err == nil {
			t.Error("expected an error with no base domain")
		}
	})
}

func TestAppIDHost(t *testing.T) {
	const app = "f45d6de2b96e7f4a1b5dc093e9d5bc4db8ba5f66"
	want := app + "-8090.in1.phala.network"
	for _, base := range []string{
		"in1.phala.network",
		"IN1.Phala.Network",
		"https://in1.phala.network",
		"in1.phala.network/",
		// The form an operator is most likely to copy out of a dstack GATEWAY_DOMAIN.
		"_.in1.phala.network",
	} {
		if got := appIDHost(app, base); got != want {
			t.Errorf("appIDHost(_, %q) = %q, want %q", base, got, want)
		}
	}
	if got := appIDHost(app, ""); got != "" {
		t.Errorf("appIDHost with no base domain = %q, want empty", got)
	}
}

func TestDiffComposeFile(t *testing.T) {
	base := "services:\n  gateway:\n    image: x@sha256:aaa\n"

	if err := diffComposeFile([]byte(base), []byte(base)); err != nil {
		t.Errorf("identical: %v", err)
	}
	// Transport artifacts, not changes to what runs.
	if err := diffComposeFile([]byte(strings.ReplaceAll(base, "\n", "\r\n")), []byte(base)); err != nil {
		t.Errorf("CRLF should not differ: %v", err)
	}
	if err := diffComposeFile([]byte(strings.TrimSuffix(base, "\n")), []byte(base)); err != nil {
		t.Errorf("missing final newline should not differ: %v", err)
	}

	// A changed image digest is the whole point: it must be reported, with the line.
	changed := strings.Replace(base, "aaa", "bbb", 1)
	err := diffComposeFile([]byte(changed), []byte(base))
	if err == nil {
		t.Fatal("a changed image digest was not reported")
	}
	if !strings.Contains(err.Error(), "line 3") || !strings.Contains(err.Error(), "bbb") {
		t.Errorf("diff should name the line and show it, got: %v", err)
	}

	// Whitespace inside a line IS a difference — it changes the measured text.
	if err := diffComposeFile([]byte("services:\n  gateway:\n     image: x@sha256:aaa\n"), []byte(base)); err == nil {
		t.Error("indentation change was not reported")
	}

	// Extra / missing trailing lines.
	if err := diffComposeFile([]byte(base+"  extra: true\n"), []byte(base)); err == nil ||
		!strings.Contains(err.Error(), "extra line") {
		t.Errorf("extra line: err = %v", err)
	}
	if err := diffComposeFile([]byte("services:\n"), []byte(base)); err == nil ||
		!strings.Contains(err.Error(), "missing") {
		t.Errorf("missing lines: err = %v", err)
	}
}

func TestCodeIdentity_OK(t *testing.T) {
	sentinel := errors.New("x")
	cases := map[string]struct {
		c    CodeIdentity
		want bool
	}{
		// Nothing asked for: an unrequested check is not a failure.
		"not requested":              {CodeIdentity{}, true},
		"not requested, hash failed": {CodeIdentity{HashErr: sentinel}, true},
		"requested, hash failed":     {CodeIdentity{Requested: true, HashErr: sentinel}, false},
		"requested, fetch failed":    {CodeIdentity{Requested: true, FetchErr: sentinel}, false},
		"requested, not bound":       {CodeIdentity{Requested: true, BoundErr: sentinel}, false},
		"requested, bound":           {CodeIdentity{Requested: true}, true},
		"compose file mismatch": {CodeIdentity{
			Requested: true, ExpectRequested: true, ExpectErr: sentinel}, false},
		// A real match always names what it matched; OK() now requires that, so this
		// case has to carry a label. Without one the state is indistinguishable from an
		// early return that compared nothing.
		"compose file match": {CodeIdentity{
			Requested: true, ExpectRequested: true, MatchedExpect: "release-1"}, true},
		"compose file 'match' with no label is not a match": {CodeIdentity{
			Requested: true, ExpectRequested: true}, false},

		// A DISCOVERED lookup (DNS-derived base domain) that did not pan out is
		// advisory: nobody asked for it, and DNS or the platform endpoint being
		// unavailable is not evidence about the deployment.
		"discovered, fetch failed": {CodeIdentity{
			Requested: true, Discovered: true, FetchErr: sentinel}, true},
		// Not bound is a FINDING, not an availability problem: bytes that claim to be
		// this CVM's manifest and do not hash to the quote's compose_hash say something
		// about the deployment however they were reached. So unlike FetchErr it stays
		// fatal even when the lookup was only discovery — which also removes a
		// contradiction, since the report always printed ✗ for it.
		"discovered, not bound": {CodeIdentity{
			Requested: true, Discovered: true, BoundErr: sentinel}, false},
		// The regression this guards: -releases defaults to 5, so a DEFAULT comparison
		// normally has candidates and ExpectRequested is true. That must NOT harden the
		// discovered lookup — otherwise whether a DNS failure fails the whole run would
		// depend on whether GitHub happened to be reachable that minute.
		"discovered fetch failed, default comparison ran": {CodeIdentity{
			Requested: true, Discovered: true, FetchErr: sentinel, ExpectRequested: true}, true},
		// Explicitly asking (-expect-compose-file, or -releases typed out) is how the
		// caller says "this must work", and then it is fatal.
		"discovered fetch failed, comparison explicitly asked for": {CodeIdentity{
			Requested: true, Discovered: true, FetchErr: sentinel,
			ExpectRequested: true, ExpectExplicit: true}, false},
		// Supplying -base-domain / -app-compose is the other way to say it: not
		// discovered, so a failure is fatal with no comparison involved at all.
		"supplied base domain, fetch failed": {CodeIdentity{
			Requested: true, Discovered: false, FetchErr: sentinel}, false},

		// -no-dns-discovery with no bytes supplied: the stage never ran. The caller
		// opted out, so it is not a failure — but it must never read as a pass either,
		// which is what the zero ExpectErr used to do once the DEFAULT -releases lookup
		// had populated candidates.
		"no source": {CodeIdentity{NoSource: true}, true},
		"no source, default comparison had candidates": {CodeIdentity{
			NoSource: true, ExpectRequested: true}, true},
		// Asking explicitly for a comparison there is nothing to compare is a
		// contradiction, and fatal.
		"no source, comparison explicitly asked for": {CodeIdentity{
			NoSource: true, ExpectRequested: true, ExpectExplicit: true}, false},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			if got := tc.c.OK(); got != tc.want {
				t.Errorf("OK() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestCheckerNote(t *testing.T) {
	// note() is built from the configuration, so a bare Checker is enough. A populated
	// OS-image allowlist is supplied where the OS caveat is not the thing under test.
	pinned := []OSImage{{Name: "img", BootChain: mkBootChain(0x11)}}
	note := func(cfg Config) string {
		cfg.QuoteParser = func([]byte) (attest.Measurement, [64]byte, error) {
			return attest.Measurement{}, [64]byte{}, nil
		}
		if cfg.OSImages == nil {
			cfg.OSImages = pinned
		}
		c, err := New(cfg)
		if err != nil {
			t.Fatalf("New: %v", err)
		}
		// nil report = the configuration-only note, which is what these cases assert on.
		return c.note(nil)
	}

	// Discovery off and nothing supplied: code identity is out of scope entirely.
	if n := note(Config{NoDNSDiscovery: true}); !strings.Contains(n, "NOT checked") {
		t.Errorf("no code identity possible: note = %q", n)
	}
	// Discovery on (the default) counts as asking for the app-compose hop.
	if n := note(Config{}); !strings.Contains(n, "NOT compared") {
		t.Errorf("discovery on, no compose comparison: note = %q", n)
	}
	if n := note(Config{AppCompose: []byte("{}")}); !strings.Contains(n, "NOT compared") {
		t.Errorf("app-compose only: note = %q", n)
	}
	n := note(Config{
		AppCompose:         []byte("{}"),
		ExpectComposeFiles: []ExpectedCompose{{Label: "x", Content: []byte("x")}},
	})
	if !strings.Contains(n, "floating tag") {
		t.Errorf("complete: note should still name the pinning caveat, got %q", n)
	}
	if strings.Contains(n, "OS image is NOT pinned") {
		t.Errorf("OS image was pinned; note should not claim otherwise: %q", n)
	}

	// An empty allowlist must add the caveat that undercuts code identity, and must do
	// so even on an otherwise-complete run.
	n = note(Config{
		OSImages:           []OSImage{},
		AppCompose:         []byte("{}"),
		ExpectComposeFiles: []ExpectedCompose{{Label: "x", Content: []byte("x")}},
	})
	if !strings.Contains(n, "OS image is NOT pinned") || !strings.Contains(n, "not proof") {
		t.Errorf("unpinned OS image: note = %q", n)
	}
}

func TestDeriveBaseDomain(t *testing.T) {
	// The real chain from a dstack deployment: served name → delegation zone →
	// GATEWAY_DOMAIN, which is `_.<base>`.
	chain := map[string]string{
		"router-api-tee-staging.0g.ai":                       "router-api-tee-staging.0g.ai.integratenetwork.work.",
		"router-api-tee-staging.0g.ai.integratenetwork.work": "_.in1.phala.network.",
		"_.in1.phala.network":                                "_.in1.phala.network.",
	}
	lookup := func(_ context.Context, name string) (string, error) {
		if c, ok := chain[name]; ok {
			return c, nil
		}
		return "", fmt.Errorf("no such host: %s", name)
	}

	got, err := deriveBaseDomain(context.Background(), "router-api-tee-staging.0g.ai", lookup)
	if err != nil {
		t.Fatalf("deriveBaseDomain: %v", err)
	}
	if got != "in1.phala.network" {
		t.Errorf("base domain = %q, want in1.phala.network", got)
	}
	// A port and a trailing dot are both things an operator may paste.
	for _, in := range []string{"router-api-tee-staging.0g.ai:443", "Router-API-TEE-Staging.0G.AI."} {
		if got, err := deriveBaseDomain(context.Background(), in, lookup); err != nil || got != "in1.phala.network" {
			t.Errorf("deriveBaseDomain(%q) = %q, %v", in, got, err)
		}
	}
}

func TestDeriveBaseDomain_Errors(t *testing.T) {
	t.Run("chain does not end at a gateway domain", func(t *testing.T) {
		// A name that is not fronted by a dstack gateway: the last hop has no `_.`
		// prefix, so guessing a base domain from it would be fabrication.
		lookup := func(_ context.Context, name string) (string, error) {
			if name == "plain.example.com" {
				return "plain.example.com.", nil
			}
			return "", fmt.Errorf("unexpected %s", name)
		}
		_, err := deriveBaseDomain(context.Background(), "plain.example.com", lookup)
		if err == nil || !strings.Contains(err.Error(), "not a dstack gateway domain") {
			t.Errorf("err = %v, want it to say the chain does not end at a gateway domain", err)
		}
	})
	t.Run("resolution failure", func(t *testing.T) {
		lookup := func(context.Context, string) (string, error) { return "", errors.New("no such host") }
		if _, err := deriveBaseDomain(context.Background(), "x.example.com", lookup); err == nil {
			t.Error("expected an error when resolution fails")
		}
	})
	t.Run("empty domain", func(t *testing.T) {
		lookup := func(context.Context, string) (string, error) { return "", nil }
		if _, err := deriveBaseDomain(context.Background(), "   ", lookup); err == nil {
			t.Error("expected an error for an empty domain")
		}
	})
	t.Run("loop is bounded", func(t *testing.T) {
		// A chain that never terminates must stop, not spin.
		n := 0
		lookup := func(_ context.Context, name string) (string, error) {
			n++
			return fmt.Sprintf("hop%d.example.com.", n), nil
		}
		if _, err := deriveBaseDomain(context.Background(), "start.example.com", lookup); err == nil {
			t.Error("expected an error when the chain never reaches a gateway domain")
		}
		if n > maxCNAMEHops {
			t.Errorf("walked %d hops, want at most %d", n, maxCNAMEHops)
		}
	})
}

func TestMatchExpected(t *testing.T) {
	live := []byte("services:\n  gateway:\n    image: x@sha256:aaa\n")
	other := []byte("services:\n  gateway:\n    image: x@sha256:bbb\n")
	third := []byte("services:\n  gateway:\n    image: x@sha256:ccc\n")

	t.Run("single candidate match", func(t *testing.T) {
		label, err := MatchCompose(live, []ExpectedCompose{{Label: "release-1", Content: live}})
		if err != nil || label != "release-1" {
			t.Errorf("label = %q, err = %v", label, err)
		}
	})
	t.Run("matches a later candidate", func(t *testing.T) {
		// Newest first; the deployment is running the older one. Reporting WHICH is the
		// point — "it is release-2, not the newest" is actionable.
		label, err := MatchCompose(live, []ExpectedCompose{
			{Label: "release-3", Content: third},
			{Label: "release-2", Content: live},
		})
		if err != nil || label != "release-2" {
			t.Errorf("label = %q, err = %v", label, err)
		}
	})
	t.Run("single candidate mismatch names it", func(t *testing.T) {
		_, err := MatchCompose(live, []ExpectedCompose{{Label: "release-9", Content: other}})
		if err == nil || !strings.Contains(err.Error(), "release-9") {
			t.Errorf("err = %v, want it to name the candidate", err)
		}
	})
	t.Run("no candidate matches", func(t *testing.T) {
		_, err := MatchCompose(live, []ExpectedCompose{
			{Label: "release-3", Content: third},
			{Label: "release-2", Content: other},
		})
		if err == nil {
			t.Fatal("expected an error")
		}
		// It must say how many were tried, list them, and diff against the newest.
		for _, want := range []string{"none of 2", "release-3", "release-2", "line 3"} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("err missing %q: %v", want, err)
			}
		}
	})
	t.Run("no candidates supplied", func(t *testing.T) {
		if _, err := MatchCompose(live, nil); err == nil {
			t.Error("expected an error with no candidates")
		}
	})
}
