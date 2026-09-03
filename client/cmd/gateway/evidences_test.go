package main

import (
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/0gfoundation/0g-pc-e2ee/client/openaiproxy"
)

// evidenceBundle writes a stand-in for what dstack-ingress puts on the `evidences`
// volume — all four published files, so the tests cover the whole bundle the way
// issue #73's acceptance list asks rather than one representative file.
func evidenceBundle(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	for name, body := range map[string]string{
		"quote.json":               `{"quote":"0xdeadbeef"}`,
		"sha256sum.txt":            "abc123  cert-pc-gateway.test.pem\n",
		"cert-pc-gateway.test.pem": "-----BEGIN CERTIFICATE-----\n",
		"acme-account.json":        `{"contact":[]}`,
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}
	return dir
}

// evidenceGateway is a gateway serving the bundle, with a router that fails the
// test if the catch-all is ever reached: an /evidences request escaping to the
// untrusted router is the failure mode worth locking down, not just a 404.
func evidenceGateway(t *testing.T, dir string) *httptest.Server {
	t.Helper()
	router := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("router catch-all reached for %s %s; evidence paths must never leave the gateway", r.Method, r.URL.Path)
		w.WriteHeader(http.StatusNotFound)
	}))
	t.Cleanup(router.Close)
	gw := httptest.NewServer(newHandler(sealedClients(routeClient(), nil), mustURL(t, router.URL), testOrigins(), "", dir, noInFlightCap, nil, nil, nil, discardLogger()))
	t.Cleanup(gw.Close)
	return gw
}

// The point of issue #73: a page on ANY origin must be able to read the bundle. The
// origin here is deliberately absent from the gateway's allowlist (testOrigins),
// because the allowlist governs who may drive sealed inference and the public
// evidence bundle is not gated on it.
func TestEvidenceCORSAllowsAnyOrigin(t *testing.T) {
	gw := evidenceGateway(t, evidenceBundle(t))

	for _, name := range []string{"quote.json", "sha256sum.txt", "cert-pc-gateway.test.pem", "acme-account.json"} {
		t.Run(name, func(t *testing.T) {
			req, err := http.NewRequest(http.MethodGet, gw.URL+"/evidences/"+name, nil)
			if err != nil {
				t.Fatalf("new request: %v", err)
			}
			req.Header.Set("Origin", "https://third-party-auditor.example")
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatalf("get: %v", err)
			}
			defer resp.Body.Close()

			if resp.StatusCode != http.StatusOK {
				t.Fatalf("status = %d, want 200", resp.StatusCode)
			}
			if got := resp.Header.Get("Access-Control-Allow-Origin"); got != "*" {
				t.Errorf("Access-Control-Allow-Origin = %q, want %q", got, "*")
			}
			// `*` and credentials are mutually exclusive; a browser rejects the response
			// outright if both are present, so this is a correctness check, not hygiene.
			if got := resp.Header.Get("Access-Control-Allow-Credentials"); got != "" {
				t.Errorf("Access-Control-Allow-Credentials = %q, want unset with a wildcard origin", got)
			}
			if got := resp.Header.Get("Access-Control-Expose-Headers"); !strings.Contains(got, openaiproxy.HeaderGatewayInstance) {
				t.Errorf("Access-Control-Expose-Headers = %q, missing %s", got, openaiproxy.HeaderGatewayInstance)
			}
			body, err := io.ReadAll(resp.Body)
			if err != nil {
				t.Fatalf("read body: %v", err)
			}
			if len(body) == 0 {
				t.Error("empty body; the bundle file must be served, not just its headers")
			}
		})
	}
}

// A missing file must still carry the CORS header: a verifier page has to be able
// to tell "no such file" apart from "blocked by CORS", which is indistinguishable
// from JS when the 404 has no Access-Control-Allow-Origin.
func TestEvidenceMissingFileStillCORS(t *testing.T) {
	gw := evidenceGateway(t, evidenceBundle(t))

	req, _ := http.NewRequest(http.MethodGet, gw.URL+"/evidences/nope.json", nil)
	req.Header.Set("Origin", "https://third-party-auditor.example")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("status = %d, want 404", resp.StatusCode)
	}
	if got := resp.Header.Get("Access-Control-Allow-Origin"); got != "*" {
		t.Errorf("Access-Control-Allow-Origin = %q, want %q", got, "*")
	}
}

// The directory index is what mini_httpd served and what lets a browser verifier
// discover the cert-<domain>.pem filename without knowing the domain's spelling.
func TestEvidenceIndexListsBundle(t *testing.T) {
	gw := evidenceGateway(t, evidenceBundle(t))

	resp, err := http.Get(gw.URL + "/evidences/")
	if err != nil {
		t.Fatalf("get /evidences/: %v", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	for _, name := range []string{"quote.json", "sha256sum.txt", "cert-pc-gateway.test.pem", "acme-account.json"} {
		if !strings.Contains(string(body), name) {
			t.Errorf("index does not list %s", name)
		}
	}
}

// /evidences without the trailing slash resolves to the index rather than 404ing,
// matching what mini_httpd did behind the HAProxy ACL.
func TestEvidenceRedirectsBarePath(t *testing.T) {
	gw := evidenceGateway(t, evidenceBundle(t))

	// No redirect following: the redirect itself is what is under test.
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := client.Get(gw.URL + "/evidences")
	if err != nil {
		t.Fatalf("get /evidences: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusMovedPermanently {
		t.Fatalf("status = %d, want 301", resp.StatusCode)
	}
	if got := resp.Header.Get("Location"); got != "/evidences/" {
		t.Errorf("Location = %q, want %q", got, "/evidences/")
	}
	if got := resp.Header.Get("Access-Control-Allow-Origin"); got != "*" {
		t.Errorf("Access-Control-Allow-Origin = %q, want %q", got, "*")
	}
}

// A preflight from any origin is answered here, not 403'd by the API's origin
// allowlist — the reason evidenceRoute is wired OUTSIDE openaiproxy.CORS. Simple
// GETs need no preflight, so this covers the JS tool that sends one anyway.
func TestEvidencePreflightAnyOrigin(t *testing.T) {
	gw := evidenceGateway(t, evidenceBundle(t))

	req, _ := http.NewRequest(http.MethodOptions, gw.URL+"/evidences/quote.json", nil)
	req.Header.Set("Origin", "https://third-party-auditor.example")
	req.Header.Set("Access-Control-Request-Method", "GET")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("options: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("status = %d, want 204", resp.StatusCode)
	}
	if got := resp.Header.Get("Access-Control-Allow-Origin"); got != "*" {
		t.Errorf("Access-Control-Allow-Origin = %q, want %q", got, "*")
	}
	if got := resp.Header.Get("Access-Control-Allow-Methods"); !strings.Contains(got, "GET") {
		t.Errorf("Access-Control-Allow-Methods = %q, want GET", got)
	}
	// The answer is origin-independent, so it must not claim to vary by Origin — that
	// would split every cache entry for no reason.
	if got := resp.Header.Get("Vary"); strings.Contains(got, "Origin") {
		t.Errorf("Vary = %q, want no Origin (the wildcard answer does not vary)", got)
	}
}

// The bundle is read-only, and a write verb must not fall through to the catch-all
// (which would reverse-proxy it to the untrusted router). evidenceGateway's router
// fails the test if that happens.
func TestEvidenceRejectsWrites(t *testing.T) {
	gw := evidenceGateway(t, evidenceBundle(t))

	resp, err := http.Post(gw.URL+"/evidences/quote.json", "application/json", strings.NewReader("{}"))
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("status = %d, want 405", resp.StatusCode)
	}
	if got := resp.Header.Get("Allow"); !strings.Contains(got, "GET") {
		t.Errorf("Allow = %q, want GET", got)
	}
}

// Path traversal out of the bundle directory, in case the mount ever holds more
// than public data. http.Dir rejects it; this pins the behaviour so a future
// hand-rolled file lookup cannot regress it silently.
func TestEvidenceNoTraversal(t *testing.T) {
	dir := evidenceBundle(t)
	if err := os.WriteFile(filepath.Join(filepath.Dir(dir), "secret.txt"), []byte("private key"), 0o644); err != nil {
		t.Fatalf("write sibling: %v", err)
	}
	gw := evidenceGateway(t, dir)

	// Sent as a raw path so net/http does not clean the ../ away client-side before
	// the server ever sees it.
	req, err := http.NewRequest(http.MethodGet, gw.URL, nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.URL.Opaque = "/evidences/..%2fsecret.txt"
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	if strings.Contains(string(body), "private key") {
		t.Fatalf("served a file outside the bundle directory: %q", body)
	}
}

// What an EMPTY bundle directory actually answers — the state between the gateway
// coming up and dstack-ingress finishing its first ACME run. The index is a 200 with
// nothing in it; only the individual files 404. This is pinned because
// deploy/phala/README.md documents it for exactly the person watching a first deploy,
// and a doc claim nothing tests is a doc claim that drifts.
func TestEvidenceEmptyBundle(t *testing.T) {
	gw := evidenceGateway(t, t.TempDir())

	resp, err := http.Get(gw.URL + "/evidences/")
	if err != nil {
		t.Fatalf("get index: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("GET /evidences/ on an empty bundle = %d, want 200 (an empty index)", resp.StatusCode)
	}

	missing, err := http.Get(gw.URL + "/evidences/quote.json")
	if err != nil {
		t.Fatalf("get quote.json: %v", err)
	}
	defer missing.Body.Close()
	if missing.StatusCode != http.StatusNotFound {
		t.Errorf("GET /evidences/quote.json on an empty bundle = %d, want 404", missing.StatusCode)
	}
}

// checkEvidenceDir is what turns a bad mount into a boot failure instead of a
// bundle that 404s forever. An EMPTY directory must pass: the gateway starts before
// dstack-ingress has finished its first ACME run.
func TestCheckEvidenceDir(t *testing.T) {
	t.Run("populated", func(t *testing.T) {
		if err := checkEvidenceDir(evidenceBundle(t)); err != nil {
			t.Errorf("checkEvidenceDir(populated) = %v, want nil", err)
		}
	})
	t.Run("empty is fine (pre-ACME)", func(t *testing.T) {
		if err := checkEvidenceDir(t.TempDir()); err != nil {
			t.Errorf("checkEvidenceDir(empty) = %v, want nil", err)
		}
	})
	t.Run("missing", func(t *testing.T) {
		if err := checkEvidenceDir(filepath.Join(t.TempDir(), "nope")); err == nil {
			t.Error("checkEvidenceDir(missing) = nil, want an error")
		}
	})
	t.Run("not a directory", func(t *testing.T) {
		file := filepath.Join(t.TempDir(), "quote.json")
		if err := os.WriteFile(file, []byte("{}"), 0o644); err != nil {
			t.Fatalf("write: %v", err)
		}
		if err := checkEvidenceDir(file); err == nil {
			t.Error("checkEvidenceDir(file) = nil, want an error")
		}
	})
	t.Run("partial bundle (mid-ACME)", func(t *testing.T) {
		// acme-account.json lands before the quote exists, so a directory holding only
		// some of the four files must still pass — the check tolerates absence.
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, "acme-account.json"), []byte("{}"), 0o644); err != nil {
			t.Fatalf("write: %v", err)
		}
		if err := checkEvidenceDir(dir); err != nil {
			t.Errorf("checkEvidenceDir(partial) = %v, want nil", err)
		}
	})
	t.Run("unreadable quote.json", func(t *testing.T) {
		// The gap this closes: upstream chmods 644 onto acme-account.json and
		// cert-<domain>.pem but writes quote.json and sha256sum.txt with a bare shell
		// redirect, so their mode rides the ingress container's umask. A readable
		// DIRECTORY holding an unreadable quote.json would otherwise pass the boot check
		// and 403 every verifier.
		if os.Geteuid() == 0 {
			t.Skip("running as root; file mode is not enforced")
		}
		dir := evidenceBundle(t)
		quote := filepath.Join(dir, "quote.json")
		if err := os.Chmod(quote, 0o000); err != nil {
			t.Fatalf("chmod: %v", err)
		}
		t.Cleanup(func() { _ = os.Chmod(quote, 0o644) })
		if err := checkEvidenceDir(dir); err == nil {
			t.Error("checkEvidenceDir(unreadable quote.json) = nil, want an error")
		}
	})
	t.Run("unreadable sha256sum.txt", func(t *testing.T) {
		if os.Geteuid() == 0 {
			t.Skip("running as root; file mode is not enforced")
		}
		dir := evidenceBundle(t)
		manifest := filepath.Join(dir, "sha256sum.txt")
		if err := os.Chmod(manifest, 0o000); err != nil {
			t.Fatalf("chmod: %v", err)
		}
		t.Cleanup(func() { _ = os.Chmod(manifest, 0o644) })
		if err := checkEvidenceDir(dir); err == nil {
			t.Error("checkEvidenceDir(unreadable sha256sum.txt) = nil, want an error")
		}
	})
	t.Run("unreadable directory", func(t *testing.T) {
		// The case that motivates opening the directory rather than stat-ing it: the
		// gateway runs as `nonroot` while the ingress creates the volume as root. Skipped
		// as root, where the mode is not enforced.
		if os.Geteuid() == 0 {
			t.Skip("running as root; directory mode is not enforced")
		}
		dir := t.TempDir()
		if err := os.Chmod(dir, 0o000); err != nil {
			t.Fatalf("chmod: %v", err)
		}
		t.Cleanup(func() { _ = os.Chmod(dir, 0o700) }) // so TempDir cleanup can remove it
		if err := checkEvidenceDir(dir); err == nil {
			t.Error("checkEvidenceDir(unreadable) = nil, want an error")
		}
	})
}

// With no -evidence-dir the route is not mounted at all, so /evidences falls
// through to the catch-all like any other unknown path. That is what keeps a local
// run (and any deployment where dstack-ingress still serves the bundle) unchanged.
func TestEvidenceRouteUnmountedWhenUnset(t *testing.T) {
	reached := false
	router := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached = true
		w.WriteHeader(http.StatusNotFound)
	}))
	defer router.Close()
	gw := httptest.NewServer(newHandler(sealedClients(routeClient(), nil), mustURL(t, router.URL), testOrigins(), "", "", noInFlightCap, nil, nil, nil, discardLogger()))
	defer gw.Close()

	resp, err := http.Get(gw.URL + "/evidences/quote.json")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer resp.Body.Close()

	if !reached {
		t.Error("catch-all not reached; with no evidence dir the path must fall through to the router")
	}
	if got := resp.Header.Get("Access-Control-Allow-Origin"); got == "*" {
		t.Error("wildcard CORS header present with no evidence dir configured")
	}
}
