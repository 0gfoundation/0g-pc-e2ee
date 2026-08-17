package main

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"

	"github.com/0gfoundation/0g-pc-e2ee/client/openaiproxy"
)

// checkEvidenceDir verifies that a configured bundle directory is present and
// readable BY THIS PROCESS, so a bad mount fails the boot instead of answering 404
// to every verifier. A silently unreachable evidence bundle is the exact class of
// bug issue #73 is about, and it has no signal: `pcverify` reports a fetch error
// that looks like a hundred other things, and nobody notices for weeks.
//
// It deliberately does NOT require the bundle to be POPULATED. The gateway comes up
// before dstack-ingress finishes its first ACME run — the ingress gates on the
// gateway's health, so it must — and an empty directory is the normal early state.
//
// Blast radius, stated rather than glossed: main exits on a failure here, which
// takes the whole endpoint down (no sealed inference either), not just this route.
// That is the right trade for a value that comes from the measured compose next to
// the volume it names — a mismatch is a deploy error, caught on the first staging
// boot, not something that appears in steady state — but it is exactly why the check
// stays this narrow: presence and readability, never contents.
func checkEvidenceDir(dir string) error {
	// Open, not Stat: this also catches a directory this uid cannot traverse. The
	// gateway image runs as `nonroot` while the volume and its files are created by
	// the (root) ingress container, so "can the serving process actually read it" is a
	// different question from "does it exist".
	f, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return err
	}
	if !info.IsDir() {
		return fmt.Errorf("%s is not a directory", dir)
	}
	// Opening a directory can succeed without read permission on it; the first read
	// is what proves the index and every file lookup under it will work. An empty
	// directory returns io.EOF here, which is the expected pre-ACME state above.
	if _, err := f.Readdirnames(1); err != nil && !errors.Is(err, io.EOF) {
		return fmt.Errorf("read %s: %w", dir, err)
	}
	return nil
}

// evidencePrefix is the PUBLIC path of the evidence bundle, and it is a
// compatibility constant, not a choice: pcverify builds its requests as
// `https://<host>/evidences/<name>` (client/evidence/evidence.go), every published
// curl recipe uses it (docs/verifying-the-gateway.md, deploy/phala/README.md), and
// third-party verifiers have it hardcoded too. Serving the bundle from here rather
// than from dstack-ingress must be invisible from outside — same paths, same bytes
// — so this must never move under /v1 or anywhere else.
const evidencePrefix = "/evidences/"

// evidenceAllowMethods is the preflight's Access-Control-Allow-Methods. Reading
// static files is all this route does; a write verb has nothing to reach here.
const evidenceAllowMethods = "GET, HEAD, OPTIONS"

// evidenceAllowHeaders is a FIXED preflight answer, deliberately not a reflection
// of Access-Control-Request-Headers: keeping it constant means the response does
// not vary by request, so it needs no Vary header and any cache in front of it can
// serve one answer to every caller (see evidenceRoute on why nothing here varies).
// The names are the ones a static fetch or a conditional re-fetch actually sends.
const evidenceAllowHeaders = "Content-Type, Range, If-None-Match, If-Modified-Since"

// evidenceMaxAge lets a browser cache the preflight for 12h, matching the CORS
// middleware's corsMaxAge.
const evidenceMaxAge = "43200"

// evidenceRoute serves the public attestation evidence bundle out of dir — the
// `evidences` volume dstack-ingress writes, mounted read-only here — and delegates
// every other path to next. With dir empty it returns next unchanged: a local run
// and the sidecar have no bundle, and an empty directory served at /evidences/
// would answer 404 where the request should reach the router catch-all instead.
//
// WHY THE GATEWAY SERVES THIS AT ALL. The bundle is produced by dstack-ingress and
// used to be served by it too, from a mini_httpd behind an HAProxy path ACL. That
// path emits no CORS header and the upstream image (a pinned digest) has no knob to
// add one, so no web page could read the bundle it exists to publish — issue #73.
// Serving it here puts the response headers under this repo's control. Upstream is
// then configured with EVIDENCE_SERVER=false, which stops only mini_httpd and the
// HAProxy ACL; the collect/finalize steps that WRITE the bundle are unconditional,
// so the volume's contents are exactly what they were.
//
// WHY THAT IS NOT A TRUST REGRESSION, even though this container is the one that
// handles user prompts. The bundle is self-authenticating: quote.json is signed by
// TDX hardware, its report_data commits to sha256sum.txt, which covers the cert and
// the ACME account, and pcverify's endpoint-binding step compares the published
// cert against the one the caller's own TLS session negotiated. A process that
// tampered with any of those bytes would fail verification; one that withheld them
// fails closed. Who hands over the bytes is not part of what is being proven — the
// same reason a hostile mirror cannot forge DCAP collateral.
//
// WHY IT IS WIRED OUTSIDE openaiproxy.CORS. This route's policy is
// `Access-Control-Allow-Origin: *`, which is a DIFFERENT policy from the gateway's
// origin allowlist and must not be entangled with it: the allowlist governs which
// web origins may drive sealed inference through the enclave (a decision app_id
// commits to), while the bundle is static public data any curl already fetches, so
// restricting it to first-party origins would reintroduce exactly the hole #73
// describes. Sitting ahead of that middleware also means a preflight from an
// unlisted origin is answered here rather than 403'd there, and that no
// evidences request can ever fall through to the router catch-all.
//
// Wildcard-safe by construction: `*` and Access-Control-Allow-Credentials are
// mutually exclusive, so a browser sends these requests without cookies and
// without any credential of the caller's. There is nothing here to authorize and
// nothing that varies by who asks.
func evidenceRoute(dir string, next http.Handler) http.Handler {
	if dir == "" {
		return next
	}
	// http.FileServer gives conditional requests (Last-Modified / If-Modified-Since,
	// so a renewal is picked up but an unchanged bundle costs a 304), Range support,
	// and the directory index at /evidences/ that mini_httpd also served — a browser
	// verifier needs the index to discover the cert-<domain>.pem filename. Files are
	// read per request from the read-only mount, never cached in-process, so the
	// bundle dstack-ingress rewrites at each certificate renewal is served as-is.
	files := http.StripPrefix(evidencePrefix, http.FileServer(http.Dir(dir)))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != strings.TrimSuffix(evidencePrefix, "/") && !strings.HasPrefix(r.URL.Path, evidencePrefix) {
			next.ServeHTTP(w, r)
			return
		}
		// Unconditional, and set before any early return below so even a 405 or a 404
		// is readable by the page that asked — a verifier has to be able to tell "no
		// such file" apart from "blocked by CORS", which is the whole complaint in #73.
		w.Header().Set("Access-Control-Allow-Origin", "*")
		// So a page can read which replica answered (several CVMs can back one app_id).
		// Naming a header the response may not carry is a no-op, so this needs no
		// coupling to whether StampInstance is wired.
		w.Header().Set("Access-Control-Expose-Headers", openaiproxy.HeaderGatewayInstance)

		if r.Method == http.MethodOptions {
			w.Header().Set("Access-Control-Allow-Methods", evidenceAllowMethods)
			w.Header().Set("Access-Control-Allow-Headers", evidenceAllowHeaders)
			w.Header().Set("Access-Control-Max-Age", evidenceMaxAge)
			w.WriteHeader(http.StatusNoContent)
			return
		}
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			// Answered here rather than passed on: the catch-all would reverse-proxy it to
			// the router, which has no /evidences surface and is not the authority on this
			// path anyway.
			w.Header().Set("Allow", evidenceAllowMethods)
			openaiproxy.WriteError(w, http.StatusMethodNotAllowed, "gateway", "evidence bundle is read-only")
			return
		}
		// /evidences → /evidences/, so the index resolves the way it does under
		// mini_httpd. Done here because StripPrefix would otherwise hand FileServer a
		// path outside its root and 404.
		if r.URL.Path == strings.TrimSuffix(evidencePrefix, "/") {
			http.Redirect(w, r, evidencePrefix, http.StatusMovedPermanently)
			return
		}
		// Revalidate rather than reuse: a certificate renewal rewrites the bundle, and a
		// verifier holding a stale quote.json against a fresh certificate sees a
		// mismatch it cannot explain. Last-Modified still keeps the common case a 304.
		w.Header().Set("Cache-Control", "no-cache")
		files.ServeHTTP(w, r)
	})
}
