package main

import (
	"log/slog"
	"net/http"
	"net/http/httputil"
	"net/url"

	"github.com/0gfoundation/0g-pc-e2ee/client/core"
	"github.com/0gfoundation/0g-pc-e2ee/client/openaiproxy"
)

// newRouterProxy builds the gateway's catch-all: a reverse proxy that forwards
// every request NOT matched by a more specific route (the sealed
// POST /v1/chat/completions, plus /healthz) straight to the 0G
// router. Go's ServeMux serves the most specific pattern, so mounting this at
// "/" only ever catches otherwise-unmatched paths — it never shadows the sealed
// chat route. It lets a no-install / browser / thin client reach the router's
// non-sealed OpenAI surface (model catalog and discovery — GET /v1/models,
// /v1/service-types, /v1/providers) through the one origin it already talks to,
// instead of getting a 404 from the mux.
//
// SECURITY: this is a CLEARTEXT passthrough — it carries no E2EE seal, so the
// router sees whatever transits it in the clear. That is fine for metadata and
// discovery, which carry no prompt, and is the ONLY thing this path is for. If a
// content-bearing endpoint that must stay end-to-end encrypted is later added to
// the router (e.g. /v1/completions or /v1/embeddings, which carry the
// prompt/input), it MUST get its own seal path in openaiproxy — routing it
// through this proxy would hand that content to the untrusted router in the
// clear, defeating the gateway's whole purpose. Keep the catch-all for metadata;
// never let it become the path for sealed content.
func newRouterProxy(target *url.URL, logger *slog.Logger) http.Handler {
	return &httputil.ReverseProxy{
		// Every request this proxy makes goes to the one router host, so it needs the
		// same server-sized idle-connection pool as the sealed path. Left nil,
		// ReverseProxy falls through to the process-global http.DefaultTransport and
		// its 2 idle connections per host — which would make this the one gateway path
		// still throttled that way, and the one sharing a pool with whatever else
		// happens to use the global default. It is not per-chat, but it IS per page
		// load for the browser clients this catch-all exists to serve (the model
		// catalog and discovery fan-out), so the concurrency is real.
		Transport: core.NewPooledTransport(),
		Rewrite: func(pr *httputil.ProxyRequest) {
			// Route the outbound to the router, preserving any base path on the
			// configured URL (…/api + /v1/models → …/api/v1/models) and merging query
			// params. SetURL also clears Out.Host, so the Transport sends the router's
			// host as the Host header (its TLS SNI / vhost routing needs that, not the
			// gateway's own listen host). We deliberately do NOT SetXForwarded: the
			// gateway runs inside the enclave behind dstack-ingress and must not
			// advertise client IPs or its internal hostname to the untrusted router.
			pr.SetURL(target)
		},
		ModifyResponse: func(resp *http.Response) error {
			// The router runs its own CORS middleware off its own allowlist, and this
			// proxy copies upstream headers verbatim — so without this the browser would
			// see two Access-Control-Allow-Origin values (a hard failure: "contains
			// multiple values") whenever both the router and the gateway allowed the
			// origin, and the router's verdict whenever they disagreed. Strip them and
			// let the gateway's own middleware (openaiproxy.CORS, which wraps this
			// handler) be the single authority for what a browser may reach here.
			openaiproxy.StripCORSHeaders(resp.Header)
			return nil
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			// A transport-level failure reaching the router — this fires only when the
			// round trip never produced a response (connection refused, TLS, timeout); a
			// router that answers with its own 4xx/5xx is a successful proxy round trip
			// and passes through verbatim, never reaching here. The default handler logs
			// to a std logger the gateway doesn't use, so emit one redaction-safe line
			// (method and path only, no headers or body) and return 502 as the SAME JSON
			// envelope the sealed path uses, so a thin client parses errors identically
			// across both paths. The message is generic (the transport err — which can
			// carry the router host/port — goes only to the enclave log), and the source
			// is "upstream": like the sealed path, a failure reaching the router is
			// attributed upstream, not to a fault in this proxy.
			logger.Error("router passthrough failed", "method", r.Method, "path", r.URL.Path, "err", err)
			openaiproxy.WriteError(w, http.StatusBadGateway, "upstream", "upstream request failed")
		},
	}
}
