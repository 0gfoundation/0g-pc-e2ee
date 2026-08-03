package main

import (
	"log/slog"
	"net/http"
	"net/http/httputil"
	"net/url"
)

// newRouterProxy builds the gateway's catch-all: a reverse proxy that forwards
// every request NOT matched by a more specific route (the sealed
// POST /v1/chat/completions, plus /healthz and /quote) straight to the 0G
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
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			// A transport-level failure reaching the router (the default handler would
			// log to a std logger the gateway doesn't use). Emit one redaction-safe
			// line — method and path only, no headers or body — and return a plain 502;
			// the sealed path's richer error envelope lives in openaiproxy and does not
			// apply to this passthrough.
			logger.Error("router passthrough failed", "method", r.Method, "path", r.URL.Path, "err", err)
			http.Error(w, "bad gateway", http.StatusBadGateway)
		},
	}
}
