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
// router sees whatever transits it in the clear. Every response it produces is
// marked X-0G-E2EE: none (openaiproxy.MarkE2EE, applied where this handler is
// mounted), so "the router read this one" is something a caller can see rather
// than infer.
//
// What may travel it is one of two things, and the difference is whether anybody
// DECIDED:
//
//   - Metadata and discovery, always. The model catalog and the provider list
//     carry no prompt, and this path exists for them.
//   - A sealed surface's sub-resources, only under -unsealed-subtree=passthrough,
//     and only because the global-entry topology leaves a caller no other door
//     (see the endpoint.All loop in main.go). That content IS read by the router;
//     the marker is what keeps it disclosed rather than silent.
//
// Everything else must not. If a content-bearing endpoint that must stay
// end-to-end encrypted is later added to the router (e.g. /v1/completions or
// /v1/embeddings, which carry the prompt/input), it MUST get its own row in
// endpoint.All and its own seal path — routing it through this proxy would hand
// that content to the untrusted router in the clear, defeating the gateway's whole
// purpose.
//
// A sealed surface's own POST never reaches here, in ANY spelling of its path. An
// earlier version of this note claimed that for "either spelling (with or without
// a trailing slash)", which was wrong and was wrong in the direction that matters:
// `%2F` and a differently-cased segment are two more spellings, both of them
// matched no pattern, and both of them arrived here with the prompt in the clear.
// sealedNamespaceGuard (main.go) now folds every spelling to the registered one
// before the mux matches, so the claim holds by construction rather than by
// enumeration — do not narrow it back to a list.
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
			// Same class of bug as the doubled CORS header above, and the same fix. The
			// E2EE marker is set on w.Header() before this proxy runs (MarkE2EE), and
			// ReverseProxy copies upstream headers with Add — so a router that ever
			// emitted this name would APPEND to ours, and a client reading the header
			// would see two contradictory values on one response. The router does not send
			// it today; this makes that fact stop mattering.
			resp.Header.Del(openaiproxy.HeaderE2EE)
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
