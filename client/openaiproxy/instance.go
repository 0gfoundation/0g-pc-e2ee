package openaiproxy

import "net/http"

// HeaderGatewayInstance carries the id of the gateway CVM that served a
// response. It answers the one question a caller cannot otherwise ask: an app_id
// can be backed by several replicas, and the dstack platform chooses which one a
// connection reaches (it races a TCP connect against the few instances with the
// freshest WireGuard handshake and keeps the first to answer, re-picking that
// candidate set every ~30s — so it is neither round-robin nor sticky by
// contract). Without this header, "this request was slow / failed and the next
// one was fine" is indistinguishable from "one replica is unhealthy".
//
// The value is the dstack instance_id, which is already public — the platform
// routes to it by name in the <instance_id>-443s.<base_domain> hostname form. It
// is still not emitted by default: see StampInstance.
const HeaderGatewayInstance = "X-0G-Gateway-Instance"

// StampInstance returns h with HeaderGatewayInstance set to instanceID on every
// response. An empty instanceID returns h unchanged, so a caller can wire it
// unconditionally.
//
// The gateway keeps this OFF by default (-instance-header). What it exposes is
// not the id itself — that is public — but the fleet SHAPE: a client that keeps
// opening connections and reading the header learns how many replicas stand
// behind the domain and how traffic distributes over them, which is free
// reconnaissance for anyone deciding where to aim load. Operators who want the
// debugging affordance turn it on deliberately; the metrics and log dimensions
// (which stay inside the enclave) are on unconditionally and are where the same
// information belongs by default.
//
// It is set before the handler runs, so it survives on error responses and on the
// streaming path, where headers are flushed with the first SSE frame.
func StampInstance(instanceID string, h http.Handler) http.Handler {
	if instanceID == "" {
		return h
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set(HeaderGatewayInstance, instanceID)
		h.ServeHTTP(w, r)
	})
}
