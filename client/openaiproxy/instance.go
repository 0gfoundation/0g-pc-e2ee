package openaiproxy

import "net/http"

// HeaderGatewayInstance carries the id of the gateway CVM that served a
// response. It answers the one question a caller cannot otherwise ask: an app_id
// can be backed by several replicas, and the dstack platform chooses which one a
// connection reaches (it races a TCP connect against the few instances with the
// freshest WireGuard handshake and keeps the first to answer, re-picking that
// candidate set every ~30s — so it is neither round-robin nor sticky by
// contract). Without this header, "this request was slow / failed and the next
// one was fine" is indistinguishable from "one replica is unhealthy", for anyone
// who cannot read our logs.
//
// It is the same convention a CDN ships as X-Served-By or CF-Ray, and it is sent
// unconditionally rather than behind a toggle. The value is the dstack
// instance_id, which is already public — the platform routes to it by name in the
// <instance_id>-443s.<base_domain> hostname form — so what a caller learns from
// collecting these is the fleet SHAPE (how many replicas, how traffic spreads).
// That is real but slight, and a toggle would not have protected it: the setting
// lives in the CVM's encrypted environment, so flipping it means restarting the
// deployment, which is exactly what nobody does mid-incident. A knob that is off
// when you need it is worse than a decision.
const HeaderGatewayInstance = "X-0G-Gateway-Instance"

// StampInstance returns h with HeaderGatewayInstance set to instanceID on every
// response. An empty instanceID returns h unchanged, so a caller can wire it
// unconditionally — which is what the gateway does; the id is empty only when the
// process could not learn its own identity (a local run, or a deployment that
// wired neither source).
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
