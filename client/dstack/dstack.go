// Package dstack reads the CVM's own identity from the dstack guest agent.
//
// A gateway replica has no way to name itself: it is one of N CVMs that share an
// app_id (deploy/phala/blue-green.md "Scaling one side"), it sits behind an L4
// passthrough that adds no headers, and the dstack platform picks which replica a
// connection lands on. So a merged log stream, a shared Prometheus remote-write
// store, and a client debugging a slow request all see two indistinguishable
// sources. The guest agent's Info RPC is what breaks the tie: it returns this
// CVM's instance_id (and the app_id / compose_hash the platform measured it
// under), read over the unix socket the runtime mounts into the container.
//
// The socket is a privileged surface — the same endpoint also derives keys and
// issues quotes — so this package deliberately implements ONLY Info: identity in,
// nothing else. It is read at startup, once; nothing here runs on the request
// path.
//
// Attestation-wise the values are self-reported, not proven: they come from the
// runtime the container already trusts for everything else, and nothing here is
// a substitute for the cert-binding quote dstack-ingress publishes
// (docs/design/cloud-gateway.md §6). Treat them as operational labels, not as
// evidence.
package dstack

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

// DefaultSocket is where the dstack runtime exposes the guest agent inside a
// CVM. It has to be bind-mounted into the container to be reachable (see
// deploy/phala/docker-compose.yml).
const DefaultSocket = "/var/run/dstack.sock"

// DefaultTimeout bounds the startup lookup. The agent is a local unix socket, so
// a healthy call is sub-millisecond; this only caps how long a wedged agent can
// delay the gateway coming up.
const DefaultTimeout = 3 * time.Second

// maxResponseBytes caps the reply we read. The real Info response is a few
// hundred bytes (it does embed a TCB-info blob); the bound is generous but keeps
// a malfunctioning agent from streaming unbounded data into startup.
const maxResponseBytes = 1 << 20

// maxIDLen bounds an identifier before it can become a metric label or a log
// field. The real ids are 40-hex app/instance digests; see validID.
const maxIDLen = 128

// Info is the subset of the guest agent's Info reply this gateway uses. The RPC
// returns more (TCB info, key-provider details, the app cert); those belong to
// the attestation path, which the gateway does not run — it publishes no quote of
// its own — so they are deliberately not decoded here.
type Info struct {
	// InstanceID identifies THIS CVM among the replicas sharing AppID. It is the
	// value the dstack gateway routes by in the per-instance hostname form
	// (<instance_id>-443s.<base_domain>), so it is already public.
	InstanceID string `json:"instance_id"`
	// AppID is SHA-256(app-compose) — the same value the cert-binding quote commits
	// to, and the one that distinguishes a blue side from a green one.
	AppID string `json:"app_id"`
	// AppName and ComposeHash are logged at startup for operator orientation only;
	// they are not exported as metric labels.
	AppName     string `json:"app_name"`
	ComposeHash string `json:"compose_hash"`
}

// FetchInfo asks the guest agent at socket for this CVM's identity. An empty
// socket path uses DefaultSocket.
//
// It fails when the socket is absent (the ordinary case outside a CVM: a local
// run, a test, the sidecar) — callers treat that as "no instance identity" and
// carry on rather than refusing to serve, because this is telemetry, not a
// security control.
func FetchInfo(ctx context.Context, socket string) (Info, error) {
	if socket == "" {
		socket = DefaultSocket
	}
	// The guest agent speaks plain HTTP/JSON over the unix socket: POST /<Method>
	// with a JSON body (dstack SDK's DstackClient, PATH_PREFIX "/"). The host in the
	// URL is ignored — the dialer below always lands on the socket — but it must be
	// present and syntactically valid for net/http to build the request.
	client := &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				var d net.Dialer
				return d.DialContext(ctx, "unix", socket)
			},
		},
	}
	defer client.CloseIdleConnections()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://dstack-guest-agent/Info", strings.NewReader("{}"))
	if err != nil {
		return Info{}, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return Info{}, fmt.Errorf("dstack guest agent at %s: %w", socket, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return Info{}, fmt.Errorf("dstack guest agent at %s: Info -> %s", socket, resp.Status)
	}

	var info Info
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxResponseBytes)).Decode(&info); err != nil {
		return Info{}, fmt.Errorf("dstack guest agent at %s: decode Info: %w", socket, err)
	}
	// The agent is trusted, but its output crosses into metric label values and log
	// fields, so hold it to the shape those can safely carry rather than assuming
	// it. A malformed id is dropped, not truncated — a truncated id is not an id.
	if !validID(info.InstanceID) {
		return Info{}, fmt.Errorf("dstack guest agent at %s: Info returned no usable instance_id", socket)
	}
	if !validID(info.AppID) {
		info.AppID = ""
	}
	return info, nil
}

// validID reports whether s is a plausible dstack identifier: non-empty, bounded,
// and lowercase hex. Both app_id and instance_id are hex digests, so this is not a
// narrowing — it is the guard that keeps an unexpected value out of the metric
// label set (where an unbounded or high-cardinality value would be a real problem;
// see client/metrics' redaction discipline).
func validID(s string) bool {
	if s == "" || len(s) > maxIDLen {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}
