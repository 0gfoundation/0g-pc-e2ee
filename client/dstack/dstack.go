// Package dstack reads the CVM's own identity from the dstack guest agent, and
// passes it between containers of one CVM as a small JSON file.
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
// issues quotes — so this package deliberately implements ONLY Info: identity and
// the manifest that Info already carries, nothing else. In the deployed form it is
// kept off the GATEWAY specifically: cmd/cvmid opens the socket once at boot,
// writes the identity file and the app-compose, and exits, so the container that
// handles user prompts reads plain files and never touches the agent
// (WriteIdentityFile / ReadIdentityFile / FetchAppCompose). Other containers of the
// same CVM do hold the socket — dstack-ingress needs it for cert binding — so this
// is a narrowing, not an exclusion. Nothing here runs on the request path.
//
// On what the values are worth: instance_id and app_id are not merely
// self-reported. dstack-util derives instance_id at boot as
// sha256(instance_id_seed ‖ app_id)[:20] and extends BOTH into RTMR3, so a
// verifier replaying the event log against a quote can confirm them. This package
// does no such verification — it takes the agent's word, which is appropriate for
// the operational labels it feeds and is no substitute for the cert-binding quote
// dstack-ingress publishes (docs/design/cloud-gateway.md §6). The attested path
// exists if these ever need to be evidence rather than labels.
package dstack

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/0gfoundation/0g-pc-e2ee/protocol/attest"
)

// DefaultSocket is where the dstack runtime exposes the guest agent inside a
// CVM. It has to be bind-mounted into the container to be reachable (see
// deploy/phala/docker-compose.yml).
const DefaultSocket = "/var/run/dstack.sock"

// DefaultTimeout bounds the startup lookup. The agent is a local unix socket, so
// a healthy call is sub-millisecond; this only caps how long a wedged agent can
// delay the gateway coming up.
const DefaultTimeout = 3 * time.Second

// maxResponseBytes caps the reply we read. The Info reply embeds the whole
// tcb_info blob — which itself embeds the app-compose, which embeds the whole
// docker-compose text — plus the event log and a certificate chain, so it is far
// larger than the identity fields alone. The bound matches client/evidence's cap
// on the same document, and keeps a malfunctioning agent from streaming unbounded
// data into startup.
const maxResponseBytes = 4 << 20

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
	// AppID is the platform's 20-byte (40 hex) name for the app: the address the
	// dstack gateway routes by, and what a blue and a green side of one deployment
	// share.
	//
	// It is NOT a function of the running compose. The id is assigned when the app is
	// created — from the app registry with KMS, or, only when nothing assigned one, by
	// deriving `truncate(compose_hash, 20)` — and is then persisted and kept across
	// compose upgrades, so `compose_hash[:20]` equals it only until the first upgrade
	// (and only for an app that derived its own id at all). This field, read from the
	// guest agent, is the authoritative one; anything that needs to address the app by
	// name should carry it rather than recompute it (see evidence.DiscoverAppID for
	// the same point from outside).
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
	body, err := postInfo(ctx, socket)
	if err != nil {
		return Info{}, err
	}
	var info Info
	if err := json.Unmarshal(body, &info); err != nil {
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

// infoEnvelope is the part of the Info reply that carries the manifest.
//
// tcb_info is taken as raw JSON because the agent has shipped it BOTH ways — as a
// nested object and as a JSON string holding the same document (the platform's
// `/prpc/Info` over HTTP returns the string form; see client/evidence's
// FetchAppCompose). Committing to one shape would make this fail on a deployment
// that serves the other, for no gain: what is read out of it is the same field
// either way. unwrapJSONString normalizes the two.
type infoEnvelope struct {
	TCBInfo json.RawMessage `json:"tcb_info"`
}

// tcbInfoEnvelope is the one field of tcb_info this reads. app_compose is a JSON
// *string* in every form of the reply, which is load-bearing rather than awkward:
// those exact bytes are the preimage of the compose hash, so anything that
// re-marshals them breaks the digest.
type tcbInfoEnvelope struct {
	AppCompose string `json:"app_compose"`
}

// FetchAppCompose returns the raw bytes of this CVM's `app-compose.json`, as the
// guest agent delivers them. An empty socket path uses DefaultSocket.
//
// It is the same Info RPC FetchInfo makes — the manifest rides along in the reply
// — which is why this package still opens exactly one endpoint. cmd/cvmid calls it
// at boot and writes the bytes to the shared volume, so the gateway can describe
// its own container list without ever holding the socket.
//
// **The bytes are NOT trusted here, and must not be used before they are checked.**
// The reply's own compose_hash proves nothing (the agent would be vouching for
// itself); what authenticates them is the compose_hash inside a verified quote's
// mr_config_id, and evidence.VerifyAppCompose is what compares the two. This
// function's contract is only "these are the bytes the agent returned, unaltered"
// — no reformatting, no re-marshalling, no re-indenting, each of which would change
// the digest while leaving the JSON "equal".
func FetchAppCompose(ctx context.Context, socket string) ([]byte, error) {
	body, err := postInfo(ctx, socket)
	if err != nil {
		return nil, err
	}
	var env infoEnvelope
	if err := json.Unmarshal(body, &env); err != nil {
		return nil, fmt.Errorf("dstack guest agent at %s: decode Info: %w", socket, err)
	}
	tcbInfo, err := attest.UnwrapJSONString(env.TCBInfo)
	if err != nil {
		return nil, fmt.Errorf("dstack guest agent at %s: decode tcb_info: %w", socket, err)
	}
	if len(bytes.TrimSpace(tcbInfo)) == 0 || string(bytes.TrimSpace(tcbInfo)) == "null" {
		// dstack returns an empty tcb_info when the app's public_tcbinfo is off. Name
		// the knob rather than reporting this as a parse failure.
		return nil, fmt.Errorf("dstack guest agent at %s: Info carries no tcb_info (the app's public_tcbinfo is off)", socket)
	}
	var tcb tcbInfoEnvelope
	if err := json.Unmarshal(tcbInfo, &tcb); err != nil {
		return nil, fmt.Errorf("dstack guest agent at %s: decode tcb_info: %w", socket, err)
	}
	if tcb.AppCompose == "" {
		return nil, fmt.Errorf("dstack guest agent at %s: tcb_info carries no app_compose", socket)
	}
	return []byte(tcb.AppCompose), nil
}

// postInfo makes the guest agent's Info call and returns the raw reply body.
//
// The guest agent speaks plain HTTP/JSON over the unix socket: POST /<Method> with
// a JSON body (dstack SDK's DstackClient, PATH_PREFIX "/"). The host in the URL is
// ignored — the dialer always lands on the socket — but it must be present and
// syntactically valid for net/http to build the request.
func postInfo(ctx context.Context, socket string) ([]byte, error) {
	if socket == "" {
		socket = DefaultSocket
	}
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
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("dstack guest agent at %s: %w", socket, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("dstack guest agent at %s: Info -> %s", socket, resp.Status)
	}
	// One byte past the cap, so an oversized reply is reported rather than silently
	// truncated into a decode error that names the wrong problem.
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes+1))
	if err != nil {
		return nil, fmt.Errorf("dstack guest agent at %s: read Info: %w", socket, err)
	}
	if len(body) > maxResponseBytes {
		return nil, fmt.Errorf("dstack guest agent at %s: Info reply is larger than %d bytes", socket, maxResponseBytes)
	}
	return body, nil
}

// publishedFileMode is what everything on the identity volume is written with:
// readable by every uid in the CVM, writable only by the (root) writer. The
// consumers run as unprivileged users of their own images — the gateway as
// distroless `nonroot`, the Prometheus agent as `nobody` — so anything narrower
// would be unreadable by exactly the containers these files exist for.
const publishedFileMode = 0o644

// publishedDirMode is the mode for a directory the writer has to create. The file
// mode above is what actually governs access; this just has to be traversable.
const publishedDirMode = 0o755

// PublishFile writes body to path on the shared identity volume, creating the
// parent directory if needed.
//
// Two properties both consumers depend on, which is why this is one helper rather
// than an os.WriteFile at each call site:
//
//   - Atomic (temp file + rename). Readers start concurrently — the gateway reads
//     its identity at boot, and Prometheus watches its file_sd path and reloads on
//     every change — so a half-written file would be read as a corrupt one.
//   - World-readable. os.CreateTemp leaves 0600 behind, and the writer is root
//     while every reader is some other unprivileged user (see publishedFileMode).
func PublishFile(path string, body []byte) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, publishedDirMode); err != nil {
		return fmt.Errorf("publish %s: %w", path, err)
	}
	tmp, err := os.CreateTemp(dir, ".publish-*")
	if err != nil {
		return fmt.Errorf("publish %s: %w", path, err)
	}
	defer os.Remove(tmp.Name()) // no-op once the rename below succeeds
	if _, err := tmp.Write(body); err != nil {
		tmp.Close()
		return fmt.Errorf("publish %s: %w", path, err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("publish %s: %w", path, err)
	}
	if err := os.Chmod(tmp.Name(), publishedFileMode); err != nil {
		return fmt.Errorf("publish %s: %w", path, err)
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		return fmt.Errorf("publish %s: %w", path, err)
	}
	return nil
}

// WriteIdentityFile writes info to path as JSON. It is how cmd/cvmid hands the
// identity to the other containers of the CVM over a shared volume, so that the
// gateway does not need the guest-agent socket to learn who it is.
func WriteIdentityFile(path string, info Info) error {
	body, err := json.MarshalIndent(info, "", "  ")
	if err != nil {
		return fmt.Errorf("identity file %s: %w", path, err)
	}
	return PublishFile(path, append(body, '\n'))
}

// ReadIdentityFile loads an identity previously written by WriteIdentityFile.
//
// It re-validates the identifiers rather than trusting the file. The file is
// produced inside the CVM by a container the compose measures, so this is not a
// trust boundary — but its contents become metric label values, and a bad path
// (a stale volume, a hand-edited file, a future writer with a bug) should fail
// the same way a bad RPC reply does instead of quietly widening the label set.
func ReadIdentityFile(path string) (Info, error) {
	body, err := os.ReadFile(path)
	if err != nil {
		return Info{}, err
	}
	var info Info
	if err := json.Unmarshal(body, &info); err != nil {
		return Info{}, fmt.Errorf("identity file %s: %w", path, err)
	}
	if !validID(info.InstanceID) {
		return Info{}, fmt.Errorf("identity file %s: no usable instance_id", path)
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
