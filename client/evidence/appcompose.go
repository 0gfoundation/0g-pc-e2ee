package evidence

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"

	"github.com/0gfoundation/0g-pc-e2ee/protocol/attest"
)

// guestAgentPort is the dstack guest-agent's external listener. The platform's
// dstack gateway routes `<app_id>-<port>.<base_domain>` to that port on the CVM,
// so this is where app-compose.json can be read from outside (see
// FetchAppCompose).
const guestAgentPort = 8090

// maxAppComposeBytes bounds the guest-agent Info read. The reply embeds the whole
// app-compose (which embeds the whole docker-compose text) plus the event log and
// a certificate chain, so it is far larger than an evidence file — but still a
// small document.
const maxAppComposeBytes = 4 << 20

// AppCompose is the part of `app-compose.json` this package reads. The file has
// many more fields (see dstack's AppCompose type); they are deliberately not
// decoded, because the *authenticated artifact is the raw bytes* — every field
// that matters is already covered by the compose-hash commitment, and decoding
// more would invite trusting a parsed value where the raw text is the contract.
type AppCompose struct {
	// Name is the app's label on the platform, for the human reading a report.
	Name string `json:"name"`
	// DockerComposeFile is the docker-compose text, embedded verbatim. This is the
	// field that names the container images, so it is what a verifier compares
	// against the compose file it published.
	DockerComposeFile string `json:"docker_compose_file"`
	// AllowedEnvs is the set of environment-variable NAMES the platform will inject
	// (never their values). It is part of the measured manifest, so it is surfaced:
	// widening it is a real change to what the deployment can be handed at boot.
	AllowedEnvs []string `json:"allowed_envs"`
}

// VerifyAppCompose checks that raw really is the app-compose the quote committed
// to — sha256(raw) == composeHash — and only then decodes it.
//
// This is the hinge of code-identity verification, and the reason raw can come
// from anywhere: the platform API, the CVM's own guest agent, an operator's
// deploy record, or an attacker. composeHash comes from the verified quote's
// mr_config_id, which no one but the platform can choose, so a substituted
// app-compose cannot survive this check. Nothing about raw is trusted before it
// passes; nothing about it needs to be trusted after.
//
// The digest is over the exact bytes given. dstack computes it as
// `sha256_file(app-compose.json)`, and the guest agent returns those same bytes
// verbatim, so callers must not reformat, re-indent, or re-marshal raw — that
// would change the digest while leaving the JSON "equal".
func VerifyAppCompose(raw []byte, composeHash [attest.ComposeHashLen]byte) (AppCompose, error) {
	got := sha256.Sum256(raw)
	if got != composeHash {
		return AppCompose{}, fmt.Errorf(
			"app-compose digest %x does not match the compose_hash %x the quote binds "+
				"(wrong app/instance, stale record, or reformatted bytes)", got, composeHash)
	}
	var ac AppCompose
	if err := json.Unmarshal(raw, &ac); err != nil {
		return AppCompose{}, fmt.Errorf("app-compose is not valid JSON: %w", err)
	}
	if strings.TrimSpace(ac.DockerComposeFile) == "" {
		// Authenticated, but with nothing to compare: an app-compose that runs no
		// docker-compose cannot support the compose-file check, so say so here rather
		// than reporting an empty diff as a match.
		return ac, errors.New("app-compose has no docker_compose_file")
	}
	return ac, nil
}

// infoResponse is the dstack guest-agent `Info` reply. Both nested documents
// arrive as JSON *strings*, which is load-bearing rather than awkward: it is what
// preserves app_compose byte-for-byte, and its bytes are what the compose hash is
// over. Re-marshalling anywhere in this path would break the digest.
type infoResponse struct {
	AppID   string `json:"app_id"`
	TCBInfo string `json:"tcb_info"`
}

type tcbInfo struct {
	ComposeHash string `json:"compose_hash"`
	AppCompose  string `json:"app_compose"`
}

// FetchAppCompose reads the raw app-compose bytes from the dstack guest agent of
// the app identified by appID, via the platform's per-app hostname
// `https://<appID>-8090.<baseDomain>/prpc/Info`.
//
// Two things about this endpoint are worth being explicit about:
//
// It is on the PLATFORM's domain, so its TLS terminates in the platform's
// gateway, not in the CVM. That is acceptable here and only here: the bytes are
// checked against the quote's compose_hash by VerifyAppCompose, so neither the
// platform nor a network attacker can substitute them. Do not extend this
// reasoning to anything that is not hash-anchored.
//
// The reply's own `compose_hash` field is deliberately IGNORED. A self-reported
// hash proves nothing — the value must come from the quote — and reading it here
// would create a path where the endpoint vouches for itself.
//
// It requires the app's `public_tcbinfo` to be true (dstack's default); when it
// is false the guest agent returns an empty tcb_info and this reports that
// clearly rather than as a parse failure.
func FetchAppCompose(ctx context.Context, hc *http.Client, appID, baseDomain string) ([]byte, error) {
	if strings.TrimSpace(appID) == "" {
		return nil, errors.New("no app_id to fetch app-compose for")
	}
	host := appIDHost(appID, baseDomain)
	if host == "" {
		return nil, fmt.Errorf("cannot build a guest-agent host from base domain %q", baseDomain)
	}
	u := "https://" + host + "/prpc/Info"

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	resp, err := hc.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch app-compose from %s: %w", host, err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxAppComposeBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read app-compose from %s: %w", host, err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GET %s -> %s", u, resp.Status)
	}
	if len(body) > maxAppComposeBytes {
		return nil, fmt.Errorf("guest-agent Info from %s is larger than %d bytes", host, maxAppComposeBytes)
	}

	var info infoResponse
	if err := json.Unmarshal(body, &info); err != nil {
		return nil, fmt.Errorf("decode guest-agent Info: %w", err)
	}
	if strings.TrimSpace(info.TCBInfo) == "" {
		return nil, fmt.Errorf("guest-agent Info from %s carries no tcb_info; the app's public_tcbinfo is off, so app-compose must be supplied out of band", host)
	}
	var tcb tcbInfo
	if err := json.Unmarshal([]byte(info.TCBInfo), &tcb); err != nil {
		return nil, fmt.Errorf("decode tcb_info: %w", err)
	}
	if tcb.AppCompose == "" {
		return nil, fmt.Errorf("tcb_info from %s carries no app_compose", host)
	}
	// The string's bytes, as delivered. This is the digest preimage.
	return []byte(tcb.AppCompose), nil
}

// maxCNAMEHops bounds the DNS walk in DeriveBaseDomain. The real chain is two hops
// (served name → delegation zone → gateway domain); the cap is only a loop guard.
const maxCNAMEHops = 8

// DeriveBaseDomain works out the platform base domain for a served gateway domain
// by following its CNAME chain to the end.
//
// A dstack deployment points its served name, via its delegation zone, at the
// cluster's GATEWAY_DOMAIN, which by convention is `_.<base_domain>` (see the
// DELEGATION_ZONE / GATEWAY_DOMAIN contract in deploy/phala/). So the last hop of
// the chain names the base domain, and an operator does not have to know — or
// correctly retype — their cluster's topology to run a verification.
//
// **DNS is not authenticated, and this does not pretend otherwise.** The result is
// used only to LOCATE the app-compose bytes; those bytes are then checked against
// the compose_hash from the verified quote (VerifyAppCompose), so a hijacked or
// merely wrong answer here can cause a failed lookup or a failed binding — never a
// false pass. Nothing else in this package takes input from DNS.
func DeriveBaseDomain(ctx context.Context, domain string) (string, error) {
	return deriveBaseDomain(ctx, domain, net.DefaultResolver.LookupCNAME)
}

// deriveBaseDomain is DeriveBaseDomain over an injectable resolver, so the chain
// walk and the gateway-domain shape check are testable without DNS.
func deriveBaseDomain(ctx context.Context, domain string, lookupCNAME func(context.Context, string) (string, error)) (string, error) {
	name := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(domain)), ".")
	if h, _, err := net.SplitHostPort(name); err == nil {
		name = h
	}
	if name == "" {
		return "", errors.New("no domain to derive a base domain from")
	}

	last := name
	for i := 0; i < maxCNAMEHops; i++ {
		cname, err := lookupCNAME(ctx, last)
		if err != nil {
			return "", fmt.Errorf("resolve CNAME for %s: %w", last, err)
		}
		cname = strings.TrimSuffix(strings.ToLower(cname), ".")
		if cname == "" || cname == last {
			break // end of the chain
		}
		last = cname
	}
	// The gateway domain is the `_.<base>` form; anything else means this name is not
	// fronted by a dstack gateway the way the deployment docs describe.
	base, ok := strings.CutPrefix(last, "_.")
	if !ok || base == "" {
		return "", fmt.Errorf("CNAME chain for %s ends at %q, which is not a dstack gateway domain (_.<base>); pass the base domain explicitly", name, last)
	}
	return base, nil
}

// appIDHost builds the platform's per-app hostname for the guest agent. baseDomain
// may be given bare ("in1.phala.network") or as a URL; a leading "_." — the form
// that appears in a dstack GATEWAY_DOMAIN — is stripped, since operators tend to
// copy it from there.
func appIDHost(appID, baseDomain string) string {
	d := strings.TrimSpace(baseDomain)
	if d == "" {
		return ""
	}
	if strings.Contains(d, "://") {
		if u, err := url.Parse(d); err == nil && u.Host != "" {
			d = u.Host
		}
	}
	d = strings.Trim(d, "/")
	d = strings.TrimPrefix(d, "_.")
	if d == "" {
		return ""
	}
	return fmt.Sprintf("%s-%d.%s", strings.ToLower(strings.TrimSpace(appID)), guestAgentPort, strings.ToLower(d))
}

// MatchCompose finds the candidate whose compose text equals got, returning its
// label. When none matches it reports how many were tried plus the diff against the
// FIRST candidate — callers pass them newest-first, and the newest release is the
// one an operator most likely meant to be running.
//
// Exported for the same reason as CheckOSImage: the gateway reports which release
// it corresponds to and pcverify verifies the same thing, and the two must not be
// able to disagree about what "matches" means. The comparison is byte-exact modulo
// line endings (diffComposeFile) — a field-by-field comparison would accept texts
// the hash-anchored check rejects.
func MatchCompose(got []byte, candidates []ExpectedCompose) (string, error) {
	for _, c := range candidates {
		if diffComposeFile(got, c.Content) == nil {
			return c.Label, nil
		}
	}
	switch len(candidates) {
	case 0:
		return "", errors.New("no candidate compose files supplied")
	case 1:
		return "", fmt.Errorf("does not match %s: %w", candidates[0].Label, diffComposeFile(got, candidates[0].Content))
	default:
		labels := make([]string, 0, len(candidates))
		for _, c := range candidates {
			labels = append(labels, c.Label)
		}
		return "", fmt.Errorf("matches none of %d candidates (%s); versus %s: %w",
			len(candidates), strings.Join(labels, ", "), candidates[0].Label,
			diffComposeFile(got, candidates[0].Content))
	}
}

// diffComposeFile compares the authenticated docker-compose text against the one
// the verifier expected, and on a mismatch reports the first line that differs
// plus the line counts.
//
// The comparison is byte-exact on content but tolerant of the line ending and a
// trailing newline: the compose text makes a round trip through JSON and a file on
// disk, and CRLF or a missing final newline is a transport artifact, not a change
// to what runs. Anything else — including whitespace inside a line — is a real
// difference and is reported.
func diffComposeFile(got, want []byte) error {
	g, w := splitLines(got), splitLines(want)
	if len(g) == len(w) {
		same := true
		for i := range g {
			if g[i] != w[i] {
				same = false
				break
			}
		}
		if same {
			return nil
		}
	}
	for i := 0; i < len(g) && i < len(w); i++ {
		if g[i] != w[i] {
			return fmt.Errorf("differs at line %d:\n    deployed: %s\n    expected: %s",
				i+1, truncate(g[i]), truncate(w[i]))
		}
	}
	// One is a prefix of the other.
	switch {
	case len(g) > len(w):
		return fmt.Errorf("deployed has %d extra line(s) after line %d, first: %s",
			len(g)-len(w), len(w), truncate(g[len(w)]))
	default:
		return fmt.Errorf("deployed is missing %d line(s) after line %d, first expected: %s",
			len(w)-len(g), len(g), truncate(w[len(g)]))
	}
}

// splitLines normalizes line endings and drops a single trailing empty line, so a
// CRLF checkout or a missing final newline is not reported as a difference.
func splitLines(b []byte) []string {
	s := strings.ReplaceAll(string(b), "\r\n", "\n")
	lines := strings.Split(s, "\n")
	if n := len(lines); n > 0 && lines[n-1] == "" {
		lines = lines[:n-1]
	}
	return lines
}

func truncate(s string) string {
	const max = 100
	if len(s) <= max {
		return s
	}
	return s[:max] + "…"
}
