package evidence

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"

	"github.com/0gfoundation/0g-pc-e2ee/protocol/attest"
)

// The labels dstack's gateway prefixes to a served name to find the app behind it.
// `_dstack-app-address.<sni>` is a TXT record holding `<app_id>:<port>`; the gateway
// falls back to `_dstack-app-address-wildcard.<parent>` when the exact name has none
// (dstack gateway proxy/tls_passthough.rs, docs/rc-testing-runbook.md). DiscoverAppID
// tries the same two names in the same order, so a deployment the platform can route
// is a deployment this can name.
const (
	appAddressPrefix         = "_dstack-app-address"
	appAddressWildcardPrefix = "_dstack-app-address-wildcard"
)

// appIDHexLen is the length of a dstack app_id written in hex.
const appIDHexLen = 2 * attest.AppIDLen

// DiscoverAppID finds the dstack `app_id` serving a domain, by reading the
// `_dstack-app-address` TXT record the deployment publishes for the platform
// gateway's own SNI routing (deploy/phala/README.md "Serving domain" creates the
// CNAME that delegates it; dstack-ingress keeps the record itself up to date).
//
// **WHY THIS EXISTS: app_id is not a function of compose_hash.** dstack assigns an
// app its id when the app is created and then persists it — the guest only derives
// one when nothing assigned one (dstack-util system_setup.rs: `if
// instance_info.app_id.is_empty() { app_id = truncate(compose_hash, 20) }`), which
// for a KMS-enabled app on Phala Cloud never happens; there the id is the app's
// registry entry. compose_hash then moves under a fixed app_id on every upgrade, so
// `compose_hash[:20]` (attest.AppIDFromComposeHash) names the app only for a
// deployment that both derived its own id and still runs the compose it derived it
// from. Using it anywhere else asks the platform about an app that does not exist,
// whose symptom is not an error but a hostname nothing routes: the request hangs
// until the client's own timeout. That is what broke verification of a gateway moved
// to a new cluster, where the app was created once and upgraded since.
//
// **DNS is not authenticated, and this does not pretend otherwise** — the same
// stance, for the same reason, as DeriveBaseDomain. The answer is used only to
// LOCATE app-compose bytes, and those bytes are then checked against the
// compose_hash from the verified quote (VerifyAppCompose). A hijacked or merely
// stale record can cost a failed lookup; it cannot buy a false pass. In particular
// it cannot point a verification at a *different* app's manifest and have it
// accepted, because that app's manifest does not hash to this quote's commitment.
func DiscoverAppID(ctx context.Context, domain string) (string, error) {
	return discoverAppID(ctx, domain, net.DefaultResolver.LookupTXT)
}

// discoverAppID is DiscoverAppID over an injectable resolver, so the two-name walk
// and the record parsing are testable without DNS.
func discoverAppID(ctx context.Context, domain string, lookupTXT func(context.Context, string) ([]string, error)) (string, error) {
	name := bareHost(domain)
	if name == "" {
		return "", errors.New("no domain to discover an app_id for")
	}
	queries := []string{appAddressPrefix + "." + name}
	if parent := parentDomain(name); parent != "" {
		queries = append(queries, appAddressWildcardPrefix+"."+parent)
	}

	var errs []error
	for _, q := range queries {
		records, err := lookupTXT(ctx, q)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", q, err))
			continue
		}
		if len(records) == 0 {
			errs = append(errs, fmt.Errorf("%s: no TXT record", q))
			continue
		}
		for _, rec := range records {
			id, err := parseAppAddress(rec)
			if err != nil {
				errs = append(errs, fmt.Errorf("%s: %w", q, err))
				continue
			}
			return id, nil
		}
	}
	return "", fmt.Errorf("no usable %s record for %s: %w", appAddressPrefix, name, errors.Join(errs...))
}

// parseAppAddress reads the app_id out of a dstack app-address record, whose format
// is `<app_id>:<port>` (dstack gateway's AppAddress::parse). The port is the one the
// gateway forwards SNI-routed traffic to and has nothing to do with the guest agent,
// so it is deliberately dropped here rather than returned for someone to reuse.
func parseAppAddress(record string) (string, error) {
	s := strings.TrimSpace(record)
	id, _, ok := strings.Cut(s, ":")
	if !ok {
		return "", fmt.Errorf("app address %q is not <app_id>:<port>", s)
	}
	id = strings.ToLower(strings.TrimSpace(id))
	if !validAppID(id) {
		return "", fmt.Errorf("app address %q does not begin with a %d-hex app_id", s, appIDHexLen)
	}
	return id, nil
}

// normalizeAppID cleans up an app_id a CALLER supplied: whitespace, case, and a
// leading "0x".
//
// The 0x is not a courtesy. Phala Cloud reports the same 20 bytes as the app's
// `contract_address` in that form, and it is the field an operator is most likely to
// copy from when pinning `-app-id` by hand — rejecting it would be rejecting the
// right value for looking like the neighbouring one. DNS records are held to the
// strict form instead (see parseAppAddress): there a stray prefix is a malformed
// record, not a paste.
func normalizeAppID(s string) string {
	id := strings.ToLower(strings.TrimSpace(s))
	return strings.TrimPrefix(id, "0x")
}

// validAppID reports whether s is the shape dstack writes an app_id in: exactly
// appIDHexLen lowercase hex digits. The check is here so a garbled or truncated DNS
// record fails at the point it is read, rather than becoming a hostname or a URL
// path that fails somewhere less obvious.
func validAppID(s string) bool {
	if len(s) != appIDHexLen {
		return false
	}
	for _, r := range s {
		if (r < '0' || r > '9') && (r < 'a' || r > 'f') {
			return false
		}
	}
	return true
}

// bareHost reduces a served name to the form used to build DNS queries:
// lowercase, no trailing dot, no port.
func bareHost(domain string) string {
	name := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(domain)), ".")
	if h, _, err := net.SplitHostPort(name); err == nil {
		name = h
	}
	return name
}

// parentDomain drops the leftmost label, for the wildcard app-address name. It
// returns "" when the parent would be a single label: `example.com` is a zone whose
// owner might plausibly hold a wildcard record, `com` is a public suffix and
// querying under it is pointless.
func parentDomain(name string) string {
	_, rest, ok := strings.Cut(name, ".")
	if !ok || !strings.Contains(rest, ".") {
		return ""
	}
	return rest
}
