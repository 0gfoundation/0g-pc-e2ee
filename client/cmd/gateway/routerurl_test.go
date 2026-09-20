package main

import (
	"net/url"
	"testing"

	"github.com/0gfoundation/0g-pc-e2ee/client/route"
)

// The gateway's upstream default and the public entry must not be the same
// name. After the global-entry cutover `router-api.0g.ai` resolves to THIS
// process, so a gateway defaulting there proxies to itself: every passthrough
// and every route-preview re-enters the front door and recurses until sockets
// or the in-flight limiter run out, all inside the deployment's own TLS where
// nothing in between can see a loop.
//
// The split is two constants in one const block, which is exactly the shape
// somebody tidies up — "these are both the router, why two?" — so this pins it.
// If the collapse ever is correct (the topology changes back, the gateway stops
// being the entry), delete this test deliberately rather than adjusting it.
func TestGatewayDefaultsToTheRouterOriginNotThePublicEntry(t *testing.T) {
	if defaultRouterURL != route.DefaultRouterOriginURL {
		t.Errorf("gateway default is %q, want the router's origin name %q: the gateway serves "+
			"the public entry and must reach the router directly",
			defaultRouterURL, route.DefaultRouterOriginURL)
	}
	if defaultRouterURL == route.DefaultRouterURL {
		t.Fatalf("the gateway's -router-url default (%q) is the PUBLIC ENTRY, which is this "+
			"gateway itself — it would proxy to its own front door and recurse. The two "+
			"constants have been collapsed back into one name; re-split them.",
			defaultRouterURL)
	}

	entry, err := url.Parse(route.DefaultRouterURL)
	if err != nil {
		t.Fatalf("parse entry %q: %v", route.DefaultRouterURL, err)
	}
	origin, err := url.Parse(defaultRouterURL)
	if err != nil {
		t.Fatalf("parse origin %q: %v", defaultRouterURL, err)
	}
	// Compare hosts, not whole URLs: two spellings of the same host (a trailing
	// slash, a base path) would pass the string check above and still loop.
	if origin.Host == entry.Host {
		t.Errorf("origin host %q == entry host %q; the URLs differ only in path/scheme, "+
			"so the gateway still resolves to itself", origin.Host, entry.Host)
	}
	if origin.Scheme != "https" || origin.Host == "" {
		t.Errorf("origin %q must be an absolute https URL with a host", defaultRouterURL)
	}
}
