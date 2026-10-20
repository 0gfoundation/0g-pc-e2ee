package main

import (
	"bufio"
	"bytes"
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/0gfoundation/0g-pc-e2ee/client/chain"
)

// composeNetwork matches the compose's ZG_GATEWAY_NETWORK entry and its fallback.
var composeNetwork = regexp.MustCompile(`"ZG_GATEWAY_NETWORK=\$\{ZG_GATEWAY_NETWORK:-([^}]*)\}"`)

// TestComposeNamesTheChainByNetworkOnly keeps hop 5's root out of the encrypted
// environment's reach. That environment is confidential, not authenticated, so
// whatever the measured compose lets it set, the host can set: a network NAME limits
// that to the networks compiled into the gateway, an RPC URL or contract would hand
// over the registry itself. Re-adding either variable to the compose is the change
// this test exists to stop — the sidecar and local runs still have them as flags.
func TestComposeNamesTheChainByNetworkOnly(t *testing.T) {
	compose, err := os.ReadFile(composePath)
	if err != nil {
		t.Fatalf("read %s: %v", composePath, err)
	}
	m := composeNetwork.FindSubmatch(compose)
	if m == nil {
		t.Fatalf("no ZG_GATEWAY_NETWORK=${...:-<default>} entry in %s", composePath)
	}
	if string(m[1]) != chain.NetworkMainnet {
		t.Errorf("the compose defaults to network %q; a deployment that sets nothing must be on mainnet", m[1])
	}
	sc := bufio.NewScanner(bytes.NewReader(compose))
	for line := 1; sc.Scan(); line++ {
		text := strings.TrimSpace(sc.Text())
		if strings.HasPrefix(text, "#") {
			continue
		}
		for _, v := range []string{"ZG_GATEWAY_CHAIN_RPC_URL", "ZG_GATEWAY_SERVING_CONTRACT"} {
			if strings.Contains(text, v) {
				t.Errorf("%s:%d sets %s: the chain is chosen by ZG_GATEWAY_NETWORK alone", composePath, line, v)
			}
		}
	}
}
