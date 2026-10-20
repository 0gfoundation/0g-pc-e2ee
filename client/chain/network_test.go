package chain

import (
	"strings"
	"testing"
)

func TestLookupNetwork(t *testing.T) {
	for _, tc := range []struct {
		in       string
		rpc      string
		contract string
	}{
		{"mainnet", DefaultChainRPCURL, DefaultInferenceServingAddress},
		{" Mainnet ", DefaultChainRPCURL, DefaultInferenceServingAddress},
		{"testnet", "https://evmrpc-testnet.0g.ai", "0xa79F4c8311FF93C06b8CfB403690cc987c93F91E"},
	} {
		n, err := LookupNetwork(tc.in)
		if err != nil {
			t.Fatalf("LookupNetwork(%q): %v", tc.in, err)
		}
		if n.RPCURL != tc.rpc || n.ServingContract != tc.contract {
			t.Errorf("LookupNetwork(%q) = %+v, want rpc %s contract %s", tc.in, n, tc.rpc, tc.contract)
		}
		if !isHexAddress(n.ServingContract) {
			t.Errorf("%s: contract %q is not an address", n.Name, n.ServingContract)
		}
	}
}

// An unknown name is refused rather than falling back to mainnet: a deployment that
// asked for a network it did not get would be grounded against the wrong registry.
func TestLookupNetworkRefusesUnknown(t *testing.T) {
	for _, in := range []string{"", "galileo", "https://evmrpc.0g.ai"} {
		_, err := LookupNetwork(in)
		if err == nil {
			t.Fatalf("LookupNetwork(%q) accepted", in)
		}
		if !strings.Contains(err.Error(), "mainnet, testnet") {
			t.Errorf("LookupNetwork(%q) error %q does not name the choices", in, err)
		}
	}
}
