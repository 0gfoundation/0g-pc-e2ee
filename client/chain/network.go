package chain

// network.go names the 0G networks a deployment may ground providers against, each
// as a FIXED pair of JSON-RPC endpoint and InferenceServing contract.
//
// WHY A NAME AND NOT TWO VALUES. The RPC endpoint and the contract are the on-chain
// root of trust (hop 5): whoever chooses them chooses which teeSignerAddress a
// provider is held to. In a dstack CVM, the measured compose decides what is fixed
// and the encrypted environment decides the rest — and that environment is
// confidential, not authenticated: anyone with VMM access can encrypt a replacement
// to the app's public key (dstack docs/encrypted-env-spec.md, "Encryption provides
// confidentiality, not origin authentication"). An RPC URL taken from it would let
// the host answer every getService itself, with nothing in compose_hash or app_id to
// show it. A network name taken from it lets the host choose only between the real
// chains named here, and the process reports which one it is on.

import (
	"fmt"
	"sort"
	"strings"
)

// Network is one 0G network's on-chain root: the JSON-RPC endpoint the registry is
// read from and the InferenceServing contract it is read at.
type Network struct {
	Name            string
	RPCURL          string
	ServingContract string
}

// The networks a deployment can name.
const (
	NetworkMainnet = "mainnet"
	NetworkTestnet = "testnet"
)

// networks is every named network. Testnet is testnet-V4 (see
// DefaultInferenceServingAddress): the contract the testnet deployment in
// client/evidence/compose/brokercompose.json is registered in.
var networks = map[string]Network{
	NetworkMainnet: {Name: NetworkMainnet, RPCURL: DefaultChainRPCURL, ServingContract: DefaultInferenceServingAddress},
	NetworkTestnet: {Name: NetworkTestnet, RPCURL: "https://evmrpc-testnet.0g.ai", ServingContract: "0xa79F4c8311FF93C06b8CfB403690cc987c93F91E"},
}

// LookupNetwork returns the named network. The name is matched case-insensitively
// and without surrounding space; anything else is an error naming the choices.
func LookupNetwork(name string) (Network, error) {
	if n, ok := networks[strings.ToLower(strings.TrimSpace(name))]; ok {
		return n, nil
	}
	return Network{}, fmt.Errorf("unknown network %q (want one of %s)", name, strings.Join(NetworkNames(), ", "))
}

// NetworkNames lists the named networks, sorted.
func NetworkNames() []string {
	names := make([]string, 0, len(networks))
	for name := range networks {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}
