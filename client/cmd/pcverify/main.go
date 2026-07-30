// Command pcverify is a read-only diagnostic that checks a provider against the
// 0G trust chain (docs/design/trust-chain.md), one hop at a time. This first cut
// covers the on-chain hop — SPEC §4.4 step 3 / trust-chain hop 5: it reads the
// provider's acknowledged teeSignerAddress from the on-chain InferenceServing
// registry and, when given a signer to expect (e.g. a provider's self-reported
// signer, or a quote's signer once TDX verification lands here), asserts they
// match. TDX quote verification is a planned follow-up that wires client/dcap +
// protocol/attest into this same tool.
//
// It is a pre-enable gate: run it against the chain you will point -onchain at
// before flipping the sidecar/gateway into enforce, to confirm the on-chain read
// and decode line up with reality. It makes NO changes and sends NOTHING to any
// provider — it only reads the chain over the RPC you give it. Exit code is
// non-zero on any failed check, so it drops into CI or a deploy gate.
//
//	pcverify -provider 0x... -chain-rpc-url https://... [-serving-contract 0x...] [-expect-signer 0x...]
//
// The provider's serving endpoint is itself on chain (Service.url), so a future
// quote check can default its endpoint from the same getService read rather than
// taking it as a flag.
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/0gfoundation/0g-pc-e2ee/client/chain"
)

func main() {
	os.Exit(run(context.Background(), os.Stdout, os.Args[1:]))
}

func run(ctx context.Context, out io.Writer, args []string) int {
	fs := flag.NewFlagSet("pcverify", flag.ContinueOnError)
	fs.SetOutput(out)
	provider := fs.String("provider", "", "provider on-chain account address (0x + 40 hex, required)")
	chainRPCURL := fs.String("chain-rpc-url", "", "0G chain JSON-RPC endpoint; a source trusted independently of the router (required)")
	servingContract := fs.String("serving-contract", chain.DefaultInferenceServingAddress, "InferenceServing contract address")
	expectSigner := fs.String("expect-signer", "", "if set, require the on-chain teeSignerAddress to equal this (e.g. a quote's signer)")
	timeout := fs.Duration("timeout", 15*time.Second, "overall timeout for the chain read")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if strings.TrimSpace(*provider) == "" || strings.TrimSpace(*chainRPCURL) == "" {
		fmt.Fprintln(out, "pcverify: -provider and -chain-rpc-url are required")
		fs.Usage()
		return 2
	}

	reg, err := chain.NewOnChainRegistry(chain.Config{RPCURL: *chainRPCURL, ContractAddress: *servingContract})
	if err != nil {
		fmt.Fprintf(out, "pcverify: %v\n", err)
		return 2
	}

	ctx, cancel := context.WithTimeout(ctx, *timeout)
	defer cancel()
	return report(ctx, out, reg, *provider, *servingContract, *expectSigner)
}

// report runs the on-chain hop and prints a per-check result, returning the
// process exit code (0 pass, 1 failed check). It takes the SignerRegistry
// interface so tests can drive it without a live chain.
func report(ctx context.Context, out io.Writer, reg chain.SignerRegistry, provider, contract, expectSigner string) int {
	fmt.Fprintf(out, "provider           %s\n", provider)
	fmt.Fprintf(out, "contract           %s\n", contract)

	signer, acknowledged, err := reg.AcknowledgedSigner(ctx, provider)
	if err != nil {
		fmt.Fprintf(out, "%s on-chain lookup    %v\n", mark(false), err)
		fmt.Fprintln(out, "\nFAIL")
		return 1
	}
	fmt.Fprintf(out, "  teeSignerAddress %s\n", signer)
	fmt.Fprintf(out, "%s acknowledged     %v\n", mark(acknowledged), acknowledged)

	ok := acknowledged
	if strings.TrimSpace(expectSigner) != "" {
		match := strings.EqualFold(strings.TrimSpace(signer), strings.TrimSpace(expectSigner))
		fmt.Fprintf(out, "%s matches expected %s\n", mark(match), expectSigner)
		ok = ok && match
	}

	if ok {
		fmt.Fprintln(out, "\nPASS")
		return 0
	}
	fmt.Fprintln(out, "\nFAIL")
	return 1
}

func mark(ok bool) string {
	if ok {
		return "✓" // ✓
	}
	return "✗" // ✗
}
