package main

// chainroot.go checks which 0G network the gateway grounds providers against — the
// one setting that decides hop 5 and that the evidence bundle cannot show.
//
// The gateway picks its network from ZG_GATEWAY_NETWORK, in the encrypted
// environment, and that environment is confidential but not authenticated: anyone
// with VMM access can replace it (dstack docs/encrypted-env-spec.md). The measured
// compose limits the choice to the networks built into the gateway, and the gateway
// reports the one it got at /v1/gateway/identity. So the report is read here, over a
// connection pinned to the certificate step 4 bound to the quote: what answers is the
// attested code, and it is believed exactly as far as code identity (step 6) says
// which code that is.

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"

	"github.com/0gfoundation/0g-pc-e2ee/client/chain"
)

// gatewayIdentityPath is the gateway's identity route (cmd/gateway identityPath).
const gatewayIdentityPath = "/v1/gateway/identity"

// chainReport is the part of the gateway's identity document this reads.
type chainReport struct {
	// Network is the named network, or nil when the gateway's root was set by endpoint
	// and contract instead.
	Network         *string `json:"network"`
	RPCURL          string  `json:"rpc_url"`
	ServingContract string  `json:"serving_contract"`
}

// errNoChainReport is a gateway that predates the chain field.
var errNoChainReport = errors.New("the gateway's identity carries no chain root (a build older than the one that reports it)")

// chainReader reads the gateway's chain root over a connection whose leaf certificate
// has the given SHA-256.
type chainReader interface {
	ReadChain(ctx context.Context, domain string, leafSHA256 [sha256.Size]byte) (chainReport, error)
}

// chainCheck is gateway mode's network expectation. A nil read skips the step
// without a word (a caller that never asked); want "" is the operator turning it off.
type chainCheck struct {
	want string
	read chainReader
}

// httpChainReader is the chainReader that speaks to the gateway.
type httpChainReader struct {
	timeout time.Duration
	// allowUntrustedCert skips ordinary PKI validation (ACME staging); the pin to the
	// quote-bound certificate is checked either way.
	allowUntrustedCert bool
}

func (r httpChainReader) ReadChain(ctx context.Context, domain string, leafSHA256 [sha256.Size]byte) (chainReport, error) {
	serverName := domain
	if host, _, err := net.SplitHostPort(domain); err == nil {
		serverName = host
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = &tls.Config{
		ServerName:         serverName,
		InsecureSkipVerify: r.allowUntrustedCert, //nolint:gosec // pinned below
		VerifyConnection: func(cs tls.ConnectionState) error {
			if len(cs.PeerCertificates) == 0 {
				return errors.New("no certificate served")
			}
			if sha256.Sum256(cs.PeerCertificates[0].Raw) != leafSHA256 {
				return errors.New("the certificate served is not the one the quote binds")
			}
			return nil
		},
	}
	client := &http.Client{Transport: transport, Timeout: r.timeout}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+domain+gatewayIdentityPath, nil)
	if err != nil {
		return chainReport{}, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return chainReport{}, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return chainReport{}, err
	}
	if resp.StatusCode != http.StatusOK {
		return chainReport{}, fmt.Errorf("%s answered %s", gatewayIdentityPath, resp.Status)
	}
	return parseChainReport(body)
}

func parseChainReport(body []byte) (chainReport, error) {
	var doc struct {
		Chain json.RawMessage `json:"chain"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return chainReport{}, fmt.Errorf("%s: %v", gatewayIdentityPath, err)
	}
	if len(doc.Chain) == 0 || bytes.Equal(doc.Chain, []byte("null")) {
		return chainReport{}, errNoChainReport
	}
	var c chainReport
	if err := json.Unmarshal(doc.Chain, &c); err != nil {
		return chainReport{}, fmt.Errorf("%s chain: %v", gatewayIdentityPath, err)
	}
	return c, nil
}

// reportChain prints step 8 and returns whether it failed, and why it did not run
// when it did not ("" when it ran).
func reportChain(ctx context.Context, out io.Writer, cc chainCheck, rep endpointBound, domain string) (failed bool, skipped string) {
	if cc.read == nil {
		return false, ""
	}
	switch {
	case cc.want == "":
		fmt.Fprintf(out, "- chain              not checked (-network is empty)\n")
		return false, "the gateway's network was not checked"
	case !rep.bound:
		fmt.Fprintf(out, "- chain              not checked (needs the endpoint binding above)\n")
		return false, "the gateway's network was not checked"
	}
	c, err := cc.read.ReadChain(ctx, domain, rep.leaf)
	switch {
	case errors.Is(err, errNoChainReport):
		// Builds from before the report could not be pointed off mainnet at all: their
		// compose referenced no network, RPC or contract variable, so the defaults
		// compiled into them were the only root. Which compose is the one step 6 says.
		ok := cc.want == chain.NetworkMainnet
		fmt.Fprintf(out, "%s chain              mainnet, the only network a build that does not report one can use (want %s)\n",
			mark(ok), cc.want)
		return !ok, ""
	case err != nil:
		fmt.Fprintf(out, "- chain              not checked: %v\n", err)
		return false, "the gateway's network could not be read"
	}
	got := "custom"
	if c.Network != nil {
		got = *c.Network
	}
	ok := got == cc.want
	fmt.Fprintf(out, "%s chain              %s, as the gateway reports it (want %s)\n", mark(ok), got, cc.want)
	fmt.Fprintf(out, "  rpc              %s\n", c.RPCURL)
	fmt.Fprintf(out, "  contract         %s\n", c.ServingContract)
	return !ok, ""
}

// endpointBound is what step 8 needs from step 4: whether the served certificate is
// the quote-bound one, and its digest.
type endpointBound struct {
	bound bool
	leaf  [sha256.Size]byte
}
