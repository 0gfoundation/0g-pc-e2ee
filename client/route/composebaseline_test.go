package route

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/0gfoundation/0g-pc-e2ee/client/evidence"
	"github.com/0gfoundation/0g-pc-e2ee/client/evidence/compose"
	"github.com/0gfoundation/0g-pc-e2ee/protocol/attest"
)

// The two deployments the shipped baseline records, by the keys it records them under.
const (
	blTestnetContract = "0xa79F4c8311FF93C06b8CfB403690cc987c93F91E"
	blTestnetProvider = "0x1cB95Eb66Cc67C62d4DE0CC96726C5A5d82e7C85"
	blMainnetContract = "0x47340d900bdFec2BD393c626E12ea0656F938d84"
	blCN20Provider    = "0x4870CbC4D07d6Ac2EE5aA865588e5985FE77a4E9"
)

// blManifest is one of the real app-composes in evidence/compose/testdata — the bytes the
// recorded deployments were taken from.
func blManifest(t *testing.T, name string) []byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "evidence", "compose", "testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// blRouter serves one candidate at address, whose quote commits to the compose hash of
// committed and whose reply carries served as its app-compose — the same bytes, unless a
// test is serving a manifest the quote does not bind. The Router compares against the
// shipped baseline on contract.
func blRouter(t *testing.T, address, contract string, committed, served []byte, rels evidence.ReleaseVerifier,
	opts ...Option) (*Router, string) {
	t.Helper()
	sum := sha256.Sum256(committed)
	raw := pidQuote(t, qvMeasurement(0xaa), pidMRConfigID(t, 1, hex.EncodeToString(sum[:])))
	var srv *httptest.Server
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/routing/preview", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(previewResponse{
			Object: "routing.preview", ServiceType: "chatbot",
			Providers: []previewProvider{{Address: address, CanonicalID: "canon-1", Endpoint: srv.URL, ModelID: "m"}},
		})
	})
	mux.HandleFunc("GET /v1/providers", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = fmt.Fprintf(w, `{"object":"list","data":[{"address":%q}]}`, address)
	})
	mux.HandleFunc("GET /v1/quote", func(w http.ResponseWriter, r *http.Request) {
		tcb, _ := json.Marshal(map[string]string{"app_compose": string(served)})
		_ = json.NewEncoder(w).Encode(map[string]string{"quote": hex.EncodeToString(raw), "tcb_info": string(tcb)})
	})
	srv = httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	b, err := compose.BuiltinComposeBaseline()
	if err != nil {
		t.Fatal(err)
	}
	v := attest.New(pidAllowAll(), attest.WithQuoteParser(qvParser(qvMeasurement(0xaa), qvReportData(t))))
	base := []Option{WithQuoteVerification(v, discardLogger()), WithComposeBaseline(b, contract)}
	if rels != nil {
		base = append(base, WithReleaseVerifier(rels, discardLogger()))
	}
	return New(srv.URL, append(base, opts...)...), srv.URL
}

// blSettled reads address's record until its baseline verdict is not the one a release
// check in flight reports, or fails after a few seconds.
func blSettled(t *testing.T, r *Router, address string) ProviderIdentity {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		id, ok := r.ProviderIdentity(address)
		if !ok {
			t.Fatal("no record for the provider this request sealed to")
		}
		if id.ComposeBaseline != VerdictUnavailable || time.Now().After(deadline) {
			return id
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// The verdicts pcverify reaches on the same manifests, through the path a request takes:
// testnet's manifest is its recorded deployment (its broker on v0.5.4, a release);
// cn-20's matches its record except for the three services on v0.5.1, which the release
// policy refuses; and either manifest under an address nobody recorded is not compared.
func TestComposeBaseline_RecordedDeployments(t *testing.T) {
	testnet, cn20 := blManifest(t, "testnet-app-compose.json"), blManifest(t, "cn20-app-compose.json")
	const unrecorded = "0x00000000000000000000000000000000000000aa"
	for _, tc := range []struct {
		name, address, contract string
		manifest                []byte
		verdict                 Verdict
		deployment              string
	}{
		{"testnet", blTestnetProvider, blTestnetContract, testnet, VerdictPass, "testnet compute-network-20-dev"},
		{"cn-20", blCN20Provider, blMainnetContract, cn20, VerdictNoMatch, "mainnet compute-network-20"},
		{"unrecorded", unrecorded, blMainnetContract, cn20, VerdictNoBaseline, ""},
		// The right provider on the wrong contract is a different registration.
		{"testnet key on mainnet", blTestnetProvider, blMainnetContract, testnet, VerdictNoBaseline, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r, _ := blRouter(t, tc.address, tc.contract, tc.manifest, tc.manifest, fleetStub())
			if err := rtServe(r); err != nil {
				t.Fatalf("the request failed: %v", err)
			}
			id := blSettled(t, r, tc.address)
			if id.ComposeBaseline != tc.verdict || id.BaselineDeployment != tc.deployment {
				t.Fatalf("got %q against %q, want %q against %q",
					id.ComposeBaseline, id.BaselineDeployment, tc.verdict, tc.deployment)
			}
		})
	}
}

// The comparison is of the manifest the quote BINDS: a reply serving other bytes is not
// compared at all, and the provider is still served, since nothing is enforced.
func TestComposeBaseline_OnlyTheAuthenticatedManifest(t *testing.T) {
	testnet := blManifest(t, "testnet-app-compose.json")
	r, _ := blRouter(t, blTestnetProvider, blTestnetContract, testnet, blManifest(t, "cn20-app-compose.json"), fleetStub())
	if err := rtServe(r); err != nil {
		t.Fatalf("the request failed: %v", err)
	}
	if id, _ := r.ProviderIdentity(blTestnetProvider); id.ComposeBaseline != VerdictUnavailable {
		t.Fatalf("a manifest the quote does not bind: %q", id.ComposeBaseline)
	}
}

// A broker build the record lets move is judged off the request path: until its verdict
// lands the comparison is incomplete, and the verdict reaches the record without a second
// verification. Without a release verifier it can never complete.
func TestComposeBaseline_BrokerBuildsAreJudgedInTheBackground(t *testing.T) {
	testnet := blManifest(t, "testnet-app-compose.json")
	rels := fleetStub()
	rels.gate = make(chan struct{})
	r, _ := blRouter(t, blTestnetProvider, blTestnetContract, testnet, testnet, rels)
	if err := rtServe(r); err != nil {
		t.Fatalf("the request failed: %v", err)
	}
	if id, _ := r.ProviderIdentity(blTestnetProvider); id.ComposeBaseline != VerdictUnavailable {
		t.Fatalf("while the release check is in flight: %q", id.ComposeBaseline)
	}
	close(rels.gate)
	if id := blSettled(t, r, blTestnetProvider); id.ComposeBaseline != VerdictPass {
		t.Fatalf("after it answered: %q", id.ComposeBaseline)
	}

	r, _ = blRouter(t, blTestnetProvider, blTestnetContract, testnet, testnet, nil)
	if err := rtServe(r); err != nil {
		t.Fatalf("the request failed: %v", err)
	}
	if id, _ := r.ProviderIdentity(blTestnetProvider); id.ComposeBaseline != VerdictUnavailable {
		t.Fatalf("with no release verifier: %q", id.ComposeBaseline)
	}
}

// Observed on verifications, not on every request: a request answered from the quote
// cache records but does not count again.
func TestComposeBaseline_ObservedPerVerification(t *testing.T) {
	testnet := blManifest(t, "testnet-app-compose.json")
	rels := fleetStub()
	r, _ := blRouter(t, blTestnetProvider, blTestnetContract, testnet, testnet, rels)
	for i := 0; i < 3; i++ {
		if err := rtServe(r); err != nil {
			t.Fatalf("request %d failed: %v", i, err)
		}
	}
	blSettled(t, r, blTestnetProvider)
	// One verification, so the broker build was sent for a verdict once — and the read
	// above started nothing.
	if n := rels.calls.Load(); n != 1 {
		t.Fatalf("the broker build was judged %d times, want once", n)
	}
}

// The warmer, the record's other writer, compares too.
func TestComposeBaseline_Warmer(t *testing.T) {
	testnet := blManifest(t, "testnet-app-compose.json")
	r, srvURL := blRouter(t, blTestnetProvider, blTestnetContract, testnet, testnet, fleetStub(),
		WithOnChainVerification(&stubRegistry{signer: qvSignerStr, ack: true}, false, discardLogger()))
	r.WarmOnce(context.Background(), fakeResolver{url: srvURL})
	if id := blSettled(t, r, blTestnetProvider); id.ComposeBaseline != VerdictPass {
		t.Fatalf("after a sweep: %q", id.ComposeBaseline)
	}
}

// A Router without a baseline makes no comparison and says so.
func TestComposeBaseline_NotConfigured(t *testing.T) {
	r, _ := rtRouter(t, rtVector(t, "testnet-rehearsal-v0.5.4", nil), fleetStub())
	if err := rtServe(r); err != nil {
		t.Fatalf("the request failed: %v", err)
	}
	if id, _ := r.ProviderIdentity(testProviderAddr); id.ComposeBaseline != VerdictNotChecked {
		t.Fatalf("got %q", id.ComposeBaseline)
	}
}
