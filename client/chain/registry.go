// Package chain grounds a provider's TEE signer in the on-chain InferenceServing
// registry — SPEC §4.4 step 3, the "on-chain root" of docs/design/trust-chain.md
// (hop 5).
//
// DCAP verification (client/dcap) proves a provider's quote is genuine and binds
// its enc_pub + signer_addr, but it cannot tell a legitimate provider from a
// look-alike enclave running the same audited image: both produce valid quotes
// with valid measurements. The measurement answers "is the code right?"; this
// package answers "is it the *expected* enclave?" by reading the provider's
// acknowledged teeSignerAddress from the 0G chain — an independent source the
// untrusted router cannot forge — so the caller can assert the quote-bound signer
// equals it.
//
// Like client/dcap, it lives in the client module (not protocol): it carries a
// network/chain dependency, while protocol stays lean and portable. To avoid
// pulling all of go-ethereum into the otherwise dependency-light client, it
// speaks the JSON-RPC eth_call directly and decodes only the two static fields it
// needs — teeSignerAddress and teeSignerAcknowledged — from their fixed offsets in
// the ABI-encoded getService return (see decodeService). The byte offsets are
// pinned by a KAT in the tests, mirroring protocol/attest.ParseTDXQuoteBody.
package chain

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"strings"
	"time"
)

// DefaultInferenceServingAddress is the InferenceServing contract address the
// broker defaults to (0g-serving-broker api/inference/config default). Callers
// SHOULD set it explicitly for their target chain rather than rely on this.
const DefaultInferenceServingAddress = "0x47340d900bdFec2BD393c626E12ea0656F938d84"

// getServiceSelector is the 4-byte selector for getService(address) on the
// InferenceServing contract (abigen binding: method 0x15a52302). Hard-coding it
// avoids a keccak dependency; a KAT locks it against drift.
const getServiceSelector = "15a52302"

// maxRPCBodyBytes bounds an eth_call response read, defending against a hostile
// or misconfigured RPC returning an unbounded body.
const maxRPCBodyBytes = 1 << 20

// SignerRegistry looks up a provider's on-chain, acknowledged TEE signer address.
// providerAddr is the provider's account address (the same value the router
// advertises as the routing pin). Callers MUST trust the returned signer only
// when acknowledged is true.
type SignerRegistry interface {
	AcknowledgedSigner(ctx context.Context, providerAddr string) (signer string, acknowledged bool, err error)
}

// Config configures an OnChainRegistry.
type Config struct {
	// RPCURL is the 0G chain JSON-RPC endpoint. It MUST be a source the client
	// trusts independently of the router/provider (SPEC's "on-chain published
	// value: NEVER from the router or the provider"). Required.
	RPCURL string
	// ContractAddress is the InferenceServing contract. Empty uses
	// DefaultInferenceServingAddress.
	ContractAddress string
	// HTTPClient overrides the HTTP client. Nil uses one with a bounded timeout.
	HTTPClient *http.Client
	// BlockTag is the block the call reads at ("latest", "finalized", …). Empty
	// uses "latest".
	BlockTag string
}

// OnChainRegistry reads getService(provider) from the InferenceServing contract
// over JSON-RPC. It is immutable after New and safe for concurrent use.
type OnChainRegistry struct {
	rpcURL   string
	contract string
	http     *http.Client
	blockTag string
}

// NewOnChainRegistry validates cfg and returns a registry. It does not dial —
// the RPC is reached lazily on each lookup.
func NewOnChainRegistry(cfg Config) (*OnChainRegistry, error) {
	if strings.TrimSpace(cfg.RPCURL) == "" {
		return nil, errors.New("chain: empty RPC URL")
	}
	contract := cfg.ContractAddress
	if contract == "" {
		contract = DefaultInferenceServingAddress
	}
	if !isHexAddress(contract) {
		return nil, fmt.Errorf("chain: bad contract address %q (want 0x + 40 hex)", contract)
	}
	httpc := cfg.HTTPClient
	if httpc == nil {
		httpc = &http.Client{Timeout: 15 * time.Second}
	}
	blockTag := cfg.BlockTag
	if blockTag == "" {
		blockTag = "latest"
	}
	return &OnChainRegistry{
		rpcURL:   cfg.RPCURL,
		contract: contract,
		http:     httpc,
		blockTag: blockTag,
	}, nil
}

// AcknowledgedSigner reads getService(providerAddr) and returns its
// teeSignerAddress and teeSignerAcknowledged.
func (r *OnChainRegistry) AcknowledgedSigner(ctx context.Context, providerAddr string) (string, bool, error) {
	if !isHexAddress(providerAddr) {
		return "", false, fmt.Errorf("chain: bad provider address %q (want 0x + 40 hex)", providerAddr)
	}
	calldata := "0x" + getServiceSelector + leftPad32(providerAddr)
	raw, err := r.ethCall(ctx, calldata)
	if err != nil {
		return "", false, err
	}
	return decodeService(raw)
}

// jsonRPCRequest / jsonRPCResponse model the subset of JSON-RPC eth_call used.
type jsonRPCRequest struct {
	JSONRPC string `json:"jsonrpc"`
	ID      int    `json:"id"`
	Method  string `json:"method"`
	Params  []any  `json:"params"`
}

type jsonRPCResponse struct {
	Result string `json:"result"`
	Error  *struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}

// ethCall performs eth_call(to=contract, data=calldata) at the configured block
// and returns the decoded return bytes.
func (r *OnChainRegistry) ethCall(ctx context.Context, calldata string) ([]byte, error) {
	reqBody, err := json.Marshal(jsonRPCRequest{
		JSONRPC: "2.0",
		ID:      1,
		Method:  "eth_call",
		Params: []any{
			map[string]string{"to": r.contract, "data": calldata},
			r.blockTag,
		},
	})
	if err != nil {
		return nil, fmt.Errorf("chain: marshal eth_call: %w", err)
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, r.rpcURL, strings.NewReader(string(reqBody)))
	if err != nil {
		return nil, fmt.Errorf("chain: build eth_call request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := r.http.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("chain: eth_call request: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxRPCBodyBytes))
	if err != nil {
		return nil, fmt.Errorf("chain: read eth_call response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("chain: eth_call returned HTTP %d", resp.StatusCode)
	}
	var rpcResp jsonRPCResponse
	if err := json.Unmarshal(body, &rpcResp); err != nil {
		return nil, fmt.Errorf("chain: decode eth_call response: %w", err)
	}
	if rpcResp.Error != nil {
		return nil, fmt.Errorf("chain: eth_call error %d: %s", rpcResp.Error.Code, rpcResp.Error.Message)
	}
	out, err := hex.DecodeString(strings.TrimPrefix(rpcResp.Result, "0x"))
	if err != nil {
		return nil, fmt.Errorf("chain: decode eth_call result hex: %w", err)
	}
	return out, nil
}

// decodeService extracts teeSignerAddress and teeSignerAcknowledged from the
// ABI-encoded getService return.
//
// getService returns a single dynamic tuple (the Service struct has string
// fields), so the outer encoding is one head word holding the offset to the
// struct, followed by the struct's own encoding. Within the struct, the two
// fields we need are STATIC types and therefore sit inline at fixed head slots,
// regardless of the dynamic string contents around them:
//
//	struct head slot 9  → teeSignerAddress (address, right-aligned in the word)
//	struct head slot 10 → teeSignerAcknowledged (bool)
//
// So we read the offset, then index slots 9 and 10 — no string parsing needed.
// The Service tuple layout (11 fields) is:
//
//	0 provider(address) 1 serviceType(string) 2 url(string) 3 inputPrice(uint256)
//	4 outputPrice(uint256) 5 updatedAt(uint256) 6 model(string) 7 verifiability(string)
//	8 additionalInfo(string) 9 teeSignerAddress(address) 10 teeSignerAcknowledged(bool)
func decodeService(raw []byte) (string, bool, error) {
	const word = 32
	if len(raw) < word {
		return "", false, fmt.Errorf("chain: getService return too short (%d bytes)", len(raw))
	}
	// Offset to the struct encoding (canonically 0x20). Read it rather than assume.
	off := new(big.Int).SetBytes(raw[:word])
	if !off.IsUint64() {
		return "", false, errors.New("chain: getService struct offset out of range")
	}
	base := off.Uint64()
	// Need slots 0..10 of the struct head present (11 words).
	end := base + 11*word
	if end < base || uint64(len(raw)) < end {
		return "", false, fmt.Errorf("chain: getService return too short for Service struct (%d bytes)", len(raw))
	}
	signerWord := raw[base+9*word : base+10*word]
	ackWord := raw[base+10*word : base+11*word]

	// An address is left-padded to 32 bytes: the high 12 bytes MUST be zero. A
	// nonzero prefix means our offsets do not line up (e.g. an ABI change) — fail
	// closed rather than return a garbage address.
	for _, b := range signerWord[:12] {
		if b != 0 {
			return "", false, errors.New("chain: getService teeSignerAddress slot is not a padded address (ABI mismatch?)")
		}
	}
	signer := "0x" + hex.EncodeToString(signerWord[12:])

	// A bool is 0 or 1 in the low byte, rest zero.
	acknowledged := false
	for _, b := range ackWord {
		if b != 0 {
			acknowledged = true
			break
		}
	}
	return signer, acknowledged, nil
}

// isHexAddress reports whether s is a 0x-prefixed 20-byte hex address.
func isHexAddress(s string) bool {
	if len(s) != 42 || !strings.HasPrefix(s, "0x") {
		return false
	}
	_, err := hex.DecodeString(s[2:])
	return err == nil
}

// leftPad32 renders a 20-byte hex address as a 32-byte (64 hex char) ABI word.
func leftPad32(addr string) string {
	h := strings.ToLower(strings.TrimPrefix(addr, "0x"))
	return strings.Repeat("0", 64-len(h)) + h
}
