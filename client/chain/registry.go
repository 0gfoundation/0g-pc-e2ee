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

// DefaultInferenceServingAddress is the InferenceServing proxy on 0G mainnet
// (0g-serving-contract deployments/zgMainnet). Callers SHOULD set the address
// explicitly for their target chain rather than rely on this — e.g. testnet-V4
// is 0xa79F4c8311FF93C06b8CfB403690cc987c93F91E and testnet-dev is
// 0x41bD7Ac5c19000A974D5c192bcd5FB67b56C85c5.
//
// This is a beacon-proxy address: it is stable across implementation upgrades
// (the impl is swapped behind a fixed proxy). So a contract upgrade does NOT
// change the address — meaning a change to the Service struct layout that
// decodeService depends on can ship WITHOUT an address change to signal it. That
// is safe here only because such a mismatch fails closed (see decodeService): a
// misaligned decode rejects the candidate, it never accepts a wrong signer. A
// Service-struct change is therefore a coordinated migration that must update
// decodeService's offsets (and its KAT).
const DefaultInferenceServingAddress = "0x47340d900bdFec2BD393c626E12ea0656F938d84"

// DefaultChainRPCURL is the 0G mainnet JSON-RPC endpoint, a convenient default
// that pairs with DefaultInferenceServingAddress (also mainnet). It MUST be a
// source trusted independently of the router; override it (with a matching
// -serving-contract) for testnet or to point at your own node.
const DefaultChainRPCURL = "https://evmrpc.0g.ai"

// getServiceSelector is the 4-byte selector for getService(address) on the
// InferenceServing contract (abigen binding: method 0x15a52302). Hard-coding it
// avoids a keccak dependency; a KAT locks it against drift.
const getServiceSelector = "15a52302"

// maxRPCBodyBytes bounds an eth_call response read, defending against a hostile
// or misconfigured RPC returning an unbounded body.
const maxRPCBodyBytes = 1 << 20

// RPC attempt policy. The lookup sits on the REQUEST path (the route resolver
// grounds every candidate it materializes), so the shape that matters is "absorb
// a blip quickly", not "wait a long time for one attempt": a hung RPC is worse
// for a user than a fast failure, because the candidate loop pays it once per
// candidate, serially. Hence a short per-attempt deadline and a couple of quick
// retries rather than a single long one.
const (
	// rpcAttempts is the total number of eth_call attempts per lookup.
	rpcAttempts = 3
	// rpcAttemptTimeout bounds ONE attempt. The caller's context still applies and
	// wins when it is shorter.
	rpcAttemptTimeout = 3 * time.Second
	// rpcRetryBackoff is the pause before the second attempt; it doubles for each
	// attempt after that.
	rpcRetryBackoff = 200 * time.Millisecond
	// rpcTotalTimeout is the belt-and-braces ceiling on the HTTP client, covering
	// the whole retry sequence in case a per-attempt deadline is somehow not
	// honored. It is not the operative bound — rpcAttemptTimeout is.
	rpcTotalTimeout = 15 * time.Second
)

// Signer is a provider's on-chain TEE signer as of one lookup, plus the
// provenance a caller needs to decide how much weight to put on it.
type Signer struct {
	// Address is the acknowledged teeSignerAddress. Meaningful only when
	// Acknowledged is true.
	Address string
	// Acknowledged mirrors the contract's teeSignerAcknowledged. A caller MUST
	// trust Address only when this is true.
	Acknowledged bool
	// Stale reports that the value came from a cache entry past its TTL, kept
	// usable by the grace window because the refresh RPC failed. A stale reading is
	// good enough to CONFIRM that a quote-bound signer matches, and never good
	// enough to REJECT one — see the asymmetry documented on Cached.
	Stale bool
}

// SignerRegistry looks up a provider's on-chain, acknowledged TEE signer address.
// providerAddr is the provider's account address (the same value the router
// advertises as the routing pin). Callers MUST trust the returned signer only
// when Signer.Acknowledged is true.
type SignerRegistry interface {
	// AcknowledgedSigner returns the provider's acknowledged TEE signer, which may
	// come from a cache and may be Stale (see Signer.Stale).
	AcknowledgedSigner(ctx context.Context, providerAddr string) (Signer, error)
	// RefreshSigner returns a reading taken live from the chain, bypassing any
	// cache — including the grace window, so it never returns a Stale value. A
	// caller about to REJECT a provider on the strength of a lookup calls this
	// first, so a benign signer rotation cannot be indicted by a stale cache entry.
	RefreshSigner(ctx context.Context, providerAddr string) (Signer, error)
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
		httpc = &http.Client{Timeout: rpcTotalTimeout}
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
// teeSignerAddress and teeSignerAcknowledged. The reading is always live — this
// type holds no cache — so the returned Signer is never Stale.
func (r *OnChainRegistry) AcknowledgedSigner(ctx context.Context, providerAddr string) (Signer, error) {
	raw, err := r.getServiceRaw(ctx, providerAddr)
	if err != nil {
		return Signer{}, err
	}
	signer, acknowledged, err := decodeService(raw)
	if err != nil {
		return Signer{}, err
	}
	return Signer{Address: signer, Acknowledged: acknowledged}, nil
}

// RefreshSigner is AcknowledgedSigner: this registry reads through to the chain
// on every call, so there is no cache for a refresh to bypass. The method exists
// so *OnChainRegistry satisfies SignerRegistry on its own, unwrapped — a caller
// that skips chain.Cached still gets the same contract.
func (r *OnChainRegistry) RefreshSigner(ctx context.Context, providerAddr string) (Signer, error) {
	return r.AcknowledgedSigner(ctx, providerAddr)
}

// ServiceInfo is the subset of a provider's on-chain Service a caller needs to
// both locate it (URL — the serving endpoint, e.g. where its /quote lives) and
// trust its signer (Signer + Acknowledged, the hop-5 fields).
type ServiceInfo struct {
	URL          string
	Signer       string
	Acknowledged bool
}

// ServiceInfo reads getService(providerAddr) and returns the provider's serving
// URL alongside its teeSignerAddress and teeSignerAcknowledged, from one call.
// The signer fields decode from fixed static offsets (same as AcknowledgedSigner,
// fail-closed); the URL is a best-effort read of a dynamic string and is left
// empty rather than erroring, since it is informational, not security-critical.
func (r *OnChainRegistry) ServiceInfo(ctx context.Context, providerAddr string) (ServiceInfo, error) {
	raw, err := r.getServiceRaw(ctx, providerAddr)
	if err != nil {
		return ServiceInfo{}, err
	}
	signer, acknowledged, err := decodeService(raw)
	if err != nil {
		return ServiceInfo{}, err
	}
	url, _ := decodeServiceURL(raw) // best-effort; informational only
	return ServiceInfo{URL: url, Signer: signer, Acknowledged: acknowledged}, nil
}

// getServiceRaw builds and sends the getService(provider) eth_call, returning the
// raw ABI return bytes.
func (r *OnChainRegistry) getServiceRaw(ctx context.Context, providerAddr string) ([]byte, error) {
	if !isHexAddress(providerAddr) {
		return nil, fmt.Errorf("chain: bad provider address %q (want 0x + 40 hex)", providerAddr)
	}
	return r.ethCall(ctx, "0x"+getServiceSelector+leftPad32(providerAddr))
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
// and returns the decoded return bytes, retrying a TRANSIENT failure up to
// rpcAttempts times with a doubling backoff.
//
// Only transport failures and retryable HTTP statuses (429, 5xx) are retried: a
// JSON-RPC application error ("execution reverted") and a malformed/undecodable
// reply are deterministic, so repeating them just multiplies the latency the
// caller's request pays. The caller's context is honored between attempts, so a
// cancelled or expired request stops retrying immediately.
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

	backoff := rpcRetryBackoff
	var lastErr error
	for attempt := 0; attempt < rpcAttempts; attempt++ {
		if attempt > 0 {
			// Wait out the backoff, but abandon the sequence the moment the caller
			// gives up — its deadline bounds the whole lookup, not just one attempt.
			t := time.NewTimer(backoff)
			select {
			case <-ctx.Done():
				t.Stop()
				return nil, fmt.Errorf("chain: eth_call: %w (last error: %v)", ctx.Err(), lastErr)
			case <-t.C:
			}
			backoff *= 2
		}
		out, retryable, err := r.ethCallOnce(ctx, reqBody)
		if err == nil {
			return out, nil
		}
		lastErr = err
		if !retryable || ctx.Err() != nil {
			return nil, err
		}
	}
	return nil, fmt.Errorf("chain: eth_call failed after %d attempts: %w", rpcAttempts, lastErr)
}

// ethCallOnce runs a single eth_call attempt under its own short deadline
// (rpcAttemptTimeout, or the caller's remaining budget when that is shorter). It
// reports whether the failure is worth another attempt.
func (r *OnChainRegistry) ethCallOnce(ctx context.Context, reqBody []byte) (out []byte, retryable bool, err error) {
	attemptCtx, cancel := context.WithTimeout(ctx, rpcAttemptTimeout)
	defer cancel()

	httpReq, err := http.NewRequestWithContext(attemptCtx, http.MethodPost, r.rpcURL, strings.NewReader(string(reqBody)))
	if err != nil {
		return nil, false, fmt.Errorf("chain: build eth_call request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := r.http.Do(httpReq)
	if err != nil {
		// A transport failure (refused, reset, DNS, attempt deadline) is the classic
		// blip another attempt clears.
		return nil, true, fmt.Errorf("chain: eth_call request: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxRPCBodyBytes))
	if err != nil {
		return nil, true, fmt.Errorf("chain: read eth_call response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, retryableStatus(resp.StatusCode), fmt.Errorf("chain: eth_call returned HTTP %d", resp.StatusCode)
	}
	var rpcResp jsonRPCResponse
	if err := json.Unmarshal(body, &rpcResp); err != nil {
		return nil, false, fmt.Errorf("chain: decode eth_call response: %w", err)
	}
	if rpcResp.Error != nil {
		return nil, false, fmt.Errorf("chain: eth_call error %d: %s", rpcResp.Error.Code, rpcResp.Error.Message)
	}
	decoded, err := hex.DecodeString(strings.TrimPrefix(rpcResp.Result, "0x"))
	if err != nil {
		return nil, false, fmt.Errorf("chain: decode eth_call result hex: %w", err)
	}
	return decoded, false, nil
}

// retryableStatus reports whether an RPC endpoint's HTTP status is worth another
// attempt: a rate limit or a server-side error may clear, a 4xx will not.
func retryableStatus(status int) bool {
	return status == http.StatusTooManyRequests || (status >= 500 && status <= 599)
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

// decodeServiceURL extracts Service.url (field index 2, a dynamic string) from a
// getService return. Unlike decodeService this reads a dynamic field, so it must
// follow the head-slot offset to the string tail: head slot 2 holds the string's
// offset relative to the struct base, and there sit a length word then the UTF-8
// bytes. It is informational only (it tells a caller where to fetch a quote), so
// callers treat any error as "no URL on chain" rather than a hard failure.
func decodeServiceURL(raw []byte) (string, error) {
	const word = 32
	base, ok := readWordUint(raw, 0)
	if !ok {
		return "", errors.New("chain: getService return too short for offset")
	}
	rel, ok := readWordUint(raw, base+2*word) // head slot 2 = url offset
	if !ok {
		return "", errors.New("chain: getService return too short for url slot")
	}
	strStart := base + rel
	n, ok := readWordUint(raw, strStart) // string length
	if !ok {
		return "", errors.New("chain: getService url length out of range")
	}
	dataStart := strStart + word
	end := dataStart + n
	if end < dataStart || uint64(len(raw)) < end {
		return "", errors.New("chain: getService url data truncated")
	}
	return string(raw[dataStart:end]), nil
}

// readWordUint reads the 32-byte big-endian word at byte offset off as a uint64,
// reporting ok=false if the word is out of bounds or does not fit in uint64.
func readWordUint(raw []byte, off uint64) (uint64, bool) {
	const word = 32
	end := off + word
	if end < off || uint64(len(raw)) < end {
		return 0, false
	}
	v := new(big.Int).SetBytes(raw[off:end])
	if !v.IsUint64() {
		return 0, false
	}
	return v.Uint64(), true
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
