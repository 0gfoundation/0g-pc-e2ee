package chain

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// buildServiceReturn encodes a getService return for a Service struct with the
// given teeSignerAddress + teeSignerAcknowledged and empty strings elsewhere —
// a faithful ABI encoding (single dynamic tuple → outer offset, 11 head words,
// empty-string tails) that pins the byte offsets decodeService relies on.
func buildServiceReturn(signerHex string, ack bool) []byte {
	u := func(n uint64) []byte { w := make([]byte, 32); binary.BigEndian.PutUint64(w[24:], n); return w }
	addr := func(h string) []byte {
		w := make([]byte, 32)
		b, _ := hex.DecodeString(strings.TrimPrefix(h, "0x"))
		copy(w[32-len(b):], b)
		return w
	}
	boolw := func(v bool) []byte {
		w := make([]byte, 32)
		if v {
			w[31] = 1
		}
		return w
	}
	var buf []byte
	buf = append(buf, u(32)...) // outer offset to the struct (0x20)
	head := [][]byte{
		addr("0x0000000000000000000000000000000000000001"), // 0 provider
		u(352),          // 1 serviceType offset
		u(384),          // 2 url offset
		u(0),            // 3 inputPrice
		u(0),            // 4 outputPrice
		u(0),            // 5 updatedAt
		u(416),          // 6 model offset
		u(448),          // 7 verifiability offset
		u(480),          // 8 additionalInfo offset
		addr(signerHex), // 9 teeSignerAddress
		boolw(ack),      // 10 teeSignerAcknowledged
	}
	for _, w := range head {
		buf = append(buf, w...)
	}
	for i := 0; i < 5; i++ { // 5 empty-string tails
		buf = append(buf, u(0)...)
	}
	return buf
}

func TestDecodeService(t *testing.T) {
	const signer = "0x1122334455667788990011223344556677889900"

	got, ack, err := decodeService(buildServiceReturn(signer, true))
	if err != nil {
		t.Fatalf("decodeService: %v", err)
	}
	if !strings.EqualFold(got, signer) {
		t.Errorf("signer = %s, want %s", got, signer)
	}
	if !ack {
		t.Errorf("acknowledged = false, want true")
	}

	// Unacknowledged.
	_, ack, err = decodeService(buildServiceReturn(signer, false))
	if err != nil {
		t.Fatalf("decodeService (unack): %v", err)
	}
	if ack {
		t.Errorf("acknowledged = true, want false")
	}
}

// Trailing bytes after the struct (as longer string tails would produce) must not
// affect slots 9/10 — they are static and sit at fixed head offsets.
func TestDecodeService_TrailingDataIgnored(t *testing.T) {
	const signer = "0x00000000000000000000000000000000000000ff"
	raw := buildServiceReturn(signer, true)
	raw = append(raw, make([]byte, 256)...) // simulate extra dynamic tail data
	for i := len(raw) - 256; i < len(raw); i++ {
		raw[i] = 0xff
	}
	got, ack, err := decodeService(raw)
	if err != nil {
		t.Fatalf("decodeService: %v", err)
	}
	if !strings.EqualFold(got, signer) || !ack {
		t.Errorf("got (%s, %v), want (%s, true)", got, ack, signer)
	}
}

func TestDecodeService_Errors(t *testing.T) {
	if _, _, err := decodeService([]byte{0x01, 0x02}); err == nil {
		t.Error("want error on too-short input")
	}
	// Valid offset but truncated before the struct head completes.
	short := make([]byte, 32+5*32)
	short[31] = 0x20
	if _, _, err := decodeService(short); err == nil {
		t.Error("want error when struct head is truncated")
	}
	// teeSignerAddress slot with a nonzero high byte (ABI mismatch) must fail
	// closed rather than return a garbage address.
	bad := buildServiceReturn("0x0000000000000000000000000000000000000001", true)
	bad[32+9*32] = 0xff // first (high) byte of the address word
	if _, _, err := decodeService(bad); err == nil {
		t.Error("want error on non-padded address slot")
	}
}

func TestOnChainRegistry_AcknowledgedSigner(t *testing.T) {
	const (
		provider = "0xaabbccddeeff00112233445566778899aabbccdd"
		signer   = "0x99887766554433221100ffeeddccbbaa99887766"
	)
	var gotTo, gotData string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req jsonRPCRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Errorf("decode rpc request: %v", err)
		}
		if req.Method != "eth_call" {
			t.Errorf("method = %q, want eth_call", req.Method)
		}
		if call, ok := req.Params[0].(map[string]any); ok {
			gotTo, _ = call["to"].(string)
			gotData, _ = call["data"].(string)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":"0x` +
			hex.EncodeToString(buildServiceReturn(signer, true)) + `"}`))
	}))
	defer srv.Close()

	reg, err := NewOnChainRegistry(Config{RPCURL: srv.URL, ContractAddress: DefaultInferenceServingAddress})
	if err != nil {
		t.Fatalf("NewOnChainRegistry: %v", err)
	}
	got, err := reg.AcknowledgedSigner(context.Background(), provider)
	if err != nil {
		t.Fatalf("AcknowledgedSigner: %v", err)
	}
	if !strings.EqualFold(got.Address, signer) || !got.Acknowledged {
		t.Errorf("got %+v, want (%s, true)", got, signer)
	}
	if got.Stale {
		t.Error("a direct on-chain read must never be marked Stale")
	}
	if !strings.EqualFold(gotTo, DefaultInferenceServingAddress) {
		t.Errorf("call.to = %s, want %s", gotTo, DefaultInferenceServingAddress)
	}
	// calldata = selector + left-padded provider address.
	wantData := "0x" + getServiceSelector + "000000000000000000000000" + strings.TrimPrefix(provider, "0x")
	if !strings.EqualFold(gotData, wantData) {
		t.Errorf("call.data = %s, want %s", gotData, wantData)
	}
}

func TestOnChainRegistry_RPCError(t *testing.T) {
	var calls int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"error":{"code":-32000,"message":"execution reverted"}}`))
	}))
	defer srv.Close()
	reg, _ := NewOnChainRegistry(Config{RPCURL: srv.URL})
	if _, err := reg.AcknowledgedSigner(context.Background(), "0xaabbccddeeff00112233445566778899aabbccdd"); err == nil {
		t.Error("want error on JSON-RPC error response")
	}
	// A JSON-RPC application error is deterministic: retrying it only multiplies
	// the latency the caller's request pays.
	if calls != 1 {
		t.Errorf("RPC called %d times, want 1 (application errors are not retried)", calls)
	}
}

// A transient server-side failure is exactly what the retry exists for: the
// lookup should absorb it rather than fail a candidate over a blip.
func TestOnChainRegistry_RetriesTransientFailure(t *testing.T) {
	const signer = "0x99887766554433221100ffeeddccbbaa99887766"
	var calls int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if calls < 3 {
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":"0x` +
			hex.EncodeToString(buildServiceReturn(signer, true)) + `"}`))
	}))
	defer srv.Close()

	reg, _ := NewOnChainRegistry(Config{RPCURL: srv.URL})
	got, err := reg.AcknowledgedSigner(context.Background(), "0xaabbccddeeff00112233445566778899aabbccdd")
	if err != nil {
		t.Fatalf("want the retry to absorb two 502s, got: %v", err)
	}
	if !strings.EqualFold(got.Address, signer) || !got.Acknowledged {
		t.Errorf("got %+v, want (%s, true)", got, signer)
	}
	if calls != 3 {
		t.Errorf("RPC called %d times, want 3 (two failures then a success)", calls)
	}
}

// A 4xx says the request itself is wrong, so repeating it is pure latency.
func TestOnChainRegistry_DoesNotRetryClientError(t *testing.T) {
	var calls int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.WriteHeader(http.StatusBadRequest)
	}))
	defer srv.Close()

	reg, _ := NewOnChainRegistry(Config{RPCURL: srv.URL})
	if _, err := reg.AcknowledgedSigner(context.Background(), "0xaabbccddeeff00112233445566778899aabbccdd"); err == nil {
		t.Error("want error on HTTP 400")
	}
	if calls != 1 {
		t.Errorf("RPC called %d times, want 1 (4xx is not retried)", calls)
	}
}

// The caller's deadline bounds the whole lookup, not one attempt: a cancelled
// request must stop retrying immediately.
func TestOnChainRegistry_RetryHonorsContext(t *testing.T) {
	var calls int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()

	ctx, cancel := context.WithCancel(context.Background())
	reg, _ := NewOnChainRegistry(Config{RPCURL: srv.URL})
	cancel()
	if _, err := reg.AcknowledgedSigner(ctx, "0xaabbccddeeff00112233445566778899aabbccdd"); err == nil {
		t.Error("want error on a cancelled context")
	}
	if calls > 1 {
		t.Errorf("RPC called %d times after cancellation, want at most 1", calls)
	}
}

func TestOnChainRegistry_BadInputs(t *testing.T) {
	if _, err := NewOnChainRegistry(Config{RPCURL: ""}); err == nil {
		t.Error("want error on empty RPC URL")
	}
	if _, err := NewOnChainRegistry(Config{RPCURL: "http://x", ContractAddress: "0xnothex"}); err == nil {
		t.Error("want error on bad contract address")
	}
	reg, _ := NewOnChainRegistry(Config{RPCURL: "http://127.0.0.1:0"})
	if _, err := reg.AcknowledgedSigner(context.Background(), "not-an-address"); err == nil {
		t.Error("want error on bad provider address")
	}
}

func TestIsHexAddressAndPad(t *testing.T) {
	if !isHexAddress("0xaabbccddeeff00112233445566778899aabbccdd") {
		t.Error("valid address rejected")
	}
	for _, bad := range []string{"", "0x", "aabb", "0xZZ", "0x1234"} {
		if isHexAddress(bad) {
			t.Errorf("isHexAddress(%q) = true, want false", bad)
		}
	}
	if got := leftPad32("0xff"); got != strings.Repeat("0", 62)+"ff" {
		t.Errorf("leftPad32 = %s", got)
	}
}
