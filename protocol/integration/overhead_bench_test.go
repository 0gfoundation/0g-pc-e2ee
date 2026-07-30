package integration

// Benchmarks that isolate the cost E2EE adds to a chat completion versus a
// plain (no-E2EE) passthrough, for both non-streaming and streaming. Each
// scenario has an `_E2EE` variant (the full seal/open round trip across the two
// hops) and a `_Plain` variant (the same payload marshaled/unmarshaled at each
// hop, no crypto). The difference between the two is the marginal cost of E2EE:
// the HPKE handshake, the ChaCha20-Poly1305 AEAD, and the JCS canonicalization.
//
// The E2EE round trip attributes work to the two participants:
//
//	Gateway (client):  SealRequest      + OpenResponse / OpenFrame
//	Broker  (enclave): OpenRequest      + SealResponse / SealFrame
//
// TDX/quote verification is deliberately excluded — it is a one-off, out-of-band
// step, not a per-request cost. Run:
//
//	go test -run '^$' -bench 'Overhead' -benchmem ./integration/...
//
// then compare the paired `_E2EE` / `_Plain` lines (or the human-readable table
// from `go run ./cmd/e2ee-overhead`).

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/0gfoundation/0g-pc-e2ee/protocol/crypto"
	"github.com/0gfoundation/0g-pc-e2ee/protocol/wire"
)

// benchKeys are the fixed keypairs a round trip needs: the enclave's sealing key
// (opens requests / the client seals to it) and the client's response ephemeral
// key (opens responses / the enclave seals to it).
type benchKeys struct {
	encPriv crypto.PrivateKey
	encPub  crypto.PublicKey
	ephPriv crypto.PrivateKey
	ephPub  crypto.PublicKey
}

func mustBenchKeys(b *testing.B) benchKeys {
	b.Helper()
	encPriv, encPub, err := crypto.GenerateRecipientKey()
	if err != nil {
		b.Fatal(err)
	}
	ephPriv, ephPub, err := crypto.GenerateRecipientKey()
	if err != nil {
		b.Fatal(err)
	}
	return benchKeys{encPriv, encPub, ephPriv, ephPub}
}

func benchRequest(nBytes int) wire.Request {
	content, _ := json.Marshal(strings.Repeat("x", nBytes))
	return wire.Request{
		"model":       json.RawMessage(`"gpt-4o"`),
		"temperature": json.RawMessage(`0.7`),
		"messages":    json.RawMessage(`[{"role":"user","content":` + string(content) + `}]`),
		"tools":       json.RawMessage(`[{"type":"function","function":{"name":"calc"}}]`),
	}
}

func benchResponse(nBytes int) wire.Response {
	content, _ := json.Marshal(strings.Repeat("x", nBytes))
	return wire.Response{
		"id":      json.RawMessage(`"chatcmpl-1"`),
		"model":   json.RawMessage(`"gpt-4o"`),
		"usage":   json.RawMessage(`{"prompt_tokens":50,"completion_tokens":120,"total_tokens":170}`),
		"choices": json.RawMessage(`[{"index":0,"message":{"role":"assistant","content":` + string(content) + `},"finish_reason":"stop"}]`),
	}
}

func benchDeltaFrame() wire.Response {
	return wire.Response{
		"id":      json.RawMessage(`"chatcmpl-1"`),
		"model":   json.RawMessage(`"gpt-4o"`),
		"choices": json.RawMessage(`[{"index":0,"delta":{"content":" word"}}]`),
	}
}

// nonStreamSizes pair a request body with a response body, small through large.
var nonStreamSizes = []struct {
	name string
	req  int
	resp int
}{
	{"small", 512, 512},
	{"medium", 4 << 10, 2 << 10},
	{"large", 32 << 10, 8 << 10},
}

// BenchmarkOverheadNonStreaming_E2EE times the full sealed round trip for a
// non-streaming completion: gateway seals the request, the broker opens it,
// seals the response, and the gateway opens that — all four crypto stages a
// single request/response pays.
func BenchmarkOverheadNonStreaming_E2EE(b *testing.B) {
	for _, s := range nonStreamSizes {
		k := mustBenchKeys(b)
		req := benchRequest(s.req)
		resp := benchResponse(s.resp)
		b.Run(s.name, func(b *testing.B) {
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				env, err := wire.SealRequest(k.encPub, req, nil, brokerSigner, k.ephPub) // gateway
				if err != nil {
					b.Fatal(err)
				}
				if _, err := wire.OpenRequest(k.encPriv, env); err != nil { // broker
					b.Fatal(err)
				}
				sealed, err := wire.SealResponse(k.ephPub, resp, nil) // broker
				if err != nil {
					b.Fatal(err)
				}
				if _, err := wire.OpenResponse(k.ephPriv, sealed); err != nil { // gateway
					b.Fatal(err)
				}
			}
		})
	}
}

// BenchmarkOverheadNonStreaming_Plain is the no-E2EE baseline: the same payloads
// marshaled at the sender and unmarshaled at the receiver on each hop, the
// (de)serialization a request pays whether or not E2EE is on. Subtract this from
// the _E2EE result to get the crypto overhead.
func BenchmarkOverheadNonStreaming_Plain(b *testing.B) {
	for _, s := range nonStreamSizes {
		req := benchRequest(s.req)
		resp := benchResponse(s.resp)
		b.Run(s.name, func(b *testing.B) {
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				reqBytes, err := json.Marshal(req) // gateway serialize
				if err != nil {
					b.Fatal(err)
				}
				var gotReq wire.Request
				if err := json.Unmarshal(reqBytes, &gotReq); err != nil { // broker deserialize
					b.Fatal(err)
				}
				respBytes, err := json.Marshal(resp) // broker serialize
				if err != nil {
					b.Fatal(err)
				}
				var gotResp wire.Response
				if err := json.Unmarshal(respBytes, &gotResp); err != nil { // gateway deserialize
					b.Fatal(err)
				}
			}
		})
	}
}

// streamLengths are token counts (one sealed SSE frame per token, plus the last
// marked final) for the streaming benchmarks.
var streamLengths = []int{32, 256, 1024}

// BenchmarkOverheadStreaming_E2EE times a full streaming round trip: seal +
// open the request once, then seal (broker) and open (gateway) every delta
// frame under one shared HPKE context — the realistic streaming cost, where the
// per-request handshake is amortized over many small per-frame AEAD passes.
func BenchmarkOverheadStreaming_E2EE(b *testing.B) {
	req := benchRequest(1 << 10)
	frame := benchDeltaFrame()
	for _, n := range streamLengths {
		k := mustBenchKeys(b)
		b.Run(fmt.Sprintf("%dframes", n), func(b *testing.B) {
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				env, err := wire.SealRequest(k.encPub, req, nil, brokerSigner, k.ephPub) // gateway
				if err != nil {
					b.Fatal(err)
				}
				if _, err := wire.OpenRequest(k.encPriv, env); err != nil { // broker
					b.Fatal(err)
				}

				sealer, err := wire.NewResponseSealer(k.ephPub) // broker: one context
				if err != nil {
					b.Fatal(err)
				}
				frames := make([]wire.Response, n)
				for j := 0; j < n; j++ {
					f, err := sealer.SealFrame(frame, nil, j == n-1)
					if err != nil {
						b.Fatal(err)
					}
					frames[j] = f
				}

				opener, err := wire.NewResponseOpener(k.ephPriv, frames[0]) // gateway
				if err != nil {
					b.Fatal(err)
				}
				for _, f := range frames {
					if _, err := opener.OpenFrame(f); err != nil {
						b.Fatal(err)
					}
				}
			}
		})
	}
}

// BenchmarkOverheadStreaming_Plain is the no-E2EE streaming baseline: marshal +
// unmarshal the request and each delta frame, no crypto.
func BenchmarkOverheadStreaming_Plain(b *testing.B) {
	req := benchRequest(1 << 10)
	frame := benchDeltaFrame()
	for _, n := range streamLengths {
		b.Run(fmt.Sprintf("%dframes", n), func(b *testing.B) {
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				reqBytes, err := json.Marshal(req)
				if err != nil {
					b.Fatal(err)
				}
				var gotReq wire.Request
				if err := json.Unmarshal(reqBytes, &gotReq); err != nil {
					b.Fatal(err)
				}
				for j := 0; j < n; j++ {
					fb, err := json.Marshal(frame) // broker serialize frame
					if err != nil {
						b.Fatal(err)
					}
					var gotFrame wire.Response
					if err := json.Unmarshal(fb, &gotFrame); err != nil { // gateway deserialize frame
						b.Fatal(err)
					}
				}
			}
		})
	}
}
