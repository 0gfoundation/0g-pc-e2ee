package wire

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/0gfoundation/0g-pc-e2ee/protocol/crypto"
)

// responseOfSize builds a non-streaming response whose `choices` content is
// about n bytes.
func responseOfSize(n int) Response {
	content, err := json.Marshal(strings.Repeat("x", n))
	if err != nil {
		panic(err)
	}
	return Response{
		"id":      json.RawMessage(`"chatcmpl-1"`),
		"model":   json.RawMessage(`"gpt-4o"`),
		"usage":   json.RawMessage(`{"prompt_tokens":5,"completion_tokens":1,"total_tokens":6}`),
		"choices": json.RawMessage(`[{"index":0,"message":{"role":"assistant","content":` + string(content) + `}}]`),
	}
}

// BenchmarkSealResponse measures the enclave sealing a complete non-streaming
// response (a single final frame): handshake + AAD + AEAD across body sizes.
func BenchmarkSealResponse(b *testing.B) {
	_, ephPub, err := crypto.GenerateRecipientKey()
	if err != nil {
		b.Fatal(err)
	}
	for _, n := range benchBodySizes {
		resp := responseOfSize(n)
		b.Run(bodySizeName(n), func(b *testing.B) {
			b.SetBytes(int64(n))
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if _, err := SealResponse(ephPub, resp, nil); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// BenchmarkOpenResponse measures the client opening a complete non-streaming
// response. OpenResponse sets up a fresh receiver each call, so opening the
// same sealed response repeatedly is valid.
func BenchmarkOpenResponse(b *testing.B) {
	ephPriv, ephPub, err := crypto.GenerateRecipientKey()
	if err != nil {
		b.Fatal(err)
	}
	for _, n := range benchBodySizes {
		sealed, err := SealResponse(ephPub, responseOfSize(n), nil)
		if err != nil {
			b.Fatal(err)
		}
		b.Run(bodySizeName(n), func(b *testing.B) {
			b.SetBytes(int64(n))
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if _, err := OpenResponse(ephPriv, sealed); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// BenchmarkResponseSealFrame measures the marginal cost of one streamed frame: a
// single ResponseSealer (one HPKE context) seals many small delta frames, as
// SSE streaming does. This is per-frame JSON/JCS + AEAD with no re-handshake —
// the cost that recurs for every chunk of a long completion.
func BenchmarkResponseSealFrame(b *testing.B) {
	_, ephPub, err := crypto.GenerateRecipientKey()
	if err != nil {
		b.Fatal(err)
	}
	sealer, err := NewResponseSealer(ephPub)
	if err != nil {
		b.Fatal(err)
	}
	// A typical SSE delta frame is small; SealFrame does not mutate its input,
	// so one shared frame value is safe to reseal each iteration.
	frame := Response{
		"model":   json.RawMessage(`"gpt-4o"`),
		"choices": json.RawMessage(`[{"index":0,"delta":{"content":"hello"}}]`),
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := sealer.SealFrame(frame, nil, false); err != nil {
			b.Fatal(err)
		}
	}
}
