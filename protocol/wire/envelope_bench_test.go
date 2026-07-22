package wire

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/0gfoundation/0g-pc-e2ee/protocol/crypto"
)

var benchProviderID = "0x" + strings.Repeat("a", 40)

// benchBodySizes are approximate sizes for the sensitive body (`messages` /
// `choices`): a short prompt up through a large multi-turn context. The wire
// benches deliberately include JCS canonicalization + JSON, so these show how
// much of the end-to-end cost is (de)serialization rather than crypto.
var benchBodySizes = []int{1 << 10, 16 << 10, 256 << 10, 1 << 20}

func bodySizeName(n int) string {
	switch {
	case n >= 1<<20:
		return fmt.Sprintf("%dMiB", n>>20)
	case n >= 1<<10:
		return fmt.Sprintf("%dKiB", n>>10)
	default:
		return fmt.Sprintf("%dB", n)
	}
}

// requestOfSize builds a chat request whose `messages` content is about n
// bytes, so SealRequest/OpenRequest exercise JCS + JSON over a realistic body.
func requestOfSize(n int) Request {
	content, err := json.Marshal(strings.Repeat("x", n))
	if err != nil {
		panic(err)
	}
	return Request{
		"model":       json.RawMessage(`"gpt-4o"`),
		"temperature": json.RawMessage(`0.7`),
		"messages":    json.RawMessage(`[{"role":"user","content":` + string(content) + `}]`),
		"tools":       json.RawMessage(`[{"type":"function","function":{"name":"calc"}}]`),
	}
}

// BenchmarkSealRequest measures the full client-side request path: build the
// §5 envelope, JCS-canonicalize the AAD, HPKE-seal the body. SetBytes is the
// body size, so the reported MB/s is end-to-end (crypto + serialization).
func BenchmarkSealRequest(b *testing.B) {
	_, encPub, err := crypto.GenerateRecipientKey()
	if err != nil {
		b.Fatal(err)
	}
	_, ephPub, err := crypto.GenerateRecipientKey()
	if err != nil {
		b.Fatal(err)
	}
	for _, n := range benchBodySizes {
		req := requestOfSize(n)
		b.Run(bodySizeName(n), func(b *testing.B) {
			b.SetBytes(int64(n))
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if _, err := SealRequest(encPub, req, nil, benchProviderID, ephPub); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// BenchmarkOpenRequest measures the enclave-side path: recompute the AAD, open,
// and reconstruct the request. OpenRequest sets up a fresh receiver each call,
// so opening the same envelope repeatedly is valid.
func BenchmarkOpenRequest(b *testing.B) {
	encPriv, encPub, err := crypto.GenerateRecipientKey()
	if err != nil {
		b.Fatal(err)
	}
	_, ephPub, err := crypto.GenerateRecipientKey()
	if err != nil {
		b.Fatal(err)
	}
	for _, n := range benchBodySizes {
		env, err := SealRequest(encPub, requestOfSize(n), nil, benchProviderID, ephPub)
		if err != nil {
			b.Fatal(err)
		}
		b.Run(bodySizeName(n), func(b *testing.B) {
			b.SetBytes(int64(n))
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if _, err := OpenRequest(encPriv, env); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
