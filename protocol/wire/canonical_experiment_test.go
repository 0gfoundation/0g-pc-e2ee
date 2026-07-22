package wire

import (
	"encoding/json"
	"testing"

	"github.com/gowebpki/jcs"
)

// This file is a MEASUREMENT EXPERIMENT, not a proposed change. The profiles
// showed canonicalJSON (json.Marshal + jcs.Transform) dominates SealRequest at
// large payloads — ~40% CPU and ~65% allocs, with jcs re-emitting the body's
// big content string byte-by-byte. Before deciding whether to touch the
// canonicalization (which is byte-for-byte load-bearing across Go/TS/Rust), we
// quantify the ceiling: how much would drop if the body were NOT canonicalized
// before sealing.
//
// The plaintext body is JCS'd today only to feed the SPEC §8 signature hash
// (the AEAD itself protects exact bytes regardless of canonical form). If §8
// hashed the bytes as produced/decrypted rather than an independently
// re-derived canonical form, this pass could go away. These benches put a
// number on that "if".

// canonMarshalOnly is the lower bound: assemble the bytes once, no canonical
// re-pass. NOT wire-compatible (numbers/strings/inner key order are not
// normalized, so it would not match a TS/Rust peer) — it exists only to show
// the achievable floor.
func canonMarshalOnly(v any) ([]byte, error) { return json.Marshal(v) }

// bodyOfSize is the sealed body the request path canonicalizes: {messages, tools}.
func bodyOfSize(n int) map[string]json.RawMessage {
	req := requestOfSize(n)
	return map[string]json.RawMessage{
		"messages": req["messages"],
		"tools":    req["tools"],
	}
}

// BenchmarkCanon_Current is today's path: json.Marshal then jcs.Transform.
func BenchmarkCanon_Current(b *testing.B) {
	for _, n := range benchBodySizes {
		body := bodyOfSize(n)
		b.Run(bodySizeName(n), func(b *testing.B) {
			b.SetBytes(int64(n))
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				out, err := canonicalJSON(body)
				if err != nil {
					b.Fatal(err)
				}
				_ = out
			}
		})
	}
}

// BenchmarkCanon_MarshalOnly is the ceiling: drop the canonical re-pass.
func BenchmarkCanon_MarshalOnly(b *testing.B) {
	for _, n := range benchBodySizes {
		body := bodyOfSize(n)
		b.Run(bodySizeName(n), func(b *testing.B) {
			b.SetBytes(int64(n))
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				out, err := canonMarshalOnly(body)
				if err != nil {
					b.Fatal(err)
				}
				_ = out
			}
		})
	}
}

// BenchmarkCanon_TransformOnly isolates the jcs re-pass alone (the marshal
// output fed straight to jcs.Transform), to attribute the split within
// canonicalJSON between the first marshal and the second parse+emit.
func BenchmarkCanon_TransformOnly(b *testing.B) {
	for _, n := range benchBodySizes {
		marshaled, err := json.Marshal(bodyOfSize(n))
		if err != nil {
			b.Fatal(err)
		}
		b.Run(bodySizeName(n), func(b *testing.B) {
			b.SetBytes(int64(n))
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				out, err := jcs.Transform(marshaled)
				if err != nil {
					b.Fatal(err)
				}
				_ = out
			}
		})
	}
}

// TestMarshalOnlyIsNotCanonical documents WHY the ceiling above is only a
// ceiling, not a drop-in: Go's json.Marshal is not RFC 8785. It sorts top-level
// map keys, but does not normalize numbers or re-order keys inside a
// json.RawMessage value, so its bytes diverge from jcs — which is exactly what
// a TS/Rust peer would compute. If this test's diffs were empty, dropping jcs
// would be free; they are not.
func TestMarshalOnlyIsNotCanonical(t *testing.T) {
	// A value whose canonical form differs from Go's default marshal: unsorted
	// inner keys and a non-canonical number, carried through as RawMessage.
	body := map[string]json.RawMessage{
		"messages": json.RawMessage(`[{"z":1,"a":2,"score":1.0e2}]`),
		"tools":    json.RawMessage(`[]`),
	}
	marshalOnly, err := canonMarshalOnly(body)
	if err != nil {
		t.Fatal(err)
	}
	canonical, err := canonicalJSON(body)
	if err != nil {
		t.Fatal(err)
	}
	if string(marshalOnly) == string(canonical) {
		t.Fatalf("expected marshal-only to diverge from JCS, both were:\n%s", canonical)
	}
	t.Logf("marshal-only: %s", marshalOnly)
	t.Logf("jcs canon   : %s", canonical)
}
