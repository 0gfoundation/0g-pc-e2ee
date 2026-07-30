// Command e2ee-overhead measures how much extra wall-clock time the E2EE layer
// costs versus a plain (no-E2EE) passthrough, for both non-streaming and
// streaming chat completions.
//
// It answers a single question: "if I turn E2EE on, how much slower is a
// request?" — deliberately ignoring TDX/quote verification (a one-off,
// out-of-band step), so the numbers reflect only the per-request sealing work:
//
//	Gateway (client):  seal the request   + open the response
//	Broker  (enclave): open the request   + seal the response
//
// The baseline is the same payload marshaled/unmarshaled at each hop WITHOUT
// crypto — the (de)serialization you pay regardless. The reported "overhead" is
// therefore the marginal cost of E2EE: the HPKE handshake, the ChaCha20-Poly1305
// AEAD, and the JCS canonicalization of the AAD.
//
// Run:
//
//	go run ./cmd/e2ee-overhead              # default iterations
//	go run ./cmd/e2ee-overhead -iter 5000   # more iterations = steadier numbers
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/0gfoundation/0g-pc-e2ee/protocol/crypto"
	"github.com/0gfoundation/0g-pc-e2ee/protocol/wire"
)

const signerAddr = "0x" + "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

// keys holds the fixed keypairs for a run: the provider enc key (the enclave's
// long-lived sealing key) and the client's per-call response ephemeral key. In
// production a fresh ephemeral is generated per request; its keygen cost is
// measured separately in the stage breakdown, not folded into every stage.
type keys struct {
	encPriv crypto.PrivateKey // enclave sealing private key (opens requests)
	encPub  crypto.PublicKey  // enclave sealing public key (client seals to it)
	ephPriv crypto.PrivateKey // client response ephemeral private key (opens responses)
	ephPub  crypto.PublicKey  // client response ephemeral public key (enclave seals to it)
}

func mustKeys() keys {
	encPriv, encPub, err := crypto.GenerateRecipientKey()
	if err != nil {
		panic(err)
	}
	ephPriv, ephPub, err := crypto.GenerateRecipientKey()
	if err != nil {
		panic(err)
	}
	return keys{encPriv, encPub, ephPriv, ephPub}
}

// requestOfSize builds a chat request whose sealed body (`messages` + `tools`)
// is roughly n bytes — a short prompt through a large multi-turn context.
func requestOfSize(n int) wire.Request {
	content, _ := json.Marshal(strings.Repeat("x", n))
	return wire.Request{
		"model":       json.RawMessage(`"gpt-4o"`),
		"temperature": json.RawMessage(`0.7`),
		"stream":      json.RawMessage(`false`),
		"messages":    json.RawMessage(`[{"role":"user","content":` + string(content) + `}]`),
		"tools":       json.RawMessage(`[{"type":"function","function":{"name":"calc"}}]`),
	}
}

// responseOfSize builds a non-streaming response whose `choices` is ~n bytes.
func responseOfSize(n int) wire.Response {
	content, _ := json.Marshal(strings.Repeat("x", n))
	return wire.Response{
		"id":      json.RawMessage(`"chatcmpl-1"`),
		"model":   json.RawMessage(`"gpt-4o"`),
		"created": json.RawMessage(`1700000000`),
		"usage":   json.RawMessage(`{"prompt_tokens":50,"completion_tokens":120,"total_tokens":170}`),
		"choices": json.RawMessage(`[{"index":0,"message":{"role":"assistant","content":` + string(content) + `},"finish_reason":"stop"}]`),
	}
}

// deltaFrame is one SSE delta frame carrying `tok` as the streamed token text —
// the small per-token payload a streaming completion emits many times over.
func deltaFrame(tok string) wire.Response {
	c, _ := json.Marshal(tok)
	return wire.Response{
		"id":      json.RawMessage(`"chatcmpl-1"`),
		"model":   json.RawMessage(`"gpt-4o"`),
		"choices": json.RawMessage(`[{"index":0,"delta":{"content":` + string(c) + `}}]`),
	}
}

// stat is a timed stage: its total wall time over iter iterations.
type stat struct {
	name  string
	total time.Duration
	iter  int
}

func (s stat) perOp() time.Duration {
	if s.iter == 0 {
		return 0
	}
	return s.total / time.Duration(s.iter)
}

// timeIt runs fn iter times and returns the aggregate wall time. fn must do the
// real work each call (it is not allowed to be optimized away — every stage here
// returns a value that feeds the next, and we assert on errors).
func timeIt(name string, iter int, fn func()) stat {
	start := time.Now()
	for i := 0; i < iter; i++ {
		fn()
	}
	return stat{name: name, total: time.Since(start), iter: iter}
}

func fatal(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func main() {
	iter := flag.Int("iter", 2000, "iterations per stage (higher = steadier numbers)")
	flag.Parse()

	fmt.Printf("E2EE per-request overhead — %d iterations/stage, %s\n", *iter, runtimeLabel())
	fmt.Println(strings.Repeat("=", 78))
	fmt.Println("Baseline = same payload JSON-marshaled/unmarshaled at each hop, no crypto.")
	fmt.Println("Overhead = E2EE round-trip time minus that baseline (the cost E2EE adds).")
	fmt.Println("TDX/quote verification is intentionally excluded (one-off, out of band).")
	fmt.Println()

	reportNonStreaming(*iter)
	fmt.Println()
	reportStreaming(*iter)
}

func runtimeLabel() string {
	return fmt.Sprintf("go measurement (wall clock)")
}

// ---- non-streaming ---------------------------------------------------------

func reportNonStreaming(iter int) {
	fmt.Println("NON-STREAMING (single request, single full response)")
	fmt.Println(strings.Repeat("-", 78))

	type sizeCase struct {
		label     string
		reqBytes  int
		respBytes int
	}
	cases := []sizeCase{
		{"small  (~0.5 KB prompt / 0.5 KB reply)", 512, 512},
		{"medium (~4 KB prompt / 2 KB reply)", 4 << 10, 2 << 10},
		{"large  (~32 KB context / 8 KB reply)", 32 << 10, 8 << 10},
	}

	fmt.Printf("%-40s %11s %11s %11s %8s\n", "payload", "E2EE", "plain", "overhead", "×")
	for _, c := range cases {
		k := mustKeys()
		req := requestOfSize(c.reqBytes)
		resp := responseOfSize(c.respBytes)

		// --- E2EE stages (client seal, broker open, broker seal, client open) ---
		// Pre-seal a stable envelope for the open stages so each stage times only
		// its own work.
		env, err := wire.SealRequest(k.encPub, req, nil, signerAddr, k.ephPub)
		fatal(err)
		sealedResp, err := wire.SealResponse(k.ephPub, resp, nil)
		fatal(err)

		gwSeal := timeIt("gw-seal-req", iter, func() {
			_, err := wire.SealRequest(k.encPub, req, nil, signerAddr, k.ephPub)
			fatal(err)
		})
		brOpen := timeIt("br-open-req", iter, func() {
			_, err := wire.OpenRequest(k.encPriv, env)
			fatal(err)
		})
		brSeal := timeIt("br-seal-resp", iter, func() {
			_, err := wire.SealResponse(k.ephPub, resp, nil)
			fatal(err)
		})
		gwOpen := timeIt("gw-open-resp", iter, func() {
			_, err := wire.OpenResponse(k.ephPriv, sealedResp)
			fatal(err)
		})
		e2ee := gwSeal.perOp() + brOpen.perOp() + brSeal.perOp() + gwOpen.perOp()

		// --- plain baseline: marshal/unmarshal at each hop, no crypto ---
		reqBytes, _ := json.Marshal(req)
		respBytes, _ := json.Marshal(resp)
		plain := timeIt("plain", iter, func() {
			b, _ := json.Marshal(req) // gateway serialize
			var r wire.Request
			_ = json.Unmarshal(b, &r)   // broker deserialize
			b2, _ := json.Marshal(resp) // broker serialize
			var rr wire.Response
			_ = json.Unmarshal(b2, &rr) // gateway deserialize
			_ = reqBytes
			_ = respBytes
		}).perOp()

		overhead := e2ee - plain
		fmt.Printf("%-40s %11s %11s %11s %7.1fx\n",
			c.label, dur(e2ee), dur(plain), dur(overhead), ratio(e2ee, plain))
		fmt.Printf("    breakdown  gw-seal %s | br-open %s | br-seal %s | gw-open %s\n",
			dur(gwSeal.perOp()), dur(brOpen.perOp()), dur(brSeal.perOp()), dur(gwOpen.perOp()))
	}
}

// ---- streaming -------------------------------------------------------------

func reportStreaming(iter int) {
	fmt.Println("STREAMING (single request, then N sealed delta frames + final)")
	fmt.Println(strings.Repeat("-", 78))

	// Fewer iterations for streaming: each iteration seals+opens N frames, so it
	// already does N× the per-op work. Scale down to keep total runtime sane.
	streamIter := iter / 4
	if streamIter < 50 {
		streamIter = 50
	}

	type streamCase struct {
		label  string
		frames int
	}
	cases := []streamCase{
		{"short  (32 tokens)", 32},
		{"medium (256 tokens)", 256},
		{"long   (1024 tokens)", 1024},
	}

	// A representative small prompt for the request half of every stream case.
	reqBytes := 1 << 10

	fmt.Printf("%-24s %11s %11s %11s %8s %14s\n", "stream length", "E2EE", "plain", "overhead", "×", "per-frame E2EE")
	for _, c := range cases {
		k := mustKeys()
		req := requestOfSize(reqBytes)
		tokens := makeTokens(c.frames)

		// E2EE full stream round trip: seal req, open req, seal N frames, open N.
		e2eeStream := timeIt("e2ee-stream", streamIter, func() {
			env, err := wire.SealRequest(k.encPub, req, nil, signerAddr, k.ephPub)
			fatal(err)
			_, err = wire.OpenRequest(k.encPriv, env)
			fatal(err)

			sealer, err := wire.NewResponseSealer(k.ephPub)
			fatal(err)
			frames := make([]wire.Response, c.frames)
			for i, tok := range tokens {
				f, err := sealer.SealFrame(deltaFrame(tok), nil, i == len(tokens)-1)
				fatal(err)
				frames[i] = f
			}

			opener, err := wire.NewResponseOpener(k.ephPriv, frames[0])
			fatal(err)
			for _, f := range frames {
				_, err := opener.OpenFrame(f)
				fatal(err)
			}
		}).perOp()

		// Plain baseline: same shape, JSON only.
		plainStream := timeIt("plain-stream", streamIter, func() {
			b, _ := json.Marshal(req)
			var r wire.Request
			_ = json.Unmarshal(b, &r)
			for _, tok := range tokens {
				fb, _ := json.Marshal(deltaFrame(tok)) // broker serialize frame
				var fr wire.Response
				_ = json.Unmarshal(fb, &fr) // gateway deserialize frame
			}
		}).perOp()

		overhead := e2eeStream - plainStream
		perFrame := time.Duration(0)
		if c.frames > 0 {
			perFrame = overhead / time.Duration(c.frames)
		}
		fmt.Printf("%-24s %11s %11s %11s %7.1fx %14s\n",
			c.label, dur(e2eeStream), dur(plainStream), dur(overhead), ratio(e2eeStream, plainStream), dur(perFrame))
	}

	// Isolate the fixed per-request handshake cost (one X25519 keygen + encap)
	// vs the marginal per-frame AEAD cost, since streaming amortizes the former.
	k := mustKeys()
	sealer, err := wire.NewResponseSealer(k.ephPub)
	fatal(err)
	frame := deltaFrame("hello")
	perFrameSeal := timeIt("seal-frame", iter, func() {
		_, err := sealer.SealFrame(frame, nil, false)
		fatal(err)
	}).perOp()
	handshake := timeIt("handshake", iter, func() {
		_, err := wire.NewResponseSealer(k.ephPub)
		fatal(err)
	}).perOp()
	fmt.Printf("\n  fixed per-stream handshake (HPKE setup): %s | marginal per-frame seal (AEAD+JSON): %s\n",
		dur(handshake), dur(perFrameSeal))
}

func makeTokens(n int) []string {
	toks := make([]string, n)
	for i := range toks {
		toks[i] = " word" // ~5-byte token, typical SSE delta
	}
	return toks
}

// ---- formatting ------------------------------------------------------------

func dur(d time.Duration) string {
	switch {
	case d >= time.Millisecond:
		return fmt.Sprintf("%.3fms", float64(d)/float64(time.Millisecond))
	case d >= time.Microsecond:
		return fmt.Sprintf("%.2fµs", float64(d)/float64(time.Microsecond))
	default:
		return fmt.Sprintf("%dns", d.Nanoseconds())
	}
}

func ratio(e2ee, plain time.Duration) float64 {
	if plain == 0 {
		return 0
	}
	return float64(e2ee) / float64(plain)
}
