// Command mockupstream is the load-test fixture for the gateway: one process
// that impersonates EVERYTHING the gateway talks to upstream — the 0G router's
// route-preview and chat-completions endpoints, a provider broker's e2ee pubkey
// endpoint, the sealed inference itself, and the §8 signature endpoint.
//
// It exists because a load test against the real router and real providers
// measures the PROVIDER's capacity (inference dominates every other cost) and
// costs real inference spend, so it cannot answer "how much concurrency can the
// gateway itself carry". Pointing the gateway at this fixture replaces the
// variable part of the chain with a controllable one — a configurable
// time-to-first-token, inter-chunk gap and chunk count, and unlimited capacity —
// so what is left to saturate is the gateway: its sealing, its per-request
// control-plane round trips, its connection pooling, and its CPU. See
// loadtest/README.md for the method this fits into.
//
// It is a FIXTURE, never a deployment: it holds its own X25519 recipient key and
// its own secp256k1 signing key, both generated fresh at startup, so nothing it
// serves is attested and no measurement of it means anything. It emits no
// attestation quote, so the gateway must run with -attest=false against it
// (and therefore -onchain=false and -warm=false, which require it). Response
// signing is real (a genuine EIP-191 secp256k1 signature over the SPEC §8
// binding, which the gateway verifies fail-closed), so -verify-responses=true
// does work — that path is one of the things worth measuring.
//
// Because it does real HPKE work (it opens every sealed request and seals every
// response frame, the same work a provider enclave does), it is not free: give
// it its own CPU — ideally its own host — or it becomes the bottleneck and you
// end up measuring the fixture instead of the gateway.
//
//	go run ./cmd/mockupstream -listen :8080 -ttft 200ms -chunk-interval 40ms -chunks 64
package main

import (
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"strconv"
	"time"
)

func main() {
	cfg := config{}
	listen := flag.String("listen", envOr("MOCK_LISTEN", ":8080"), "address to listen on (env MOCK_LISTEN)")
	flag.DurationVar(&cfg.TTFT, "ttft", envDuration("MOCK_TTFT", 200*time.Millisecond),
		"simulated time to first token: how long a completion waits before its first response frame (env MOCK_TTFT)")
	flag.DurationVar(&cfg.ChunkInterval, "chunk-interval", envDuration("MOCK_CHUNK_INTERVAL", 40*time.Millisecond),
		"simulated inter-token gap between subsequent streamed frames (env MOCK_CHUNK_INTERVAL)")
	flag.IntVar(&cfg.Chunks, "chunks", envInt("MOCK_CHUNKS", 64),
		"number of response frames per streamed completion; a non-streamed completion waits the equivalent total time and answers in one frame (env MOCK_CHUNKS)")
	flag.IntVar(&cfg.ChunkBytes, "chunk-bytes", envInt("MOCK_CHUNK_BYTES", 16),
		"content bytes per response frame — the knob for response size, which drives the gateway's per-frame AEAD open cost (env MOCK_CHUNK_BYTES)")
	flag.IntVar(&cfg.Providers, "providers", envInt("MOCK_PROVIDERS", 1),
		"how many candidates the route preview returns; >1 exercises the gateway's fallback chain length without changing the happy path (env MOCK_PROVIDERS)")
	flag.DurationVar(&cfg.PreviewDelay, "preview-delay", envDuration("MOCK_PREVIEW_DELAY", 0),
		"simulated router latency on the per-request route-preview call (env MOCK_PREVIEW_DELAY)")
	flag.DurationVar(&cfg.SignatureDelay, "signature-delay", envDuration("MOCK_SIGNATURE_DELAY", 0),
		"simulated broker latency on the §8 signature fetch, which the gateway makes once per response when -verify-responses is on (env MOCK_SIGNATURE_DELAY)")
	flag.BoolVar(&cfg.Sign, "sign", envBool("MOCK_SIGN", true),
		"compute and serve the §8 response signature. Required by a gateway running -verify-responses; turn it OFF when the gateway is not verifying, so the fixture does not pay the per-frame binding cost for a signature nobody fetches (env MOCK_SIGN)")
	flag.StringVar(&cfg.Advertise, "advertise", envOr("MOCK_ADVERTISE", ""),
		"base URL to advertise as the provider endpoint in route previews, e.g. http://mockupstream:8080. Empty derives it from each request's Host header, which is what a container-network or loopback run wants (env MOCK_ADVERTISE)")
	flag.StringVar(&cfg.Model, "model", envOr("MOCK_MODEL", "mock-model"),
		"canonical model id the preview advertises and the responses report (env MOCK_MODEL)")
	flag.IntVar(&cfg.SignatureCache, "signature-cache", envInt("MOCK_SIGNATURE_CACHE", 1<<16),
		"how many recent response signatures to retain for fetching; the oldest is evicted past this, so a sustained load cannot grow the fixture's memory without bound. Keep it well ABOVE peak concurrency: a signature evicted before the gateway fetches it surfaces as a fail-closed verification error that looks like a gateway fault (env MOCK_SIGNATURE_CACHE)")
	flag.Parse()

	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))

	srv, err := newServer(cfg)
	if err != nil {
		logger.Error("mockupstream: invalid configuration", "err", err)
		os.Exit(1)
	}

	logger.Info("mockupstream listening",
		"listen", *listen,
		"ttft", cfg.TTFT,
		"chunk_interval", cfg.ChunkInterval,
		"chunks", cfg.Chunks,
		"chunk_bytes", cfg.ChunkBytes,
		"providers", cfg.Providers,
		"sign", cfg.Sign,
		"model", cfg.Model,
		"signer_address", srv.signerAddr,
		"simulated_completion", cfg.TTFT+time.Duration(cfg.Chunks-1)*cfg.ChunkInterval)

	httpSrv := &http.Server{
		Addr:    *listen,
		Handler: srv.handler(),
		// Bound the header wait only. No WriteTimeout: a streamed completion is
		// long-lived by design, and a write deadline would cut it mid-stream and
		// show up in the results as gateway-side errors that never happened.
		ReadHeaderTimeout: 10 * time.Second,
	}
	if err := httpSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		logger.Error("mockupstream: server exited", "err", err)
		os.Exit(1)
	}
}

// envOr / envBool / envInt / envDuration mirror proxycli's env-as-flag-default
// convention (flag > env > built-in default) so the fixture is configurable the
// same way the binaries it stands in front of are — it is driven from a compose
// file, where env is the only ergonomic knob. A set-but-unparseable value is
// fatal rather than silently defaulting.
func envOr(key, def string) string {
	if v, ok := os.LookupEnv(key); ok {
		return v
	}
	return def
}

func envBool(key string, def bool) bool {
	v, ok := os.LookupEnv(key)
	if !ok {
		return def
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		fatalEnv(key, v, "a boolean (true/false)")
	}
	return b
}

func envInt(key string, def int) int {
	v, ok := os.LookupEnv(key)
	if !ok {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		fatalEnv(key, v, "an integer")
	}
	return n
}

func envDuration(key string, def time.Duration) time.Duration {
	v, ok := os.LookupEnv(key)
	if !ok {
		return def
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		fatalEnv(key, v, "a Go duration (e.g. 200ms, 4m)")
	}
	return d
}

func fatalEnv(key, value, want string) {
	fmt.Fprintf(os.Stderr, "mockupstream: invalid %s=%q: must be %s\n", key, value, want)
	os.Exit(1)
}
