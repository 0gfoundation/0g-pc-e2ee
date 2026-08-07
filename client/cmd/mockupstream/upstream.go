package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
	"golang.org/x/crypto/sha3"

	"github.com/0gfoundation/0g-pc-e2ee/protocol/crypto"
	"github.com/0gfoundation/0g-pc-e2ee/protocol/proof"
	"github.com/0gfoundation/0g-pc-e2ee/protocol/wire"
)

// maxRequestBytes caps a sealed request body read. Generous (a long prompt is a
// legitimate load-test shape) but bounded, so a runaway generator cannot make the
// fixture the thing that runs out of memory.
const maxRequestBytes = 32 << 20

// b64 is base64url without padding — the enc_pub / enc encoding on the wire
// (SPEC §3), matching how a real broker publishes its key.
var b64 = base64.RawURLEncoding

// config is the fixture's simulated-provider shape. See main.go for the flag and
// env-var spelling of each field.
type config struct {
	TTFT           time.Duration
	ChunkInterval  time.Duration
	Chunks         int
	ChunkBytes     int
	Providers      int
	PreviewDelay   time.Duration
	SignatureDelay time.Duration
	Sign           bool
	Advertise      string
	Model          string
	SignatureCache int
}

// server is the fixture: the router, the broker and the provider enclave in one
// process. Everything it precomputes at startup is immutable afterwards, so the
// only shared mutable state on the request path is the signature store (which is
// mutex-guarded) — the handlers are otherwise allocation-light and lock-free,
// which is what keeps the fixture from becoming the bottleneck.
type server struct {
	cfg config

	// The provider enclave's HPKE identity. Generated fresh per process: nothing
	// here is attested, and nothing depends on it being stable across restarts
	// (the gateway re-fetches it, and its pubkey cache TTL is minutes).
	encPriv crypto.PrivateKey
	encPub  crypto.PublicKey

	// The provider enclave's §8 response-signing identity. The address is what a
	// gateway running -verify-responses anchors on; it reaches the gateway through
	// the pubkey reply's signer_address, exactly as a real broker's does.
	signKey    *secp256k1.PrivateKey
	signerAddr string

	sigs *sigStore

	// Precomputed response bodies and JSON fragments. The per-request work is then
	// only the parts that genuinely vary (ids, timestamps, the seal itself).
	pubkeyBody    []byte
	providerAddrs []string
	providersBody []byte
	modelRaw      json.RawMessage
	firstChoices  json.RawMessage
	chunkChoices  json.RawMessage
	finalChoices  json.RawMessage
	fullChoices   json.RawMessage
	usageRaw      json.RawMessage
}

func newServer(cfg config) (*server, error) {
	if cfg.Chunks < 1 {
		return nil, fmt.Errorf("-chunks must be at least 1, got %d", cfg.Chunks)
	}
	if cfg.ChunkBytes < 1 {
		return nil, fmt.Errorf("-chunk-bytes must be at least 1, got %d", cfg.ChunkBytes)
	}
	if cfg.Providers < 1 {
		return nil, fmt.Errorf("-providers must be at least 1, got %d", cfg.Providers)
	}
	if cfg.SignatureCache < 1 {
		return nil, fmt.Errorf("-signature-cache must be at least 1, got %d", cfg.SignatureCache)
	}
	if strings.TrimSpace(cfg.Model) == "" {
		return nil, fmt.Errorf("-model must not be empty")
	}
	if cfg.Advertise != "" && !strings.HasPrefix(cfg.Advertise, "http://") && !strings.HasPrefix(cfg.Advertise, "https://") {
		return nil, fmt.Errorf("-advertise %q must be an absolute http(s) URL", cfg.Advertise)
	}

	encPriv, encPub, err := crypto.GenerateRecipientKey()
	if err != nil {
		return nil, fmt.Errorf("generate recipient key: %w", err)
	}
	signKey, err := secp256k1.GeneratePrivateKey()
	if err != nil {
		return nil, fmt.Errorf("generate signing key: %w", err)
	}

	s := &server{
		cfg:        cfg,
		encPriv:    encPriv,
		encPub:     encPub,
		signKey:    signKey,
		signerAddr: addressOf(signKey.PubKey()),
		sigs:       newSigStore(cfg.SignatureCache),
	}

	keyID := sha256.Sum256(encPub)
	s.pubkeyBody, err = json.Marshal(map[string]any{
		"v":              wire.Version,
		"kem_id":         wire.KEMID,
		"enc_pub":        b64.EncodeToString(encPub),
		"key_id":         b64.EncodeToString(keyID[:8]),
		"signer_address": s.signerAddr,
	})
	if err != nil {
		return nil, fmt.Errorf("encode pubkey body: %w", err)
	}

	// Candidate addresses are synthetic but well-formed (0x + 40 hex): the gateway
	// validates the shape and pins the head candidate with X-0G-Provider-Address.
	s.providerAddrs = make([]string, cfg.Providers)
	catalog := make([]map[string]string, cfg.Providers)
	for i := range s.providerAddrs {
		s.providerAddrs[i] = fmt.Sprintf("0x%040x", i+1)
		catalog[i] = map[string]string{"address": s.providerAddrs[i]}
	}
	s.providersBody, err = json.Marshal(map[string]any{"object": "list", "data": catalog})
	if err != nil {
		return nil, fmt.Errorf("encode providers body: %w", err)
	}

	content := strings.Repeat("x", cfg.ChunkBytes)
	full := strings.Repeat(content, cfg.Chunks)
	if err := marshalInto(&s.modelRaw, cfg.Model); err != nil {
		return nil, err
	}
	// Streaming frames: the first carries the role (as OpenAI's does), the last
	// carries finish_reason and no content. Only "choices" is sealed, so these are
	// the plaintext the gateway's per-frame AEAD open has to produce.
	if err := marshalInto(&s.firstChoices, []any{map[string]any{
		"index": 0, "delta": map[string]any{"role": "assistant", "content": content},
	}}); err != nil {
		return nil, err
	}
	if err := marshalInto(&s.chunkChoices, []any{map[string]any{
		"index": 0, "delta": map[string]any{"content": content},
	}}); err != nil {
		return nil, err
	}
	if err := marshalInto(&s.finalChoices, []any{map[string]any{
		"index": 0, "delta": map[string]any{}, "finish_reason": "stop",
	}}); err != nil {
		return nil, err
	}
	if err := marshalInto(&s.fullChoices, []any{map[string]any{
		"index":         0,
		"message":       map[string]any{"role": "assistant", "content": full},
		"finish_reason": "stop",
	}}); err != nil {
		return nil, err
	}
	if err := marshalInto(&s.usageRaw, map[string]any{
		"prompt_tokens": 0, "completion_tokens": cfg.Chunks, "total_tokens": cfg.Chunks,
	}); err != nil {
		return nil, err
	}
	return s, nil
}

// handler mounts the four upstream surfaces the gateway uses. They are all served
// by one process on one port because the gateway reaches them the same way it
// would in production: the router base URL points here, and the provider
// endpoint the route preview advertises points here too.
func (s *server) handler() http.Handler {
	mux := http.NewServeMux()
	// Router surface.
	mux.HandleFunc("POST /v1/routing/preview", s.handlePreview)
	mux.HandleFunc("POST /v1/chat/completions", s.handleCompletions)
	mux.HandleFunc("GET /v1/providers", s.handleProviders)
	// Provider-broker surface (reached at the endpoint the preview advertises).
	mux.HandleFunc("GET /v1/e2ee/pubkey", s.handlePubkey)
	mux.HandleFunc("GET /v1/proxy/signature/{chatKey}", s.handleSignature)
	// The broker's OWN sealed-inference path, under its "/v1/proxy" service
	// prefix. The routed path never uses it (the sealed request goes through the
	// router's /v1/chat/completions above), but direct-broker mode
	// (-provider-url) posts here — which is the only way to exercise
	// -verify-responses without attestation, since router mode requires the signer
	// to come from a verified quote. Same handler: the two modes differ in how the
	// gateway got here, not in what it sends.
	mux.HandleFunc("POST /v1/proxy/chat/completions", s.handleCompletions)
	// There is deliberately no GET /v1/quote: the fixture cannot produce a genuine
	// TDX quote, so a gateway pointed at it must run with -attest=false. Leaving
	// the route absent makes that a loud 404 at startup rather than a confusing
	// DCAP failure per request.
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = io.WriteString(w, "ok\n")
	})
	return mux
}

// handlePreview answers the gateway's per-request route preview with the
// configured number of candidates, all pointing back at this process.
func (s *server) handlePreview(w http.ResponseWriter, r *http.Request) {
	drain(r.Body)
	if !sleep(r.Context(), s.cfg.PreviewDelay) {
		return
	}
	endpoint := s.endpointFor(r)
	providers := make([]map[string]string, len(s.providerAddrs))
	for i, addr := range s.providerAddrs {
		providers[i] = map[string]string{
			"address":      addr,
			"canonical_id": s.cfg.Model,
			"model_id":     s.cfg.Model,
			"endpoint":     endpoint,
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"object":       "routing.preview",
		"service_type": "chatbot",
		"providers":    providers,
	})
}

func (s *server) handleProviders(w http.ResponseWriter, r *http.Request) {
	writeRaw(w, http.StatusOK, s.providersBody)
}

func (s *server) handlePubkey(w http.ResponseWriter, r *http.Request) {
	writeRaw(w, http.StatusOK, s.pubkeyBody)
}

// handleSignature serves the §8 ChatSignature the completion handler cached under
// the chatKey it returned in ZG-Res-Key. A miss is a 404, which is exactly what a
// real broker returns before the signature is written and what the gateway's
// fetcher retries on.
func (s *server) handleSignature(w http.ResponseWriter, r *http.Request) {
	if !sleep(r.Context(), s.cfg.SignatureDelay) {
		return
	}
	sig, ok := s.sigs.get(r.PathValue("chatKey"))
	if !ok {
		writeError(w, http.StatusNotFound, "no signature for that chatKey")
		return
	}
	writeJSON(w, http.StatusOK, sig)
}

// handleCompletions is the sealed inference path: open the gateway's sealed
// request with the fixture's recipient key (the same HPKE work a provider enclave
// does, so a mis-sealed request fails here rather than silently passing), then
// answer with sealed frames paced by the configured TTFT / inter-chunk gap.
func (s *server) handleCompletions(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(io.LimitReader(r.Body, maxRequestBytes))
	if err != nil {
		writeError(w, http.StatusBadRequest, "read request body")
		return
	}
	var env wire.Request
	if err := json.Unmarshal(body, &env); err != nil {
		writeError(w, http.StatusBadRequest, "request body is not a JSON object")
		return
	}
	meta, err := env.E2EE()
	if err != nil {
		writeError(w, http.StatusBadRequest, "request carries no readable _e2ee metadata")
		return
	}
	if _, err := wire.OpenRequest(s.encPriv, env); err != nil {
		// A real enclave fails closed here too. Under load this is the check that
		// catches a gateway change that breaks sealing, instead of the load test
		// happily measuring a path that produces garbage.
		writeError(w, http.StatusBadRequest, "sealed request did not open")
		return
	}
	ephPub, err := b64.DecodeString(meta.ClientEphPub)
	if err != nil || len(ephPub) != 32 {
		writeError(w, http.StatusBadRequest, "bad _e2ee.client_eph_pub")
		return
	}

	// The §8 request half is bound at open time, exactly as the broker does it —
	// before the request envelope goes out of scope.
	var reqH [32]byte
	if s.cfg.Sign {
		if reqH, err = proof.FrameBindingHash(env); err != nil {
			writeError(w, http.StatusBadRequest, "cannot bind the sealed request")
			return
		}
	}

	chatKey, err := newChatKey()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "generate chat key")
		return
	}
	created := time.Now().Unix()
	var idRaw, createdRaw json.RawMessage
	if err := marshalInto(&idRaw, "chatcmpl-"+chatKey); err != nil {
		writeError(w, http.StatusInternalServerError, "encode response id")
		return
	}
	if err := marshalInto(&createdRaw, created); err != nil {
		writeError(w, http.StatusInternalServerError, "encode response timestamp")
		return
	}

	if streamRequested(env) {
		s.serveStream(w, r, ephPub, reqH, chatKey, idRaw, createdRaw)
		return
	}
	s.serveBuffered(w, r, ephPub, reqH, chatKey, idRaw, createdRaw)
}

// serveBuffered answers a non-streaming completion: wait out the time the same
// content would have taken to stream, then return one sealed final frame.
func (s *server) serveBuffered(w http.ResponseWriter, r *http.Request, ephPub []byte, reqH [32]byte, chatKey string, idRaw, createdRaw json.RawMessage) {
	if !sleep(r.Context(), s.completionDuration()) {
		return
	}
	frame := wire.Response{
		"id":      idRaw,
		"object":  json.RawMessage(`"chat.completion"`),
		"created": createdRaw,
		"model":   s.modelRaw,
		"usage":   s.usageRaw,
		"choices": s.fullChoices,
	}
	sealed, err := wire.SealResponse(crypto.PublicKey(ephPub), frame, nil)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "seal response")
		return
	}
	// Store the signature BEFORE the body goes out: the gateway fetches it as soon
	// as it has the response, so writing it afterwards would race its first attempt
	// (survivable — the fetcher retries a 404 — but it would show up as latency
	// that the real broker, which caches at end-of-response, does not add).
	if s.cfg.Sign {
		respH, err := proof.FrameBindingHash(sealed)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "bind sealed response")
			return
		}
		s.sigs.put(chatKey, s.sign(proof.SignedTextE2EEFromHashes(reqH, respH)))
	}
	w.Header().Set("ZG-Res-Key", chatKey)
	writeJSON(w, http.StatusOK, sealed)
}

// serveStream answers a streaming completion as SSE: one sealed frame per chunk,
// paced by TTFT then the inter-chunk gap, terminated by the final frame and
// `data: [DONE]`.
func (s *server) serveStream(w http.ResponseWriter, r *http.Request, ephPub []byte, reqH [32]byte, chatKey string, idRaw, createdRaw json.RawMessage) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		writeError(w, http.StatusInternalServerError, "streaming unsupported")
		return
	}
	sealer, err := wire.NewResponseSealer(crypto.PublicKey(ephPub))
	if err != nil {
		writeError(w, http.StatusInternalServerError, "set up response sealing")
		return
	}
	var binder *proof.StreamBinder
	if s.cfg.Sign {
		binder = proof.NewStreamBinderFromReqHash(reqH)
	}

	// Headers go out immediately, like a real provider's: the simulated TTFT is the
	// wait for the first TOKEN, not for the response head, and conflating the two
	// would move the gateway's own header handling out of the measurement.
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("ZG-Res-Key", chatKey)
	w.WriteHeader(http.StatusOK)
	flusher.Flush()

	pace := newPacer()
	defer pace.stop()
	buf := &bytes.Buffer{}
	ctx := r.Context()
	for i := 0; i < s.cfg.Chunks; i++ {
		gap := s.cfg.ChunkInterval
		if i == 0 {
			gap = s.cfg.TTFT
		}
		if !pace.wait(ctx, gap) {
			return
		}
		final := i == s.cfg.Chunks-1
		frame := wire.Response{
			"id":      idRaw,
			"object":  json.RawMessage(`"chat.completion.chunk"`),
			"created": createdRaw,
			"model":   s.modelRaw,
			"choices": s.chunkChoices,
		}
		switch {
		case i == 0:
			frame["choices"] = s.firstChoices
		case final:
			frame["choices"] = s.finalChoices
			frame["usage"] = s.usageRaw
		}
		sealed, err := sealer.SealFrame(frame, nil, final)
		if err != nil {
			// Mid-stream: the status is long gone, so the only honest signal is to cut
			// the connection, which the gateway reports as a truncated stream.
			return
		}
		if binder != nil {
			if err := binder.AddFrame(sealed); err != nil {
				return
			}
		}
		// The signature must be readable by the time the gateway finishes the stream,
		// and it finishes on the final frame — so store it before that frame is on
		// the wire, not after [DONE].
		if final && binder != nil {
			text, err := binder.Text()
			if err != nil {
				return
			}
			s.sigs.put(chatKey, s.sign(text))
		}
		buf.Reset()
		buf.WriteString("data: ")
		if err := json.NewEncoder(buf).Encode(sealed); err != nil { // Encode appends the newline
			return
		}
		buf.WriteString("\n")
		if _, err := w.Write(buf.Bytes()); err != nil {
			return
		}
		flusher.Flush()
	}
	_, _ = io.WriteString(w, "data: [DONE]\n\n")
	flusher.Flush()
}

// completionDuration is how long the configured chunk schedule takes end to end —
// what a non-streaming completion waits, so streaming and buffered runs at the
// same settings are comparable.
func (s *server) completionDuration() time.Duration {
	return s.cfg.TTFT + time.Duration(s.cfg.Chunks-1)*s.cfg.ChunkInterval
}

// endpointFor is the provider endpoint advertised in a route preview. Deriving it
// from the request Host by default means the fixture needs no configuration to
// work behind a container network name, a loopback port, or an httptest server —
// whatever the gateway used to reach it is what it will be told to use.
func (s *server) endpointFor(r *http.Request) string {
	if s.cfg.Advertise != "" {
		return strings.TrimRight(s.cfg.Advertise, "/")
	}
	return "http://" + r.Host
}

// sign produces the §8 ChatSignature over text: an EIP-191 personal_sign
// signature in go-ethereum's r‖s‖v layout, which is what client/sig.Recover — the
// gateway's verifier — expects.
func (s *server) sign(text string) proof.ChatSignature {
	compact := ecdsa.SignCompact(s.signKey, eip191Hash(text), false) // [v‖r‖s], v = 27+recid
	raw := make([]byte, 65)
	copy(raw, compact[1:])
	raw[64] = compact[0] - 27
	return proof.ChatSignature{
		Text:           text,
		Signature:      "0x" + hex.EncodeToString(raw),
		SigningAddress: s.signerAddr,
		SigningAlgo:    "secp256k1-eip191",
	}
}

// sigStore retains the most recent signatures in a fixed-size ring, so a load run
// of any length holds a bounded amount of memory: a signature is only ever fetched
// moments after its response, so evicting the oldest is free in practice.
type sigStore struct {
	mu   sync.Mutex
	m    map[string]proof.ChatSignature
	ring []string
	next int
}

func newSigStore(size int) *sigStore {
	return &sigStore{m: make(map[string]proof.ChatSignature, size), ring: make([]string, size)}
}

func (s *sigStore) put(key string, sig proof.ChatSignature) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if evicted := s.ring[s.next]; evicted != "" {
		delete(s.m, evicted)
	}
	s.ring[s.next] = key
	s.next = (s.next + 1) % len(s.ring)
	s.m[key] = sig
}

func (s *sigStore) get(key string) (proof.ChatSignature, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sig, ok := s.m[key]
	return sig, ok
}

// pacer is a single reusable timer for one request's chunk schedule. A fresh
// time.After per chunk would allocate a timer per token per request — at load-test
// concurrency that is enough garbage to distort what is being measured.
type pacer struct{ t *time.Timer }

func newPacer() *pacer {
	t := time.NewTimer(time.Hour)
	if !t.Stop() {
		<-t.C
	}
	return &pacer{t: t}
}

func (p *pacer) stop() { p.t.Stop() }

// wait blocks for d, reporting false if ctx ended first (a disconnected caller —
// stop producing for it).
func (p *pacer) wait(ctx context.Context, d time.Duration) bool {
	if d <= 0 {
		return ctx.Err() == nil
	}
	p.t.Reset(d)
	select {
	case <-ctx.Done():
		if !p.t.Stop() {
			<-p.t.C
		}
		return false
	case <-p.t.C:
		return true
	}
}

// sleep is pacer.wait for a one-shot delay.
func sleep(ctx context.Context, d time.Duration) bool {
	if d <= 0 {
		return ctx.Err() == nil
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}

// streamRequested reads the cleartext "stream" field. It is not a sealed field,
// so the fixture reads it straight off the envelope, as the router does.
func streamRequested(env wire.Request) bool {
	raw, ok := env["stream"]
	if !ok {
		return false
	}
	var stream bool
	return json.Unmarshal(raw, &stream) == nil && stream
}

// newChatKey returns a fresh handle for the ZG-Res-Key header. Hex keeps it inside
// the broker's [A-Za-z0-9_-]{1,64} allowlist, which the gateway's fetcher enforces
// before putting it in a URL path.
func newChatKey() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}

// eip191Hash = keccak256("\x19Ethereum Signed Message:\n" + len(text) + text),
// matching go-ethereum's accounts.TextHash — the hash client/sig.Recover recovers
// over.
func eip191Hash(text string) []byte {
	h := sha3.NewLegacyKeccak256()
	fmt.Fprintf(h, "\x19Ethereum Signed Message:\n%d", len(text))
	_, _ = io.WriteString(h, text)
	return h.Sum(nil)
}

// addressOf = "0x" + hex(keccak256(uncompressed_pubkey_without_prefix)[12:]).
func addressOf(pub *secp256k1.PublicKey) string {
	raw := pub.SerializeUncompressed() // 0x04 ‖ X(32) ‖ Y(32)
	h := sha3.NewLegacyKeccak256()
	h.Write(raw[1:])
	sum := h.Sum(nil)
	return "0x" + hex.EncodeToString(sum[12:])
}

func marshalInto(dst *json.RawMessage, v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return fmt.Errorf("encode %T: %w", v, err)
	}
	*dst = b
	return nil
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	b, err := json.Marshal(v)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "encode response")
		return
	}
	writeRaw(w, status, b)
}

func writeRaw(w http.ResponseWriter, status int, body []byte) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write(body)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]any{
		"error": map[string]any{"message": "mockupstream: " + msg, "type": "mockupstream_error"},
	})
}

// drain consumes and closes a request body the handler does not need, so the
// connection stays reusable instead of being closed and re-dialed — which would
// make the fixture, not the gateway, the source of connection churn.
func drain(body io.ReadCloser) {
	_, _ = io.Copy(io.Discard, io.LimitReader(body, maxRequestBytes))
}
