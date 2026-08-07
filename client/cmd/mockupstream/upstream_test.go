package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/0gfoundation/0g-pc-e2ee/client/core"
	"github.com/0gfoundation/0g-pc-e2ee/client/route"
	"github.com/0gfoundation/0g-pc-e2ee/client/sig"
	"github.com/0gfoundation/0g-pc-e2ee/protocol/proof"
	"github.com/0gfoundation/0g-pc-e2ee/protocol/wire"
)

// testConfig is the fixture tuned for tests: the same code paths as a load run,
// with the pacing collapsed so the suite stays fast.
func testConfig() config {
	return config{
		TTFT:           time.Millisecond,
		ChunkInterval:  0,
		Chunks:         3,
		ChunkBytes:     4,
		Providers:      1,
		Sign:           true,
		Model:          "mock-model",
		SignatureCache: 16,
	}
}

func newTestFixture(t *testing.T, cfg config) *httptest.Server {
	t.Helper()
	s, err := newServer(cfg)
	if err != nil {
		t.Fatalf("newServer: %v", err)
	}
	ts := httptest.NewServer(s.handler())
	t.Cleanup(ts.Close)
	return ts
}

// newTestClient wires the REAL client core against the fixture, the same way
// proxycli.Build wires the gateway (route resolver + sealing + §8 response
// verification), minus the attestation options the fixture cannot satisfy.
func newTestClient(ts *httptest.Server) *core.Client {
	router := route.New(ts.URL, route.WithSensitiveFields(wire.DefaultSealedFields()))
	return core.NewWithResolver(router,
		core.WithSealFields(wire.DefaultSealedFields()),
		core.WithUnboundFields(wire.DefaultUnboundFields()),
		core.WithResponseVerification(route.NewSignatureFetcher(ts.Client()), sig.Recover),
	)
}

func chatRequest(stream bool) wire.Request {
	req := wire.Request{
		"model":    json.RawMessage(`"mock-model"`),
		"messages": json.RawMessage(`[{"role":"user","content":"hello"}]`),
	}
	if stream {
		req["stream"] = json.RawMessage(`true`)
	}
	return req
}

// The whole point of the fixture is that it is protocol-exact: if the client core
// can seal to it, open its frames, and verify its §8 signature, then a load run
// against it exercises the real gateway path rather than a lookalike. This test is
// what keeps that true as the protocol evolves.
func TestFixtureRoundTripsWithClientCore(t *testing.T) {
	cfg := testConfig()
	ts := newTestFixture(t, cfg)
	c := newTestClient(ts)
	want := strings.Repeat(strings.Repeat("x", cfg.ChunkBytes), cfg.Chunks)

	t.Run("buffered", func(t *testing.T) {
		resp, err := c.Complete(context.Background(), chatRequest(false))
		if err != nil {
			t.Fatalf("Complete: %v", err)
		}
		var choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		}
		if err := json.Unmarshal(resp["choices"], &choices); err != nil {
			t.Fatalf("decode choices: %v", err)
		}
		if len(choices) != 1 || choices[0].Message.Content != want {
			t.Fatalf("content: got %q, want %q", choices, want)
		}
	})

	t.Run("streamed", func(t *testing.T) {
		var got strings.Builder
		frames := 0
		err := c.CompleteStream(context.Background(), chatRequest(true), func(f wire.Response) error {
			frames++
			var choices []struct {
				Delta struct {
					Content string `json:"content"`
				} `json:"delta"`
			}
			if err := json.Unmarshal(f["choices"], &choices); err != nil {
				return err
			}
			for _, ch := range choices {
				got.WriteString(ch.Delta.Content)
			}
			return nil
		})
		if err != nil {
			t.Fatalf("CompleteStream: %v", err)
		}
		if frames != cfg.Chunks {
			t.Errorf("frames: got %d, want %d", frames, cfg.Chunks)
		}
		// The final frame carries finish_reason and no content, so the delivered text
		// is one chunk short of the buffered form — the same shape a real provider's
		// stream has.
		if wantStream := strings.TrimSuffix(want, strings.Repeat("x", cfg.ChunkBytes)); got.String() != wantStream {
			t.Errorf("content: got %q, want %q", got.String(), wantStream)
		}
	})
}

// A one-frame stream is the shortest legitimate load shape, and its single frame
// is both the first and the last — so it must still be terminated (final +
// finish_reason) rather than ending on a content-only frame. The core rejects a
// stream that never delivers a final frame, so this failing looks like a
// truncated-stream error, not a subtly odd payload.
func TestSingleChunkStreamIsTerminated(t *testing.T) {
	cfg := testConfig()
	cfg.Chunks = 1
	ts := newTestFixture(t, cfg)
	c := newTestClient(ts)

	frames := 0
	var finish string
	err := c.CompleteStream(context.Background(), chatRequest(true), func(f wire.Response) error {
		frames++
		var choices []struct {
			FinishReason string `json:"finish_reason"`
			Delta        struct {
				Role    string `json:"role"`
				Content string `json:"content"`
			} `json:"delta"`
		}
		if err := json.Unmarshal(f["choices"], &choices); err != nil {
			return err
		}
		if len(choices) > 0 {
			finish = choices[0].FinishReason
			if choices[0].Delta.Role != "assistant" {
				t.Errorf("delta.role: got %q, want assistant", choices[0].Delta.Role)
			}
			if choices[0].Delta.Content == "" {
				t.Error("delta.content: empty, want the chunk content")
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("CompleteStream: %v", err)
	}
	if frames != 1 {
		t.Errorf("frames: got %d, want 1", frames)
	}
	if finish != "stop" {
		t.Errorf("finish_reason: got %q, want stop", finish)
	}
}

// The fixture is only useful if it holds up under the concurrency it exists to
// generate. This drives it from many goroutines at once so `go test -race`
// actually covers the state shared across requests — the signature ring and the
// precomputed frame fragments — which a sequential test cannot reach.
func TestFixtureIsConcurrencySafe(t *testing.T) {
	const workers = 24
	cfg := testConfig()
	// Above the worker count on purpose: the ring must outlive the window between a
	// response being written and its signature being fetched (see sigStore). Sizing
	// it below concurrency is the documented misconfiguration, not the thing under
	// test here — eviction logic itself is covered by TestSigStoreEvictsOldest.
	cfg.SignatureCache = 4 * workers
	ts := newTestFixture(t, cfg)
	c := newTestClient(ts)

	errs := make(chan error, workers)
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			// Half streaming, half buffered: the two paths seal, bind and sign
			// differently, so both need to be in flight together.
			if i%2 == 0 {
				errs <- c.CompleteStream(context.Background(), chatRequest(true), func(wire.Response) error { return nil })
				return
			}
			_, err := c.Complete(context.Background(), chatRequest(false))
			errs <- err
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Errorf("concurrent completion: %v", err)
		}
	}
}

// With -sign=false the fixture serves no signature, so a gateway configured to
// verify responses must fail closed rather than silently accept an unverified
// one. This pins the flag's contract (and the operator error it produces).
func TestUnsignedFixtureFailsResponseVerification(t *testing.T) {
	cfg := testConfig()
	cfg.Sign = false
	ts := newTestFixture(t, cfg)
	c := newTestClient(ts)

	if _, err := c.Complete(context.Background(), chatRequest(false)); err == nil {
		t.Fatal("Complete: got nil error, want a fail-closed verification error")
	}
}

// The preview must advertise an endpoint the caller can actually reach. Deriving
// it from the request Host is what lets the fixture work unconfigured behind a
// compose service name, a loopback port, or httptest.
func TestPreviewAdvertisesReachableEndpoint(t *testing.T) {
	ts := newTestFixture(t, testConfig())

	resp, err := ts.Client().Post(ts.URL+"/v1/routing/preview", "application/json", strings.NewReader(`{"model":"mock-model"}`))
	if err != nil {
		t.Fatalf("preview: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("preview: got %d, want 200", resp.StatusCode)
	}
	var preview struct {
		Providers []struct {
			Address     string `json:"address"`
			CanonicalID string `json:"canonical_id"`
			Endpoint    string `json:"endpoint"`
		} `json:"providers"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&preview); err != nil {
		t.Fatalf("decode preview: %v", err)
	}
	if len(preview.Providers) != 1 {
		t.Fatalf("providers: got %d, want 1", len(preview.Providers))
	}
	if got := preview.Providers[0].Endpoint; got != ts.URL {
		t.Errorf("endpoint: got %q, want %q", got, ts.URL)
	}
	if got := preview.Providers[0].CanonicalID; got != "mock-model" {
		t.Errorf("canonical_id: got %q, want mock-model", got)
	}
}

// -advertise overrides the derived endpoint, for the case the gateway reaches the
// fixture under a different name than the fixture sees (a proxy, a port mapping).
func TestAdvertiseOverridesEndpoint(t *testing.T) {
	cfg := testConfig()
	cfg.Advertise = "http://mockupstream:8080/"
	ts := newTestFixture(t, cfg)

	resp, err := ts.Client().Post(ts.URL+"/v1/routing/preview", "application/json", strings.NewReader(`{}`))
	if err != nil {
		t.Fatalf("preview: %v", err)
	}
	defer resp.Body.Close()
	var preview struct {
		Providers []struct {
			Endpoint string `json:"endpoint"`
		} `json:"providers"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&preview); err != nil {
		t.Fatalf("decode preview: %v", err)
	}
	if got := preview.Providers[0].Endpoint; got != "http://mockupstream:8080" {
		t.Errorf("endpoint: got %q, want the trimmed -advertise value", got)
	}
}

// The signature store is what a long load run writes to on every response, so its
// bound is load-bearing: past the configured size the oldest entry must go, and
// the newest must still be readable.
func TestSigStoreEvictsOldest(t *testing.T) {
	s := newSigStore(2)
	for _, k := range []string{"a", "b", "c"} {
		s.put(k, proof.ChatSignature{Text: k})
	}
	if _, ok := s.get("a"); ok {
		t.Error("a: still present, want evicted")
	}
	for _, k := range []string{"b", "c"} {
		sig, ok := s.get(k)
		if !ok {
			t.Errorf("%s: missing, want retained", k)
			continue
		}
		if sig.Text != k {
			t.Errorf("%s: got text %q", k, sig.Text)
		}
	}
}

// A provider missing its own quote route is deliberate: the fixture cannot forge
// a TDX quote, so a gateway must run against it with -attest off. A 404 says that
// once, loudly, instead of failing DCAP on every request.
func TestNoQuoteRoute(t *testing.T) {
	ts := newTestFixture(t, testConfig())
	resp, err := ts.Client().Get(ts.URL + "/v1/quote?legacy=false")
	if err != nil {
		t.Fatalf("get quote: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("quote: got %d, want 404", resp.StatusCode)
	}
}
