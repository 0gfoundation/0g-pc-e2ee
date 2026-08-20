package core

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/0gfoundation/0g-pc-e2ee/protocol/crypto"
	"github.com/0gfoundation/0g-pc-e2ee/protocol/proof"
	"github.com/0gfoundation/0g-pc-e2ee/protocol/wire"
)

// maxSSELine caps a single SSE data line read from the provider (one sealed
// frame), guarding against an unbounded line.
const maxSSELine = 4 << 20 // 4 MiB

// CompleteStream performs a streaming chat completion. It seals req, sends it,
// then reads the provider's SSE stream of sealed frames, opens each in order,
// and calls onFrame with the plaintext frame. onFrame returning an error stops
// the stream and is returned as-is (e.g. a client disconnect).
//
// No total deadline is imposed (a stream may run long), but two stalls are
// bounded to match the router: the wait for response headers (the Client's
// ResponseHeaderTimeout) and the gap between frames (an idle watchdog at
// providerTimeout). A user disconnect cancels via ctx.
//
// The same response-authenticity caveat as Complete applies (see its doc): the
// frames are confidential but their origin is not yet authenticated.
func (c *Client) CompleteStream(ctx context.Context, req wire.Request, onFrame func(wire.Response) error) error {
	// Cancellable so the idle watchdog (and a parent-context cancel) can abort a
	// blocked read on the provider stream.
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	// Pick the candidates to seal to, best first (a static resolver returns one
	// fixed provider; the route resolver consults the router/broker — a network
	// call bounded by ctx).
	cands, err := c.resolver.Resolve(ctx, req)
	if err != nil {
		return resolveErr(err)
	}

	// One ephemeral keypair for the whole call, reused across fallback attempts:
	// nothing has been opened until the first frame is delivered, so re-sealing to
	// the next candidate with the same response key is safe.
	ephPriv, ephPub, err := crypto.GenerateRecipientKey()
	if err != nil {
		return stageErr(StageInternal, fmt.Errorf("generate ephemeral key: %w", err))
	}

	// Fall back down the candidate chain, but only until the first frame reaches
	// onFrame: once a token has been delivered to the caller the stream is
	// committed to that provider and cannot be restarted on another (streaming
	// fallback is pre-first-token only — docs/design/router-e2e.md "Limitations").
	var lastErr error
	// One shared materialization budget for the whole walk, as in Complete — a
	// stream that has not started yet has a caller waiting on it just the same (see
	// resolveBudget).
	walk := candidateWalk{budget: c.resolveBudgetTO}
	for i := 0; i < cands.Len(); i++ {
		provider, err := walk.provider(ctx, cands, i)
		if err != nil {
			if walk.exhausted() {
				// Keep the better error, as in Complete: a previous candidate's upstream
				// status outlives "we ran out of budget preparing the next one".
				if lastErr == nil {
					lastErr = resolveErr(err)
				}
				break
			}
			lastErr = resolveErr(err)
			c.metricFallback(FallbackMaterialize, i, cands.Len())
			continue
		}
		sealed, err := c.seal(provider, req, ephPub)
		if err != nil {
			// Request-level failure — identical for every candidate; fail fast.
			return stageErr(StageRequest, fmt.Errorf("seal request: %w", err))
		}
		retry, err := c.streamOnce(ctx, provider, sealed, ephPriv, onFrame)
		if err == nil {
			return nil
		}
		lastErr = err
		if retry {
			// Nothing was delivered yet and the failure is provider-transient — try
			// the next candidate.
			c.metricFallback(FallbackUpstream, i, cands.Len())
			continue
		}
		// Terminal: a frame already reached the caller, the caller aborted, or the
		// failure would recur on another provider — surface it, do not retry.
		return err
	}

	if lastErr == nil {
		lastErr = stageErr(StageUpstream, fmt.Errorf("no provider candidates to try"))
	}
	return lastErr
}

// streamOnce posts one sealed envelope to a single provider and pumps its SSE
// stream of sealed frames into onFrame. retry reports whether the caller may
// fall back to the next candidate: true only while nothing has yet been
// delivered to onFrame (streaming fallback is pre-first-token only) AND the
// failure is worth retrying — a transient status (429 / 5xx), an unusable 2xx
// body, or this provider's idle stall. It is false once a frame is delivered, on
// a 4xx / transport failure, and on a parent-context abort (client disconnect /
// deadline). onFrame's own error is returned as-is with retry=false.
func (c *Client) streamOnce(parent context.Context, provider Provider, sealed wire.Request, ephPriv crypto.PrivateKey, onFrame func(wire.Response) error) (retry bool, err error) {
	// A per-attempt cancel drives the idle watchdog, so a stall aborts only this
	// attempt's read — not the parent context, which would poison a fallback to
	// the next candidate. The parent still cancels this attempt (child of parent).
	ctx, cancel := context.WithCancel(parent)
	defer cancel()

	// Meter this attempt: one outcome, set at each failure site and reported by the
	// defer, so no return escapes the counter. The duration is how long the stream
	// stayed OPEN — a different question from how long the caller waited for its
	// first token, which is recorded separately when that frame is delivered.
	start := time.Now()
	outcome := UpstreamOK
	defer func() { c.metricUpstreamAttempt(UpstreamStream, outcome, time.Since(start)) }()

	resp, err := c.doRequest(ctx, provider, sealed)
	if err != nil {
		// Transport failure reaching the router (which fronts every candidate) — it
		// would recur, so do not fall back.
		outcome = UpstreamTransport
		if canceledBy(parent) {
			outcome = UpstreamCanceled
		}
		return false, &Error{Stage: StageUpstream, Err: fmt.Errorf("post to provider: %w", err)}
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		// The body is untrusted upstream content: carry it as Error.Body for local
		// debugging (the sidecar can surface it) but keep it out of the message, so
		// a multi-tenant gateway never echoes it back (see Error.Body). Fall back
		// only on a transient provider status (429 / 5xx).
		body, _ := io.ReadAll(io.LimitReader(resp.Body, maxSSELine))
		outcome = upstreamStatusOutcome(resp.StatusCode)
		return retryableStatus(resp.StatusCode), &Error{Stage: StageUpstream, Status: resp.StatusCode, Err: fmt.Errorf("provider returned %d", resp.StatusCode), Body: string(body), Header: resp.Header.Clone()}
	}
	// A 200 that is not an event stream (a provider that ignored stream:true) would
	// be read as zero frames and silently yield an empty stream; fail loud. Nothing
	// was delivered, so fall back to the next candidate.
	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/event-stream") {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, maxSSELine))
		outcome = UpstreamNotStream
		return true, &Error{Stage: StageUpstream, Err: fmt.Errorf("provider did not stream (content-type %q)", ct), Body: string(body), Header: resp.Header.Clone()}
	}

	// Abort if the provider stalls between frames.
	idle := time.AfterFunc(providerTimeout, cancel)
	defer idle.Stop()

	sse := newSSEReader(resp.Body)
	var opener *wire.ResponseOpener
	// committed flips once a frame reaches onFrame; from then a failure is terminal
	// (the stream cannot be restarted on another provider), so retry = !committed.
	committed := false
	sawFinal := false
	// If response verification is on, fold each sealed frame into a binder so the
	// stream can be verified after the final frame without buffering it (hop 11).
	var binder *proof.StreamBinder
	if c.verifyEnabled() {
		var berr error
		if binder, berr = proof.NewStreamBinder(sealed); berr != nil {
			// Our own fault, not the provider's — an envelope we built that will not
			// bind. Given its own bucket so it can never be read as a provider failure.
			outcome = UpstreamInternal
			return false, stageErr(StageInternal, fmt.Errorf("start response binding: %w", berr))
		}
	}
	// frameIdx is the 0-based ordinal of the sealed frame being processed (blank
	// SSE events and [DONE] do not count). It rides in the per-frame error text so
	// a decode/open failure names its frame: index 0 points at a setup/key/AAD
	// mismatch, index >0 at a dropped or reordered later frame (the AEAD sequence
	// increments per frame, so one lost frame fails every frame after it).
	frameIdx := 0
	for {
		idle.Reset(providerTimeout) // time only the provider read...
		data, err := sse.next()
		idle.Stop() // ...not the onFrame write (a slow client is not a provider stall)
		// Benign, microsecond race: if the timer fires between a successful read
		// and Stop, ctx is cancelled and the *next* read returns "stream aborted".
		// Only possible if a frame arrives right at the idle boundary; acceptable.
		if err == io.EOF {
			// A stream that ends without its final frame was truncated (provider
			// crash / dropped connection) — not a complete answer.
			if !sawFinal {
				outcome = UpstreamBody
				return !committed, stageErr(StageUpstream, fmt.Errorf("stream ended before the final frame (truncated)"))
			}
			if binder != nil {
				if vo, verr := c.verifyStream(ctx, provider, resp.Header, binder); verr != nil {
					outcome = verifyOutcome(parent, vo)
					return false, stageErr(StageUpstream, verr)
				}
			}
			return false, nil
		}
		if err != nil {
			if ctx.Err() != nil {
				// A parent-context cancel (client disconnect / deadline) is terminal;
				// a child-only cancel is this provider's idle stall — fall back if
				// nothing was delivered yet. The same split decides the metric bucket:
				// the caller going away is not the provider going quiet.
				if parent.Err() != nil {
					outcome = UpstreamCanceled
					return false, stageErr(StageUpstream, fmt.Errorf("stream aborted: %w", ctx.Err()))
				}
				outcome = UpstreamTimeout
				return !committed, stageErr(StageUpstream, fmt.Errorf("stream aborted: %w", ctx.Err()))
			}
			outcome = UpstreamBody
			return !committed, stageErr(StageUpstream, fmt.Errorf("read stream: %w", err))
		}
		if bytes.Equal(bytes.TrimSpace(data), []byte("[DONE]")) {
			if !sawFinal {
				outcome = UpstreamBody
				return !committed, stageErr(StageUpstream, fmt.Errorf("stream reached [DONE] before the final frame (truncated)"))
			}
			if binder != nil {
				if vo, verr := c.verifyStream(ctx, provider, resp.Header, binder); verr != nil {
					outcome = verifyOutcome(parent, vo)
					return false, stageErr(StageUpstream, verr)
				}
			}
			return false, nil
		}

		var frame wire.Response
		if err := json.Unmarshal(data, &frame); err != nil {
			outcome = UpstreamUndecodable
			return !committed, stageErr(StageUpstream, fmt.Errorf("decode stream frame %d: %w", frameIdx, err))
		}
		fe, err := frame.E2EE()
		if err != nil {
			outcome = UpstreamUndecodable
			return !committed, stageErr(StageUpstream, fmt.Errorf("read metadata of stream frame %d: %w", frameIdx, err))
		}
		if opener == nil {
			// The first frame carries enc; it sets up the shared HPKE context.
			opener, err = wire.NewResponseOpener(ephPriv, frame)
			if err != nil {
				c.logOpenFailure(frameIdx, frame, err)
				outcome = UpstreamUndecodable
				return !committed, stageErr(StageUpstream, fmt.Errorf("stream setup on frame %d: %w", frameIdx, err))
			}
		}
		out, err := opener.OpenFrame(frame)
		if err != nil {
			c.logOpenFailure(frameIdx, frame, err)
			outcome = UpstreamUndecodable
			return !committed, stageErr(StageUpstream, fmt.Errorf("open stream frame %d: %w", frameIdx, err))
		}
		// Bind the sealed frame (not the opened plaintext) for §8 verification, in
		// delivery order. frame is unchanged by OpenFrame (which builds a new map).
		if binder != nil {
			if err := binder.AddFrame(frame); err != nil {
				outcome = UpstreamUndecodable
				return !committed, stageErr(StageUpstream, fmt.Errorf("bind stream frame %d: %w", frameIdx, err))
			}
		}
		// From here the caller receives bytes: the stream is committed to this
		// provider and can no longer be retried on another.
		if !committed {
			committed = true
			// The wait for the first token — what a streaming caller experiences as
			// latency, and unrelated to how long the stream then runs, which is set by
			// how much the model has to say.
			c.metricStreamFirstFrame(time.Since(start))
			// Once committed, no fallback can change which provider answered, so this
			// is the metadata for the response the caller receives; surface it for a
			// caller that asked (WithResponseMeta). Recorded before the first onFrame
			// so a front end can set the headers before it writes response headers.
			recordMeta(ctx, provider, resp.Header)
		}
		if err := onFrame(out); err != nil {
			// The caller's frame handler rejected a frame. Either way the provider did
			// nothing wrong, but WHICH caller-side failure it was matters, and core
			// cannot see inside an opaque callback — so ask the parent, as everywhere
			// else here. A done parent is a disconnect; a live one means the handler
			// failed on its own (the gateway's re-serialization, or a write that failed
			// just before the disconnect became visible), which is our fault, not the
			// user's navigation. Filing the first case as internal would cry wolf;
			// filing the second as canceled would hide a real bug of ours in a bucket
			// every alert deliberately ignores.
			outcome = UpstreamInternal
			if canceledBy(parent) {
				outcome = UpstreamCanceled
			}
			return false, err
		}
		if fe.Final {
			sawFinal = true
		}
		frameIdx++
	}
}

// sseReader reads Server-Sent Events, returning each event's `data` payload. It
// handles the subset OpenAI uses: one `data:` value per event, events separated
// by a blank line, comments and other fields ignored.
type sseReader struct{ sc *bufio.Scanner }

func newSSEReader(r io.Reader) *sseReader {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64<<10), maxSSELine)
	return &sseReader{sc: sc}
}

// next returns the next event's data bytes, or io.EOF when the stream ends.
func (s *sseReader) next() ([]byte, error) {
	var data []byte
	have := false
	for s.sc.Scan() {
		line := s.sc.Bytes()
		if len(line) == 0 { // blank line terminates an event
			if have {
				return data, nil
			}
			continue
		}
		if after, ok := bytes.CutPrefix(line, []byte("data:")); ok {
			payload := bytes.TrimPrefix(after, []byte(" "))
			if have {
				data = append(data, '\n')
			}
			data = append(data, payload...)
			have = true
		}
		// Other SSE fields (event:, id:, :comment) are ignored.
	}
	if err := s.sc.Err(); err != nil {
		return nil, err
	}
	if have { // final event with no trailing blank line
		return data, nil
	}
	return nil, io.EOF
}
