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
	for i := 0; i < cands.Len(); i++ {
		provider, err := cands.Provider(ctx, i)
		if err != nil {
			lastErr = resolveErr(err)
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

	resp, err := c.doRequest(ctx, provider, sealed)
	if err != nil {
		// Transport failure reaching the router (which fronts every candidate) — it
		// would recur, so do not fall back.
		return false, &Error{Stage: StageUpstream, Err: fmt.Errorf("post to provider: %w", err)}
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		// The body is untrusted upstream content: carry it as Error.Body for local
		// debugging (the sidecar can surface it) but keep it out of the message, so
		// a multi-tenant gateway never echoes it back (see Error.Body). Fall back
		// only on a transient provider status (429 / 5xx).
		body, _ := io.ReadAll(io.LimitReader(resp.Body, maxSSELine))
		return retryableStatus(resp.StatusCode), &Error{Stage: StageUpstream, Status: resp.StatusCode, Err: fmt.Errorf("provider returned %d", resp.StatusCode), Body: string(body)}
	}
	// A 200 that is not an event stream (a provider that ignored stream:true) would
	// be read as zero frames and silently yield an empty stream; fail loud. Nothing
	// was delivered, so fall back to the next candidate.
	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/event-stream") {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, maxSSELine))
		return true, &Error{Stage: StageUpstream, Err: fmt.Errorf("provider did not stream (content-type %q)", ct), Body: string(body)}
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
				return !committed, stageErr(StageUpstream, fmt.Errorf("stream ended before the final frame (truncated)"))
			}
			return false, nil
		}
		if err != nil {
			if ctx.Err() != nil {
				// A parent-context cancel (client disconnect / deadline) is terminal;
				// a child-only cancel is this provider's idle stall — fall back if
				// nothing was delivered yet.
				if parent.Err() != nil {
					return false, stageErr(StageUpstream, fmt.Errorf("stream aborted: %w", ctx.Err()))
				}
				return !committed, stageErr(StageUpstream, fmt.Errorf("stream aborted: %w", ctx.Err()))
			}
			return !committed, stageErr(StageUpstream, fmt.Errorf("read stream: %w", err))
		}
		if bytes.Equal(bytes.TrimSpace(data), []byte("[DONE]")) {
			if !sawFinal {
				return !committed, stageErr(StageUpstream, fmt.Errorf("stream reached [DONE] before the final frame (truncated)"))
			}
			return false, nil
		}

		var frame wire.Response
		if err := json.Unmarshal(data, &frame); err != nil {
			return !committed, stageErr(StageUpstream, fmt.Errorf("decode stream frame: %w", err))
		}
		fe, err := frame.E2EE()
		if err != nil {
			return !committed, stageErr(StageUpstream, fmt.Errorf("read frame metadata: %w", err))
		}
		if opener == nil {
			// The first frame carries enc; it sets up the shared HPKE context.
			opener, err = wire.NewResponseOpener(ephPriv, frame)
			if err != nil {
				return !committed, stageErr(StageUpstream, fmt.Errorf("stream setup: %w", err))
			}
		}
		out, err := opener.OpenFrame(frame)
		if err != nil {
			return !committed, stageErr(StageUpstream, fmt.Errorf("open stream frame: %w", err))
		}
		// From here the caller receives bytes: the stream is committed to this
		// provider and can no longer be retried on another.
		committed = true
		if err := onFrame(out); err != nil {
			return false, err
		}
		if fe.Final {
			sawFinal = true
		}
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
