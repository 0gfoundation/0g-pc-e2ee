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

	ephPriv, ephPub, err := crypto.GenerateRecipientKey()
	if err != nil {
		return stageErr(StageInternal, fmt.Errorf("generate ephemeral key: %w", err))
	}

	sealed, err := wire.SealRequest(c.provider.EncPubKey, req, c.sealedFieldsFor(req), c.provider.SignerAddr, ephPub)
	if err != nil {
		return stageErr(StageRequest, fmt.Errorf("seal request: %w", err))
	}

	resp, err := c.doRequest(ctx, sealed)
	if err != nil {
		return &Error{Stage: StageUpstream, Err: fmt.Errorf("post to provider: %w", err)}
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		// Like post: the error embeds the raw upstream body (see the TODO(gateway)
		// on post) — fine for the local sidecar, but the gateway shell must not
		// echo it back.
		body, _ := io.ReadAll(io.LimitReader(resp.Body, maxSSELine))
		return &Error{Stage: StageUpstream, Status: resp.StatusCode, Err: fmt.Errorf("provider returned %d: %s", resp.StatusCode, body)}
	}
	// A 200 that is not an event stream (a provider that ignored stream:true)
	// would be read as zero frames and silently yield an empty stream; fail loud.
	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/event-stream") {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, maxSSELine))
		return stageErr(StageUpstream, fmt.Errorf("provider did not stream (content-type %q): %s", ct, body))
	}

	// Abort if the provider stalls between frames.
	idle := time.AfterFunc(providerTimeout, cancel)
	defer idle.Stop()

	sse := newSSEReader(resp.Body)
	var opener *wire.ResponseOpener
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
				return stageErr(StageUpstream, fmt.Errorf("stream ended before the final frame (truncated)"))
			}
			return nil
		}
		if err != nil {
			if ctx.Err() != nil {
				return stageErr(StageUpstream, fmt.Errorf("stream aborted: %w", ctx.Err()))
			}
			return stageErr(StageUpstream, fmt.Errorf("read stream: %w", err))
		}
		if bytes.Equal(bytes.TrimSpace(data), []byte("[DONE]")) {
			if !sawFinal {
				return stageErr(StageUpstream, fmt.Errorf("stream reached [DONE] before the final frame (truncated)"))
			}
			return nil
		}

		var frame wire.Response
		if err := json.Unmarshal(data, &frame); err != nil {
			return stageErr(StageUpstream, fmt.Errorf("decode stream frame: %w", err))
		}
		fe, err := frame.E2EE()
		if err != nil {
			return stageErr(StageUpstream, fmt.Errorf("read frame metadata: %w", err))
		}
		if opener == nil {
			// The first frame carries enc; it sets up the shared HPKE context.
			opener, err = wire.NewResponseOpener(ephPriv, frame)
			if err != nil {
				return stageErr(StageUpstream, fmt.Errorf("stream setup: %w", err))
			}
		}
		out, err := opener.OpenFrame(frame)
		if err != nil {
			return stageErr(StageUpstream, fmt.Errorf("open stream frame: %w", err))
		}
		if err := onFrame(out); err != nil {
			return err
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
