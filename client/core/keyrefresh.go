package core

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/0gfoundation/0g-pc-e2ee/protocol/crypto"
)

// KeyRefresher is an optional extension of Candidates: a list that can re-read one
// candidate's enc key when the provider has said the key we sealed to is no longer
// its current one.
//
// The provider says so with a 409 whose error message starts with
// "e2ee_key_mismatch" (0g-serving-broker ctrl.ErrE2EEKeyMismatch). It answers that
// before inference and before billing, so nothing happened upstream and re-sealing
// to the same provider is safe. Without this the 409 reached the caller as a client
// error, for every request sealed from a cached quote during the window between a
// broker rotating its key (an upgrade changes the measurement-tied key) and the
// quote cache expiring.
//
// stale is the key the rejected request was sealed to. An implementation returns
// the candidate re-materialized with the provider's CURRENT key, bypassing any
// cache that still holds stale — and only when it holds stale, so a burst of
// rejected requests that raced one rotation costs one re-verification, not one
// each. Re-reading goes through the same verification as a first read; the 409
// only decides that we look again, never what we accept.
//
// A Candidates that does not implement it keeps the old behaviour except that the
// mismatch now falls back to the next candidate instead of ending the walk.
type KeyRefresher interface {
	RefreshProvider(ctx context.Context, i int, stale crypto.PublicKey) (Provider, error)
}

// keyMismatchToken is the message prefix the broker puts on a stale-key 409. Both
// the broker's own `{"error":"<msg>"}` and the router's normalized
// `{"error":{"message":"<msg>",...}}` carry it at the start of the message.
const keyMismatchToken = "e2ee_key_mismatch"

// Outcomes reported through MetricsHook.KeyRefresh.
const (
	// KeyRefreshResealed: the provider's key had changed; the request was re-sealed
	// to the new one and sent again.
	KeyRefreshResealed = "resealed"
	// KeyRefreshUnchanged: re-reading returned the same key the provider just
	// rejected. Nothing to re-seal to, so the walk falls back. A forged 409 (the
	// router is untrusted) ends here.
	KeyRefreshUnchanged = "unchanged"
	// KeyRefreshFailed: the re-read itself failed — the quote fetch or
	// verification failed, or the re-verification was throttled.
	KeyRefreshFailed = "failed"
	// KeyRefreshUnsupported: the candidate list cannot re-read keys (static
	// providers).
	KeyRefreshUnsupported = "unsupported"
)

// isKeyMismatch reports whether err is a provider's stale-enc-key 409.
//
// The status alone is not enough — a 409 can mean other things upstream — so the
// body's message must also carry the token. The body is untrusted (it came through
// the router), which is fine: the most a forged one can do is make us re-read a
// key through the full verification, at most once per candidate per request, and
// the route resolver throttles the re-verification itself.
func isKeyMismatch(err error) bool {
	var e *Error
	if !errors.As(err, &e) || e.Status != http.StatusConflict {
		return false
	}
	var probe struct {
		Error json.RawMessage `json:"error"`
	}
	if json.Unmarshal([]byte(e.Body), &probe) != nil || len(probe.Error) == 0 {
		return false
	}
	var msg string
	if json.Unmarshal(probe.Error, &msg) != nil {
		var obj struct {
			Message string `json:"message"`
		}
		if json.Unmarshal(probe.Error, &obj) != nil {
			return false
		}
		msg = obj.Message
	}
	return strings.HasPrefix(msg, keyMismatchToken)
}

// refresh re-materializes candidate i with a re-read enc key, under whatever is
// left of the budget and charging what it takes — provider()'s rules, for the same
// reasons.
func (w *candidateWalk) refresh(ctx context.Context, kr KeyRefresher, i int, stale crypto.PublicKey) (Provider, error) {
	remaining := w.limit() - w.spent
	if remaining <= 0 {
		return Provider{}, &Error{Stage: StageUpstream, Err: fmt.Errorf(
			"provider selection budget (%s) spent before candidate %d's key could be re-read", w.limit(), i)}
	}
	start := time.Now()
	ctx, cancel := context.WithDeadline(ctx, start.Add(remaining))
	defer cancel()
	p, err := kr.RefreshProvider(ctx, i, stale)
	w.spent += time.Since(start)
	return p, err
}

// attemptRekeying runs attempt against candidate i and, if the provider rejects it
// for a stale enc key, re-reads the key and runs it once more. It charges each
// failed attempt to the walk and records it in fail, as the walk loops did inline.
//
// retry is attempt's own verdict, except that a stale-key rejection we could not
// recover from is retryable: the key is the provider's problem, not the request's,
// and another candidate may take it.
func (c *Client) attemptRekeying(ctx context.Context, walk *candidateWalk, fail *walkErr, cands Candidates, i int, provider Provider, attempt func(Provider) (bool, error)) (retry bool, err error) {
	for rekeyed := false; ; rekeyed = true {
		start := time.Now()
		retry, err = attempt(provider)
		if err == nil {
			return false, nil
		}
		walk.charge(time.Since(start))
		fail.record(tierAttempt, err)
		if !isKeyMismatch(err) {
			return retry, err
		}
		if rekeyed || canceledBy(ctx) || walk.exhausted() {
			return true, err
		}
		fresh, ok := c.rekey(ctx, walk, cands, i, provider)
		if !ok {
			return true, err
		}
		provider = fresh
	}
}

// rekey re-reads candidate i's enc key after the provider rejected stale. ok is
// true only when there is a different key to re-seal to.
func (c *Client) rekey(ctx context.Context, walk *candidateWalk, cands Candidates, i int, stale Provider) (Provider, bool) {
	kr, ok := cands.(KeyRefresher)
	if !ok {
		c.metricKeyRefresh(KeyRefreshUnsupported)
		return Provider{}, false
	}
	fresh, err := walk.refresh(ctx, kr, i, stale.EncPubKey)
	switch {
	case err != nil:
		if c.debug != nil {
			c.debug.Warn("e2ee key re-read failed after a stale-key rejection", "candidate", i, "err", err)
		}
		c.metricKeyRefresh(KeyRefreshFailed)
		return Provider{}, false
	case bytes.Equal(fresh.EncPubKey, stale.EncPubKey):
		c.metricKeyRefresh(KeyRefreshUnchanged)
		return Provider{}, false
	}
	c.metricKeyRefresh(KeyRefreshResealed)
	return fresh, true
}

func (c *Client) metricKeyRefresh(outcome string) {
	if c.metrics != nil {
		c.metrics.KeyRefresh(outcome)
	}
}
