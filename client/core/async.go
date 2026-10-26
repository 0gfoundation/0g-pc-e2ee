package core

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/0gfoundation/0g-pc-e2ee/protocol/crypto"
	"github.com/0gfoundation/0g-pc-e2ee/protocol/wire"
)

// maxSubmitResponseBytes bounds the read of a 2xx async submit answer. It is a
// job id and a status, so anything near this is not a submit answer.
const maxSubmitResponseBytes = 64 << 10

// SubmitAsync seals req to a provider under the client's async profile (SPEC
// §7.5) and submits it, returning the router's 2xx answer with its `jobId`
// replaced by the user job id: the broker's id plus the response key the result
// will be opened with (wire.UserJobID). The key is not kept anywhere else, so
// the returned id is the only way to read the result.
//
// The candidate walk is Complete's: on a transient failure (429 / 5xx) the
// request is re-sealed to the next candidate, with a fresh key and binding each
// time, since a key that has been sent once is spent. It stops at the first 2xx:
// a job accepted by one enclave is that enclave's, and there is no fallback
// after acceptance.
//
// The 2xx must name the provider the request was pinned and sealed to; a router
// that accepted it elsewhere has a job no other enclave can open, so the answer
// is refused rather than handed back as an id that can only ever fail.
func (c *Client) SubmitAsync(ctx context.Context, req wire.Request) (wire.Response, int, error) {
	if !c.ep.Async {
		return nil, 0, stageErr(StageInternal, fmt.Errorf("endpoint %s is not an async surface", c.ep.Path))
	}
	cands, err := c.resolver.Resolve(ctx, c.ep, req)
	if err != nil {
		return nil, 0, resolveErr(err)
	}

	var fail walkErr
	walk := candidateWalk{budget: c.resolveBudgetTO}
	for i := 0; i < cands.Len(); i++ {
		provider, err := walk.provider(ctx, cands, i)
		if err != nil {
			if canceledBy(ctx) {
				fail.record(tierMaterialize, resolveErr(err))
				break
			}
			if walk.exhausted() {
				c.metricWalkBudgetExhausted()
				fail.record(tierBudget, budgetErr(walk.limit(), err))
				break
			}
			fail.record(tierMaterialize, resolveErr(err))
			c.metricFallback(FallbackMaterialize, i, cands.Len())
			continue
		}

		attemptStart := time.Now()
		out, status, retry, err := c.submitOnce(ctx, provider, req)
		if err == nil {
			return out, status, nil
		}
		walk.charge(time.Since(attemptStart))
		fail.record(tierAttempt, err)
		if retry {
			if canceledBy(ctx) {
				break
			}
			if walk.exhausted() {
				c.metricWalkBudgetBlockedFallback(i, cands.Len())
				break
			}
			c.metricFallback(FallbackUpstream, i, cands.Len())
			continue
		}
		return nil, 0, err
	}
	if fail.err == nil {
		return nil, 0, stageErr(StageUpstream, fmt.Errorf("no provider candidates to try"))
	}
	return nil, 0, fail.err
}

// submitOnce seals and submits to one candidate. A fresh response key per
// attempt, not per request: the key is what the job id will carry, and each
// attempt that reaches a router is a separate job.
func (c *Client) submitOnce(parent context.Context, provider Provider, req wire.Request) (wire.Response, int, bool, error) {
	ctx, cancel := context.WithTimeout(parent, bufferedTimeout)
	defer cancel()

	ephPriv, ephPub, err := crypto.GenerateRecipientKey()
	if err != nil {
		return nil, 0, false, stageErr(StageInternal, fmt.Errorf("generate ephemeral key: %w", err))
	}
	bound, err := wire.AttachAsyncBind(req, ephPriv)
	if err != nil {
		return nil, 0, false, stageErr(StageRequest, fmt.Errorf("bind request: %w", err))
	}
	sealed, err := c.seal(provider, bound, ephPriv, ephPub)
	if err != nil {
		return nil, 0, false, stageErr(StageRequest, fmt.Errorf("seal request: %w", err))
	}

	start := time.Now()
	outcome := UpstreamOK
	defer func() { c.metricUpstreamAttempt(UpstreamBuffered, outcome, time.Since(start)) }()

	resp, err := c.doRequest(ctx, provider, sealed)
	if err != nil {
		outcome = upstreamFailureOutcome(parent, ctx, err, UpstreamTransport)
		return nil, 0, false, &Error{Stage: StageUpstream, Err: fmt.Errorf("post to provider: %w", err)}
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, maxUpstreamErrorBytes))
		outcome = upstreamStatusOutcome(resp.StatusCode)
		e := &Error{Stage: StageUpstream, Status: resp.StatusCode, Err: fmt.Errorf("provider returned %d", resp.StatusCode), Body: string(body), Header: resp.Header.Clone()}
		return nil, 0, retryableStatus(resp.StatusCode), e
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxSubmitResponseBytes+1))
	if err != nil {
		outcome = upstreamFailureOutcome(parent, ctx, err, UpstreamBody)
		return nil, 0, false, stageErr(StageUpstream, fmt.Errorf("read submit response: %w", err))
	}
	// Past this point the job exists upstream, so nothing below falls back: a
	// second submit would be a second job (and a second charge) for a request
	// whose first one may well be running.
	out, err := userJobResponse(body, provider, ephPriv)
	if err != nil {
		outcome = UpstreamUndecodable
		return nil, 0, false, &Error{Stage: StageUpstream, Err: err, Header: resp.Header.Clone()}
	}
	recordMeta(ctx, provider, resp.Header)
	return out, resp.StatusCode, false, nil
}

// userJobResponse checks a 2xx submit answer and rewrites its `jobId` into the
// user job id. Its errors name what was wrong and never the job id: once the
// key is attached the id is a credential.
func userJobResponse(body []byte, provider Provider, ephPriv crypto.PrivateKey) (wire.Response, error) {
	if len(body) > maxSubmitResponseBytes {
		return nil, fmt.Errorf("submit response exceeds %d bytes", maxSubmitResponseBytes)
	}
	var out wire.Response
	if err := json.Unmarshal(body, &out); err != nil || out == nil {
		return nil, fmt.Errorf("submit response is not a JSON object")
	}
	if _, sealed := out["_e2ee"]; sealed {
		return nil, fmt.Errorf("submit response carries %q; a submit answer is never sealed", "_e2ee")
	}
	var jobID string
	if err := json.Unmarshal(out["jobId"], &jobID); err != nil || jobID == "" {
		return nil, fmt.Errorf("submit response has no string jobId")
	}
	// Only the pin is checked, not the reverse: a static provider (no Address)
	// was never pinned, so there is nothing the router could have diverted.
	if provider.Address != "" {
		var got string
		_ = json.Unmarshal(out["provider_address"], &got)
		if !strings.EqualFold(got, provider.Address) {
			return nil, fmt.Errorf("submit was accepted by provider %q, not the pinned %q the request is sealed to", got, provider.Address)
		}
	}
	userJobID, err := wire.UserJobID(jobID, ephPriv)
	if err != nil {
		// UserJobID refuses an id outside the router's job-id charset, which is
		// what makes splitting it back on the last "." unambiguous.
		return nil, fmt.Errorf("submit response jobId cannot carry a key: %w", err)
	}
	raw, err := json.Marshal(userJobID)
	if err != nil {
		return nil, err
	}
	out["jobId"] = raw
	return out, nil
}
