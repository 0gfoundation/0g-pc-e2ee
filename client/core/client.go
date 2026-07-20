package core

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/0gfoundation/0g-pc/protocol/crypto"
	"github.com/0gfoundation/0g-pc/protocol/wire"
)

// defaultTimeout bounds a whole request/response to the provider. Chat
// completions can be slow, so it is generous; callers that need a different
// bound can pass their own context deadline.
const defaultTimeout = 120 * time.Second

// Stage names where a Complete call failed, so callers (the sidecar) can map it
// to an HTTP status: a bad client request vs an upstream/provider failure vs a
// client-side internal error.
const (
	StageRequest  = "request"  // invalid client request (seal-side)
	StageUpstream = "upstream" // provider transport or sealed-response failure
	StageInternal = "internal" // client-side internal error
)

// Error wraps a Complete failure with the Stage it happened at.
type Error struct {
	Stage string
	Err   error
}

func (e *Error) Error() string { return e.Err.Error() }
func (e *Error) Unwrap() error { return e.Err }

func stageErr(stage string, err error) error { return &Error{Stage: stage, Err: err} }

// Provider identifies the enclave the client seals to. In production EncPubKey
// and SignerAddr are extracted from a verified attestation quote; here they are
// supplied directly — attestation is a later step.
type Provider struct {
	URL        string           // OpenAI-shaped endpoint (router or broker)
	EncPubKey  crypto.PublicKey // provider HPKE recipient key
	SignerAddr string           // provider on-chain signer address; used as the pin
}

// Client is the shared client core: it seals a request's sensitive fields to
// the provider, sends the envelope, and opens the sealed response. It holds no
// server of its own — the sidecar, the cloud-TEE gateway, and the in-process
// SDK all wrap this. A Client is safe for concurrent use.
type Client struct {
	provider Provider
	http     *http.Client
}

// New returns a Client for the given provider.
func New(p Provider) *Client {
	return &Client{provider: p, http: &http.Client{Timeout: defaultTimeout}}
}

// Complete performs one non-streaming chat completion. req and the result are
// OpenAI-shaped JSON objects; the sensitive fields are sealed on the way out and
// the sealed response is opened on the way back, so the caller only ever handles
// plaintext. Failures are wrapped in *Error with a Stage.
//
// TODO(attestation): the response is sealed to client_eph_pub, which travels in
// cleartext in the request envelope. Complete does NOT yet authenticate the
// response's origin — a middleman could read that key and seal a forged
// response that OpenResponse accepts as plaintext. Verifying the provider enc
// key out of an attestation quote (§4) and the TEE response signature (§8; the
// "verify response signature" step in doc.go) is a later step. Until then this
// provides confidentiality but NOT response authenticity.
func (c *Client) Complete(ctx context.Context, req wire.Request) (wire.Response, error) {
	// Fresh ephemeral keypair per request; the enclave seals the response to the
	// public half (§7) and we keep the private half to open it.
	ephPriv, ephPub, err := crypto.GenerateRecipientKey()
	if err != nil {
		return nil, stageErr(StageInternal, fmt.Errorf("generate ephemeral key: %w", err))
	}

	sealed, err := wire.SealRequest(c.provider.EncPubKey, req, sealedFieldsFor(req), c.provider.SignerAddr, ephPub)
	if err != nil {
		// Given a valid provider config (validated at startup), a seal failure is
		// a bad request — e.g. no messages to seal.
		return nil, stageErr(StageRequest, fmt.Errorf("seal request: %w", err))
	}

	respBody, err := c.post(ctx, sealed)
	if err != nil {
		return nil, stageErr(StageUpstream, err)
	}

	var sealedResp wire.Response
	if err := json.Unmarshal(respBody, &sealedResp); err != nil {
		return nil, stageErr(StageUpstream, fmt.Errorf("decode sealed response: %w", err))
	}
	out, err := wire.OpenResponse(ephPriv, sealedResp)
	if err != nil {
		return nil, stageErr(StageUpstream, fmt.Errorf("open response: %w", err))
	}
	return out, nil
}

func (c *Client) post(ctx context.Context, env wire.Request) ([]byte, error) {
	body, err := json.Marshal(env)
	if err != nil {
		return nil, fmt.Errorf("marshal envelope: %w", err)
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, c.provider.URL, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := c.http.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("post to provider: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read provider response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("provider returned %d: %s", resp.StatusCode, respBody)
	}
	return respBody, nil
}

// sealedFieldsFor picks the default sensitive fields that are actually present
// in req. A valid chat request always carries "messages"; "tools" often is
// absent. Filtering by presence seals the prompt (and the tool definitions when
// sent) without erroring on a tools-less request, while keeping the default set
// defined in exactly one place (wire.DefaultSealedFields).
func sealedFieldsFor(req wire.Request) []string {
	// Non-nil even when empty: SealRequest treats a nil sealedFields as "use the
	// default set", which would silently mask this presence-filter. An empty
	// (non-nil) result instead makes SealRequest fail with "no sealed fields" —
	// the right outcome for a request with nothing sensitive to seal.
	fs := []string{}
	for _, f := range wire.DefaultSealedFields() {
		if _, ok := req[f]; ok {
			fs = append(fs, f)
		}
	}
	return fs
}
