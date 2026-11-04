package core

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/0gfoundation/0g-pc-e2ee/client/endpoint"
	"github.com/0gfoundation/0g-pc-e2ee/protocol/crypto"
	"github.com/0gfoundation/0g-pc-e2ee/protocol/wire"
)

// transitCands is a candidate list that knows the request's encrypted_transit.
// With p unset every candidate fails to materialize (nothing is ever sent);
// with p set every candidate is p.
type transitCands struct {
	transit string
	n       int
	p       *Provider
}

func (t transitCands) Len() int                 { return t.n }
func (t transitCands) EncryptedTransit() string { return t.transit }
func (t transitCands) Provider(context.Context, int) (Provider, error) {
	if t.p == nil {
		return Provider{}, errors.New("no key to seal to")
	}
	return *t.p, nil
}

func transitChatReq() wire.Request {
	return wire.Request{
		"model":    json.RawMessage(`"glm-5"`),
		"messages": json.RawMessage(`[{"role":"user","content":"hi"}]`),
	}
}

// preferred + a cleartext path + nothing sent: hand the request back to go out
// in the clear, on all three walks.
func TestNoEncryptedProvider_DowngradesUnsentPreferred(t *testing.T) {
	ctx := WithCleartextFallback(context.Background())
	cands := transitCands{transit: TransitPreferred, n: 3}

	c := NewWithResolver(fixedResolver{cands})
	if _, err := c.Complete(ctx, transitChatReq()); !errors.Is(err, ErrNoEncryptedProvider) {
		t.Errorf("Complete: err = %v, want ErrNoEncryptedProvider", err)
	}
	stream := transitChatReq()
	stream["stream"] = json.RawMessage(`true`)
	if err := c.CompleteStream(ctx, stream, func(wire.Response) error { return nil }); !errors.Is(err, ErrNoEncryptedProvider) {
		t.Errorf("CompleteStream: err = %v, want ErrNoEncryptedProvider", err)
	}
	async := NewWithResolver(fixedResolver{cands}, WithEndpoint(endpoint.AsyncImage))
	if _, _, err := async.SubmitAsync(ctx, wire.Request{"model": json.RawMessage(`"z-image"`), "prompt": json.RawMessage(`"p"`)}); !errors.Is(err, ErrNoEncryptedProvider) {
		t.Errorf("SubmitAsync: err = %v, want ErrNoEncryptedProvider", err)
	}
}

// Everything else keeps the walk's own error: another policy, no value (a
// router with its routing policy off), no cleartext path, a caller gone.
func TestNoEncryptedProvider_OnlyForExplicitPreferred(t *testing.T) {
	for name, tc := range map[string]struct {
		ctx     context.Context
		transit string
	}{
		"no value":          {WithCleartextFallback(context.Background()), ""},
		"required":          {WithCleartextFallback(context.Background()), TransitRequired},
		"no cleartext path": {context.Background(), TransitPreferred},
	} {
		c := NewWithResolver(fixedResolver{transitCands{transit: tc.transit, n: 2}})
		if _, err := c.Complete(tc.ctx, transitChatReq()); err == nil || errors.Is(err, ErrNoEncryptedProvider) {
			t.Errorf("%s: err = %v, want the walk's own error", name, err)
		}
	}
	ctx, cancel := context.WithCancel(WithCleartextFallback(context.Background()))
	cancel()
	c := NewWithResolver(fixedResolver{transitCands{transit: TransitPreferred, n: 2}})
	if _, err := c.Complete(ctx, transitChatReq()); errors.Is(err, ErrNoEncryptedProvider) {
		t.Error("a caller that went away must not be downgraded")
	}
}

// A walk that SENT a sealed request is never downgraded: a provider may already
// be serving it, and sending it again in the clear would run it twice.
func TestNoEncryptedProvider_NotAfterASend(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "busy", http.StatusServiceUnavailable)
	}))
	defer srv.Close()
	_, encPub, err := crypto.GenerateRecipientKey()
	if err != nil {
		t.Fatal(err)
	}
	p := &Provider{URL: srv.URL, EncPubKey: encPub, Address: "0xC0FFEE0000000000000000000000000000000001",
		SignerAddr: "0xd45b4301940B297F76d6e622c1CeA2AE660617d4"}
	c := NewWithResolver(fixedResolver{transitCands{transit: TransitPreferred, n: 2, p: p}})
	_, err = c.Complete(WithCleartextFallback(context.Background()), transitChatReq())
	var e *Error
	if errors.Is(err, ErrNoEncryptedProvider) || !errors.As(err, &e) || e.Status != http.StatusServiceUnavailable {
		t.Errorf("err = %v, want the provider's 503", err)
	}
}
