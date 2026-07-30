package chain

import (
	"context"
	"errors"
	"testing"
	"time"
)

type fakeRegistry struct {
	signer string
	ack    bool
	err    error
	calls  int
}

func (f *fakeRegistry) AcknowledgedSigner(context.Context, string) (string, bool, error) {
	f.calls++
	return f.signer, f.ack, f.err
}

func TestCached_HitWithinTTL(t *testing.T) {
	inner := &fakeRegistry{signer: "0xabc", ack: true}
	now := time.Unix(1000, 0)
	c := &cachedRegistry{inner: inner, ttl: time.Minute, entries: map[string]cacheEntry{}, now: func() time.Time { return now }}

	for i := 0; i < 3; i++ {
		s, ack, err := c.AcknowledgedSigner(context.Background(), "0xProvider")
		if err != nil || s != "0xabc" || !ack {
			t.Fatalf("call %d: got (%s,%v,%v)", i, s, ack, err)
		}
	}
	if inner.calls != 1 {
		t.Errorf("inner called %d times, want 1 (cached)", inner.calls)
	}
}

func TestCached_Expiry(t *testing.T) {
	inner := &fakeRegistry{signer: "0xabc", ack: true}
	now := time.Unix(1000, 0)
	c := &cachedRegistry{inner: inner, ttl: time.Minute, entries: map[string]cacheEntry{}, now: func() time.Time { return now }}

	if _, _, err := c.AcknowledgedSigner(context.Background(), "0xP"); err != nil {
		t.Fatal(err)
	}
	now = now.Add(2 * time.Minute) // past TTL
	if _, _, err := c.AcknowledgedSigner(context.Background(), "0xP"); err != nil {
		t.Fatal(err)
	}
	if inner.calls != 2 {
		t.Errorf("inner called %d times, want 2 (expired)", inner.calls)
	}
}

func TestCached_ErrorsNotCached(t *testing.T) {
	inner := &fakeRegistry{err: errors.New("rpc down")}
	now := time.Unix(1000, 0)
	c := &cachedRegistry{inner: inner, ttl: time.Minute, entries: map[string]cacheEntry{}, now: func() time.Time { return now }}

	for i := 0; i < 2; i++ {
		if _, _, err := c.AcknowledgedSigner(context.Background(), "0xP"); err == nil {
			t.Fatal("want error")
		}
	}
	if inner.calls != 2 {
		t.Errorf("inner called %d times, want 2 (errors not cached)", inner.calls)
	}
}

func TestCached_ZeroTTLDisables(t *testing.T) {
	inner := &fakeRegistry{signer: "0xabc", ack: true}
	c := Cached(inner, 0)
	if c != SignerRegistry(inner) {
		t.Error("Cached with non-positive TTL should return the inner registry unchanged")
	}
}
