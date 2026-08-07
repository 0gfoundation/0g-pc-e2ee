package core

import (
	"net/http"
	"testing"
)

// The pool size is the whole point of this helper, and Go's 2-per-host default is
// exactly the value a regression would silently fall back to — so assert both the
// per-host size and the total, which would cap it if left at Go's 100.
func TestNewPooledTransportSizesThePool(t *testing.T) {
	for _, tc := range []struct {
		name        string
		n           int
		wantPerHost int
		wantTotal   int
	}{
		{"explicit", 64, 64, 256},
		{"zero falls back to the default", 0, DefaultMaxIdleConnsPerHost, 4 * DefaultMaxIdleConnsPerHost},
		{"negative falls back to the default", -1, DefaultMaxIdleConnsPerHost, 4 * DefaultMaxIdleConnsPerHost},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tr := NewPooledTransport(tc.n)
			if tr.MaxIdleConnsPerHost != tc.wantPerHost {
				t.Errorf("MaxIdleConnsPerHost: got %d, want %d", tr.MaxIdleConnsPerHost, tc.wantPerHost)
			}
			if tr.MaxIdleConns != tc.wantTotal {
				t.Errorf("MaxIdleConns: got %d, want %d", tr.MaxIdleConns, tc.wantTotal)
			}
			// A per-host CAP would queue requests behind the pool instead of dialing;
			// the pool is about reuse, not admission control.
			if tr.MaxConnsPerHost != 0 {
				t.Errorf("MaxConnsPerHost: got %d, want 0 (unbounded)", tr.MaxConnsPerHost)
			}
		})
	}
}

// A Client built the normal way must not be left on http.DefaultTransport's
// 2-idle-connections-per-host: every request it makes goes to the same router
// host, so that default is a throughput ceiling, not a neutral setting.
func TestNewWithResolverUsesAPooledTransport(t *testing.T) {
	c := NewWithResolver(staticResolver{Provider{URL: "https://example.invalid"}})
	tr, ok := c.http.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("transport: got %T, want *http.Transport", c.http.Transport)
	}
	if tr.MaxIdleConnsPerHost != DefaultMaxIdleConnsPerHost {
		t.Errorf("MaxIdleConnsPerHost: got %d, want %d", tr.MaxIdleConnsPerHost, DefaultMaxIdleConnsPerHost)
	}
	if tr.ResponseHeaderTimeout != providerTimeout {
		t.Errorf("ResponseHeaderTimeout: got %v, want %v", tr.ResponseHeaderTimeout, providerTimeout)
	}
}

// WithMaxIdleConnsPerHost rebuilds the transport, so it must carry the long
// provider header timeout over — dropping it would turn a slow-but-healthy
// provider into a request failure.
func TestWithMaxIdleConnsPerHostKeepsTheHeaderTimeout(t *testing.T) {
	c := NewWithResolver(staticResolver{Provider{URL: "https://example.invalid"}}, WithMaxIdleConnsPerHost(7))
	tr := c.http.Transport.(*http.Transport)
	if tr.MaxIdleConnsPerHost != 7 {
		t.Errorf("MaxIdleConnsPerHost: got %d, want 7", tr.MaxIdleConnsPerHost)
	}
	if tr.ResponseHeaderTimeout != providerTimeout {
		t.Errorf("ResponseHeaderTimeout: got %v, want %v", tr.ResponseHeaderTimeout, providerTimeout)
	}
}

// A non-positive value is "leave it alone", so an unset config value can be passed
// straight through without the caller special-casing it.
func TestWithMaxIdleConnsPerHostIgnoresNonPositive(t *testing.T) {
	c := NewWithResolver(staticResolver{Provider{URL: "https://example.invalid"}}, WithMaxIdleConnsPerHost(0))
	tr := c.http.Transport.(*http.Transport)
	if tr.MaxIdleConnsPerHost != DefaultMaxIdleConnsPerHost {
		t.Errorf("MaxIdleConnsPerHost: got %d, want the untouched default %d", tr.MaxIdleConnsPerHost, DefaultMaxIdleConnsPerHost)
	}
}
