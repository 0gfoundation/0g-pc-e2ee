package core

import (
	"net/http"
	"testing"
)

// The pool size is the whole point of this helper, and Go's 2-per-host default is
// exactly the value a regression would silently fall back to — so assert the
// per-host size, the total (which would cap it if left at Go's 100), and that the
// per-host CONNECTION cap stays off: this is a reuse pool, and capping connections
// would queue requests behind it instead of dialing.
func TestNewPooledTransportSizesThePool(t *testing.T) {
	tr := NewPooledTransport()
	if tr.MaxIdleConnsPerHost != maxIdleConnsPerHost {
		t.Errorf("MaxIdleConnsPerHost: got %d, want %d", tr.MaxIdleConnsPerHost, maxIdleConnsPerHost)
	}
	if want := 4 * maxIdleConnsPerHost; tr.MaxIdleConns != want {
		t.Errorf("MaxIdleConns: got %d, want %d", tr.MaxIdleConns, want)
	}
	if tr.MaxIdleConns < tr.MaxIdleConnsPerHost {
		t.Errorf("MaxIdleConns %d below MaxIdleConnsPerHost %d: the total would silently cap the per-host pool",
			tr.MaxIdleConns, tr.MaxIdleConnsPerHost)
	}
	if tr.MaxConnsPerHost != 0 {
		t.Errorf("MaxConnsPerHost: got %d, want 0 (unbounded)", tr.MaxConnsPerHost)
	}
	// Cloning http.DefaultTransport is what carries the environment proxy support
	// and the dial/handshake timeouts; a hand-built transport would drop them.
	if tr.Proxy == nil {
		t.Error("Proxy: nil, want http.DefaultTransport's ProxyFromEnvironment")
	}
	if tr.TLSHandshakeTimeout == 0 {
		t.Error("TLSHandshakeTimeout: 0, want http.DefaultTransport's")
	}
}

// A Client built the normal way must not be left on http.DefaultTransport's
// 2-idle-connections-per-host: every request it makes goes to the same router
// host, so that default is a throughput ceiling, not a neutral setting. The long
// provider header timeout has to survive alongside it — dropping that would turn a
// slow-but-healthy provider into a request failure.
func TestNewWithResolverUsesAPooledTransport(t *testing.T) {
	c := NewWithResolver(staticResolver{Provider{URL: "https://example.invalid"}})
	tr, ok := c.http.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("transport: got %T, want *http.Transport", c.http.Transport)
	}
	if tr.MaxIdleConnsPerHost != maxIdleConnsPerHost {
		t.Errorf("MaxIdleConnsPerHost: got %d, want %d", tr.MaxIdleConnsPerHost, maxIdleConnsPerHost)
	}
	if tr.ResponseHeaderTimeout != providerTimeout {
		t.Errorf("ResponseHeaderTimeout: got %v, want %v", tr.ResponseHeaderTimeout, providerTimeout)
	}
	// A blunt client timeout would cut a long stream; the header wait above is the
	// only bound on the data path (see NewWithResolver).
	if c.http.Timeout != 0 {
		t.Errorf("Client.Timeout: got %v, want 0 (it would cut a long stream)", c.http.Timeout)
	}
}
