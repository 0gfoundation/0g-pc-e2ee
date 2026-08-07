package core

import "net/http"

// maxIdleConnsPerHost is the idle-connection pool size the proxy forms' HTTP
// transports keep per upstream host.
//
// Go's own default (http.DefaultMaxIdleConnsPerHost) is 2, which is sized for a
// command-line client, not for a server that fans every one of its own requests
// out to the SAME upstream. Both proxy forms are the latter: every request makes
// several calls to the one router host (route preview, the sealed completion) and
// to a handful of provider endpoints (pubkey, quote, §8 signature). Past two
// concurrent calls to a host, a pool of 2 forces each additional connection to be
// dialed, TLS-handshaked, and then DISCARDED on release because the pool is
// already full — so the cost is paid again on the next request. The symptom is a
// throughput ceiling far below what the CPU can do, with handshake churn and
// TIME_WAIT accumulation instead of useful work.
//
// 128 sits above the concurrency a single gateway instance is expected to carry
// against one host, so a steady load reuses connections instead of re-dialing.
//
// It is a constant, not a flag, on purpose: the value that is right for a
// deployment cannot be reasoned about without the measurement in loadtest/, and a
// knob whose correct setting nobody can judge is a knob someone eventually sets to
// something slow. If a measurement shows 128 is wrong, change it here — that is
// one number in one place, and it reaches both proxy forms and all three
// transports at once.
const maxIdleConnsPerHost = 128

// NewPooledTransport clones http.DefaultTransport (keeping its environment proxy
// support, dial and TLS handshake timeouts, and keepalives) and resizes the idle
// connection pool for server-side proxy use: maxIdleConnsPerHost per host, and a
// process-wide MaxIdleConns four times that, since the proxy talks to a small
// number of hosts (the router plus a few provider endpoints) and a total cap below
// the per-host cap would silently defeat it.
//
// MaxConnsPerHost is deliberately left at 0 (unbounded): this is a REUSE pool, not
// admission control. A burst beyond it still gets connections — they are just
// closed rather than kept when released.
//
// It is exported because all three transports that need it are built in different
// packages (core here, route's control-plane client, and route's §8 signature
// fetcher), and they must not each re-derive the sizing. The caller still owns any
// timeout that depends on what the transport is used for — notably
// ResponseHeaderTimeout, which core sets to the long provider timeout and route to
// a short control-plane one.
func NewPooledTransport() *http.Transport {
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.MaxIdleConnsPerHost = maxIdleConnsPerHost
	tr.MaxIdleConns = 4 * maxIdleConnsPerHost
	return tr
}
