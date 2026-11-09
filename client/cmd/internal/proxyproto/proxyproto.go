// Package proxyproto reads the PROXY protocol v2 header dstack-ingress puts in
// front of each connection it hands the gateway, so the gateway sees the client's
// address instead of HAProxy's.
//
// Why it exists. The client's TCP connection ends twice before it reaches the
// gateway: at the dstack gateway (an L4 relay keyed on SNI) and at dstack-ingress's
// HAProxy (which terminates TLS in this CVM and opens a new plaintext connection to
// the gateway). Without help, r.RemoteAddr is HAProxy's compose-network address for
// every request. With the app's port policy set to `pp`, the dstack gateway prepends
// a PROXY header to the connection it relays; with ACCEPT_PROXY_PROTOCOL HAProxy
// reads it, and with SEND_PROXY_PROTOCOL it writes a v2 header carrying the same
// client address onto its own connection to us. This package reads that last one.
//
// Who is trusted to send it. Every connection from a non-loopback peer MUST start
// with a v2 header; one that does not is refused. That is only sound because the
// gateway's listen port is not published to the host (deploy/phala/docker-compose.yml)
// and so the only non-loopback peer is dstack-ingress. A loopback peer is never
// expected to send one and is passed through untouched: that is the container's own
// health probe (`gateway -health`), which dials 127.0.0.1 directly.
//
// Only v2 is accepted. HAProxy is configured with `send-proxy-v2`; a v1 (text)
// header, or anything else, means the two ends disagree, and failing closed makes
// that visible on the first connection rather than letting HAProxy's address pass
// for the client's.
//
// The header is read lazily, on the connection's own goroutine (the first Read or
// RemoteAddr call — net/http calls RemoteAddr first thing in its per-connection
// goroutine), never in Accept: a peer that connects and sends nothing must not stall
// the accept loop for everyone else.
package proxyproto

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"
)

// signature is the fixed 12-byte prefix of every v2 header.
var signature = []byte{0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A}

const (
	cmdLocal = 0x0
	cmdProxy = 0x1

	famTCP4 = 0x11
	famTCP6 = 0x21

	// maxPayload bounds the address block plus TLVs. `send-proxy-v2` with no
	// options carries 12 (IPv4) or 36 (IPv6) bytes and no TLVs; the cap only stops
	// a malformed length from making us read 64 KiB per connection.
	maxPayload = 2048
)

// DefaultHeaderTimeout bounds how long a peer may take to deliver the header.
const DefaultHeaderTimeout = 10 * time.Second

// ErrNoHeader is returned (from Read) when a peer that must send a header did not
// start the connection with a v2 signature.
var ErrNoHeader = errors.New("proxyproto: connection did not start with a PROXY v2 header")

// Listener wraps a net.Listener so that connections from non-loopback peers have
// their PROXY v2 header consumed and their RemoteAddr replaced by the address it
// names.
type Listener struct {
	net.Listener
	// HeaderTimeout bounds the header read; zero means DefaultHeaderTimeout.
	HeaderTimeout time.Duration
	// OnError, if set, is called once for each connection whose header was missing
	// or malformed. The connection is closed after it returns.
	OnError func(peer net.Addr, err error)
	// OnResult, if set, is called once per accepted connection with its outcome:
	// ResultLoopback at accept, and one of ResultProxied, ResultLocal or
	// ResultRefused once the header has been read. It carries no address on
	// purpose (see the metric it feeds).
	OnResult func(result string)
}

// Connection outcomes reported to Listener.OnResult.
const (
	ResultProxied  = "proxied"  // a v2 header named a TCP client
	ResultLocal    = "local"    // a valid header naming no client (LOCAL, or a non-TCP family)
	ResultLoopback = "loopback" // exempt peer; no header expected
	ResultRefused  = "refused"  // header missing or malformed; connection closed
)

// Accept returns the next connection. It does not read from it.
func (l *Listener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	if isLoopback(c.RemoteAddr()) {
		if l.OnResult != nil {
			l.OnResult(ResultLoopback)
		}
		return c, nil
	}
	timeout := l.HeaderTimeout
	if timeout <= 0 {
		timeout = DefaultHeaderTimeout
	}
	return &Conn{Conn: c, timeout: timeout, onError: l.OnError, onResult: l.OnResult}, nil
}

// Conn is a connection whose first bytes are a PROXY v2 header.
type Conn struct {
	net.Conn
	timeout  time.Duration
	onError  func(peer net.Addr, err error)
	onResult func(result string)

	once   sync.Once
	remote net.Addr // the client address the header named; nil until read, or for LOCAL
	err    error
}

func (c *Conn) readHeader() {
	c.once.Do(func() {
		_ = c.Conn.SetReadDeadline(time.Now().Add(c.timeout))
		c.remote, c.err = parseHeader(c.Conn)
		// Clear it: net/http sets its own read deadlines per request afterwards.
		_ = c.Conn.SetReadDeadline(time.Time{})
		if c.err != nil {
			if c.onError != nil {
				c.onError(c.Conn.RemoteAddr(), c.err)
			}
			_ = c.Conn.Close()
		}
		if c.onResult != nil {
			switch {
			case c.err != nil:
				c.onResult(ResultRefused)
			case c.remote != nil:
				c.onResult(ResultProxied)
			default:
				c.onResult(ResultLocal)
			}
		}
	})
}

// Read reads application data, after the header.
func (c *Conn) Read(p []byte) (int, error) {
	c.readHeader()
	if c.err != nil {
		return 0, c.err
	}
	return c.Conn.Read(p)
}

// RemoteAddr is the client address the header named. For a LOCAL header (a
// health check from the proxy itself), or one whose address family is not TCP
// over IPv4/IPv6, it is the TCP peer's address; so is it when the header could
// not be read, in which case the connection is already closed.
func (c *Conn) RemoteAddr() net.Addr {
	c.readHeader()
	if c.remote != nil {
		return c.remote
	}
	return c.Conn.RemoteAddr()
}

// parseHeader reads exactly one v2 header from r — no more, because the length is
// explicit — and returns the source address it carries, or nil when it carries
// none the caller should use.
func parseHeader(r io.Reader) (net.Addr, error) {
	var hdr [16]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, fmt.Errorf("proxyproto: read header: %w", err)
	}
	if !bytes.Equal(hdr[:12], signature) {
		return nil, ErrNoHeader
	}
	if v := hdr[12] >> 4; v != 2 {
		return nil, fmt.Errorf("proxyproto: version %d, want 2", v)
	}
	cmd := hdr[12] & 0x0F
	fam := hdr[13]
	n := int(binary.BigEndian.Uint16(hdr[14:16]))
	if n > maxPayload {
		return nil, fmt.Errorf("proxyproto: header payload %d bytes exceeds %d", n, maxPayload)
	}
	payload := make([]byte, n)
	if _, err := io.ReadFull(r, payload); err != nil {
		return nil, fmt.Errorf("proxyproto: read header payload: %w", err)
	}
	switch cmd {
	case cmdLocal:
		return nil, nil
	case cmdProxy:
	default:
		return nil, fmt.Errorf("proxyproto: unknown command %#x", cmd)
	}
	switch fam {
	case famTCP4:
		if n < 12 {
			return nil, fmt.Errorf("proxyproto: TCP/IPv4 payload %d bytes, want at least 12", n)
		}
		ip := make(net.IP, net.IPv4len)
		copy(ip, payload[0:4])
		return &net.TCPAddr{IP: ip, Port: int(binary.BigEndian.Uint16(payload[8:10]))}, nil
	case famTCP6:
		if n < 36 {
			return nil, fmt.Errorf("proxyproto: TCP/IPv6 payload %d bytes, want at least 36", n)
		}
		ip := make(net.IP, net.IPv6len)
		copy(ip, payload[0:16])
		return &net.TCPAddr{IP: ip, Port: int(binary.BigEndian.Uint16(payload[32:34]))}, nil
	default:
		// UNSPEC, UDP or UNIX: a valid header that names no TCP client. Keep the
		// peer's address rather than inventing one.
		return nil, nil
	}
}

func isLoopback(a net.Addr) bool {
	if t, ok := a.(*net.TCPAddr); ok {
		return t.IP.IsLoopback()
	}
	host, _, err := net.SplitHostPort(a.String())
	if err != nil {
		return false
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
