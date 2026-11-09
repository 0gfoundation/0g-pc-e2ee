package proxyproto

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"
)

func v2Header(cmd, fam byte, payload []byte) []byte {
	var b bytes.Buffer
	b.Write(signature)
	b.WriteByte(0x20 | cmd)
	b.WriteByte(fam)
	_ = binary.Write(&b, binary.BigEndian, uint16(len(payload)))
	b.Write(payload)
	return b.Bytes()
}

func tcp4Payload(src net.IP, sport uint16) []byte {
	p := make([]byte, 12)
	copy(p[0:4], src.To4())
	copy(p[4:8], net.IPv4(10, 0, 0, 1).To4())
	binary.BigEndian.PutUint16(p[8:10], sport)
	binary.BigEndian.PutUint16(p[10:12], 443)
	return p
}

func tcp6Payload(src net.IP, sport uint16) []byte {
	p := make([]byte, 36)
	copy(p[0:16], src.To16())
	copy(p[16:32], net.ParseIP("fd00::1").To16())
	binary.BigEndian.PutUint16(p[32:34], sport)
	binary.BigEndian.PutUint16(p[34:36], 443)
	return p
}

func TestParseHeader(t *testing.T) {
	tests := []struct {
		name    string
		in      []byte
		want    string // "" = nil addr
		wantErr bool
	}{
		{name: "tcp4", in: v2Header(cmdProxy, famTCP4, tcp4Payload(net.ParseIP("203.0.113.7"), 51000)), want: "203.0.113.7:51000"},
		{name: "tcp6", in: v2Header(cmdProxy, famTCP6, tcp6Payload(net.ParseIP("2001:db8::7"), 51000)), want: "[2001:db8::7]:51000"},
		{name: "tcp4 with TLVs", in: v2Header(cmdProxy, famTCP4, append(tcp4Payload(net.ParseIP("198.51.100.2"), 1), 0x04, 0x00, 0x01, 0x00)), want: "198.51.100.2:1"},
		{name: "local keeps peer", in: v2Header(cmdLocal, 0x00, nil)},
		{name: "unspec keeps peer", in: v2Header(cmdProxy, 0x00, nil)},
		{name: "v1 text refused", in: []byte("PROXY TCP4 203.0.113.7 10.0.0.1 51000 443\r\n"), wantErr: true},
		{name: "plain http refused", in: []byte("GET / HTTP/1.1\r\nHost: x\r\n\r\n"), wantErr: true},
		{name: "short tcp4", in: v2Header(cmdProxy, famTCP4, make([]byte, 8)), wantErr: true},
		{name: "truncated", in: v2Header(cmdProxy, famTCP4, tcp4Payload(net.ParseIP("203.0.113.7"), 1))[:20], wantErr: true},
		{name: "oversized", in: v2Header(cmdProxy, famTCP4, make([]byte, maxPayload+1)), wantErr: true},
		{name: "bad command", in: v2Header(0x7, famTCP4, tcp4Payload(net.ParseIP("203.0.113.7"), 1)), wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			addr, err := parseHeader(bytes.NewReader(tt.in))
			if (err != nil) != tt.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, tt.wantErr)
			}
			got := ""
			if addr != nil {
				got = addr.String()
			}
			if got != tt.want {
				t.Fatalf("addr = %q, want %q", got, tt.want)
			}
		})
	}
}

// The header is consumed exactly: the bytes after it reach the reader intact.
func TestParseHeaderLeavesTheStreamAfterIt(t *testing.T) {
	r := bytes.NewReader(append(v2Header(cmdProxy, famTCP4, tcp4Payload(net.ParseIP("203.0.113.7"), 1)), "GET /"...))
	if _, err := parseHeader(r); err != nil {
		t.Fatal(err)
	}
	rest, _ := io.ReadAll(r)
	if string(rest) != "GET /" {
		t.Fatalf("rest = %q", rest)
	}
}

// serveOn starts an http.Server on a Listener wrapping a real TCP socket whose
// accepted connections are made to look non-loopback (asProxied) or not.
func serveOn(t *testing.T, asProxied bool, onErr func(net.Addr, error)) (addr string, seen chan string) {
	t.Helper()
	inner, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	seen = make(chan string, 4)
	var ln net.Listener = &Listener{Listener: inner, HeaderTimeout: 2 * time.Second, OnError: onErr}
	if asProxied {
		ln = &Listener{Listener: fakePeer{inner}, HeaderTimeout: 2 * time.Second, OnError: onErr}
	}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen <- r.RemoteAddr
		_, _ = io.WriteString(w, "ok")
	})}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })
	return inner.Addr().String(), seen
}

// fakePeer makes accepted loopback connections report a non-loopback peer, so the
// test exercises the path dstack-ingress's connections take.
type fakePeer struct{ net.Listener }

func (f fakePeer) Accept() (net.Conn, error) {
	c, err := f.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return remoteOverride{c}, nil
}

type remoteOverride struct{ net.Conn }

func (remoteOverride) RemoteAddr() net.Addr {
	return &net.TCPAddr{IP: net.ParseIP("172.18.0.3"), Port: 40000}
}

func rawRequest(t *testing.T, addr string, prefix []byte) string {
	t.Helper()
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	_, _ = c.Write(append(prefix, "GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n"...))
	b, _ := io.ReadAll(c)
	return string(b)
}

func TestProxiedConnectionGetsTheClientAddress(t *testing.T) {
	addr, seen := serveOn(t, true, nil)
	resp := rawRequest(t, addr, v2Header(cmdProxy, famTCP4, tcp4Payload(net.ParseIP("203.0.113.7"), 51000)))
	if !strings.HasPrefix(resp, "HTTP/1.1 200") {
		t.Fatalf("response %q", resp)
	}
	if got := <-seen; got != "203.0.113.7:51000" {
		t.Fatalf("RemoteAddr = %q", got)
	}
}

func TestProxiedConnectionWithoutHeaderIsRefused(t *testing.T) {
	errs := make(chan error, 1)
	addr, seen := serveOn(t, true, func(_ net.Addr, err error) { errs <- err })
	if resp := rawRequest(t, addr, nil); resp != "" {
		t.Fatalf("got a response without a header: %q", resp)
	}
	if err := <-errs; !errors.Is(err, ErrNoHeader) {
		t.Fatalf("OnError got %v", err)
	}
	select {
	case got := <-seen:
		t.Fatalf("handler ran for %q", got)
	default:
	}
}

// The container health probe dials 127.0.0.1 with plain HTTP and must keep working.
func TestLoopbackPeerNeedsNoHeader(t *testing.T) {
	addr, seen := serveOn(t, false, nil)
	resp := rawRequest(t, addr, nil)
	if !strings.HasPrefix(resp, "HTTP/1.1 200") {
		t.Fatalf("response %q", resp)
	}
	if got := <-seen; !strings.HasPrefix(got, "127.0.0.1:") {
		t.Fatalf("RemoteAddr = %q", got)
	}
}

// A peer that connects and sends nothing must not hold up other connections.
func TestSilentPeerDoesNotBlockAccept(t *testing.T) {
	addr, seen := serveOn(t, true, nil)
	idle, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer idle.Close()
	resp := rawRequest(t, addr, v2Header(cmdProxy, famTCP4, tcp4Payload(net.ParseIP("203.0.113.9"), 2)))
	if !strings.HasPrefix(resp, "HTTP/1.1 200") {
		t.Fatalf("response %q", resp)
	}
	if got := <-seen; got != "203.0.113.9:2" {
		t.Fatalf("RemoteAddr = %q", got)
	}
}
