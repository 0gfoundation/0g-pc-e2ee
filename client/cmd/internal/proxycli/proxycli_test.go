package proxycli

import (
	"bufio"
	"errors"
	"flag"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"syscall"
	"testing"
	"time"

	"github.com/0gfoundation/0g-pc-e2ee/client/endpoint"
)

// testLogger discards output; the shutdown tests assert on serve's return value
// and the listener state, not on log lines.
func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// serve returns nil once a shutdown signal triggers a graceful drain, and the
// listener is released so a redeploy can rebind the port.
func TestServeGracefulShutdownOnSignal(t *testing.T) {
	// Bind an ephemeral port ourselves so we know the address (ListenAndServe
	// with :0 hides the chosen port), then close it: serve rebinds the same
	// address, and after shutdown we confirm it is free again.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve port: %v", err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()

	srv := &http.Server{Addr: addr, Handler: http.NewServeMux()}
	sigCh := make(chan os.Signal, 1)
	done := make(chan error, 1)
	go func() { done <- serve(srv, testLogger(), sigCh) }()

	// Wait until serve has bound the port before signalling, so the drain path
	// (not the pre-bind shortcut) is what's exercised.
	waitListening(t, addr)

	sigCh <- syscall.SIGTERM
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("serve returned error on clean shutdown: %v", err)
		}
	case <-time.After(ShutdownTimeout + 2*time.Second):
		t.Fatal("serve did not return after shutdown signal")
	}

	// The port must be released: a graceful shutdown that leaked the listener
	// would block the redeploy this feature exists to support.
	reln, err := net.Listen("tcp", addr)
	if err != nil {
		t.Fatalf("port not released after shutdown: %v", err)
	}
	_ = reln.Close()
}

// serve returns the listen error (and does not block waiting for a signal) when
// the address is already bound.
func TestServeReturnsListenError(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("occupy port: %v", err)
	}
	defer ln.Close()

	srv := &http.Server{Addr: ln.Addr().String(), Handler: http.NewServeMux()}
	sigCh := make(chan os.Signal, 1) // never fires
	done := make(chan error, 1)
	go func() { done <- serve(srv, testLogger(), sigCh) }()

	select {
	case err := <-done:
		if err == nil {
			t.Fatal("serve returned nil for an occupied port; want a listen error")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("serve blocked instead of returning the listen error")
	}
}

// waitListening polls addr until a TCP connection succeeds or the deadline
// passes, so a test can synchronize on the server actually being up.
func waitListening(t *testing.T, addr string) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		c, err := net.DialTimeout("tcp", addr, 100*time.Millisecond)
		if err == nil {
			_ = c.Close()
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("server did not start listening on %s", addr)
}

// envOr uses an env var only when it is present; a set-but-empty value is
// honored (not treated as unset), since "" is meaningful for the CSV fields.
func TestEnvOr(t *testing.T) {
	const key = "ZG_PROXYCLI_TEST_ENVOR"
	t.Setenv(key, "from-env")
	if got := envOr(key, "def"); got != "from-env" {
		t.Fatalf("set var: got %q, want %q", got, "from-env")
	}
	t.Setenv(key, "")
	if got := envOr(key, "def"); got != "" {
		t.Fatalf("empty var: got %q, want empty (honored, not defaulted)", got)
	}
	if got := envOr("ZG_PROXYCLI_TEST_UNSET", "def"); got != "def" {
		t.Fatalf("unset var: got %q, want %q", got, "def")
	}
}

// envBool falls back to def when unset and parses standard boolean forms when
// set. (The set-but-unparseable case is log.Fatal, so it is not exercised here.)
func TestEnvBool(t *testing.T) {
	const key = "ZG_PROXYCLI_TEST_ENVBOOL"
	if got := envBool("ZG_PROXYCLI_TEST_UNSET_BOOL", true); !got {
		t.Fatal("unset var: want fallback to def=true")
	}
	for _, tc := range []struct {
		val  string
		want bool
	}{{"true", true}, {"1", true}, {"false", false}, {"0", false}} {
		t.Setenv(key, tc.val)
		if got := envBool(key, !tc.want); got != tc.want {
			t.Fatalf("%s=%q: got %v, want %v", key, tc.val, got, tc.want)
		}
	}
}

// envDuration falls back to def when unset and parses Go duration syntax when
// set. (The set-but-unparseable case is log.Fatal, so it is not exercised here.)
func TestEnvDuration(t *testing.T) {
	const key = "ZG_PROXYCLI_TEST_ENVDUR"
	if got := envDuration("ZG_PROXYCLI_TEST_UNSET_DUR", 4*time.Minute); got != 4*time.Minute {
		t.Fatalf("unset var: got %v, want fallback 4m", got)
	}
	t.Setenv(key, "90s")
	if got := envDuration(key, time.Minute); got != 90*time.Second {
		t.Fatalf("%s=90s: got %v, want 90s", key, got)
	}
}

// StartWarmer is a no-op that returns a safe-to-call stop when warming was not
// configured (the common case: -warm off leaves warmInterval zero and resolver
// nil), so the mains can wire it unconditionally.
func TestStartWarmerNoopWhenOff(t *testing.T) {
	stop := (&Built{}).StartWarmer(testLogger())
	if stop == nil {
		t.Fatal("StartWarmer returned a nil stop func")
	}
	stop() // must not panic or block
}

// TestBuildDirectMode: -provider-url selects direct-broker mode — Build wires a
// working client with no router (so no warmer), and -verify-responses is allowed
// without -attest (in direct mode the signer comes from the broker the operator
// pointed at, not an untrusted router). Exercises the direct branch via the real
// flag path; a valid combination never hits Build's os.Exit.
func TestBuildDirectMode(t *testing.T) {
	fs := flag.NewFlagSet("t", flag.ContinueOnError)
	f := RegisterFlags(fs, "ZG_TEST", ":0")
	if err := fs.Parse([]string{"-provider-url", "https://broker.example/v1", "-verify-responses"}); err != nil {
		t.Fatalf("parse: %v", err)
	}
	built := f.Build("test", testLogger())
	if built.Clients[endpoint.Chat.Path] == nil {
		t.Fatal("direct mode should build a chat client")
	}
	if len(built.Clients) != 1 {
		t.Errorf("direct mode must build chat ONLY (its broker paths are chat-shaped), got %d clients", len(built.Clients))
	}
	if built.router != nil {
		t.Error("direct mode should not build a router")
	}
	// No warmer in direct mode: StartWarmer must be a no-op that returns cleanly.
	built.StartWarmer(testLogger())()
	// And no provider-identity source: direct mode pins no on-chain provider address,
	// so there is nothing a record could be keyed by and nothing for the gateway to
	// mount a route over.
	if built.ProviderIdentities() != nil {
		t.Error("direct mode should expose no provider-identity source")
	}
}

// The provider-identity source exists exactly when a verdict could ever be
// produced: router mode with -attest. Without -attest nothing is verified, and a
// gateway that mounted the route anyway would serve a surface that can only 404 —
// which reads, to a panel, as "this provider is unknown" rather than "this
// deployment does not verify providers".
func TestBuildProviderIdentitiesRequiresAttest(t *testing.T) {
	for _, tc := range []struct {
		name string
		args []string
		want bool
	}{
		{"router mode without -attest", nil, false},
		{"router mode with -attest", []string{"-attest"}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fs := flag.NewFlagSet("t", flag.ContinueOnError)
			f := RegisterFlags(fs, "ZG_TEST", ":0")
			if err := fs.Parse(tc.args); err != nil {
				t.Fatalf("parse: %v", err)
			}
			if got := f.Build("test", testLogger()).ProviderIdentities() != nil; got != tc.want {
				t.Errorf("ProviderIdentities() non-nil = %v, want %v", got, tc.want)
			}
		})
	}
}

// IdleTimeout's whole justification is a net/http behaviour that is easy to
// misread: ReadHeaderTimeout does NOT bound a connection sitting idle between
// requests, only IdleTimeout does. Both halves are asserted here, so if a future
// Go release changes either one the constant's doc comment stops being true and
// this test says so — rather than the comment quietly becoming folklore.
func TestIdleKeepAliveIsBoundedOnlyByIdleTimeout(t *testing.T) {
	// Short enough to keep the test fast, long enough that a loaded machine does
	// not close the connection for unrelated reasons.
	const short = 150 * time.Millisecond

	for _, tc := range []struct {
		name        string
		idleTimeout time.Duration
		wantClosed  bool
	}{
		{"IdleTimeout set closes the idle connection", short, true},
		{"ReadHeaderTimeout alone leaves it open", 0, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ln, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatalf("listen: %v", err)
			}
			srv := &http.Server{
				Handler:           http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("ok")) }),
				ReadHeaderTimeout: short,
				IdleTimeout:       tc.idleTimeout,
			}
			go func() { _ = srv.Serve(ln) }()
			defer func() { _ = srv.Close() }()

			conn, err := net.Dial("tcp", ln.Addr().String())
			if err != nil {
				t.Fatalf("dial: %v", err)
			}
			defer func() { _ = conn.Close() }()

			// One complete request/response first: the state under test is IDLE
			// (between requests), which a never-used connection is not in.
			if _, err := io.WriteString(conn, "GET / HTTP/1.1\r\nHost: test\r\n\r\n"); err != nil {
				t.Fatalf("write request: %v", err)
			}
			br := bufio.NewReader(conn)
			resp, err := http.ReadResponse(br, nil)
			if err != nil {
				t.Fatalf("read response: %v", err)
			}
			if _, err := io.Copy(io.Discard, resp.Body); err != nil {
				t.Fatalf("drain body: %v", err)
			}
			_ = resp.Body.Close()

			// Now send nothing and see whether the server hangs up. A server-side
			// close surfaces as EOF (or a reset); a connection still held open
			// surfaces as our own read deadline. Waiting several multiples of
			// `short` keeps a slow machine from flipping the verdict.
			if err := conn.SetReadDeadline(time.Now().Add(6 * short)); err != nil {
				t.Fatalf("set deadline: %v", err)
			}
			_, err = br.Peek(1)
			closed := err != nil && !errors.Is(err, os.ErrDeadlineExceeded)
			if closed != tc.wantClosed {
				t.Errorf("idle connection closed = %v (err %v), want closed = %v", closed, err, tc.wantClosed)
			}
		})
	}
}

// Direct-broker mode serves chat alone whatever the binary asked for: NewDirect
// derives the broker's paths as chat, so any other row would seal to a chat
// endpoint. A binary that asks for endpoint.All must therefore still end up with
// exactly one client.
//
// The served set used to be decided twice — the Serves list drove the startup
// field-set validation while the direct branch hard-coded chat — so a direct-mode
// gateway asking for endpoint.All refused to start on a setting that was only
// invalid for the image profile it would never seal under. That validation is
// gone with the flags that fed it, but the narrowing it exposed is the behavior
// asserted here.
func TestBuildDirectModeServesChatOnly(t *testing.T) {
	fs := flag.NewFlagSet("t", flag.ContinueOnError)
	f := RegisterFlags(fs, "ZG_TEST", ":0")
	if err := fs.Parse([]string{"-provider-url", "https://broker.example/v1"}); err != nil {
		t.Fatalf("parse: %v", err)
	}
	built := f.Build("test", testLogger(), Serves(endpoint.All...))
	if len(built.Clients) != 1 || built.Clients[endpoint.Chat.Path] == nil {
		t.Errorf("direct mode must build the chat client and nothing else, got %d clients", len(built.Clients))
	}
}

// Composing Serves more than once must not warm a fleet twice or validate a
// profile twice: the served set is de-duplicated by Path before anything reads
// it. Only the clients map is observable from here (the warm list is internal
// to route), so that is what is asserted.
func TestBuildServesDeduplicates(t *testing.T) {
	fs := flag.NewFlagSet("t", flag.ContinueOnError)
	f := RegisterFlags(fs, "ZG_TEST", ":0")
	if err := fs.Parse(nil); err != nil {
		t.Fatalf("parse: %v", err)
	}
	built := f.Build("test", testLogger(), Serves(endpoint.All...), Serves(endpoint.Chat), Serves(endpoint.All...))
	if len(built.Clients) != len(endpoint.All) {
		t.Errorf("built %d clients from a triple-composed Serves, want %d", len(built.Clients), len(endpoint.All))
	}
	got := servedSurfaces([]endpoint.Endpoint{endpoint.Chat, endpoint.Image, endpoint.Chat}, false)
	if len(got) != 2 || got[0].Path != endpoint.Chat.Path || got[1].Path != endpoint.Image.Path {
		t.Errorf("servedSurfaces must de-duplicate preserving first-seen order, got %v", got)
	}
}

// A client is built per served row and only per served row: the gateway passes
// endpoint.All and gets one per surface, the sidecar passes nothing and gets
// chat alone. The same list picks the router's warm service types — warming a
// fleet the binary will never seal to buys nothing and takes on that
// enumeration's failure modes for free — but that list is not observable from
// outside route, so this asserts only the clients. What WithWarmServiceTypes then
// does with the list is covered in route (TestWarmer_OneFailingServiceType...).
func TestBuildClientsFollowWhatTheBinaryServes(t *testing.T) {
	for _, tc := range []struct {
		name string
		opts []BuildOption
		want []endpoint.Endpoint
	}{
		{"sidecar-shaped: chat only", nil, []endpoint.Endpoint{endpoint.Chat}},
		{"gateway-shaped: every row", []BuildOption{Serves(endpoint.All...)}, endpoint.All},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fs := flag.NewFlagSet("t", flag.ContinueOnError)
			f := RegisterFlags(fs, "ZG_TEST", ":0")
			if err := fs.Parse(nil); err != nil {
				t.Fatalf("parse: %v", err)
			}
			built := f.Build("test", testLogger(), tc.opts...)
			if len(built.Clients) != len(tc.want) {
				t.Errorf("built %d clients, want %d", len(built.Clients), len(tc.want))
			}
			for _, ep := range tc.want {
				if built.Clients[ep.Path] == nil {
					t.Errorf("no client for served surface %s", ep.Path)
				}
			}
		})
	}
}
