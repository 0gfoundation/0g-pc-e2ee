package dstack

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// serveSocket starts an HTTP server on a unix socket in a temp dir and returns
// its path. It mirrors how the dstack guest agent is reached: no TCP, no TLS,
// plain HTTP over a filesystem socket the runtime bind-mounts in.
func serveSocket(t *testing.T, h http.Handler) string {
	t.Helper()
	// macOS caps a unix socket path at ~104 bytes and t.TempDir() can be long, so
	// keep the file name short.
	path := filepath.Join(t.TempDir(), "s.sock")
	ln, err := net.Listen("unix", path)
	if err != nil {
		t.Fatalf("listen unix: %v", err)
	}
	srv := &httptest.Server{Listener: ln, Config: &http.Server{Handler: h}}
	srv.Start()
	t.Cleanup(srv.Close)
	return path
}

func TestFetchInfo(t *testing.T) {
	var gotPath, gotBody, gotContentType string
	path := serveSocket(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotContentType = r.Header.Get("Content-Type")
		b, _ := io.ReadAll(r.Body)
		gotBody = string(b)
		// A trimmed copy of a real reply, including fields we deliberately ignore —
		// decoding must not care that the agent returns more than we asked for.
		_, _ = io.WriteString(w, `{
			"app_id": "3327603e03f5bd1f830812ca4a789277fc31f577",
			"instance_id": "aa11bb22cc33dd44ee55ff6600112233445566aa",
			"app_name": "0g-pc-gateway",
			"compose_hash": "beef00",
			"device_id": "cafe11",
			"tcb_info": {"mrtd": "…"},
			"key_provider_info": "{}"
		}`)
	}))

	info, err := FetchInfo(context.Background(), path)
	if err != nil {
		t.Fatalf("FetchInfo: %v", err)
	}
	if info.InstanceID != "aa11bb22cc33dd44ee55ff6600112233445566aa" {
		t.Errorf("InstanceID = %q", info.InstanceID)
	}
	if info.AppID != "3327603e03f5bd1f830812ca4a789277fc31f577" {
		t.Errorf("AppID = %q", info.AppID)
	}
	if info.AppName != "0g-pc-gateway" || info.ComposeHash != "beef00" {
		t.Errorf("AppName/ComposeHash = %q/%q", info.AppName, info.ComposeHash)
	}
	// The wire shape is the guest agent's contract (SDK DstackClient: POST /<Method>
	// with a JSON body), so pin it — a silent change here would surface only as a
	// missing label in production.
	if gotPath != "/Info" {
		t.Errorf("request path = %q, want /Info", gotPath)
	}
	if strings.TrimSpace(gotBody) != "{}" {
		t.Errorf("request body = %q, want {}", gotBody)
	}
	if gotContentType != "application/json" {
		t.Errorf("Content-Type = %q", gotContentType)
	}
}

// A missing socket is the ordinary case outside a CVM (local run, sidecar, CI).
// It must be a plain error the caller can log and move past, never a panic or a
// hang.
func TestFetchInfoMissingSocket(t *testing.T) {
	path := filepath.Join(t.TempDir(), "absent.sock")
	if _, err := os.Stat(path); err == nil {
		t.Fatal("socket unexpectedly exists")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if _, err := FetchInfo(ctx, path); err == nil {
		t.Fatal("FetchInfo on a missing socket = nil error, want failure")
	}
}

func TestFetchInfoRejectsBadResponses(t *testing.T) {
	cases := map[string]http.HandlerFunc{
		"non-200": func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		},
		"malformed json": func(w http.ResponseWriter, r *http.Request) {
			_, _ = io.WriteString(w, `{"instance_id":`)
		},
		"no instance id": func(w http.ResponseWriter, r *http.Request) {
			_, _ = io.WriteString(w, `{"app_id":"aa11"}`)
		},
		// An id that is not a bounded hex digest must not reach a metric label or a
		// log field, whatever the agent claims (see validID).
		"non-hex instance id": func(w http.ResponseWriter, r *http.Request) {
			_, _ = io.WriteString(w, `{"instance_id":"../../etc/passwd"}`)
		},
		"overlong instance id": func(w http.ResponseWriter, r *http.Request) {
			_, _ = io.WriteString(w, `{"instance_id":"`+strings.Repeat("a", maxIDLen+1)+`"}`)
		},
	}
	for name, h := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := FetchInfo(context.Background(), serveSocket(t, h)); err == nil {
				t.Fatal("FetchInfo = nil error, want failure")
			}
		})
	}
}

// A usable instance_id with an unusable app_id still yields identity: the
// instance label is what separates colliding replica series, so losing the app
// label must not cost us both.
func TestFetchInfoDropsBadAppIDOnly(t *testing.T) {
	path := serveSocket(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, `{"instance_id":"aa11","app_id":"NOT HEX"}`)
	}))
	info, err := FetchInfo(context.Background(), path)
	if err != nil {
		t.Fatalf("FetchInfo: %v", err)
	}
	if info.InstanceID != "aa11" {
		t.Errorf("InstanceID = %q, want aa11", info.InstanceID)
	}
	if info.AppID != "" {
		t.Errorf("AppID = %q, want dropped", info.AppID)
	}
}
