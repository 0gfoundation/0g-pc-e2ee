package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/0gfoundation/0g-pc-e2ee/client/dstack"
)

func writeIdentity(t *testing.T, info dstack.Info) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "identity.json")
	if err := dstack.WriteIdentityFile(path, info); err != nil {
		t.Fatalf("WriteIdentityFile: %v", err)
	}
	return path
}

func TestLoadIdentityFromFile(t *testing.T) {
	want := dstack.Info{InstanceID: "aa11bb22", AppID: "cc33dd44"}
	got, source, err := loadIdentity(writeIdentity(t, want), "")
	if err != nil {
		t.Fatalf("loadIdentity: %v", err)
	}
	if got != want {
		t.Errorf("identity = %+v, want %+v", got, want)
	}
	if !strings.HasPrefix(source, "file:") {
		t.Errorf("source = %q, want a file: source", source)
	}
}

// The file wins over the socket, because it is the lower-privilege path: the
// deployed gateway reads a file written by a container that exited, and never
// opens the guest-agent socket (which also derives keys and issues quotes). A
// socket path pointing nowhere must not be consulted at all when a file is set —
// if it were, this call would take the dial timeout and then fail.
func TestLoadIdentityPrefersFileOverSocket(t *testing.T) {
	path := writeIdentity(t, dstack.Info{InstanceID: "aa11bb22"})
	got, source, err := loadIdentity(path, filepath.Join(t.TempDir(), "absent.sock"))
	if err != nil {
		t.Fatalf("loadIdentity: %v", err)
	}
	if got.InstanceID != "aa11bb22" {
		t.Errorf("identity = %+v, want the file's", got)
	}
	if !strings.HasPrefix(source, "file:") {
		t.Errorf("source = %q, want the file to win", source)
	}
}

// A configured file that is missing or unreadable is an error the caller warns
// about and serves past — the deployed compose gates the gateway on the writer
// having completed, so this means something is wrong, and it should say so rather
// than silently falling back to the socket the deployment deliberately removed.
func TestLoadIdentityMissingFileErrors(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "absent.json")
	if _, err := os.Stat(missing); err == nil {
		t.Fatal("file unexpectedly exists")
	}
	_, source, err := loadIdentity(missing, "")
	if err == nil {
		t.Fatal("loadIdentity on a missing file = nil error, want failure")
	}
	if !strings.HasPrefix(source, "file:") {
		t.Errorf("source = %q, want the failing source named", source)
	}
}

// Neither source configured is a deliberate local-run setup, not a failure: it
// must return no error AND no source, so the caller logs nothing at all rather
// than warning about an absence the operator asked for.
func TestLoadIdentityUnconfigured(t *testing.T) {
	info, source, err := loadIdentity("", "")
	if err != nil {
		t.Fatalf("loadIdentity = %v, want no error", err)
	}
	if source != "" {
		t.Errorf("source = %q, want empty", source)
	}
	if info != (dstack.Info{}) {
		t.Errorf("identity = %+v, want zero", info)
	}
}
