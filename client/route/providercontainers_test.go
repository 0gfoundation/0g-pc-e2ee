package route

import (
	"crypto/sha256"
	"encoding/json"
	"testing"
)

// appComposeWith wraps a compose text in the app-compose.json envelope, the way
// dstack does, and returns the bytes plus the compose hash a quote would commit to.
// The hash is taken over exactly these bytes — the property VerifyAppCompose
// enforces and the reason nothing may reformat them on the way.
func appComposeWith(t *testing.T, composeText string) ([]byte, [32]byte) {
	t.Helper()
	raw, err := json.Marshal(map[string]string{"docker_compose_file": composeText})
	if err != nil {
		t.Fatalf("marshal app-compose: %v", err)
	}
	return raw, sha256.Sum256(raw)
}

const testComposeText = `services:
  broker:
    image: ghcr.io/0gfoundation/0g-serving-broker@sha256:ec5df834
  sglang:
    image: lmsysorg/sglang:v0.5.17@sha256:220bb1a1
  prometheus:
    image: prom/prometheus:v2.45.2
`

func TestContainersOfParsesVerifiedCompose(t *testing.T) {
	r := &Router{logger: discardLogger()}
	raw, hash := appComposeWith(t, testComposeText)

	got := r.containersOf(raw, hash, "https://broker.example/v1/quote")
	if len(got) != 3 {
		t.Fatalf("got %d services, want 3: %+v", len(got), got)
	}
	// File order, not map order: a list that reshuffles between two fetches of an
	// unchanged deployment reads as the deployment having changed.
	if got[0].Name != "broker" || got[1].Name != "sglang" || got[2].Name != "prometheus" {
		t.Errorf("services out of file order: %v, %v, %v", got[0].Name, got[1].Name, got[2].Name)
	}
	if got[0].Digest != "sha256:ec5df834" {
		t.Errorf("broker digest = %q, want the pinned one", got[0].Digest)
	}
	// The finding a reader can draw unaided: an image pinned only by tag leaves
	// compose_hash committing to a name whose contents can be republished under it.
	if got[2].Digest != "" {
		t.Errorf("prometheus digest = %q, want empty for a tag-only reference", got[2].Digest)
	}
	if got[2].Tag != "v2.45.2" {
		t.Errorf("prometheus tag = %q, want v2.45.2", got[2].Tag)
	}
}

// The hash gate is the whole security argument of this path: before it the text is
// whatever the provider (or anyone on the path) sent. A mismatch must yield nothing
// — never a "probably right" list.
func TestContainersOfRejectsUnmatchedComposeHash(t *testing.T) {
	r := &Router{logger: discardLogger()}
	raw, _ := appComposeWith(t, testComposeText)
	_, otherHash := appComposeWith(t, "services:\n  evil:\n    image: attacker/x:latest\n")

	if got := r.containersOf(raw, otherHash, "https://broker.example/v1/quote"); got != nil {
		t.Fatalf("containers = %+v, want nil when the app-compose does not hash to the quote's compose_hash", got)
	}
}

// A single flipped byte must fail too — the check is over the exact bytes, not over
// JSON that happens to be equivalent.
func TestContainersOfRejectsTamperedBytes(t *testing.T) {
	r := &Router{logger: discardLogger()}
	raw, hash := appComposeWith(t, testComposeText)
	tampered := append([]byte(nil), raw...)
	tampered[len(tampered)-2] ^= 0x01

	if got := r.containersOf(tampered, hash, "https://broker.example/v1/quote"); got != nil {
		t.Fatalf("containers = %+v, want nil for tampered bytes", got)
	}
}

// Every non-success path is "nothing to show", never a failed request: a provider is
// not less usable because its container list could not be drawn.
func TestContainersOfDegradesQuietly(t *testing.T) {
	r := &Router{logger: discardLogger()}

	t.Run("no app-compose in the reply", func(t *testing.T) {
		_, hash := appComposeWith(t, testComposeText)
		if got := r.containersOf(nil, hash, "u"); got != nil {
			t.Errorf("containers = %+v, want nil", got)
		}
	})

	t.Run("authenticated but not a compose file", func(t *testing.T) {
		raw, hash := appComposeWith(t, "just: a scalar mapping\nwith: no services\n")
		if got := r.containersOf(raw, hash, "u"); got != nil {
			t.Errorf("containers = %+v, want nil", got)
		}
	})

	t.Run("authenticated but unparseable YAML", func(t *testing.T) {
		raw, hash := appComposeWith(t, "services:\n  broker:\n   image: \"unterminated\n")
		if got := r.containersOf(raw, hash, "u"); got != nil {
			t.Errorf("containers = %+v, want nil", got)
		}
	})
}
