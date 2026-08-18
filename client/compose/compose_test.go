package compose

import (
	"errors"
	"strings"
	"testing"
)

// The real shape: the deployment's own compose file, trimmed to what this package
// reads. Service order here is the order the assertions expect back.
const deployedCompose = `services:
  cvm-identity:
    image: ghcr.io/0gfoundation/0g-pc-e2ee-gateway@sha256:9c41ab7e
    entrypoint: ["/usr/local/bin/cvmid"]

  dstack-ingress:
    image: dstacktee/dstack-ingress:2.3@sha256:527c5352
    restart: unless-stopped

  gateway:
    image: ghcr.io/0gfoundation/0g-pc-e2ee-gateway@sha256:9c41ab7e
    environment:
      - "ZG_GATEWAY_LISTEN=0.0.0.0:8443"

  prometheus-agent:
    image: prom/prometheus:v2.55.1@sha256:2659f4c2

volumes:
  identity:
`

func TestParseServices(t *testing.T) {
	got, err := ParseServices([]byte(deployedCompose))
	if err != nil {
		t.Fatalf("ParseServices: %v", err)
	}
	want := []Service{
		{Name: "cvm-identity", Image: "ghcr.io/0gfoundation/0g-pc-e2ee-gateway", Digest: "sha256:9c41ab7e"},
		{Name: "dstack-ingress", Image: "dstacktee/dstack-ingress", Tag: "2.3", Digest: "sha256:527c5352"},
		{Name: "gateway", Image: "ghcr.io/0gfoundation/0g-pc-e2ee-gateway", Digest: "sha256:9c41ab7e"},
		{Name: "prometheus-agent", Image: "prom/prometheus", Tag: "v2.55.1", Digest: "sha256:2659f4c2"},
	}
	if len(got) != len(want) {
		t.Fatalf("got %d services, want %d: %+v", len(got), len(want), got)
	}
	for i := range want {
		if got[i].Name != want[i].Name || got[i].Image != want[i].Image ||
			got[i].Tag != want[i].Tag || got[i].Digest != want[i].Digest {
			t.Errorf("service %d = %+v, want %+v", i, got[i], want[i])
		}
	}
}

// File order, not map order. Unmarshalling into a Go map would return these in a
// random order on every call, so a UI refetching an unchanged deployment would see
// its container list reshuffle and read that as a change.
func TestParseServices_PreservesFileOrder(t *testing.T) {
	doc := []byte("services:\n  zebra:\n    image: a\n  alpha:\n    image: b\n  middle:\n    image: c\n")
	// Repeated because a map-based implementation passes this by luck once in six.
	for i := 0; i < 20; i++ {
		got, err := ParseServices(doc)
		if err != nil {
			t.Fatalf("ParseServices: %v", err)
		}
		if got[0].Name != "zebra" || got[1].Name != "alpha" || got[2].Name != "middle" {
			t.Fatalf("order = %s, %s, %s; want the file's", got[0].Name, got[1].Name, got[2].Name)
		}
	}
}

// The raw reference is kept so a caller can show what the file says rather than
// what this package made of it.
func TestParseServices_KeepsRawRef(t *testing.T) {
	got, err := ParseServices([]byte("services:\n  x:\n    image: prom/prometheus:v2.55.1@sha256:2659f4c2\n"))
	if err != nil {
		t.Fatalf("ParseServices: %v", err)
	}
	if want := "prom/prometheus:v2.55.1@sha256:2659f4c2"; got[0].Ref != want {
		t.Errorf("Ref = %q, want %q", got[0].Ref, want)
	}
}

// A service with no `image:` is REPORTED with an empty one, never dropped: a
// container the deployment runs must not vanish from a list of what it runs.
func TestParseServices_ServiceWithoutImage(t *testing.T) {
	got, err := ParseServices([]byte("services:\n  built:\n    build: .\n  pulled:\n    image: alpine:3\n"))
	if err != nil {
		t.Fatalf("ParseServices: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("got %d services, want both: %+v", len(got), got)
	}
	if got[0].Name != "built" || got[0].Image != "" || got[0].Ref != "" {
		t.Errorf("service without an image = %+v, want it listed with empty image fields", got[0])
	}
}

func TestParseServices_Errors(t *testing.T) {
	for name, doc := range map[string]string{
		"empty":              "",
		"no services key":    "volumes:\n  identity:\n",
		"services is null":   "services:\n",
		"services is a list": "services:\n  - gateway\n",
		"not yaml":           "\tthis: is: not: yaml\n",
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseServices([]byte(doc)); err == nil {
				t.Errorf("expected an error for %q", doc)
			}
		})
	}
	// The "parsed, but is not a compose file" case is distinguishable, because a
	// caller reports it differently from a YAML syntax error.
	if _, err := ParseServices([]byte("volumes:\n  identity:\n")); !errors.Is(err, ErrNoServices) {
		t.Errorf("err = %v, want ErrNoServices", err)
	}
}

// An oversized document is refused before the parser sees it.
func TestParseServices_SizeBound(t *testing.T) {
	huge := "services:\n  x:\n    image: alpine\n" + strings.Repeat("# padding\n", maxDocBytes/10)
	if _, err := ParseServices([]byte(huge)); err == nil || !strings.Contains(err.Error(), "larger than") {
		t.Errorf("err = %v, want a size complaint", err)
	}
}

func TestSplitImageRef(t *testing.T) {
	for _, tc := range []struct{ ref, image, tag, digest string }{
		{"alpine", "alpine", "", ""},
		{"alpine:3.20", "alpine", "3.20", ""},
		{"ghcr.io/0g/gw@sha256:abc", "ghcr.io/0g/gw", "", "sha256:abc"},
		{"ghcr.io/0g/gw:latest@sha256:abc", "ghcr.io/0g/gw", "latest", "sha256:abc"},
		// A registry port is not a tag.
		{"localhost:5000/app", "localhost:5000/app", "", ""},
		{"localhost:5000/app:v1", "localhost:5000/app", "v1", ""},
		{"", "", "", ""},
	} {
		image, tag, digest := SplitImageRef(tc.ref)
		if image != tc.image || tag != tc.tag || digest != tc.digest {
			t.Errorf("SplitImageRef(%q) = %q, %q, %q; want %q, %q, %q",
				tc.ref, image, tag, digest, tc.image, tc.tag, tc.digest)
		}
	}
}
