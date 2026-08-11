package evidence

import (
	"encoding/hex"
	"strings"
	"testing"

	"github.com/0gfoundation/0g-pc-e2ee/protocol/attest"
)

func mkBootChain(fill byte) attest.BootChain {
	var m attest.Measurement
	for i := range m.MRTD {
		m.MRTD[i] = fill
		m.RTMR0[i] = fill + 1
		m.RTMR1[i] = fill + 2
		m.RTMR2[i] = fill + 3
		m.RTMR3[i] = fill + 4
	}
	return attest.BootChainOf(m)
}

func mkMeasurement(fill byte) attest.Measurement {
	var m attest.Measurement
	for i := range m.MRTD {
		m.MRTD[i] = fill
		m.RTMR0[i] = fill + 1
		m.RTMR1[i] = fill + 2
		m.RTMR2[i] = fill + 3
		m.RTMR3[i] = fill + 4
	}
	return m
}

// The embedded allowlist must always parse — a malformed one is a build-time mistake
// here, and New surfaces it rather than dropping the check.
func TestBuiltinOSImages_Parses(t *testing.T) {
	if _, err := BuiltinOSImages(); err != nil {
		t.Fatalf("the embedded osimages.json does not parse: %v", err)
	}
}

func TestParseOSImages(t *testing.T) {
	good := `{"images":[{"name":"dstack-0.5.3",` +
		`"os_image_hash":"86b18137","mrtd":"` + reg(0xaa) + `",` +
		`"rtmr1":"` + reg(0xcc) + `","rtmr2":"` + reg(0xdd) + `"}]}`

	imgs, err := ParseOSImages([]byte(good))
	if err != nil {
		t.Fatalf("ParseOSImages: %v", err)
	}
	if len(imgs) != 1 || imgs[0].Name != "dstack-0.5.3" {
		t.Fatalf("parsed = %+v", imgs)
	}
	if imgs[0].BootChain.MRTD[0] != 0xaa || imgs[0].BootChain.RTMR2[0] != 0xdd {
		t.Errorf("registers did not decode into the right fields: %+v", imgs[0].BootChain)
	}
}

func TestParseOSImages_Rejects(t *testing.T) {
	full := func(name, mrtd, rtmr1, rtmr2 string) string {
		return `{"images":[{"name":"` + name + `","mrtd":"` + mrtd +
			`","rtmr1":"` + rtmr1 + `","rtmr2":"` + rtmr2 + `"}]}`
	}
	cases := map[string]string{
		"not json":       `{`,
		"missing name":   full("", reg(0xaa), reg(0xcc), reg(0xdd)),
		"short register": full("x", "aabb", reg(0xcc), reg(0xdd)),
		"non-hex":        full("x", strings.Repeat("zz", 48), reg(0xcc), reg(0xdd)),
		// The dangerous one: a placeholder of all zeros would match a quote whose
		// registers failed to parse.
		"all zero": full("x", reg(0x00), reg(0x00), reg(0x00)),
		// An rtmr0 field is no longer part of the schema; supplying one must not smuggle
		// a value into the compared set, and the entry is judged on the three that are.
		"rtmr0 is ignored, not compared": `{"images":[{"name":"x","rtmr0":"` + reg(0xbb) + `"}]}`,
	}
	for name, in := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseOSImages([]byte(in)); err == nil {
				t.Error("expected an error, got nil")
			}
		})
	}
}

func TestCheckOSImage(t *testing.T) {
	m := mkMeasurement(0x11)
	allowed := []OSImage{
		{Name: "other", BootChain: mkBootChain(0x99)},
		{Name: "dstack-0.5.3", BootChain: attest.BootChainOf(m)},
	}

	t.Run("match names the entry", func(t *testing.T) {
		got := checkOSImage(allowed, m)
		if !got.OK() || got.Err != nil {
			t.Fatalf("err = %v", got.Err)
		}
		if !strings.Contains(got.Matched, "dstack-0.5.3") {
			t.Errorf("Matched = %q, want the image name", got.Matched)
		}
	})

	// The whole point of dropping RTMR0: one entry covers the image whatever VM shape
	// it was booted on. If this ever fails, the allowlist is back to needing an entry
	// per (image, shape) pair.
	t.Run("RTMR0 must not affect the result", func(t *testing.T) {
		reshaped := m
		reshaped.RTMR0 = mkMeasurement(0x55).RTMR0
		if got := checkOSImage(allowed, reshaped); !got.OK() {
			t.Errorf("a differing RTMR0 (a different VM shape) broke the match: %v", got.Err)
		}
	})

	t.Run("RTMR3 must not affect the result", func(t *testing.T) {
		// Same OS image, different app: RTMR3 differs and the check must still pass.
		other := m
		other.RTMR3 = mkMeasurement(0x77).RTMR3
		if got := checkOSImage(allowed, other); !got.OK() {
			t.Errorf("a differing RTMR3 broke the boot-chain match: %v", got.Err)
		}
	})

	t.Run("no match fails and lists what was expected", func(t *testing.T) {
		got := checkOSImage(allowed, mkMeasurement(0x44))
		if got.OK() {
			t.Fatal("OK() = true for an unlisted OS image")
		}
		if !strings.Contains(got.Err.Error(), "dstack-0.5.3") {
			t.Errorf("the error should name the allowlisted images: %v", got.Err)
		}
		// The observed value must be reported so an operator can add a legitimate upgrade.
		if got.Observed != attest.BootChainOf(mkMeasurement(0x44)) {
			t.Error("Observed does not carry the boot chain that was seen")
		}
	})

	t.Run("empty allowlist is unavailable, not a failure", func(t *testing.T) {
		got := checkOSImage(nil, m)
		if got.Configured {
			t.Error("Configured = true for an empty allowlist")
		}
		if !got.OK() {
			t.Error("an unconfigured check must not fail the report")
		}
		if got.Observed.IsZero() {
			t.Error("Observed should still be filled in so a value can be recorded")
		}
	})
}

// reg builds a full-length register as hex.
func reg(fill byte) string {
	return strings.Repeat(string("0123456789abcdef"[fill>>4])+string("0123456789abcdef"[fill&0xf]), 48)
}

// Guards the embedded allowlist as DATA. Its entries are hand-transcribed hex, and a
// mistyped or duplicated register would either reject the real deployment or, worse,
// accept something it should not. None of that is caught by "does it parse".
func TestBuiltinOSImages_EntriesAreWellFormed(t *testing.T) {
	imgs, err := BuiltinOSImages()
	if err != nil {
		t.Fatalf("BuiltinOSImages: %v", err)
	}
	seen := map[attest.BootChain]string{}
	for _, img := range imgs {
		// os_image_hash is the release's digest.txt — sha256, so 64 hex characters. It is
		// how a reviewer finds the artifact these values came from, so a truncated one
		// makes the entry unauditable even though matching still works.
		if len(img.OSImageHash) != 64 {
			t.Errorf("%s: os_image_hash is %d chars, want 64 (sha256 hex): %q",
				img.Name, len(img.OSImageHash), img.OSImageHash)
		}
		if _, err := hex.DecodeString(img.OSImageHash); err != nil {
			t.Errorf("%s: os_image_hash is not hex: %v", img.Name, err)
		}
		// Three registers measuring three different things must not be equal. Equality
		// is the signature of a copy-paste error, and it would not otherwise fail.
		bc := img.BootChain
		if bc.MRTD == bc.RTMR1 || bc.MRTD == bc.RTMR2 || bc.RTMR1 == bc.RTMR2 {
			t.Errorf("%s: two registers are identical; almost certainly a paste error", img.Name)
		}
		if prev, dup := seen[bc]; dup {
			t.Errorf("%s and %s carry the same boot chain", prev, img.Name)
		}
		seen[bc] = img.Name
	}
}
