package evidence

import (
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
	good := `{"images":[{"name":"dstack-nvidia-0.5.4.1","vm_shape":"1 vCPU / 2 GiB / 0 GPU",` +
		`"os_image_hash":"86b18137","mrtd":"` + reg(0xaa) + `","rtmr0":"` + reg(0xbb) + `",` +
		`"rtmr1":"` + reg(0xcc) + `","rtmr2":"` + reg(0xdd) + `"}]}`

	imgs, err := ParseOSImages([]byte(good))
	if err != nil {
		t.Fatalf("ParseOSImages: %v", err)
	}
	if len(imgs) != 1 || imgs[0].Name != "dstack-nvidia-0.5.4.1" {
		t.Fatalf("parsed = %+v", imgs)
	}
	if imgs[0].BootChain.MRTD[0] != 0xaa || imgs[0].BootChain.RTMR2[0] != 0xdd {
		t.Errorf("registers did not decode into the right fields: %+v", imgs[0].BootChain)
	}
}

func TestParseOSImages_Rejects(t *testing.T) {
	full := func(name, mrtd, rtmr0, rtmr1, rtmr2 string) string {
		return `{"images":[{"name":"` + name + `","mrtd":"` + mrtd + `","rtmr0":"` + rtmr0 +
			`","rtmr1":"` + rtmr1 + `","rtmr2":"` + rtmr2 + `"}]}`
	}
	cases := map[string]string{
		"not json":       `{`,
		"missing name":   full("", reg(0xaa), reg(0xbb), reg(0xcc), reg(0xdd)),
		"short register": full("x", "aabb", reg(0xbb), reg(0xcc), reg(0xdd)),
		"non-hex":        full("x", strings.Repeat("zz", 48), reg(0xbb), reg(0xcc), reg(0xdd)),
		// The dangerous one: a placeholder of all zeros would match a quote whose
		// registers failed to parse.
		"all zero": full("x", reg(0x00), reg(0x00), reg(0x00), reg(0x00)),
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
		{Name: "dstack-nvidia-0.5.4.1", VMShape: "1 vCPU / 2 GiB", BootChain: attest.BootChainOf(m)},
	}

	t.Run("match names the entry and its shape", func(t *testing.T) {
		got := checkOSImage(allowed, m)
		if !got.OK() || got.Err != nil {
			t.Fatalf("err = %v", got.Err)
		}
		if !strings.Contains(got.Matched, "dstack-nvidia-0.5.4.1") ||
			!strings.Contains(got.Matched, "1 vCPU") {
			t.Errorf("Matched = %q, want the image and the VM shape", got.Matched)
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
		if !strings.Contains(got.Err.Error(), "dstack-nvidia-0.5.4.1") {
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
