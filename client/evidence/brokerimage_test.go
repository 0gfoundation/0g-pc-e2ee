package evidence

import (
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/0gfoundation/0g-pc-e2ee/protocol/attest"
)

// The embedded file must parse. It is a trust input on the sealing path, so a
// malformed one is fatal at startup — which is only a safe design if a broken file
// cannot reach a release.
func TestBuiltinBrokerImages_Parses(t *testing.T) {
	if _, err := BuiltinBrokerImages(); err != nil {
		t.Fatalf("BuiltinBrokerImages: %v", err)
	}
}

// Every entry must be well-formed in the ways ParseOSImages cannot check for itself:
// a name a human can act on, a hex os_image_hash, a non-zero boot chain, and no
// duplicate chain.
//
// It does NOT check provenance, and os_image_hash is not provenance: dstack reports
// that same value in vm_config, so it is one of the things a copied entry would carry.
// Provenance lives in fields ParseOSImages drops, so enforcing it needs the raw file —
// see TestBrokerImagesFile_EveryEntryRecordsItsProvenance.
func TestBuiltinBrokerImages_EntriesAreWellFormed(t *testing.T) {
	imgs, err := BuiltinBrokerImages()
	if err != nil {
		t.Fatalf("BuiltinBrokerImages: %v", err)
	}
	if len(imgs) == 0 {
		t.Skip("no entries yet; the allowlist is not configured")
	}
	seen := map[attest.BootChain]string{}
	for _, img := range imgs {
		if img.Name == "" {
			t.Error("entry with no name")
		}
		if img.OSImageHash == "" {
			t.Errorf("%s: no os_image_hash, so nobody can tell which release this is",
				img.Name)
		}
		if _, err := hex.DecodeString(img.OSImageHash); err != nil {
			t.Errorf("%s: os_image_hash is not hex: %v", img.Name, err)
		}
		if img.BootChain.IsZero() {
			t.Errorf("%s: all-zero boot chain", img.Name)
		}
		if prior, dup := seen[img.BootChain]; dup {
			t.Errorf("%s duplicates %s: same boot chain listed twice", img.Name, prior)
		}
		seen[img.BootChain] = img.Name
	}
}

// dstack-nvidia-0.5.9's registers, pinned so a change to the embedded file has to be
// deliberate. These are not transcribed from the deployment: they were computed with
// dstack-mr from the published meta-dstack v0.5.9 release (whose sha256sum.txt hashes
// to the os_image_hash below) and then found to equal what a live provider quote
// reports, RTMR0 included. Editing this test is editing that claim.
func TestBuiltinBrokerImages_PinsTheAuditedNvidia059(t *testing.T) {
	requirePinned(t,
		"dstack-nvidia-0.5.9",
		"806a352e16175d90568de97dff563f31f680239e6b90e9b5b2e9141d0955b0d9",
		"b24d3b24e9e3c16012376b52362ca09856c4adecb709d5fac33addf1c47e193da075b125b6c364115771390a5461e217",
		"07e6f51aa763abfe75c3ddfbf4f425fe3f0ceff66d807a75e049303dce9addf68e7218729bd419638af63a370f65878c",
		"f1c82667a354194467cd8419efd14a714560dd9b85b4c13b25c11e44bf4e126248c2255fad58c303fb0ca2921765d53a")
}

// dstack-nvidia-0.5.4.1's registers, pinned on the same terms. Computed with dstack-mr
// from the published private-ml-sdk v0.5.4.1 release (whose sha256sum.txt hashes to the
// os_image_hash below), in the single-pass page-add mode, and equal to what a live
// broker quote reports for all three. RTMR0 is not part of the claim here: that CVM's
// VM shape is not published, and the boot chain excludes RTMR0 by design.
func TestBuiltinBrokerImages_PinsTheAuditedNvidia0541(t *testing.T) {
	requirePinned(t,
		"dstack-nvidia-0.5.4.1",
		"86b181377635db21c415f9ece8cc8505f7d4936ad3be7043969005a8c4690c1a",
		"b24d3b24e9e3c16012376b52362ca09856c4adecb709d5fac33addf1c47e193da075b125b6c364115771390a5461e217",
		"6e1afb7464ed0b941e8f5bf5b725cf1df9425e8105e3348dca52502f27c453f3018a28b90749cf05199d5a17820101a7",
		"89e73cedf48f976ffebe8ac1129790ff59a0f52d54d969cb73455b1a79793f1dc16edc3b1fccc0fd65ea5905774bbd57")
}

// requirePinned asserts the embedded allowlist still carries `name` with exactly these
// registers. Shared by the pins above so that adding one is writing down the values and
// nothing else — a second copy of the comparison is a second chance for one of them to
// check something weaker than the other.
func requirePinned(t *testing.T, name, hash, mrtd, rtmr1, rtmr2 string) {
	t.Helper()
	imgs, err := BuiltinBrokerImages()
	if err != nil {
		t.Fatalf("BuiltinBrokerImages: %v", err)
	}
	var got *OSImage
	for i := range imgs {
		if imgs[i].Name == name {
			got = &imgs[i]
			break
		}
	}
	if got == nil {
		t.Fatalf("%s is not in the allowlist; if it was removed on purpose, remove this "+
			"test in the same change and say why", name)
	}
	if got.OSImageHash != hash {
		t.Errorf("os_image_hash = %s, want %s", got.OSImageHash, hash)
	}
	for _, tc := range []struct {
		reg, want string
		got       []byte
	}{
		{"mrtd", mrtd, got.BootChain.MRTD[:]},
		{"rtmr1", rtmr1, got.BootChain.RTMR1[:]},
		{"rtmr2", rtmr2, got.BootChain.RTMR2[:]},
	} {
		if hex.EncodeToString(tc.got) != tc.want {
			t.Errorf("%s = %x, want %s", tc.reg, tc.got, tc.want)
		}
	}
}

// The allowlist must accept the image it lists and reject its neighbours. This is the
// decision the sealing path makes, so it is worth asserting on the real file rather
// than on a fixture: a policy built from these entries that permitted an unlisted
// boot chain would be a silent accept-anything.
func TestBrokerAllowlist_PermitsOnlyWhatItLists(t *testing.T) {
	imgs, err := BuiltinBrokerImages()
	if err != nil {
		t.Fatalf("BuiltinBrokerImages: %v", err)
	}
	policy := BootChainPolicyOf(imgs)
	for _, img := range imgs {
		if !policy.Permits(img.BootChain) {
			t.Errorf("%s is listed but not permitted", img.Name)
		}
		// One register flipped is a different image. RTMR2 is the one that separates a
		// dev build from the production build of the same version — identical firmware
		// and kernel — so a policy that ignored it would accept a development rootfs.
		near := img.BootChain
		near.RTMR2[0] ^= 0xff
		if policy.Permits(near) {
			t.Errorf("%s: a boot chain differing only in RTMR2 was permitted", img.Name)
		}
	}
	if policy.Permits(attest.BootChain{}) {
		t.Error("an all-zero boot chain — an absent or unparsed measurement — was permitted")
	}
}

// The shipped allowlist must admit the audited image and refuse others THROUGH
// attest.Verify, not merely through BootChainPolicy.Permits.
//
// The tests above check the policy in isolation; this one checks the composition the
// binaries actually build — embedded file → BootChainPolicyOf → attest.New → Verify —
// because that is where a wiring mistake would live, and a wiring mistake is invisible
// to a test that calls Permits directly. The quote parser is a fake: this asserts the
// allowlist decision, and DCAP authenticity is protocol/attest's own business.
func TestBuiltinBrokerImages_VerifierAdmitsAuditedAndRefusesOthers(t *testing.T) {
	imgs, err := BuiltinBrokerImages()
	if err != nil {
		t.Fatalf("BuiltinBrokerImages: %v", err)
	}
	if len(imgs) == 0 {
		t.Skip("no entries yet; the allowlist is not configured")
	}

	// A §4.2 report_data the parse step will accept, so the run reaches — and stops
	// at — the boot-chain decision rather than failing earlier for an unrelated reason.
	var rd [64]byte
	for i := range rd[:32] {
		rd[i] = byte(i + 1) // enc_pub, any nonzero
	}
	for i := 0; i < 20; i++ {
		rd[32+i] = 0xab // signer
	}
	binary.BigEndian.PutUint32(rd[52:56], 1) // version 1; rd[56:64] stays zero

	parserFor := func(m attest.Measurement) func([]byte) (attest.Measurement, [64]byte, error) {
		return func([]byte) (attest.Measurement, [64]byte, error) { return m, rd, nil }
	}
	// Only the three allowlisted registers are set: RTMR0 and RTMR3 stay zero on
	// purpose, so a policy that had (wrongly) compared them would fail this test.
	audited := attest.Measurement{
		MRTD:  imgs[0].BootChain.MRTD,
		RTMR1: imgs[0].BootChain.RTMR1,
		RTMR2: imgs[0].BootChain.RTMR2,
	}
	other := audited
	other.RTMR2[0] ^= 0xff

	policy := BootChainPolicyOf(imgs)
	for _, tc := range []struct {
		name        string
		mode        attest.MeasurementMode
		measurement attest.Measurement
		wantErr     error
		wantTrusted bool
	}{
		{"audited image, enforce", attest.ModeEnforce, audited, nil, true},
		{"audited image, warn", attest.ModeWarn, audited, nil, true},
		{"other image, enforce", attest.ModeEnforce, other, attest.ErrUntrustedMeasurement, false},
		// Warn must PROCEED on an unlisted image and mark it, not error: that is the
		// staged-rollout posture the gateway runs in until every provider is listed.
		{"other image, warn", attest.ModeWarn, other, nil, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			v := attest.New(policy,
				attest.WithQuoteParser(parserFor(tc.measurement)),
				attest.WithMeasurementMode(tc.mode))
			if !v.MeasurementBaselineConfigured() {
				t.Fatal("baseline reported unconfigured despite entries")
			}
			got, err := v.Verify([]byte("quote bytes; the fake parser ignores them"))
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("err = %v, want %v", err, tc.wantErr)
			}
			if err == nil && got.MeasurementTrusted != tc.wantTrusted {
				t.Errorf("MeasurementTrusted = %v, want %v", got.MeasurementTrusted, tc.wantTrusted)
			}
			// The name travels with the decision, through the same composition: it is what
			// the gateway's provider-identity endpoint reports as os_image, so a projection
			// that dropped the labels would leave that field permanently null while every
			// verdict still passed — a regression no assertion on MeasurementTrusted can see.
			if err == nil {
				want := ""
				if tc.wantTrusted {
					want = imgs[0].Name
				}
				if got.MeasurementImage != want {
					t.Errorf("MeasurementImage = %q, want %q", got.MeasurementImage, want)
				}
			}
		})
	}
}

// provenanceErrors reports what a raw allowlist file fails to record about where its
// entries came from. Separated from the test that runs it over the embedded file so the
// rules themselves can be exercised against inputs that violate them — a checker whose
// negative cases are untested is how a test comes to claim more than it verifies, which
// is the mistake this whole check exists to catch.
func provenanceErrors(raw []byte) []string {
	var doc struct {
		Images []struct {
			Name       string          `json:"name"`
			Source     string          `json:"source"`
			PageAdd    string          `json:"page_add"`
			Derivation json.RawMessage `json:"derivation"`
		} `json:"images"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return []string{fmt.Sprintf("not valid JSON: %v", err)}
	}
	var out []string
	for i, e := range doc.Images {
		label := e.Name
		if label == "" {
			label = fmt.Sprintf("entry %d", i+1)
		}
		// A downloadable artifact to recompute from. Without it, dstack-mr has nothing
		// independent to run on and the values could only have come from the deployment.
		if strings.TrimSpace(e.Source) == "" {
			out = append(out, label+": no `source`, so nothing says which published "+
				"release this was computed from")
		}
		// MRTD is (image, page-add mode), so an entry that omits the mode is not
		// reproducible even with the right release in hand.
		if strings.TrimSpace(e.PageAdd) == "" {
			out = append(out, label+": no `page_add`; MRTD depends on the page-add mode, "+
				"so an entry without it cannot be recomputed")
		}
		// How it was derived, in enough detail to repeat. A free-form list rather than a
		// schema on purpose: what matters is that a human wrote the steps down.
		var steps []string
		if len(e.Derivation) > 0 {
			if err := json.Unmarshal(e.Derivation, &steps); err != nil {
				out = append(out, fmt.Sprintf("%s: `derivation` is not a list of strings: %v",
					label, err))
			}
		}
		if len(steps) == 0 {
			out = append(out, label+": no `derivation`; a reviewer cannot tell a computed "+
				"entry from a transcribed one")
		}
	}
	return out
}

// The rules must actually reject what they claim to reject.
func TestProvenanceErrors_RejectsEntriesThatCannotSayWhereTheyCameFrom(t *testing.T) {
	const full = `{"images":[{"name":"i","source":"s","page_add":"p","derivation":["how"]}]}`
	if got := provenanceErrors([]byte(full)); len(got) != 0 {
		t.Errorf("a complete entry was rejected: %v", got)
	}
	for _, tc := range []struct{ name, doc, want string }{
		{"no source", `{"images":[{"name":"i","page_add":"p","derivation":["how"]}]}`, "`source`"},
		{"no page_add", `{"images":[{"name":"i","source":"s","derivation":["how"]}]}`, "`page_add`"},
		{"no derivation", `{"images":[{"name":"i","source":"s","page_add":"p"}]}`, "`derivation`"},
		{"empty derivation", `{"images":[{"name":"i","source":"s","page_add":"p","derivation":[]}]}`, "`derivation`"},
		{"derivation not a list", `{"images":[{"name":"i","source":"s","page_add":"p","derivation":"how"}]}`, "not a list"},
		{"whitespace source", `{"images":[{"name":"i","source":"   ","page_add":"p","derivation":["how"]}]}`, "`source`"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := provenanceErrors([]byte(tc.doc))
			if len(got) == 0 {
				t.Fatalf("accepted an entry with %s missing", tc.name)
			}
			if !strings.Contains(strings.Join(got, "; "), tc.want) {
				t.Errorf("errors %v do not name %q", got, tc.want)
			}
		})
	}
}

// Every entry must record where its values came from, enforced over the RAW file.
// Every entry must record where its values came from, enforced over the RAW file.
//
// This has to read the file rather than the parsed entries, and that is the point:
// ParseOSImages decodes only the fields that are matched on, so `source`, `page_add`
// and `derivation` are dropped at unmarshal and never reach Go. Asserting on the parsed
// struct could therefore only check os_image_hash — which is NOT provenance, since
// dstack reports that same value in vm_config and a copied entry would carry it.
//
// The file header tells a reviewer to refuse an entry that cannot say where it came
// from. Without this test that instruction is the only thing standing between the
// allowlist and an entry transcribed off a running provider, and an instruction is not
// a check.
func TestBrokerImagesFile_EveryEntryRecordsItsProvenance(t *testing.T) {
	raw, err := brokerImagesFS.ReadFile("brokerimages.json")
	if err != nil {
		t.Fatalf("read embedded file: %v", err)
	}
	var doc struct {
		Images []json.RawMessage `json:"images"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(doc.Images) == 0 {
		t.Skip("no entries yet; the allowlist is not configured")
	}
	for _, problem := range provenanceErrors(raw) {
		t.Error(problem)
	}
}
