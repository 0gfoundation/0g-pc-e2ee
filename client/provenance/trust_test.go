package provenance

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/sigstore/sigstore-go/pkg/root"

	"github.com/0gfoundation/0g-pc-e2ee/client/evidence"
)

// withRoot is the embedded Verifier with fetchRoot answering as given, counting calls.
func withRoot(t *testing.T, tm root.TrustedMaterial, err error) (*Verifier, *int) {
	t.Helper()
	v := embedded(t)
	calls := 0
	v.fetchRoot = func() (root.TrustedMaterial, error) {
		calls++
		return tm, err
	}
	return v, &calls
}

// trustRootWithout is the embedded trust root with one of its key lists emptied.
func trustRootWithout(t *testing.T, key string) root.TrustedMaterial {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(trustedRootJSON, &m); err != nil {
		t.Fatal(err)
	}
	if _, ok := m[key]; !ok {
		t.Fatalf("the trust root has no %q", key)
	}
	m[key] = []any{}
	raw, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	tr, err := root.NewTrustedRootFromJSON(raw)
	if err != nil {
		t.Fatal(err)
	}
	return tr
}

// With TUF unreachable, the snapshot still decides what verifies against it; only a bundle
// that does not verify becomes a check that did not run, since it may be newer than the
// snapshot.
func TestTrust_UnreachableFallsBackToTheSnapshot(t *testing.T) {
	v, calls := withRoot(t, nil, errors.New("dial tcp: no route to host"))
	for _, tc := range []struct {
		name    string
		digest  string
		bundles [][]byte
		status  evidence.ReleaseStatus
		says    string
	}{
		{"a release the snapshot verifies", digestV054, [][]byte{fixture(t, "v0.5.4.slsa.json")}, evidence.ReleaseAccepted, ""},
		{"a signature the snapshot verifies, refused by policy", digestV051,
			[][]byte{fixture(t, "v0.5.1.cosign-sign.json")}, evidence.ReleaseRejected, "older than the minimum"},
		{"a bundle that does not verify", digestV054, [][]byte{tamperedV054(t)}, evidence.ReleaseUnavailable,
			"could not be fetched (dial tcp: no route to host), so it was checked against the snapshot embedded on " +
				snapshotDate},
		{"a verified refusal beside an unverified bundle", digestV054,
			[][]byte{fixture(t, "v0.5.4.cosign-sign.json"), tamperedV054(t)}, evidence.ReleaseUnavailable, "not SLSA provenance"},
		{"a bundle that does not parse", digestV054, [][]byte{[]byte("not a bundle")}, evidence.ReleaseRejected, "does not parse"},
		{"no bundle", digestV054, nil, evidence.ReleaseRejected, "no Sigstore bundle"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := v.judge(tc.digest, tc.bundles)
			if got.Status != tc.status || !strings.Contains(got.Reason, tc.says) {
				t.Fatalf("got %+v, want status %d mentioning %q", got, tc.status, tc.says)
			}
		})
	}
	if *calls != 1 {
		t.Fatalf("the trust root was fetched %d times, want once per Verifier", *calls)
	}
}

// When TUF answers, its root is the one verified against — the snapshot is not consulted,
// and a bundle that does not verify is refused.
func TestTrust_TheCurrentRootDecides(t *testing.T) {
	live, err := root.NewTrustedRootFromJSON(trustedRootJSON)
	if err != nil {
		t.Fatal(err)
	}
	v, _ := withRoot(t, live, nil)
	if got := v.judge(digestV054, [][]byte{fixture(t, "v0.5.4.slsa.json")}); got.Status != evidence.ReleaseAccepted {
		t.Fatalf("v0.5.4 against the current root: %+v", got)
	}
	if got := v.judge(digestV054, [][]byte{tamperedV054(t)}); got.Status != evidence.ReleaseRejected ||
		!strings.Contains(got.Reason, "does not verify") || strings.Contains(got.Reason, "snapshot") {
		t.Fatalf("a tampered bundle against the current root: %+v", got)
	}

	// A current root without the Rekor log v0.5.4 is in: refused, though the snapshot
	// would have accepted it.
	v, _ = withRoot(t, trustRootWithout(t, "tlogs"), nil)
	if got := v.judge(digestV054, [][]byte{fixture(t, "v0.5.4.slsa.json")}); got.Status != evidence.ReleaseRejected ||
		!strings.Contains(got.Reason, "does not verify") {
		t.Fatalf("v0.5.4 against a root without its log: %+v", got)
	}
}
