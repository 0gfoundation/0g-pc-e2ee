package sig

import (
	"strings"
	"testing"

	"github.com/0gfoundation/0g-pc-e2ee/protocol/proof"
)

// KAT produced by the broker's exact signer (go-ethereum v1.16.9,
// crypto.Sign(accounts.TextHash(text), key) with the recovery id normalized to
// 27/28), private key = 32 bytes of 0x11. This locks byte-for-byte compatibility
// between the broker's go-ethereum signatures and this decred-based recover.
const (
	katText = "zg-sig-v1/e2ee-ct:" +
		"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa:" +
		"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	katAddr = "0x19E7E376E7C213B7E7e7e46cc70A5dD086DAff2A"
	katSig  = "0xbd8367999ec7d94c979edeb5538ae98e8cc565b30d3e9be41fdc27675180892a" +
		"7a2a2273ce88e3f5d1a2422b7326b14ab1ccf4acc6c05375463b4cda85a9b1c31b"
)

func decodeHex(t *testing.T, s string) []byte {
	t.Helper()
	s = strings.TrimPrefix(s, "0x")
	b := make([]byte, len(s)/2)
	for i := 0; i < len(b); i++ {
		var hi, lo byte
		fmt := func(c byte) byte {
			switch {
			case c >= '0' && c <= '9':
				return c - '0'
			case c >= 'a' && c <= 'f':
				return c - 'a' + 10
			case c >= 'A' && c <= 'F':
				return c - 'A' + 10
			}
			t.Fatalf("bad hex %q", s)
			return 0
		}
		hi, lo = fmt(s[2*i]), fmt(s[2*i+1])
		b[i] = hi<<4 | lo
	}
	return b
}

// TestRecover_BrokerKAT proves this recover reproduces the address for a real
// broker-produced signature — the cross-implementation compatibility guarantee.
func TestRecover_BrokerKAT(t *testing.T) {
	got, err := Recover(katText, decodeHex(t, katSig))
	if err != nil {
		t.Fatalf("Recover: %v", err)
	}
	if !strings.EqualFold(got, katAddr) {
		t.Fatalf("recovered %s, want %s", got, katAddr)
	}
}

// TestRecover_SatisfiesRecoverFunc confirms the signature matches the seam type
// so it drops into proof.Verify* directly.
func TestRecover_SatisfiesRecoverFunc(t *testing.T) {
	var _ proof.RecoverFunc = Recover
}

func TestRecover_WrongTextFailsAnchor(t *testing.T) {
	// Recovering over a different text yields a different (wrong) address — the
	// property the verifier relies on to detect a tampered binding.
	got, err := Recover(katText+"tamper", decodeHex(t, katSig))
	if err != nil {
		t.Fatalf("Recover: %v", err)
	}
	if strings.EqualFold(got, katAddr) {
		t.Fatal("recovered the signer for a tampered text; recovery is not text-bound")
	}
}

func TestRecover_Malformed(t *testing.T) {
	if _, err := Recover(katText, decodeHex(t, katSig)[:64]); err == nil {
		t.Fatal("want error for 64-byte signature")
	}
	bad := decodeHex(t, katSig)
	bad[64] = 40 // invalid recovery id
	if _, err := Recover(katText, bad); err == nil {
		t.Fatal("want error for invalid recovery id")
	}
}
