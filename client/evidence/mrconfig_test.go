package evidence

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/0gfoundation/0g-pc-e2ee/protocol/attest"
)

// stagingComposeHash is what router-api-staging.0g.ai's compose-hash event and its
// MrConfigV3 document both carry (fetched 2026-10-19, the first gateway CVM on
// dstack-0.6.1).
const stagingComposeHash = "017900918533612b414970e7c5cd43c4e88e7c6a7f2af2fc58092d7550633347"

// mrVector is a quote reply under testdata/mrconfig with the mr_config_id and RTMR3 of
// its quote, read out of the quote itself.
func mrVector(t *testing.T, edit func(map[string]any)) ([]byte, [48]byte, [RTMRLen]byte) {
	t.Helper()
	reply, err := os.ReadFile(filepath.Join("testdata", "mrconfig", "staging-0.6.1.quote.json"))
	if err != nil {
		t.Fatal(err)
	}
	if edit != nil {
		var m map[string]any
		if err := json.Unmarshal(reply, &m); err != nil {
			t.Fatal(err)
		}
		edit(m)
		if reply, err = json.Marshal(m); err != nil {
			t.Fatal(err)
		}
	}
	raw, err := attest.DecodeQuoteResponse(reply)
	if err != nil {
		t.Fatal(err)
	}
	qb, err := attest.ParseTDXQuoteBody(raw)
	if err != nil {
		t.Fatal(err)
	}
	return reply, qb.MRConfigID, qb.Measurement.RTMR3
}

// dstack 0.6.1 launches with a V3 mr_config_id, which carries only a document hash. The
// document rebuilt from the replayed event log reproduces it, and its compose_hash is
// the one the log names.
func TestComposeHashOf_V3(t *testing.T) {
	reply, id, rtmr3 := mrVector(t, nil)
	if id[0] != 3 {
		t.Fatalf("the vector's mr_config_id is version %d, want 3", id[0])
	}
	if _, err := attest.ComposeHashFromMRConfigID(id); !errors.Is(err, attest.ErrUnsupportedMRConfig) {
		t.Fatalf("the V1 reader accepted a V3 mr_config_id: %v", err)
	}
	got, err := ComposeHashOf(id, reply, rtmr3)
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(got[:]) != stagingComposeHash {
		t.Fatalf("got %x, want %s", got, stagingComposeHash)
	}
}

// Nothing but an exact reproduction of the signed register establishes a hash: a log
// that does not replay, a register that differs by a bit, and a reply with no log at
// all each leave the compose hash unestablished — never a guess.
func TestComposeHashOf_V3Refuses(t *testing.T) {
	t.Run("an edited log", func(t *testing.T) {
		reply, id, rtmr3 := mrVector(t, func(m map[string]any) {
			// The evidence bundle's quote.json carries the log as a JSON string.
			var log []map[string]any
			if err := json.Unmarshal([]byte(m["event_log"].(string)), &log); err != nil {
				t.Fatal(err)
			}
			for _, e := range log {
				if e["event"] == "compose-hash" {
					e["event_payload"] = strings.Repeat("ab", 32)
				}
			}
			raw, err := json.Marshal(log)
			if err != nil {
				t.Fatal(err)
			}
			m["event_log"] = string(raw)
		})
		if _, err := ComposeHashOf(id, reply, rtmr3); !errors.Is(err, attest.ErrUnsupportedMRConfig) ||
			!strings.Contains(err.Error(), "does not replay") {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("a different register", func(t *testing.T) {
		reply, id, rtmr3 := mrVector(t, nil)
		id[10] ^= 1
		if _, err := ComposeHashOf(id, reply, rtmr3); !errors.Is(err, attest.ErrUnsupportedMRConfig) ||
			!strings.Contains(err.Error(), "reproduces mr_config_id") {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("no event log", func(t *testing.T) {
		reply, id, rtmr3 := mrVector(t, func(m map[string]any) { delete(m, "event_log") })
		if _, err := ComposeHashOf(id, reply, rtmr3); !errors.Is(err, attest.ErrUnsupportedMRConfig) {
			t.Fatalf("got %v", err)
		}
	})
}

// V1 is read from the register alone, as before, whatever the reply holds.
func TestComposeHashOf_V1(t *testing.T) {
	var id [48]byte
	id[0] = 1
	for i := 1; i <= 32; i++ {
		id[i] = byte(i)
	}
	got, err := ComposeHashOf(id, nil, [RTMRLen]byte{})
	if err != nil || got[0] != 1 || got[31] != 32 {
		t.Fatalf("got %x, %v", got, err)
	}
}

// The app_id the staging gateway's guest logged at boot — the one its Phala app is
// registered under, which compose_hash's prefix is not.
func TestLoggedAppID(t *testing.T) {
	reply, _, rtmr3 := mrVector(t, nil)
	got, err := LoggedAppID(reply, rtmr3)
	if err != nil || got != "98965c22ed76848ed50757608271ab5e118db683" {
		t.Fatalf("got %q, %v", got, err)
	}
	if _, err := LoggedAppID(reply, [RTMRLen]byte{}); err == nil {
		t.Fatal("read an app_id from a log that does not replay")
	}
}
