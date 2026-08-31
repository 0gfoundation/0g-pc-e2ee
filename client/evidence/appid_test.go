package evidence

import (
	"context"
	"errors"
	"strings"
	"testing"
)

// txtResolver returns a lookupTXT stand-in serving a fixed map, and records the
// names it was asked for so a test can assert the query order.
func txtResolver(records map[string][]string) (func(context.Context, string) ([]string, error), *[]string) {
	var asked []string
	return func(_ context.Context, name string) ([]string, error) {
		asked = append(asked, name)
		recs, ok := records[name]
		if !ok {
			return nil, errors.New("NXDOMAIN")
		}
		return recs, nil
	}, &asked
}

const testAppID = "08f84bbaee1e78db04d3623eb564ad486b41f7fe"

func TestDiscoverAppID(t *testing.T) {
	t.Run("exact record", func(t *testing.T) {
		lookup, asked := txtResolver(map[string][]string{
			"_dstack-app-address.gw.example.com": {testAppID + ":443"},
		})
		got, err := discoverAppID(context.Background(), "gw.example.com", lookup)
		if err != nil {
			t.Fatalf("discoverAppID: %v", err)
		}
		if got != testAppID {
			t.Errorf("app_id = %q, want %q", got, testAppID)
		}
		// The wildcard name must not be queried once the exact one answered.
		if len(*asked) != 1 {
			t.Errorf("queried %v, want the exact name only", *asked)
		}
	})

	// The served name may be normalized on the way in — an operator pastes a URL or a
	// host:port as readily as a bare name, and the trailing dot comes from DNS output.
	t.Run("normalizes the served name", func(t *testing.T) {
		lookup, _ := txtResolver(map[string][]string{
			"_dstack-app-address.gw.example.com": {testAppID + ":443"},
		})
		for _, in := range []string{"GW.example.com", "gw.example.com.", "gw.example.com:443"} {
			got, err := discoverAppID(context.Background(), in, lookup)
			if err != nil || got != testAppID {
				t.Errorf("discoverAppID(%q) = %q, %v", in, got, err)
			}
		}
	})

	// The gateway itself falls back to the wildcard name, so this must too, or a
	// deployment the platform can route would not be one this can name.
	t.Run("wildcard fallback", func(t *testing.T) {
		lookup, asked := txtResolver(map[string][]string{
			"_dstack-app-address-wildcard.example.com": {testAppID + ":443"},
		})
		got, err := discoverAppID(context.Background(), "gw.example.com", lookup)
		if err != nil {
			t.Fatalf("discoverAppID: %v", err)
		}
		if got != testAppID {
			t.Errorf("app_id = %q, want %q", got, testAppID)
		}
		want := []string{"_dstack-app-address.gw.example.com", "_dstack-app-address-wildcard.example.com"}
		if len(*asked) != 2 || (*asked)[0] != want[0] || (*asked)[1] != want[1] {
			t.Errorf("queried %v, want %v", *asked, want)
		}
	})

	// A record that is present but not an app address must not silently become one:
	// whatever it holds would be pasted into a hostname and a URL path.
	t.Run("rejects malformed records", func(t *testing.T) {
		for name, rec := range map[string]string{
			"no port":      testAppID,
			"short id":     "08f84bba:443",
			"not hex":      strings.Repeat("z", 40) + ":443",
			"compose_hash": "dd79782d9cd5b8243acf468896d4cc81907b1ae8cf569b2331d21fab5f45d34f:443",
			"empty":        "",
		} {
			t.Run(name, func(t *testing.T) {
				lookup, _ := txtResolver(map[string][]string{
					"_dstack-app-address.gw.example.com": {rec},
				})
				if _, err := discoverAppID(context.Background(), "gw.example.com", lookup); err == nil {
					t.Errorf("record %q was accepted as an app address", rec)
				}
			})
		}
	})

	// Both names missing: the error must name what was tried, since the caller's next
	// move is either to pass -app-id or to fix DNS.
	t.Run("reports both queries", func(t *testing.T) {
		lookup, _ := txtResolver(nil)
		_, err := discoverAppID(context.Background(), "gw.example.com", lookup)
		if err == nil {
			t.Fatal("expected an error with no records at all")
		}
		for _, want := range []string{"_dstack-app-address.gw.example.com", "_dstack-app-address-wildcard.example.com"} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("error does not mention %s: %v", want, err)
			}
		}
	})

	t.Run("no domain", func(t *testing.T) {
		lookup, _ := txtResolver(nil)
		if _, err := discoverAppID(context.Background(), "  ", lookup); err == nil {
			t.Error("expected an error with no domain")
		}
	})
}

// A two-label name has no zone parent worth querying; a one-label one has nothing
// at all. Both must stop rather than query a public suffix.
func TestParentDomain(t *testing.T) {
	cases := map[string]string{
		"gw.staging.example.com": "staging.example.com",
		"gw.example.com":         "example.com",
		"example.com":            "",
		"localhost":              "",
	}
	for in, want := range cases {
		if got := parentDomain(in); got != want {
			t.Errorf("parentDomain(%q) = %q, want %q", in, got, want)
		}
	}
}
