package evidence

import (
	"context"
	"errors"
	"strings"
	"testing"
)

// txtResolver returns a resolver serving a fixed TXT map and no CNAMEs, recording
// the names it was asked for so a test can assert the query order.
func txtResolver(records map[string][]string) (dnsResolver, *[]string) {
	var asked []string
	return dnsResolver{
		lookupTXT: func(_ context.Context, name string) ([]string, error) {
			asked = append(asked, name)
			recs, ok := records[name]
			if !ok {
				return nil, errors.New("NXDOMAIN")
			}
			return recs, nil
		},
		lookupCNAME: func(_ context.Context, name string) (string, error) {
			return name, nil // no CNAME: Go returns the name itself
		},
	}, &asked
}

// cnameResolver serves TXT records that are only reachable through a CNAME, which is
// how this deployment's records are actually published — and what a resolver that
// does not chase the CNAME for a TXT query leaves the caller holding.
func cnameResolver(cnames map[string]string, records map[string][]string) (dnsResolver, *[]string) {
	var asked []string
	return dnsResolver{
		lookupTXT: func(_ context.Context, name string) ([]string, error) {
			asked = append(asked, name)
			return records[name], nil // empty and no error: the shape the trap takes
		},
		lookupCNAME: func(_ context.Context, name string) (string, error) {
			target, ok := cnames[name]
			if !ok {
				return name, nil
			}
			return target + ".", nil
		},
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

// The record this deployment publishes is always behind a delegation CNAME. A
// resolver that answers the TXT query with the CNAME alone — no records, no error —
// must not be read as "this deployment has no app-address record".
func TestDiscoverAppID_FollowsCNAME(t *testing.T) {
	const target = "_dstack-app-address.gw.example.com.delegation.example.net"
	r, asked := cnameResolver(
		map[string]string{"_dstack-app-address.gw.example.com": target},
		map[string][]string{target: {testAppID + ":443"}},
	)

	got, err := discoverAppID(context.Background(), "gw.example.com", r)
	if err != nil {
		t.Fatalf("discoverAppID: %v", err)
	}
	if got != testAppID {
		t.Errorf("app_id = %q, want %q", got, testAppID)
	}
	// The direct name first, then the CNAME target — never the target alone, since a
	// resolver that does chase it answers on the first query.
	want := []string{"_dstack-app-address.gw.example.com", target}
	if len(*asked) != 2 || (*asked)[0] != want[0] || (*asked)[1] != want[1] {
		t.Errorf("queried %v, want %v", *asked, want)
	}
}

// A name with no CNAME must not cost a second TXT query, and must still report the
// direct answer's reason rather than one invented by the redirect.
func TestDiscoverAppID_NoCNAMENoRedirect(t *testing.T) {
	r, asked := cnameResolver(nil, nil)

	_, err := discoverAppID(context.Background(), "gw.example.com", r)
	if err == nil {
		t.Fatal("expected an error when nothing publishes the record")
	}
	if !strings.Contains(err.Error(), "no TXT record") {
		t.Errorf("error does not carry the direct answer's reason: %v", err)
	}
	// One query per candidate name (exact, wildcard), and no redirect queries.
	if len(*asked) != 2 {
		t.Errorf("queried %v, want one query per candidate name", *asked)
	}
}
