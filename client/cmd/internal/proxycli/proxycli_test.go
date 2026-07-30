package proxycli

import "testing"

// envOr uses an env var only when it is present; a set-but-empty value is
// honored (not treated as unset), since "" is meaningful for the CSV fields.
func TestEnvOr(t *testing.T) {
	const key = "ZG_PROXYCLI_TEST_ENVOR"
	t.Setenv(key, "from-env")
	if got := envOr(key, "def"); got != "from-env" {
		t.Fatalf("set var: got %q, want %q", got, "from-env")
	}
	t.Setenv(key, "")
	if got := envOr(key, "def"); got != "" {
		t.Fatalf("empty var: got %q, want empty (honored, not defaulted)", got)
	}
	if got := envOr("ZG_PROXYCLI_TEST_UNSET", "def"); got != "def" {
		t.Fatalf("unset var: got %q, want %q", got, "def")
	}
}

// envBool falls back to def when unset and parses standard boolean forms when
// set. (The set-but-unparseable case is log.Fatal, so it is not exercised here.)
func TestEnvBool(t *testing.T) {
	const key = "ZG_PROXYCLI_TEST_ENVBOOL"
	if got := envBool("ZG_PROXYCLI_TEST_UNSET_BOOL", true); !got {
		t.Fatal("unset var: want fallback to def=true")
	}
	for _, tc := range []struct {
		val  string
		want bool
	}{{"true", true}, {"1", true}, {"false", false}, {"0", false}} {
		t.Setenv(key, tc.val)
		if got := envBool(key, !tc.want); got != tc.want {
			t.Fatalf("%s=%q: got %v, want %v", key, tc.val, got, tc.want)
		}
	}
}

// parseCSV trims each element and drops empty ones, so surrounding spaces and a
// trailing comma do not produce blank fields.
func TestParseCSV(t *testing.T) {
	got := parseCSV(" messages , model ,")
	want := []string{"messages", "model"}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("index %d: got %q, want %q", i, got[i], want[i])
		}
	}
}
