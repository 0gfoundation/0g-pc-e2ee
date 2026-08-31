package evidence

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// cloudInstanceJSON builds one instance of an attestations reply. tcbInfoAsString
// selects between the two shapes the field arrives in (see cloudInstance.TCBInfo):
// a nested object, or a JSON string holding the same document.
func cloudInstanceJSON(t *testing.T, name, appCompose string, tcbInfoAsString bool) map[string]any {
	t.Helper()
	inst := map[string]any{"name": name, "status": "running"}
	if appCompose == "" {
		inst["tcb_info"] = nil
		return inst
	}
	tcb := map[string]any{
		"mrtd":         "aa",
		"compose_hash": fmt.Sprintf("%x", composeHashOf(appCompose)),
		"app_compose":  appCompose,
	}
	if tcbInfoAsString {
		b, err := json.Marshal(tcb)
		if err != nil {
			t.Fatalf("fixture: %v", err)
		}
		inst["tcb_info"] = string(b)
	} else {
		inst["tcb_info"] = tcb
	}
	return inst
}

// cloudAPI serves GET /apps/<app_id>/attestations and records the path asked for.
func cloudAPI(t *testing.T, body any, status int) (base string, path *string) {
	t.Helper()
	var got string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.URL.Path
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		if raw, ok := body.([]byte); ok {
			_, _ = w.Write(raw)
			return
		}
		_ = json.NewEncoder(w).Encode(body)
	}))
	t.Cleanup(srv.Close)
	return srv.URL + "/api/v1", &got
}

func TestFetchAppComposeFromCloud(t *testing.T) {
	// The shape that matters most: several instances, only one of which is this
	// quote's. Position must not decide — a blue/green pair genuinely differs.
	other := strings.Replace(testAppCompose, "staging-a", "staging-b", 1)
	body := map[string]any{
		"app_id": testAppID,
		"instances": []any{
			cloudInstanceJSON(t, "pc-gateway-staging-b", other, true),
			cloudInstanceJSON(t, "pc-gateway-staging-a", testAppCompose, true),
		},
	}
	base, path := cloudAPI(t, body, http.StatusOK)

	raw, instance, err := FetchAppComposeFromCloud(
		context.Background(), http.DefaultClient, base, testAppID, composeHashOf(testAppCompose))
	if err != nil {
		t.Fatalf("FetchAppComposeFromCloud: %v", err)
	}
	if string(raw) != testAppCompose {
		t.Errorf("app-compose bytes did not survive the unwrap:\n got %q\nwant %q", raw, testAppCompose)
	}
	// The bytes must be usable as the digest preimage directly — nothing in the path
	// may have reformatted them.
	if _, err := VerifyAppCompose(raw, composeHashOf(testAppCompose)); err != nil {
		t.Errorf("fetched bytes do not hash to the compose_hash: %v", err)
	}
	if !strings.Contains(instance, "pc-gateway-staging-a") || !strings.Contains(instance, "instance 2 of 2") {
		t.Errorf("instance label = %q, want it to name the second instance and its name", instance)
	}
	if want := "/api/v1/apps/" + testAppID + "/attestations"; *path != want {
		t.Errorf("requested %q, want %q", *path, want)
	}
}

// tcb_info arrives as a nested object on some deployments; the outer decode must
// survive that, not just the JSON-string form.
func TestFetchAppComposeFromCloud_TCBInfoAsObject(t *testing.T) {
	body := map[string]any{"instances": []any{cloudInstanceJSON(t, "a", testAppCompose, false)}}
	base, _ := cloudAPI(t, body, http.StatusOK)

	raw, _, err := FetchAppComposeFromCloud(
		context.Background(), http.DefaultClient, base, testAppID, composeHashOf(testAppCompose))
	if err != nil {
		t.Fatalf("FetchAppComposeFromCloud: %v", err)
	}
	if string(raw) != testAppCompose {
		t.Errorf("app-compose = %q", raw)
	}
}

// An instance with no tcb_info (stopped, or tcb_info hidden) but a compose_file
// beside it: the fallback field carries the same document, and it is gated the same
// way, so the lookup must not give up.
func TestFetchAppComposeFromCloud_ComposeFileFallback(t *testing.T) {
	inst := cloudInstanceJSON(t, "a", "", false)
	inst["compose_file"] = testAppCompose
	base, _ := cloudAPI(t, map[string]any{"instances": []any{inst}}, http.StatusOK)

	raw, _, err := FetchAppComposeFromCloud(
		context.Background(), http.DefaultClient, base, testAppID, composeHashOf(testAppCompose))
	if err != nil {
		t.Fatalf("FetchAppComposeFromCloud: %v", err)
	}
	if string(raw) != testAppCompose {
		t.Errorf("app-compose = %q", raw)
	}
}

func TestFetchAppComposeFromCloud_Errors(t *testing.T) {
	t.Run("no instance matches", func(t *testing.T) {
		other := strings.Replace(testAppCompose, "staging-a", "staging-b", 1)
		base, _ := cloudAPI(t, map[string]any{
			"instances": []any{cloudInstanceJSON(t, "pc-gateway-staging-b", other, true)},
		}, http.StatusOK)

		_, _, err := FetchAppComposeFromCloud(
			context.Background(), http.DefaultClient, base, testAppID, composeHashOf(testAppCompose))
		if err == nil {
			t.Fatal("expected an error when no instance carries this quote's manifest")
		}
		// The error has to be actionable: what was asked for, and what was offered.
		if !strings.Contains(err.Error(), fmt.Sprintf("%x", composeHashOf(testAppCompose))) ||
			!strings.Contains(err.Error(), fmt.Sprintf("%x", composeHashOf(other))) {
			t.Errorf("error names neither the wanted nor the offered digest: %v", err)
		}
	})

	t.Run("no instances", func(t *testing.T) {
		base, _ := cloudAPI(t, map[string]any{"app_id": testAppID, "instances": []any{}}, http.StatusOK)
		if _, _, err := FetchAppComposeFromCloud(
			context.Background(), http.DefaultClient, base, testAppID, composeHashOf(testAppCompose)); err == nil {
			t.Error("expected an error when the app has no instances")
		}
	})

	t.Run("non-200", func(t *testing.T) {
		base, _ := cloudAPI(t, []byte(`{"detail":"not found"}`), http.StatusNotFound)
		if _, _, err := FetchAppComposeFromCloud(
			context.Background(), http.DefaultClient, base, testAppID, composeHashOf(testAppCompose)); err == nil {
			t.Error("expected an error on 404")
		}
	})

	// A compose_hash where an app_id belongs is the mistake worth catching early: it
	// is 64 hex where 40 are expected, and the API would answer a bare 404.
	t.Run("compose_hash passed as app_id", func(t *testing.T) {
		base, _ := cloudAPI(t, map[string]any{"instances": []any{}}, http.StatusOK)
		_, _, err := FetchAppComposeFromCloud(context.Background(), http.DefaultClient, base,
			"dd79782d9cd5b8243acf468896d4cc81907b1ae8cf569b2331d21fab5f45d34f", composeHashOf(testAppCompose))
		if err == nil || !strings.Contains(err.Error(), "hex digits") {
			t.Errorf("err = %v, want it to reject the length", err)
		}
	})

	t.Run("no app_id", func(t *testing.T) {
		base, _ := cloudAPI(t, map[string]any{"instances": []any{}}, http.StatusOK)
		if _, _, err := FetchAppComposeFromCloud(
			context.Background(), http.DefaultClient, base, "", composeHashOf(testAppCompose)); err == nil {
			t.Error("expected an error with no app_id")
		}
	})
}

// The default base must be the one Phala's own SDKs and Trust Center use, since a
// wrong root is a 404 that looks like a missing app.
func TestDefaultCloudAPIBase(t *testing.T) {
	if DefaultCloudAPIBase != "https://cloud-api.phala.com/api/v1" {
		t.Errorf("DefaultCloudAPIBase = %q", DefaultCloudAPIBase)
	}
	if got := cloudAppComposeSource("", testAppID, "instance 1 of 1"); !strings.HasPrefix(got, DefaultCloudAPIBase) {
		t.Errorf("source label = %q, want it to fall back to the default base", got)
	}
}

// End to end through Check: the cloud lookup is the default fetch path, and the
// bytes it returns satisfy the compose_hash gate.
func TestCheck_CodeIdentity_FromCloudAPI(t *testing.T) {
	f := newFixture(t)
	base, path := cloudAPI(t, map[string]any{
		"app_id":    testAppID,
		"instances": []any{cloudInstanceJSON(t, "pc-gateway-staging-a", testAppCompose, true)},
	}, http.StatusOK)

	// A pinned app_id, because the fixture's domain has no DNS. That is also the flag
	// an operator reaches for when the TXT record cannot be read.
	c := f.checker(t, Config{AppID: testAppID, CloudAPIBase: base})
	rep, err := c.Check(context.Background(), testDomain)
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	code := rep.Code
	if code.FetchErr != nil || code.BoundErr != nil {
		t.Fatalf("cloud lookup did not produce an authenticated app-compose: fetch=%v bound=%v",
			code.FetchErr, code.BoundErr)
	}
	if len(code.ComposeFile) == 0 {
		t.Error("ComposeFile is empty although the app-compose bound")
	}
	if code.AppID != testAppID || code.AppIDSource != appIDFromConfig {
		t.Errorf("app_id = %q from %q, want the supplied one", code.AppID, code.AppIDSource)
	}
	if !strings.Contains(code.Source, "attestations") || !strings.Contains(code.Source, "instance 1 of 1") {
		t.Errorf("Source = %q, want it to name the endpoint and the instance", code.Source)
	}
	if want := "/apps/" + testAppID + "/attestations"; !strings.HasSuffix(*path, want) {
		t.Errorf("requested %q, want it to end in %q", *path, want)
	}
	// A pinned app_id is a caller asking for the lookup, so its failure would be fatal
	// rather than advisory — the flag must not quietly weaken the verdict.
	if !code.Requested || code.Discovered {
		t.Errorf("Requested=%v Discovered=%v; a supplied app_id is a demand, not a discovery",
			code.Requested, code.Discovered)
	}
}

// When every path fails, the error must carry the app_id and where it came from:
// with the wrong app_id BOTH lookups fail, and their symptoms (a 404, a timeout)
// name neither the cause nor the fix.
func TestCheck_CodeIdentity_FetchErrorNamesTheAppIDSource(t *testing.T) {
	f := newFixture(t)
	base, _ := cloudAPI(t, []byte(`{"detail":"App not found"}`), http.StatusNotFound)

	c := f.checker(t, Config{CloudAPIBase: base, NoDNSDiscovery: true, AppID: testAppID})
	rep, err := c.Check(context.Background(), testDomain)
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if rep.Code.FetchErr == nil {
		t.Fatal("FetchErr = nil although the API answered 404")
	}
	if rep.Code.NoSource {
		t.Error("NoSource = true although a lookup was attempted")
	}
	if !strings.Contains(rep.Code.FetchErr.Error(), testAppID) {
		t.Errorf("fetch error does not name the app_id it asked for: %v", rep.Code.FetchErr)
	}
}

// The regression this whole path exists for: with no better source, the app_id is
// compose_hash's prefix — a guess — and the report must say so rather than present
// it as the platform's label.
func TestCheck_CodeIdentity_AppIDFallbackIsLabelled(t *testing.T) {
	f := newFixture(t)
	rep, err := f.checker(t, Config{}).Check(context.Background(), testDomain)
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if rep.Code.AppIDSource != appIDFromComposeHash {
		t.Errorf("AppIDSource = %q, want %q", rep.Code.AppIDSource, appIDFromComposeHash)
	}
	if want := fmt.Sprintf("%x", composeHashOf(testAppCompose))[:appIDHexLen]; rep.Code.AppID != want {
		t.Errorf("AppID = %q, want the compose_hash prefix %q", rep.Code.AppID, want)
	}
}

// cloudLookupCtx is what keeps a HANGING cloud API from spending the budget the
// guest-agent fallback needs. The halving itself is arbitrary; what must hold is
// that a fallback always has time left, and that a run with nothing to fall back
// to is not shortened for no reason.
func TestCloudLookupCtx(t *testing.T) {
	const budget = time.Second

	t.Run("halves the budget when a fallback exists", func(t *testing.T) {
		parent, cancelParent := context.WithTimeout(context.Background(), budget)
		defer cancelParent()
		ctx, cancel := cloudLookupCtx(parent, true)
		defer cancel()
		deadline, ok := ctx.Deadline()
		if !ok {
			t.Fatal("no deadline on the cloud context")
		}
		if left := time.Until(deadline); left > budget*3/4 {
			t.Errorf("cloud context keeps %v of a %v budget; the fallback would be starved", left, budget)
		}
	})

	t.Run("keeps the whole budget with no fallback", func(t *testing.T) {
		parent, cancelParent := context.WithTimeout(context.Background(), budget)
		defer cancelParent()
		ctx, cancel := cloudLookupCtx(parent, false)
		defer cancel()
		deadline, ok := ctx.Deadline()
		if !ok {
			t.Fatal("no deadline on the cloud context")
		}
		if left := time.Until(deadline); left < budget*3/4 {
			t.Errorf("cloud context keeps only %v of a %v budget, with no fallback to save it for", left, budget)
		}
	})

	// A library caller with no deadline is bounded by the HTTP client's own timeout;
	// inventing one here would cap a run the caller deliberately left open.
	t.Run("adds no deadline when the parent has none", func(t *testing.T) {
		ctx, cancel := cloudLookupCtx(context.Background(), true)
		defer cancel()
		if _, ok := ctx.Deadline(); ok {
			t.Error("a deadline was invented for a parent that had none")
		}
	})

	// An already-spent budget must still produce a usable (immediately-done) context
	// rather than a negative timeout.
	t.Run("survives an expired parent", func(t *testing.T) {
		parent, cancelParent := context.WithTimeout(context.Background(), -time.Second)
		defer cancelParent()
		ctx, cancel := cloudLookupCtx(parent, true)
		defer cancel()
		if ctx.Err() == nil {
			t.Error("an expired parent produced a live cloud context")
		}
	})
}

// The two fields of one instance can disagree mid-upgrade: the platform's record
// moves before the CVM has booted the new manifest. Whichever field holds the one
// this quote binds must win, so neither may be read as the only candidate.
func TestFetchAppComposeFromCloud_EitherFieldCanHoldTheMatch(t *testing.T) {
	other := strings.Replace(testAppCompose, "staging-a", "staging-b", 1)

	t.Run("match in compose_file while tcb_info holds another", func(t *testing.T) {
		inst := cloudInstanceJSON(t, "a", other, true)
		inst["compose_file"] = testAppCompose
		base, _ := cloudAPI(t, map[string]any{"instances": []any{inst}}, http.StatusOK)

		raw, _, err := FetchAppComposeFromCloud(
			context.Background(), http.DefaultClient, base, testAppID, composeHashOf(testAppCompose))
		if err != nil {
			t.Fatalf("FetchAppComposeFromCloud: %v", err)
		}
		if string(raw) != testAppCompose {
			t.Errorf("app-compose = %q, want the compose_file one", raw)
		}
	})

	t.Run("match in tcb_info while compose_file holds another", func(t *testing.T) {
		inst := cloudInstanceJSON(t, "a", testAppCompose, true)
		inst["compose_file"] = other
		base, _ := cloudAPI(t, map[string]any{"instances": []any{inst}}, http.StatusOK)

		raw, _, err := FetchAppComposeFromCloud(
			context.Background(), http.DefaultClient, base, testAppID, composeHashOf(testAppCompose))
		if err != nil {
			t.Fatalf("FetchAppComposeFromCloud: %v", err)
		}
		if string(raw) != testAppCompose {
			t.Errorf("app-compose = %q, want the tcb_info one", raw)
		}
	})
}

// An app_id pasted from the Cloud API's contract_address carries a 0x. It is the
// same 20 bytes, so it must be accepted rather than rejected for its prefix.
func TestFetchAppComposeFromCloud_AcceptsHexPrefixedAppID(t *testing.T) {
	base, path := cloudAPI(t, map[string]any{
		"instances": []any{cloudInstanceJSON(t, "a", testAppCompose, true)},
	}, http.StatusOK)

	raw, _, err := FetchAppComposeFromCloud(
		context.Background(), http.DefaultClient, base, "0x"+strings.ToUpper(testAppID), composeHashOf(testAppCompose))
	if err != nil {
		t.Fatalf("FetchAppComposeFromCloud: %v", err)
	}
	if string(raw) != testAppCompose {
		t.Errorf("app-compose = %q", raw)
	}
	if want := "/apps/" + testAppID + "/attestations"; !strings.HasSuffix(*path, want) {
		t.Errorf("requested %q, want the normalized app_id in %q", *path, want)
	}
}
