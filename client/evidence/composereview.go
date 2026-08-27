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
// THE HASH GATE IS NOT OPTIONAL, which is why ReviewCompose takes the compose_hash
// rather than a decoded manifest: before that check the text is whatever the provider
// (or anyone on the path) chose to send, and a review of attacker-chosen YAML is a
// review of nothing. There is no entry point here that skips it.

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
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
	// OriginFirstParty: the repository's namespace is firstPartyNamespace.
	OriginFirstParty
	// OriginThirdParty: anything else, including an unqualified Docker Hub library
	// image.
	OriginThirdParty
)

func (o ImageOrigin) String() string {
	switch o {
	case OriginFirstParty:
		return "first-party"
	case OriginThirdParty:
		return "third-party"
	default:
		return "no image"
	}
}

// firstPartyNamespace is the organisation whose builds we can answer for.
const firstPartyNamespace = "0gfoundation"

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
	// One gate, shared with the container-list path, rather than a second sha256 here:
	// two implementations of "are these the bytes the quote binds" is two answers.
	ac, err := VerifyAppCompose(raw, composeHash)
	if err != nil && !errors.Is(err, ErrNoDockerCompose) {
		return ComposeReview{}, err
	}
	noCompose := errors.Is(err, ErrNoDockerCompose)

	// Every key, not the ones AppCompose decodes: the fields with rules below are a
	// subset of what a manifest may carry, and the report has to show both.
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		return ComposeReview{}, fmt.Errorf("app-compose is not a JSON object: %w", err)
	}

	r := ComposeReview{
		Name:        ac.Name,
		AllowedEnvs: ac.AllowedEnvs,
		Fields:      sortedKeys(fields),
	}
	r.reviewAppComposeFields(fields)
	if noCompose {
		r.add(SeverityBlocking, "", "docker_compose_file",
			"the manifest embeds no compose text, so there is nothing to pin per service")
		r.sortFindings()
		return r, nil
	}
	r.reviewComposeText([]byte(ac.DockerComposeFile))
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
	// this review inventing the fact it is supposed to report.
	r.Runner = jsonString(fields["runner"])
	switch r.Runner {
	case "docker-compose":
	case "":
		r.add(SeverityBlocking, "", "runner",
			"runner is not set, and this review will not assume the platform's default; "+
				"without it, nothing below is known to describe what runs")
	default:
		r.add(SeverityBlocking, "", "runner", fmt.Sprintf(
			"runner is %q; this review reads docker-compose semantics, so it can say nothing about what runs", r.Runner))
	}
	r.Features = jsonStrings(fields["features"])

	if envs := r.AllowedEnvs; len(envs) > 0 {
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
	if jsonBool(fields["kms_enabled"]) {
		kp := jsonString(fields["key_provider"])
		id := jsonString(fields["key_provider_id"])
		if kp == "" {
			kp = "kms"
		}
		detail := fmt.Sprintf("keys come from an external key provider (%s", kp)
		if id != "" {
			detail += ", id " + id
		}
		detail += "), which is therefore in the TCB. This manifest's mr_config_id layout " +
			"carries compose_hash alone, so WHICH provider that is cannot be read from the quote — " +
			"pin it out of band or the chain has an unmeasured hop"
		r.add(SeverityJustify, "", "kms_enabled", detail)
	}
	if jsonBool(fields["local_key_provider_enabled"]) {
		r.add(SeverityNote, "", "local_key_provider_enabled",
			"keys are derived inside the CVM instead of from a KMS: one fewer party in the TCB, "+
				"and no way to recover or migrate the app's state off this machine")
	}

	if jsonBool(fields["public_logs"]) {
		r.add(SeverityJustify, "", "public_logs",
			"container logs are readable from outside the CVM; for a service handling sealed prompts, "+
				"anything a container logs is disclosed, so this is only safe if every image in the manifest is known not to log payloads")
	}
	if jsonBool(fields["public_sysinfo"]) {
		r.add(SeverityNote, "", "public_sysinfo",
			"host and CVM system info is readable from outside; useful for debugging, and a fingerprint")
	}
	if has(fields, "public_tcbinfo") && !jsonBool(fields["public_tcbinfo"]) {
		r.add(SeverityNote, "", "public_tcbinfo",
			"the CVM does not publish tcb_info, so its /v1/quote reply carries no app_compose and this review "+
				"cannot be run against it remotely — the manifest has to be supplied out of band")
	}
	if has(fields, "secure_time") && !jsonBool(fields["secure_time"]) {
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
	if jsonBool(fields["host_api_enabled"]) {
		r.add(SeverityJustify, "", "host_api_enabled",
			"the host-API channel is on: a path between the CVM and the untrusted host that nothing in the "+
				"compose text describes. What it exposes depends on the dstack version, which this review does "+
				"not read — confirm it against that version before treating the manifest as a baseline")
	}

	if s := jsonString(fields["pre_launch_script"]); strings.TrimSpace(s) != "" {
		sum := sha256.Sum256([]byte(s))
		r.PreLaunchBytes = len(s)
		r.PreLaunchSHA256 = fmt.Sprintf("%x", sum)
		r.add(SeverityJustify, "", "pre_launch_script", fmt.Sprintf(
			"%d bytes, sha256 %s: runs as root in the CVM before any container and is covered by no image digest, "+
				"so it is TCB that only the compose hash pins. Compare the digest across providers — a manifest-specific "+
				"script is a very different thing from the platform's stock one",
			r.PreLaunchBytes, r.PreLaunchSHA256))
	}
	if s := jsonString(fields["bash_script"]); strings.TrimSpace(s) != "" {
		r.add(SeverityBlocking, "", "bash_script",
			"the manifest runs a bare shell script instead of (or alongside) a compose file; there are no per-service "+
				"images to pin, so nothing here can be reduced to a baseline")
	}
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

// reviewComposeText walks the compose document. A document that will not parse is a
// blocking finding rather than an error: the bytes are authenticated, so "the manifest
// the enclave booted is not readable YAML" is a fact about the deployment and belongs
// in the report next to everything else.
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
	services := mapValue(root.Content[0], "services")
	if services == nil || services.Kind != yaml.MappingNode {
		r.add(SeverityBlocking, "", "docker_compose_file", "the compose text has no services mapping")
		return
	}

	mounts := &mountIndex{holders: map[string][]string{}, named: map[string]bool{}}
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
		if rules, ok := nodeStrings(val); !ok || len(rules) > 0 {
			r.add(SeverityBlocking, name, key,
				"the service grants itself device access by cgroup rule, which names devices the manifest does not list")
		}
		return true

	case "volumes_from":
		if from, ok := nodeStrings(val); !ok || len(from) > 0 {
			r.add(SeverityBlocking, name, key,
				"the service takes another container's mounts wholesale, so its filesystem surface is whatever "+
					"that container's is — not something this manifest states")
		}
		return true

	case "cgroup":
		if v := nodeScalar(val); strings.EqualFold(v, "host") {
			r.add(SeverityBlocking, name, key, "the container joins the host cgroup namespace")
		}
		return true

	case "cgroup_parent":
		if nodeScalar(val) != "" {
			r.add(SeverityJustify, name, key, fmt.Sprintf(
				"the container is placed under cgroup %s, outside the tree the runtime would manage", nodeScalar(val)))
		}
		return true

	case "pid":
		v := nodeScalar(val)
		switch {
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
		v := nodeScalar(val)
		switch {
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
		v := nodeScalar(val)
		l := strings.ToLower(v)
		switch {
		case l == "host", l == "shareable", strings.HasPrefix(l, "container:"), strings.HasPrefix(l, "service:"):
			// A GPU model server legitimately needs a shared IPC namespace for its
			// shared-memory transport, which is why this is not blocking.
			r.add(SeverityJustify, name, key, fmt.Sprintf(
				"the container shares an IPC namespace (%s): shared memory is a channel that does not appear "+
					"anywhere else in the manifest, so a baseline has to name which services are allowed it and why", v))
		}
		return true

	case "uts":
		if strings.EqualFold(nodeScalar(val), "host") {
			r.add(SeverityJustify, name, key, "the container shares the host UTS namespace")
		}
		return true

	case "userns_mode":
		if strings.EqualFold(nodeScalar(val), "host") {
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
		if groups, ok := nodeStrings(val); !ok || len(groups) > 0 {
			r.add(SeverityJustify, name, key,
				"the container joins extra groups, which is how access to a device or socket is granted "+
					"without a capability")
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
		if isRelativeBind(src) {
			// A relative bind resolves against wherever the manifest was deployed FROM,
			// which the manifest does not record — so "./data" and "../../../etc" are
			// indistinguishable here, and the path rules below cannot be applied honestly.
			// Reported rather than skipped, which is what treating it as a named volume
			// would silently do.
			r.add(SeverityJustify, name, "volumes", fmt.Sprintf(
				"%s -> %s: a RELATIVE bind mount. What it exposes depends on the directory the deployment was "+
					"brought up from, which is not in the manifest, so this review cannot say what the container reads",
				src, target))
			continue
		}
		if !strings.HasPrefix(src, "/") {
			continue // a named volume; the shared-mount pass is what has something to say
		}
		mode := "rw"
		if ro {
			mode = "ro"
		}
		where := fmt.Sprintf("%s -> %s (%s)", src, target, mode)
		// Each branch marks the source named, so reviewSharedMounts leaves it alone: a
		// line that says which service holds it and what it grants is strictly more than
		// "two services share this", and printing both makes one mount read as two
		// problems. The flag is set per branch rather than in a second condition list —
		// duplicating these conditions is exactly how the two would drift apart.
		switch {
		case guestAgentSockets[src]:
			mounts.named[src] = true
			r.add(SeverityJustify, name, "volumes", fmt.Sprintf(
				"%s: the guest-agent socket. A container holding it can derive the app's keys and obtain "+
					"quotes in the app's name, so every service with it is as trusted as the app itself — a "+
					"baseline must list them exactly, and read_only changes nothing for a socket", where))
		case dockerSockets[src]:
			mounts.named[src] = true
			r.add(SeverityBlocking, name, "volumes", fmt.Sprintf(
				"%s: the container runtime's socket. A container holding it can start any container it likes, "+
					"privileged included, so it is a complete escape from everything else in this manifest", where))
		case src == "/dev/shm" || strings.HasPrefix(src, "/dev/shm/"):
			mounts.named[src] = true
			r.add(SeverityJustify, name, "volumes", fmt.Sprintf(
				"%s: shared memory. Legitimate for a model server's transport, and a channel between whoever "+
					"holds it", where))
		case blockingHostExact[src], hasPrefixPath(src, blockingHostPrefixes):
			mounts.named[src] = true
			r.add(SeverityBlocking, name, "volumes", fmt.Sprintf(
				"%s: a host tree the CVM's own OS owns. Whatever the image digest says the container contains, "+
					"this is what it actually reads", where))
		}
	}
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
		// comes back as an anonymous mount.
		src = strings.TrimSpace(nodeScalar(mapValue(n, "source")))
		target = strings.TrimSpace(nodeScalar(mapValue(n, "target")))
		readOnly, _ = nodeBool(mapValue(n, "read_only"))
		return src, target, readOnly, true

	default:
		return "", "", false, false
	}
}

// classifyOrigin reads the namespace out of an image repository. See ImageOrigin for
// why the answer is a column in a report and not a rule.
func classifyOrigin(image string) ImageOrigin {
	image = strings.TrimSpace(image)
	if image == "" {
		return OriginNone
	}
	parts := strings.Split(image, "/")
	// A leading segment is a registry host only when it looks like one; otherwise the
	// reference is a Docker Hub namespace ("0gfoundation/x") or a library image
	// ("mysql"). Same rule the reference grammar uses.
	if len(parts) > 1 && (strings.Contains(parts[0], ".") || strings.Contains(parts[0], ":") || parts[0] == "localhost") {
		parts = parts[1:]
	}
	if len(parts) > 1 && strings.EqualFold(parts[0], firstPartyNamespace) {
		return OriginFirstParty
	}
	return OriginThirdParty
}

// --- small readers -------------------------------------------------------------
//
// Each of these answers "what does this node/field say", and each returns a zero
// value for a shape it cannot read. That is safe only because every CALLER that acts
// on a negative also handles the unreadable case explicitly (see reviewServiceKey) —
// these must never become the place a wrong shape turns into "not set".

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

// isRelativeBind reports whether a mount source is a host path given relative to the
// deployment directory — which the manifest does not record, so nothing here can resolve
// it. Distinguished from a NAMED volume, whose name never starts with "." or "~".
func isRelativeBind(src string) bool {
	return strings.HasPrefix(src, ".") || strings.HasPrefix(src, "~") ||
		strings.Contains(src, "/../") || strings.HasSuffix(src, "/..")
}

func nodeScalar(n *yaml.Node) string {
	if n == nil || n.Kind != yaml.ScalarNode {
		return ""
	}
	return strings.TrimSpace(n.Value)
}

// nodeBool reports the node's boolean value. ok is false for a missing node AND for a
// node that is not a boolean, and callers must distinguish the two themselves — a
// missing `privileged` is absent, an unparseable one is unknown.
func nodeBool(n *yaml.Node) (val, ok bool) {
	if n == nil {
		return false, false
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

func jsonString(raw json.RawMessage) string {
	var s string
	if len(raw) == 0 || json.Unmarshal(raw, &s) != nil {
		return ""
	}
	return s
}

func jsonStrings(raw json.RawMessage) []string {
	var s []string
	if len(raw) == 0 || json.Unmarshal(raw, &s) != nil {
		return nil
	}
	return s
}

func jsonBool(raw json.RawMessage) bool {
	var b bool
	if len(raw) == 0 || json.Unmarshal(raw, &b) != nil {
		return false
	}
	return b
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
