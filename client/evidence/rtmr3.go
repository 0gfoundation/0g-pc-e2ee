package evidence

// rtmr3.go reads what a provider's CVM says it is running NOW, from the records the 0G
// controller appends to RTMR3, and judges it.
//
// WHY. The compose checks (composereview.go, composebaseline.go) judge the manifest the
// CVM BOOTED. The controller can change two things after boot: the image the broker and
// event services run on, swapped to repo@digest with the repository taken from the
// controller's config file (which the provider writes), and the broker's config. It
// records each change in RTMR3 before making it. Without reading those records, a
// provider that booted a release and swapped to anything else afterwards verifies
// exactly like one that did not — and on 2026-10-16 three mainnet providers (cn-19,
// cn-20, cn-41) were running manual branch builds that way, behind manifests pinning
// v0.5.1 and v0.5.2.
//
// WHAT IS IMPLEMENTED, AND FROM WHAT. The broker repository's doc/rtmr3-records.md,
// which is written so a verifier can implement it without importing the code of the
// party it verifies — and this is that independent implementation; nothing here comes
// from the broker's api/common/attest. Correctness is agreement with the real vectors
// under testdata/rtmr3, the broker's own among them, not with any code.
//
// THE ANCHOR. The event log arrives in the provider's /v1/quote reply, unsigned. It is
// worth nothing until replaying it gives the RTMR3 of the DCAP-verified quote; only then
// is "the last record" a statement the hardware vouches for. A log that does not replay
// is not the log the CVM wrote, and that is a finding about the provider.
//
// WHAT THE RECORDS ARE WORTH AFTER THAT. Anything holding /var/run/dstack.sock can append
// a record, so they are exactly as trustworthy as the confinement of that socket — which
// the recorded baseline checks (only the controller may hold it) and nothing else does.
//
// THE OUTCOMES, matching the rest of pcverify: a contradiction (a log that does not
// replay, a record the grammar refuses, a running build that is not a release, keys that
// differ from report_data, an engine record) FAILS; a state the reader cannot determine
// (no log served, a record name this reader does not know, an upstream set the
// controller could not state, an instance change that aborted, a release check that
// could not run) is a check that DID NOT RUN. The upstream set and the config hash are
// reported, not judged: where plaintext may go is the gateway's question and has its
// own rules to come.

import (
	"bytes"
	"crypto/sha512"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/0gfoundation/0g-pc-e2ee/protocol/attest"
)

// RTMRLen is the width of a TDX measurement register, and of the SHA-384 extending it.
const RTMRLen = 48

// runtimeEventType is the event_type of every application-written (runtime) entry,
// 0x08000001 (rtmr3-records.md §3).
const runtimeEventType = 0x08000001

// systemReady is the entry that ends dstack's own boot facts (§2 step 4).
const systemReady = "system-ready"

// The record names this reader knows (§4). Any other zg- name after system-ready means
// the writer is newer than the reader.
const (
	recImageUpdate          = "zg-image-update"
	recConfigUpdate         = "zg-config-update"
	recUpstreamSet          = "zg-upstream-set"
	recEngineSet            = "zg-engine-set"
	recInstanceConfigUpdate = "zg-instance-config-update"
)

// ErrNoEventLog reports a /v1/quote reply that carries no event log. Not a finding about
// the provider — a broker that does not serve it has not been checked — so callers report
// it as a check that did not run.
var ErrNoEventLog = errors.New("the /v1/quote reply carries no event_log")

// RuntimeState is what a CVM's RTMR3 records say it runs now. Every field is read from a
// log that replayed to the verified quote's RTMR3.
type RuntimeState struct {
	// Entries is the number of RTMR3 entries replayed; Runtime the number after
	// system-ready.
	Entries, Runtime int
	// Ignored are zg- names found BEFORE system-ready. They cannot have been written by a
	// container (§2 step 4), so they are not read; they are reported because their
	// presence is odd.
	Ignored []string

	// Image is the last zg-image-update; nil when there is none, which means the broker
	// and event services still run the image the manifest pins.
	Image *ImageRecord
	// ImageUpdates and ConfigUpdates count the records of each kind.
	ImageUpdates, ConfigUpdates int
	// LastConfig is the last zg-config-update: sha256 of the broker config, hex.
	LastConfig string
	// Upstreams is the last zg-upstream-set; nil when the controller records none.
	Upstreams *UpstreamSet
	// Engines is the number of zg-engine-set records.
	Engines int
	// Instances is the last zg-instance-config-update per instance: the config hash, or
	// "unknown" for a change that aborted.
	Instances map[string]string
	// Unknown are zg- names after system-ready this reader does not know.
	Unknown []string
}

// ImageRecord is one zg-image-update (§4.1).
type ImageRecord struct {
	// Repository and Digest are the image reference, split at '@'.
	Repository, Digest string
	// Signer is the response-signing address derived for the image, 0x + 40 lowercase hex.
	Signer string
	// EncPub is the X25519 encryption public key derived for it.
	EncPub [32]byte
	// Index is the record's position among the runtime entries, from 1, for reports.
	Index int
}

// UpstreamSet is one zg-upstream-set (§4.3): every destination the primary broker may
// forward unsealed plaintext to, or Invalidated when the controller could not state it.
type UpstreamSet struct {
	Invalidated bool
	Members     []Upstream
}

// Upstream is one member of an upstream set.
type Upstream struct {
	Name, URL, Identity string
}

// Host is the upstream's host, without the port.
func (u Upstream) Host() string {
	p, err := url.Parse(u.URL)
	if err != nil {
		return ""
	}
	return p.Hostname()
}

// eventEntry is one entry of a /v1/quote event log. The entry's own digest field is not
// read: it is not an independent statement about anything, and dstack's GetQuote form
// leaves it empty for RTMR3 entries (§3).
type eventEntry struct {
	IMR       int    `json:"imr"`
	EventType uint32 `json:"event_type"`
	Event     string `json:"event"`
	Payload   string `json:"event_payload"`
}

// EventDigest is what dstack extends RTMR3 with for one entry (§3):
// SHA-384(event_type as 4 little-endian bytes ‖ ":" ‖ event ‖ ":" ‖ payload).
func EventDigest(eventType uint32, event string, payload []byte) [RTMRLen]byte {
	h := sha512.New384()
	var ty [4]byte
	binary.LittleEndian.PutUint32(ty[:], eventType)
	h.Write(ty[:])
	h.Write([]byte(":"))
	h.Write([]byte(event))
	h.Write([]byte(":"))
	h.Write(payload)
	var out [RTMRLen]byte
	copy(out[:], h.Sum(nil))
	return out
}

// ReadRuntimeState reads the event log out of a /v1/quote reply, requires it to replay
// to rtmr3 — the RTMR3 of the VERIFIED quote, never one read from the reply — and returns
// the state its records describe. An error other than ErrNoEventLog is a finding: the
// log is not the CVM's, or a record in it is not one the controller writes.
func ReadRuntimeState(reply []byte, rtmr3 [RTMRLen]byte) (RuntimeState, error) {
	log, err := replayRTMR3(reply, rtmr3)
	if err != nil {
		return RuntimeState{}, err
	}

	st := RuntimeState{Entries: len(log)}
	ready := -1
	for i, e := range log {
		if e.Event == systemReady {
			ready = i
			break
		}
		if strings.HasPrefix(e.Event, "zg-") {
			st.Ignored = append(st.Ignored, e.Event)
		}
	}
	if ready < 0 {
		return RuntimeState{}, errors.New("the event log has no system-ready entry, so no record in it can be read")
	}
	for i, e := range log[ready+1:] {
		st.Runtime++
		if !strings.HasPrefix(e.Event, "zg-") {
			continue // dstack's or another application's entry; carries no 0G record
		}
		n := i + 1
		if e.EventType != runtimeEventType {
			return RuntimeState{}, fmt.Errorf("runtime record %d (%s) has event_type %#x, not the runtime type %#x",
				n, e.Event, e.EventType, runtimeEventType)
		}
		if err := st.apply(n, e.Event, e.payload); err != nil {
			return RuntimeState{}, fmt.Errorf("runtime record %d (%s): %w", n, e.Event, err)
		}
	}
	return st, nil
}

// rtmr3Entry is one RTMR3 entry of an event log that replayed, with its payload decoded.
type rtmr3Entry struct {
	eventEntry
	payload []byte
}

// replayRTMR3 reads the event log out of a /v1/quote reply and requires its RTMR3 entries
// to replay to rtmr3 — the RTMR3 of the VERIFIED quote, never one read from the reply. It
// returns those entries in log order, each now as good as the quote: the replay is what
// makes any of them worth reading. ErrNoEventLog when the reply carries none.
func replayRTMR3(reply []byte, rtmr3 [RTMRLen]byte) ([]rtmr3Entry, error) {
	entries, err := eventLogOf(reply)
	if err != nil {
		return nil, err
	}
	var mr [RTMRLen]byte
	var log []rtmr3Entry
	for i, e := range entries {
		if e.IMR != 3 {
			continue // the firmware's registers; compared as the boot chain, not replayed here
		}
		payload, err := hex.DecodeString(e.Payload)
		if err != nil {
			return nil, fmt.Errorf("event log entry %d (%q): the payload is not hex: %v", i, e.Event, err)
		}
		d := EventDigest(e.EventType, e.Event, payload)
		h := sha512.New384()
		h.Write(mr[:])
		h.Write(d[:])
		copy(mr[:], h.Sum(nil))
		log = append(log, rtmr3Entry{e, payload})
	}
	if mr != rtmr3 {
		return nil, fmt.Errorf("the event log does not replay to the quote's RTMR3 (replayed %x, quote %x): "+
			"it is not the log this CVM wrote", mr, rtmr3)
	}
	return log, nil
}

// apply reads one record into the state; the last record of each kind wins (§2 step 5).
func (st *RuntimeState) apply(n int, name string, payload []byte) error {
	switch name {
	case recImageUpdate:
		rec, err := parseImageUpdate(payload)
		if err != nil {
			return err
		}
		rec.Index = n
		st.Image, st.ImageUpdates = &rec, st.ImageUpdates+1
	case recConfigUpdate:
		if !isLowerHex(string(payload), 64) {
			return fmt.Errorf("%q is not a sha256 in lowercase hex", payload)
		}
		st.LastConfig, st.ConfigUpdates = string(payload), st.ConfigUpdates+1
	case recUpstreamSet:
		set, err := parseUpstreamSet(payload)
		if err != nil {
			return err
		}
		st.Upstreams = &set
	case recEngineSet:
		st.Engines++
	case recInstanceConfigUpdate:
		inst, value, ok := strings.Cut(string(payload), " ")
		if !ok || inst == "" || strings.ContainsAny(inst, " \t\n") || (value != "unknown" && !isLowerHex(value, 64)) {
			return fmt.Errorf("%q is not `<instance> <sha256 hex>` or `<instance> unknown`", payload)
		}
		if st.Instances == nil {
			st.Instances = map[string]string{}
		}
		st.Instances[inst] = value
	default:
		st.Unknown = append(st.Unknown, name)
	}
	return nil
}

// eventLogOf returns the served event log of a /v1/quote reply. The top-level event_log
// is the GetQuote form the spec describes; tcb_info's full copy is used only when the
// reply has no top-level one. Either is fine to replay, since the replay is the check.
// Both arrive as a JSON array or as a string holding one.
func eventLogOf(reply []byte) ([]eventEntry, error) {
	var outer struct {
		EventLog json.RawMessage `json:"event_log"`
		TCBInfo  json.RawMessage `json:"tcb_info"`
	}
	if err := json.Unmarshal(reply, &outer); err != nil {
		return nil, fmt.Errorf("the /v1/quote reply is not JSON: %v", err)
	}
	raw, err := attest.UnwrapJSONString(outer.EventLog)
	if err != nil {
		return nil, fmt.Errorf("the reply's event_log does not decode: %v", err)
	}
	if isAbsent(raw) {
		tcb, err := attest.UnwrapJSONString(outer.TCBInfo)
		if err != nil {
			return nil, fmt.Errorf("the reply's tcb_info does not decode: %v", err)
		}
		if !isAbsent(tcb) {
			var t struct {
				EventLog json.RawMessage `json:"event_log"`
			}
			if err := json.Unmarshal(tcb, &t); err != nil {
				return nil, fmt.Errorf("the reply's tcb_info does not decode: %v", err)
			}
			if raw, err = attest.UnwrapJSONString(t.EventLog); err != nil {
				return nil, fmt.Errorf("tcb_info's event_log does not decode: %v", err)
			}
		}
	}
	if isAbsent(raw) {
		return nil, ErrNoEventLog
	}
	var entries []eventEntry
	if err := json.Unmarshal(raw, &entries); err != nil {
		return nil, fmt.Errorf("the event log does not decode: %v", err)
	}
	return entries, nil
}

func isAbsent(raw []byte) bool {
	t := bytes.TrimSpace(raw)
	return len(t) == 0 || bytes.Equal(t, []byte("null")) || bytes.Equal(t, []byte(`""`))
}

// parseImageUpdate reads `<repo>@sha256:<64 hex> <0x + 40 hex> <64 hex>`, all hex
// lowercase, single spaces (§4.1).
func parseImageUpdate(payload []byte) (ImageRecord, error) {
	fields := strings.Split(string(payload), " ")
	refuse := func(why string) (ImageRecord, error) {
		return ImageRecord{}, fmt.Errorf("%q is not `<repo>@sha256:<hex> <signer> <enc_pub>`: %s", payload, why)
	}
	if len(fields) != 3 {
		return refuse(fmt.Sprintf("%d fields", len(fields)))
	}
	repo, digest, ok := strings.Cut(fields[0], "@")
	switch {
	case !ok || repo == "" || strings.ContainsAny(repo, "@\t\n"):
		return refuse("the image is not repo@digest")
	case !strings.HasPrefix(digest, "sha256:") || !isLowerHex(strings.TrimPrefix(digest, "sha256:"), 64):
		return refuse("the digest is not sha256:<64 lowercase hex>")
	case !strings.HasPrefix(fields[1], "0x") || !isLowerHex(strings.TrimPrefix(fields[1], "0x"), 40):
		return refuse("the signer is not 0x + 40 lowercase hex")
	case !isLowerHex(fields[2], 64):
		return refuse("enc_pub is not 64 lowercase hex")
	}
	rec := ImageRecord{Repository: repo, Digest: digest, Signer: fields[1]}
	hex.Decode(rec.EncPub[:], []byte(fields[2]))
	return rec, nil
}

// upstreamName is an upstream's name (§4.3).
var upstreamName = regexp.MustCompile(`^[a-z0-9]([a-z0-9_-]{0,61}[a-z0-9])?$`)

const (
	maxUpstreamLine    = 4096
	maxUpstreamMembers = 1024
)

// parseUpstreamSet reads `count=<n>` and exactly n member lines, or `invalidated` (§4.3).
// The writer refuses to record anything outside the grammar, so neither does this.
func parseUpstreamSet(payload []byte) (UpstreamSet, error) {
	if string(payload) == "invalidated" {
		return UpstreamSet{Invalidated: true}, nil
	}
	lines := strings.Split(string(payload), "\n")
	for _, l := range lines {
		if len(l) > maxUpstreamLine {
			return UpstreamSet{}, fmt.Errorf("a line is longer than %d bytes", maxUpstreamLine)
		}
	}
	countText, ok := strings.CutPrefix(lines[0], "count=")
	n, err := strconv.Atoi(countText)
	if !ok || err != nil || n < 0 || strconv.Itoa(n) != countText {
		return UpstreamSet{}, fmt.Errorf("the first line %q is not count=<n>", lines[0])
	}
	members := lines[1:]
	if n == 0 && len(members) == 1 && members[0] == "" {
		members = nil
	}
	switch {
	case n > maxUpstreamMembers:
		return UpstreamSet{}, fmt.Errorf("count=%d is over the %d-member cap", n, maxUpstreamMembers)
	case len(members) != n:
		return UpstreamSet{}, fmt.Errorf("count=%d but %d member lines", n, len(members))
	}
	set := UpstreamSet{}
	seen := map[string]bool{}
	for _, m := range members {
		f := strings.Split(m, " ")
		if len(f) != 2 && len(f) != 3 {
			return UpstreamSet{}, fmt.Errorf("member %q is not `<name> <base URL> [<identity>]`", m)
		}
		if !upstreamName.MatchString(f[0]) {
			return UpstreamSet{}, fmt.Errorf("member name %q is not [a-z0-9]([a-z0-9_-]{0,61}[a-z0-9])?", f[0])
		}
		if seen[f[0]] {
			return UpstreamSet{}, fmt.Errorf("member %q appears twice", f[0])
		}
		seen[f[0]] = true
		if err := checkBaseURL(f[1]); err != nil {
			return UpstreamSet{}, fmt.Errorf("member %q: %v", f[0], err)
		}
		u := Upstream{Name: f[0], URL: f[1]}
		if len(f) == 3 {
			if f[2] == "" {
				return UpstreamSet{}, fmt.Errorf("member %q has an empty identity", f[0])
			}
			u.Identity = f[2]
		}
		set.Members = append(set.Members, u)
	}
	return set, nil
}

// checkBaseURL applies §4.3's rules for an upstream's base URL.
func checkBaseURL(s string) error {
	for _, c := range []byte(s) {
		if c <= ' ' || c >= 0x7f {
			return fmt.Errorf("base URL %q has a byte outside printable ASCII", s)
		}
	}
	u, err := url.Parse(s)
	if err != nil {
		return fmt.Errorf("base URL %q does not parse: %v", s, err)
	}
	scheme, rest, _ := strings.Cut(s, "://")
	host := u.Host
	switch {
	case scheme != "http" && scheme != "https":
		return fmt.Errorf("base URL %q is not lowercase http or https", s)
	case u.Opaque != "" || host == "":
		return fmt.Errorf("base URL %q has no host", s)
	case u.User != nil || strings.Contains(strings.SplitN(rest, "/", 2)[0], "@"):
		return fmt.Errorf("base URL %q carries userinfo", s)
	case u.RawQuery != "" || u.ForceQuery || strings.Contains(s, "#"):
		return fmt.Errorf("base URL %q carries a query or fragment", s)
	case host != strings.ToLower(host):
		return fmt.Errorf("base URL %q has an uppercase host", s)
	case scheme == "http" && u.Port() == "80", scheme == "https" && u.Port() == "443":
		return fmt.Errorf("base URL %q spells out the default port", s)
	case strings.Contains(u.EscapedPath(), "%") || strings.Contains(s, "%"):
		return fmt.Errorf("base URL %q has percent-encoding", s)
	case u.Path == "/" || strings.HasSuffix(u.Path, "/"):
		return fmt.Errorf("base URL %q ends in a slash", s)
	}
	for _, seg := range strings.Split(u.Path, "/") {
		if seg == "." || seg == ".." {
			return fmt.Errorf("base URL %q has a dot segment", s)
		}
	}
	if p := u.Port(); p != "" {
		n, err := strconv.Atoi(p)
		if err != nil || n < 1 || n > 65535 || strconv.Itoa(n) != p {
			return fmt.Errorf("base URL %q has port %q", s, p)
		}
	}
	return nil
}

func isLowerHex(s string, n int) bool {
	if len(s) != n {
		return false
	}
	for _, c := range s {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

// RuntimeCheck is the judgement of a RuntimeState.
type RuntimeCheck struct {
	State RuntimeState
	// Release is the verdict on the running broker build when a zg-image-update names
	// it; nil when none does and the manifest's pin still applies (judged by the
	// baseline, not here).
	Release *ReleaseVerdict
	// KeysBound is whether the image record's signer and enc_pub equal report_data's.
	KeysBound bool
	// Failures are contradictions: each one fails the run.
	Failures []string
	// Unverified are the parts that could not be decided: each one is a check that did
	// not run.
	Unverified []string
}

// CheckRuntime judges st against the release policy and the keys the verified quote's
// report_data carries.
//
// The running build is judged for EVERY provider, recorded deployment or not: the
// record is an anchored statement about what runs, and "not a release" does not depend
// on anyone having reviewed the rest of the manifest.
func CheckRuntime(st RuntimeState, rels ReleaseVerifier, signer string, encPub []byte) RuntimeCheck {
	c := RuntimeCheck{State: st}
	if im := st.Image; im != nil {
		v := VerifyRelease(rels, im.Repository, im.Digest)
		c.Release = &v
		switch v.Status {
		case ReleaseAccepted:
		case ReleaseUnavailable:
			c.Unverified = append(c.Unverified, fmt.Sprintf("the running broker build %s@%s could not be checked: %s",
				im.Repository, im.Digest, v.Reason))
		default:
			c.Failures = append(c.Failures, fmt.Sprintf("the running broker build %s@%s (zg-image-update, runtime "+
				"entry %d) is not an accepted release: %s", im.Repository, im.Digest, im.Index, v.Reason))
		}
		// §2 step 6: the keys the quote carries must be the ones derived for the running
		// image. Otherwise the signer acknowledged on chain is not the running broker's.
		c.KeysBound = strings.EqualFold(im.Signer, signer) && bytes.Equal(im.EncPub[:], encPub)
		if !strings.EqualFold(im.Signer, signer) {
			c.Failures = append(c.Failures, fmt.Sprintf("the running broker's signer %s (zg-image-update) is not the "+
				"signer %s in report_data", im.Signer, signer))
		}
		if !bytes.Equal(im.EncPub[:], encPub) {
			c.Failures = append(c.Failures, fmt.Sprintf("the running broker's enc_pub %x (zg-image-update) is not the "+
				"enc_pub %x in report_data", im.EncPub, encPub))
		}
	}
	if st.Engines > 0 {
		// Only a controller started with ZG_CONTROLLER_ENGINES=on writes this, and the
		// docker.sock exception requires that variable absent.
		c.Failures = append(c.Failures, fmt.Sprintf("the controller created containers after launch (%d zg-engine-set "+
			"record(s)), which only ZG_CONTROLLER_ENGINES=on allows", st.Engines))
	}
	if len(st.Unknown) > 0 {
		c.Unverified = append(c.Unverified, fmt.Sprintf("the event log has record(s) this pcverify does not know (%s): "+
			"the controller is newer than this reader", strings.Join(dedupe(st.Unknown), ", ")))
	}
	if st.Upstreams != nil && st.Upstreams.Invalidated {
		c.Unverified = append(c.Unverified, "the controller could not state the broker's upstream set (zg-upstream-set "+
			"invalidated), so where plaintext goes is unknown")
	}
	insts := make([]string, 0, len(st.Instances))
	for inst := range st.Instances {
		insts = append(insts, inst)
	}
	sort.Strings(insts)
	for _, inst := range insts {
		if st.Instances[inst] == "unknown" {
			c.Unverified = append(c.Unverified, fmt.Sprintf("a config change to broker instance %q aborted "+
				"(zg-instance-config-update unknown), so its state is unknown", inst))
		}
	}
	return c
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
