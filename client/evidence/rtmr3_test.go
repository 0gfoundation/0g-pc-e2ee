package evidence

import (
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/0gfoundation/0g-pc-e2ee/protocol/attest"
)

// The vectors under testdata/rtmr3 are real /v1/quote replies:
//
//   - testnet-rehearsal-v0.5.4.{quote,expected}.json are the broker repository's own
//     vector, copied byte for byte from 0g-serving-broker at ded9c69
//     (api/common/attest/testdata/vectors/testnet-rehearsal-v0.5.4). expected.json is
//     what that repository says a reader must recover; agreeing with it is the test that
//     this reader implements doc/rtmr3-records.md and not something of its own.
//   - cn20-2026-10-16 and cn1-2026-10-16 were fetched from compute-network-20 and -1 on
//     2026-10-16, nvidia_payload removed. cn-20 had swapped its broker image four times
//     since boot; cn-1 had changed only its config.

// vectorReply is a vector's reply with the RTMR3 and report_data of its quote, read the
// way pcverify reads them: out of the quote, never out of the reply's other fields.
func vectorReply(t *testing.T, name string) ([]byte, [RTMRLen]byte, attest.ReportData) {
	t.Helper()
	reply, err := os.ReadFile(filepath.Join("testdata", "rtmr3", name+".quote.json"))
	if err != nil {
		t.Fatal(err)
	}
	raw, err := attest.DecodeQuoteResponse(reply)
	if err != nil {
		t.Fatal(err)
	}
	qb, err := attest.ParseTDXQuoteBody(raw)
	if err != nil {
		t.Fatal(err)
	}
	rd, err := attest.ParseReportData(qb.ReportData[:])
	if err != nil {
		t.Fatal(err)
	}
	return reply, qb.Measurement.RTMR3, rd
}

func TestRuntime_BrokerVector(t *testing.T) {
	reply, rtmr3, rd := vectorReply(t, "testnet-rehearsal-v0.5.4")
	var want struct {
		RTMR3     string     `json:"quote_rtmr3"`
		Events    []string   `json:"runtime_events_after_system_ready"`
		Digest    string     `json:"broker_digest"`
		Source    string     `json:"broker_digest_source"`
		Signer    string     `json:"broker_signer"`
		EncPub    string     `json:"broker_enc_pub"`
		Upstreams [][]string `json:"upstreams"`
	}
	raw, err := os.ReadFile(filepath.Join("testdata", "rtmr3", "testnet-rehearsal-v0.5.4.expected.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, &want); err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(rtmr3[:]) != want.RTMR3 {
		t.Fatalf("the vector's quote carries RTMR3 %x, its expected.json %s", rtmr3, want.RTMR3)
	}

	// Both forms of the log replay: the served one (RTMR3 entries without digests) and
	// tcb_info's full copy, which a reader falls back to when the reply has no other.
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(reply, &fields); err != nil {
		t.Fatal(err)
	}
	delete(fields, "event_log")
	tcbOnly, err := json.Marshal(fields)
	if err != nil {
		t.Fatal(err)
	}
	for name, r := range map[string][]byte{"served event_log": reply, "tcb_info.event_log": tcbOnly} {
		t.Run(name, func(t *testing.T) {
			st, err := ReadRuntimeState(r, rtmr3)
			if err != nil {
				t.Fatal(err)
			}
			if st.Runtime != len(want.Events) || st.ImageUpdates != 1 || st.Image == nil || len(st.Unknown) != 0 {
				t.Fatalf("state %+v, want the records %v", st, want.Events)
			}
			if want.Source != "event" || st.Image.Digest != want.Digest || st.Image.Repository != brokerRepoName ||
				st.Image.Signer != want.Signer || hex.EncodeToString(st.Image.EncPub[:]) != want.EncPub {
				t.Fatalf("image record %+v, want %s %s %s", st.Image, want.Digest, want.Signer, want.EncPub)
			}
			var ups [][]string
			for _, u := range st.Upstreams.Members {
				ups = append(ups, []string{u.Name, u.URL})
			}
			if !reflect.DeepEqual(ups, want.Upstreams) {
				t.Fatalf("upstreams %v, want %v", ups, want.Upstreams)
			}
		})
	}

	// And it passes: v0.5.4, keys equal to report_data.
	st, _ := ReadRuntimeState(reply, rtmr3)
	c := CheckRuntime(st, fleetReleases, rd.SignerAddr, rd.EncPub)
	if len(c.Failures) != 0 || len(c.Unverified) != 0 || c.Release == nil || c.Release.Release.Version != "v0.5.4" {
		t.Fatalf("testnet: %+v", c)
	}
}

func TestRuntime_LiveFleet(t *testing.T) {
	t.Run("cn-20 swapped to a branch build", func(t *testing.T) {
		reply, rtmr3, rd := vectorReply(t, "cn20-2026-10-16")
		st, err := ReadRuntimeState(reply, rtmr3)
		if err != nil {
			t.Fatal(err)
		}
		const running = "sha256:66ff49f0e1ffc9904c723b7d4ba71734bc541c478b38940f5b7c004c5a9a0698"
		if st.Runtime != 8 || st.ImageUpdates != 4 || st.ConfigUpdates != 4 || st.Image.Index != 8 ||
			st.Image.Digest != running || st.Image.Signer != "0x745720517fa4a03a17a5c3525b4060f7a41b46ed" ||
			st.LastConfig != "63935d0a2d1229bcfbb8b0cb8fd040a68cec3bfe6f0a551fe2e8e7d5c7e661c5" || st.Upstreams != nil {
			t.Fatalf("state %+v, image %+v", st, st.Image)
		}
		c := CheckRuntime(st, fleetReleases, rd.SignerAddr, rd.EncPub)
		if len(c.Failures) != 1 || !strings.Contains(c.Failures[0], running) ||
			!strings.Contains(c.Failures[0], "not an accepted release") || len(c.Unverified) != 0 {
			t.Fatalf("cn-20: %+v", c)
		}
	})
	t.Run("cn-1 changed only its config", func(t *testing.T) {
		reply, rtmr3, rd := vectorReply(t, "cn1-2026-10-16")
		st, err := ReadRuntimeState(reply, rtmr3)
		if err != nil {
			t.Fatal(err)
		}
		if st.Image != nil || st.ConfigUpdates != 7 ||
			st.LastConfig != "ca9d00aa101b019f2df18ced10f38b00aa33e13c18b583c2676174208a7e0647" {
			t.Fatalf("state %+v", st)
		}
		// No image record: the manifest's pin is what runs, and that is the baseline's
		// to judge, not this check's.
		if c := CheckRuntime(st, fleetReleases, rd.SignerAddr, rd.EncPub); c.Release != nil ||
			len(c.Failures)+len(c.Unverified) != 0 {
			t.Fatalf("cn-1: %+v", c)
		}
	})
}

// A log that is not the CVM's does not replay, however it differs.
func TestRuntime_ReplayIsTheAnchor(t *testing.T) {
	reply, rtmr3, _ := vectorReply(t, "testnet-rehearsal-v0.5.4")
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(reply, &fields); err != nil {
		t.Fatal(err)
	}
	logText, err := attest.UnwrapJSONString(fields["event_log"])
	if err != nil {
		t.Fatal(err)
	}
	var entries []map[string]any
	if err := json.Unmarshal(logText, &entries); err != nil {
		t.Fatal(err)
	}
	last := len(entries) - 1
	if entries[last]["event"] != recImageUpdate {
		t.Fatalf("the vector's last entry is %v", entries[last]["event"])
	}
	edit := func(f func([]map[string]any) []map[string]any) []byte {
		cp := make([]map[string]any, 0, len(entries))
		for _, e := range entries {
			m := map[string]any{}
			for k, v := range e {
				m[k] = v
			}
			cp = append(cp, m)
		}
		raw, err := json.Marshal(f(cp))
		if err != nil {
			t.Fatal(err)
		}
		out := map[string]json.RawMessage{}
		for k, v := range fields {
			out[k] = v
		}
		// The string form, which the live fleet serves; the vector carries the array.
		quoted, err := json.Marshal(string(raw))
		if err != nil {
			t.Fatal(err)
		}
		out["event_log"] = quoted
		b, err := json.Marshal(out)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	// The untouched log, re-encoded, still replays: the edits below are what fail.
	if _, err := ReadRuntimeState(edit(func(e []map[string]any) []map[string]any { return e }), rtmr3); err != nil {
		t.Fatalf("the vector re-encoded: %v", err)
	}
	ourDigest := strings.Repeat("ab", 32)
	for name, f := range map[string]func([]map[string]any) []map[string]any{
		"a swapped image digest": func(e []map[string]any) []map[string]any {
			p, _ := hex.DecodeString(e[last]["event_payload"].(string))
			s := strings.Replace(string(p), strings.TrimPrefix(v054Digest, "sha256:"), ourDigest, 1)
			e[last]["event_payload"] = hex.EncodeToString([]byte(s))
			return e
		},
		"the last record dropped": func(e []map[string]any) []map[string]any { return e[:last] },
		"two records reordered": func(e []map[string]any) []map[string]any {
			e[last], e[last-1] = e[last-1], e[last]
			return e
		},
		// The entry's own digest is not believed: a log carrying one that matches its
		// forged payload replays exactly as badly.
		"a forged payload with a matching digest field": func(e []map[string]any) []map[string]any {
			p := []byte("ghcr.io/x/y@sha256:" + ourDigest + " 0x" + strings.Repeat("1", 40) + " " + ourDigest)
			d := EventDigest(runtimeEventType, recImageUpdate, p)
			e[last]["event_payload"], e[last]["digest"] = hex.EncodeToString(p), hex.EncodeToString(d[:])
			return e
		},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := ReadRuntimeState(edit(f), rtmr3)
			if err == nil || !strings.Contains(err.Error(), "does not replay to the quote's RTMR3") {
				t.Fatalf("got %v, want a replay mismatch", err)
			}
		})
	}
}

// entry is one RTMR3 entry of a synthetic log.
type rtEntry struct {
	event   string
	payload string
	typ     uint32
}

// synthLog builds a reply carrying entries (after dstack's boot facts and system-ready
// unless the first entry says otherwise) and the RTMR3 they replay to, computed here
// independently of ReadRuntimeState.
func synthLog(t *testing.T, withReady bool, entries ...rtEntry) ([]byte, [RTMRLen]byte) {
	t.Helper()
	all := []rtEntry{{event: "app-id", payload: "00"}, {event: "compose-hash", payload: "11"}}
	if withReady {
		all = append(all, rtEntry{event: systemReady})
	}
	all = append(all, entries...)
	var mr [RTMRLen]byte
	var log []map[string]any
	// One firmware entry, which is not replayed into RTMR3.
	log = append(log, map[string]any{"imr": 0, "event_type": 1, "digest": strings.Repeat("00", 48), "event": "",
		"event_payload": ""})
	for _, e := range all {
		typ := e.typ
		if typ == 0 {
			typ = runtimeEventType
		}
		d := EventDigest(typ, e.event, []byte(e.payload))
		h := sha512.New384()
		h.Write(mr[:])
		h.Write(d[:])
		copy(mr[:], h.Sum(nil))
		log = append(log, map[string]any{"imr": 3, "event_type": typ, "digest": "", "event": e.event,
			"event_payload": hex.EncodeToString([]byte(e.payload))})
	}
	logText, err := json.Marshal(log)
	if err != nil {
		t.Fatal(err)
	}
	reply, err := json.Marshal(map[string]any{"quote": "00", "event_log": string(logText)})
	if err != nil {
		t.Fatal(err)
	}
	return reply, mr
}

func readSynth(t *testing.T, entries ...rtEntry) (RuntimeState, error) {
	t.Helper()
	reply, mr := synthLog(t, true, entries...)
	return ReadRuntimeState(reply, mr)
}

const (
	synthDigest = "sha256:" + "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	synthSigner = "0x00112233445566778899aabbccddeeff00112233"
	synthEncPub = "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210"
)

func imageUpdate(digest string) rtEntry {
	return rtEntry{event: recImageUpdate, payload: brokerRepoName + "@" + digest + " " + synthSigner + " " + synthEncPub}
}

func TestRuntime_Records(t *testing.T) {
	t.Run("the last record of each kind decides", func(t *testing.T) {
		st, err := readSynth(t, imageUpdate(v054Digest), rtEntry{event: recConfigUpdate, payload: strings.Repeat("a", 64)},
			imageUpdate(synthDigest), rtEntry{event: recConfigUpdate, payload: strings.Repeat("b", 64)},
			rtEntry{event: "dstack-something"})
		if err != nil {
			t.Fatal(err)
		}
		if st.Image.Digest != synthDigest || st.Image.Index != 3 || st.ImageUpdates != 2 ||
			st.LastConfig != strings.Repeat("b", 64) || st.ConfigUpdates != 2 || st.Runtime != 5 {
			t.Fatalf("state %+v image %+v", st, st.Image)
		}
	})
	t.Run("a zg- record before system-ready is not read", func(t *testing.T) {
		reply, mr := synthLog(t, false, imageUpdate(synthDigest), rtEntry{event: systemReady}, imageUpdate(v054Digest))
		st, err := ReadRuntimeState(reply, mr)
		if err != nil {
			t.Fatal(err)
		}
		if st.Image.Digest != v054Digest || st.ImageUpdates != 1 || !reflect.DeepEqual(st.Ignored, []string{recImageUpdate}) {
			t.Fatalf("state %+v", st)
		}
	})
	t.Run("no system-ready", func(t *testing.T) {
		reply, mr := synthLog(t, false, imageUpdate(synthDigest))
		if _, err := ReadRuntimeState(reply, mr); err == nil || !strings.Contains(err.Error(), "no system-ready") {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("a zg- record of another event type", func(t *testing.T) {
		e := imageUpdate(synthDigest)
		e.typ = 1
		if _, err := readSynth(t, e); err == nil || !strings.Contains(err.Error(), "event_type") {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("an unknown record is collected, not skipped", func(t *testing.T) {
		st, err := readSynth(t, rtEntry{event: "zg-something-new", payload: "x"}, imageUpdate(synthDigest))
		if err != nil || !reflect.DeepEqual(st.Unknown, []string{"zg-something-new"}) {
			t.Fatalf("got %+v, %v", st, err)
		}
	})
	t.Run("instances and engines", func(t *testing.T) {
		st, err := readSynth(t, rtEntry{event: recInstanceConfigUpdate, payload: "b2 unknown"},
			rtEntry{event: recInstanceConfigUpdate, payload: "b1 " + strings.Repeat("c", 64)},
			rtEntry{event: recInstanceConfigUpdate, payload: "b2 " + strings.Repeat("d", 64)},
			rtEntry{event: recEngineSet, payload: "count=0"})
		if err != nil {
			t.Fatal(err)
		}
		if st.Instances["b1"] != strings.Repeat("c", 64) || st.Instances["b2"] != strings.Repeat("d", 64) || st.Engines != 1 {
			t.Fatalf("state %+v", st)
		}
	})
	t.Run("upstream sets", func(t *testing.T) {
		st, err := readSynth(t, rtEntry{event: recUpstreamSet,
			payload: "count=3\nlocal http://0gm-sglang:8000/v1\nzg-a_b https://api.example.com/v1/chat openai\nbare https://x.example"})
		if err != nil {
			t.Fatal(err)
		}
		want := []Upstream{{"local", "http://0gm-sglang:8000/v1", ""}, {"zg-a_b", "https://api.example.com/v1/chat", "openai"},
			{"bare", "https://x.example", ""}}
		if !reflect.DeepEqual(st.Upstreams.Members, want) || st.Upstreams.Members[0].Host() != "0gm-sglang" {
			t.Fatalf("upstreams %+v", st.Upstreams)
		}
		if st, err := readSynth(t, rtEntry{event: recUpstreamSet, payload: "invalidated"}); err != nil || !st.Upstreams.Invalidated {
			t.Fatalf("invalidated: %+v, %v", st.Upstreams, err)
		}
	})
}

// Each record the grammar refuses fails the read, naming the record.
func TestRuntime_GrammarRefusals(t *testing.T) {
	hex64, hex40 := strings.Repeat("a", 64), strings.Repeat("a", 40)
	img := func(p string) rtEntry { return rtEntry{event: recImageUpdate, payload: p} }
	ups := func(p string) rtEntry { return rtEntry{event: recUpstreamSet, payload: p} }
	for name, e := range map[string]rtEntry{
		"image: two fields":             img(brokerRepoName + "@" + synthDigest + " " + synthSigner),
		"image: a double space":         img(brokerRepoName + "@" + synthDigest + "  " + synthSigner + " " + synthEncPub),
		"image: a trailing newline":     img(brokerRepoName + "@" + synthDigest + " " + synthSigner + " " + synthEncPub + "\n"),
		"image: a tag":                  img(brokerRepoName + ":v0.5.4 " + synthSigner + " " + synthEncPub),
		"image: an uppercase digest":    img(brokerRepoName + "@sha256:" + strings.ToUpper(hex64) + " " + synthSigner + " " + synthEncPub),
		"image: a short signer":         img(brokerRepoName + "@" + synthDigest + " 0x" + hex40[:38] + " " + synthEncPub),
		"image: a signer without 0x":    img(brokerRepoName + "@" + synthDigest + " " + hex40 + " " + synthEncPub),
		"image: an uppercase enc_pub":   img(brokerRepoName + "@" + synthDigest + " " + synthSigner + " " + strings.ToUpper(hex64)),
		"image: no repository":          img("@" + synthDigest + " " + synthSigner + " " + synthEncPub),
		"config: uppercase":             {event: recConfigUpdate, payload: strings.ToUpper(hex64)},
		"config: short":                 {event: recConfigUpdate, payload: hex64[:63]},
		"instance: no value":            {event: recInstanceConfigUpdate, payload: "b1"},
		"instance: a bad hash":          {event: recInstanceConfigUpdate, payload: "b1 " + hex64[:10]},
		"upstreams: no count":           ups("local http://a:1/v1"),
		"upstreams: count too high":     ups("count=2\nlocal http://a:1/v1"),
		"upstreams: count too low":      ups("count=1\nlocal http://a:1/v1\nother http://b:1/v1"),
		"upstreams: a leading zero":     ups("count=01\nlocal http://a:1/v1"),
		"upstreams: a trailing line":    ups("count=1\nlocal http://a:1/v1\n"),
		"upstreams: an uppercase name":  ups("count=1\nLocal http://a:1/v1"),
		"upstreams: a name ending in -": ups("count=1\nlocal- http://a:1/v1"),
		"upstreams: a duplicate name":   ups("count=2\nlocal http://a:1/v1\nlocal http://b:1/v1"),
		"upstreams: an empty identity":  ups("count=1\nlocal http://a:1/v1 "),
		"url: another scheme":           ups("count=1\nlocal ftp://a/v1"),
		"url: an uppercase scheme":      ups("count=1\nlocal HTTP://a/v1"),
		"url: an uppercase host":        ups("count=1\nlocal http://A.example/v1"),
		"url: userinfo":                 ups("count=1\nlocal https://u:p@a.example/v1"),
		"url: a query":                  ups("count=1\nlocal https://a.example/v1?x=1"),
		"url: a fragment":               ups("count=1\nlocal https://a.example/v1#x"),
		"url: the default port":         ups("count=1\nlocal https://a.example:443/v1"),
		"url: a trailing slash":         ups("count=1\nlocal https://a.example/v1/"),
		"url: a bare slash":             ups("count=1\nlocal https://a.example/"),
		"url: a dot segment":            ups("count=1\nlocal https://a.example/v1/../v2"),
		"url: percent-encoding":         ups("count=1\nlocal https://a.example/v%31"),
		"url: a non-ASCII host":         ups("count=1\nlocal https://ä.example/v1"),
		"url: a bad port":               ups("count=1\nlocal https://a.example:0/v1"),
	} {
		t.Run(name, func(t *testing.T) {
			_, err := readSynth(t, e)
			if err == nil || !strings.Contains(err.Error(), "runtime record 1 ("+e.event+")") {
				t.Fatalf("got %v, want a refusal of record 1", err)
			}
		})
	}
}

func TestRuntime_NoEventLog(t *testing.T) {
	for name, reply := range map[string]string{
		"absent":         `{"quote":"00"}`,
		"null":           `{"quote":"00","event_log":null}`,
		"empty string":   `{"quote":"00","event_log":""}`,
		"tcb_info empty": `{"quote":"00","tcb_info":"{\"app_compose\":\"{}\"}"}`,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := ReadRuntimeState([]byte(reply), [RTMRLen]byte{}); !errors.Is(err, ErrNoEventLog) {
				t.Fatalf("got %v, want ErrNoEventLog", err)
			}
		})
	}
	if _, err := ReadRuntimeState([]byte(`{"event_log":"[{\"imr\":3,\"event_payload\":\"zz\"}]"}`),
		[RTMRLen]byte{}); err == nil || errors.Is(err, ErrNoEventLog) || !strings.Contains(err.Error(), "not hex") {
		t.Fatalf("a payload that is not hex: %v", err)
	}
}

// What CheckRuntime makes of each state.
func TestCheckRuntime(t *testing.T) {
	rels := fakeReleases{repo: brokerRepoName, accepted: map[string]string{synthDigest: "v9.9.9"}}
	encPub, _ := hex.DecodeString(synthEncPub)
	state := func(t *testing.T, entries ...rtEntry) RuntimeState {
		t.Helper()
		st, err := readSynth(t, entries...)
		if err != nil {
			t.Fatal(err)
		}
		return st
	}
	for _, tc := range []struct {
		name       string
		st         RuntimeState
		rels       ReleaseVerifier
		signer     string
		encPub     []byte
		fails      []string
		unverified []string
	}{
		{name: "a release, keys bound", st: state(t, imageUpdate(synthDigest)), rels: rels},
		{name: "the signer compares without case", st: state(t, imageUpdate(synthDigest)), rels: rels,
			signer: strings.ToUpper(synthSigner)},
		{name: "not a release", st: state(t, imageUpdate(v054Digest)), rels: rels,
			fails: []string{"is not an accepted release: it carries no provenance"}},
		{name: "another repository", rels: rels, st: state(t, rtEntry{event: recImageUpdate,
			payload: "ghcr.io/someone/else@" + synthDigest + " " + synthSigner + " " + synthEncPub}),
			fails: []string{"ghcr.io/someone/else@" + synthDigest}},
		{name: "the release check could not run", st: state(t, imageUpdate(synthDigest)),
			rels: fakeReleases{repo: brokerRepoName, unavailable: true}, unverified: []string{"could not be checked"}},
		{name: "no verifier", st: state(t, imageUpdate(synthDigest)), unverified: []string{"no release verifier"}},
		{name: "another signer", st: state(t, imageUpdate(synthDigest)), rels: rels, signer: "0x" + strings.Repeat("9", 40),
			fails: []string{"is not the signer 0x9999"}},
		{name: "another enc_pub", st: state(t, imageUpdate(synthDigest)), rels: rels, encPub: make([]byte, 32),
			fails: []string{"is not the enc_pub 0000"}},
		{name: "no image record", st: state(t, rtEntry{event: recConfigUpdate, payload: strings.Repeat("a", 64)}), rels: rels},
		{name: "an engine record", st: state(t, rtEntry{event: recEngineSet, payload: "count=0"}), rels: rels,
			fails: []string{"ZG_CONTROLLER_ENGINES=on"}},
		{name: "an unknown record", st: state(t, rtEntry{event: "zg-new"}, rtEntry{event: "zg-new"}), rels: rels,
			unverified: []string{"(zg-new): the controller is newer"}},
		{name: "an invalidated upstream set", st: state(t, rtEntry{event: recUpstreamSet, payload: "invalidated"}), rels: rels,
			unverified: []string{"zg-upstream-set invalidated"}},
		{name: "an aborted instance change", st: state(t,
			rtEntry{event: recInstanceConfigUpdate, payload: "b1 unknown"}), rels: rels,
			unverified: []string{`instance "b1" aborted`}},
		{name: "a later instance record settles it", st: state(t,
			rtEntry{event: recInstanceConfigUpdate, payload: "b1 unknown"},
			rtEntry{event: recInstanceConfigUpdate, payload: "b1 " + strings.Repeat("e", 64)}), rels: rels},
	} {
		t.Run(tc.name, func(t *testing.T) {
			signer, key := synthSigner, encPub
			if tc.signer != "" {
				signer = tc.signer
			}
			if tc.encPub != nil {
				key = tc.encPub
			}
			c := CheckRuntime(tc.st, tc.rels, signer, key)
			if !matchAll(c.Failures, tc.fails) || !matchAll(c.Unverified, tc.unverified) {
				t.Fatalf("failures %q, unverified %q; want %q and %q", c.Failures, c.Unverified, tc.fails, tc.unverified)
			}
			if (tc.st.Image == nil) != (c.Release == nil) {
				t.Fatalf("release verdict %+v for image %+v", c.Release, tc.st.Image)
			}
		})
	}
}

// matchAll reports whether got has one entry per fragment in want, each containing it.
func matchAll(got, want []string) bool {
	if len(got) != len(want) {
		return false
	}
	for i := range want {
		if !strings.Contains(got[i], want[i]) {
			return false
		}
	}
	return true
}
