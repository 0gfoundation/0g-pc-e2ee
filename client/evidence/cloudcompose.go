package evidence

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/0gfoundation/0g-pc-e2ee/protocol/attest"
)

// DefaultCloudAPIBase is Phala Cloud's public API root — the value both of Phala's
// own SDKs default to (phala-cloud `go/version.go` DefaultBaseURL and
// `js/src/client.ts`), and the host Phala's own Trust Center verifier reads
// attestations from.
const DefaultCloudAPIBase = "https://cloud-api.phala.com/api/v1"

// maxCloudAttestationsBytes bounds the attestations read. The reply carries one
// app-compose, one event log and one quote PER INSTANCE, so it is a small multiple
// of a guest-agent Info reply rather than a different order of magnitude; this is
// sized for a blue/green pair several times over.
const maxCloudAttestationsBytes = 16 << 20

// cloudAttestations is the part of `GET /apps/<app_id>/attestations` this package
// reads. As with infoResponse, the fields not decoded are not oversights: the
// authenticated artifact is the raw app_compose bytes, and everything else in the
// reply — the platform's own compose_hash, its measurement registers, its event log
// — is either already covered by the quote or worthless as a self-report.
type cloudAttestations struct {
	// AppID is echoed by the platform. Read only to report a mismatch with what was
	// asked for, never to redirect the lookup.
	AppID     string          `json:"app_id"`
	Instances []cloudInstance `json:"instances"`
}

// cloudInstance is one CVM backing the app. Several is the normal state here: a
// blue/green pair runs two, and a scaled side runs more (deploy/phala/blue-green.md).
type cloudInstance struct {
	// Name and Status are the platform's labels for this CVM, reported so a reader can
	// tell which replica answered (or which one was skipped) without cross-referencing
	// the dashboard. Neither is trusted for anything.
	Name   string `json:"name"`
	Status string `json:"status"`
	// TCBInfo is raw JSON rather than a struct for the same reason
	// infoResponse.TCBInfo is: deployments differ on whether it arrives as a nested
	// object or as a JSON string holding the same document, and committing to either
	// shape loses the other at the OUTER unmarshal — taking every instance down with
	// it. attest.UnwrapJSONString normalizes both. A stopped instance sends null,
	// which decodes to nil here and is skipped.
	TCBInfo json.RawMessage `json:"tcb_info"`
	// ComposeFile is the same document again, alongside tcb_info rather than inside
	// it. Read as a fallback because the two are populated by different halves of the
	// platform — tcb_info is what the CVM reported, compose_file what the platform
	// holds for the app — so one can be present when the other is not. Neither is
	// preferred on trust grounds: both are gated on the digest, and bytes that pass
	// that gate are the manifest whatever field carried them.
	ComposeFile string `json:"compose_file"`
}

// FetchAppComposeFromCloud reads the raw app-compose bytes from Phala Cloud's public
// attestations API — `GET <apiBase>/apps/<appID>/attestations` — returning the bytes
// of the instance whose app-compose IS the one composeHash commits to, plus a label
// naming which instance that was.
//
// This is the same document the guest agent serves (FetchAppCompose), reached over a
// path that does not depend on the platform routing port 8090 into the CVM, and it
// needs no API key. Phala's own Trust Center verifier reads its quotes from this
// endpoint, which is what makes it the more durable of the two sources rather than a
// workaround: the guest-agent hostname is a routing detail of one cluster, while
// this is the platform's published record of the app.
//
// Everything the FetchAppCompose comment says about trust applies here unchanged and
// for the same reason: TLS terminates at Phala, nothing in the reply is signed, and
// none of that matters because the bytes must hash to the quote's compose_hash
// before anything is read out of them. The reply's own compose_hash field is not
// consulted at all — a self-reported hash proves nothing.
//
// **Selection is by digest, not by position.** With several instances the platform
// lists them in no order this cares about, and during a blue/green rollover their
// manifests genuinely differ — so picking instances[0] would report a digest
// mismatch for a deployment that is perfectly consistent, blaming the operator for
// asking the wrong replica. Matching on the hash instead answers the only question
// worth asking: does the app the platform describes include the CVM this quote came
// from. The bytes returned still go through VerifyAppCompose in the caller; the gate
// is not moved here, it is applied twice.
func FetchAppComposeFromCloud(
	ctx context.Context,
	hc *http.Client,
	apiBase, appID string,
	composeHash [attest.ComposeHashLen]byte,
) ([]byte, string, error) {
	id := normalizeAppID(appID)
	if id == "" {
		return nil, "", errors.New("no app_id to fetch app-compose for")
	}
	if !validAppID(id) {
		// A compose_hash (64 hex) handed in where an app_id belongs is the mistake this
		// catches, and it would otherwise come back as a bare 404.
		return nil, "", fmt.Errorf("app_id %q is not %d hex digits", appID, appIDHexLen)
	}
	base := strings.TrimRight(strings.TrimSpace(apiBase), "/")
	if base == "" {
		base = DefaultCloudAPIBase
	}
	u := fmt.Sprintf("%s/apps/%s/attestations", base, id)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, "", err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := hc.Do(req)
	if err != nil {
		return nil, "", fmt.Errorf("fetch app-compose from %s: %w", base, err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxCloudAttestationsBytes+1))
	if err != nil {
		return nil, "", fmt.Errorf("read attestations from %s: %w", base, err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, "", fmt.Errorf("GET %s -> %s", u, resp.Status)
	}
	if len(body) > maxCloudAttestationsBytes {
		return nil, "", fmt.Errorf("attestations for %s are larger than %d bytes", id, maxCloudAttestationsBytes)
	}

	var doc cloudAttestations
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, "", fmt.Errorf("decode attestations from %s: %w", base, err)
	}
	if len(doc.Instances) == 0 {
		return nil, "", fmt.Errorf("%s reports no instances for app %s (stopped, or a different cluster's app)", base, id)
	}
	return pickCloudAppCompose(doc, composeHash, base, id)
}

// pickCloudAppCompose is the digest selection over an already-decoded reply, split
// out so the "which instance, and what to say when none of them" logic is testable
// without an HTTP server.
func pickCloudAppCompose(
	doc cloudAttestations,
	composeHash [attest.ComposeHashLen]byte,
	base, appID string,
) ([]byte, string, error) {
	total := len(doc.Instances)
	// What each instance offered, for the error when none of them is the right one.
	// Reported as digests rather than as compose text: the digest is the value being
	// compared, and it is what an operator can look up against a release.
	seen := make([]string, 0, total)
	for i, inst := range doc.Instances {
		label := fmt.Sprintf("instance %d of %d", i+1, total)
		if inst.Name != "" {
			label += " (" + inst.Name + ")"
		}
		candidates, err := cloudInstanceAppCompose(inst)
		if err != nil {
			seen = append(seen, fmt.Sprintf("%s: %v", label, err))
			continue
		}
		for _, c := range candidates {
			if sha256.Sum256(c.raw) == composeHash {
				return c.raw, label, nil
			}
			seen = append(seen, fmt.Sprintf("%s %s: %x", label, c.field, sha256.Sum256(c.raw)))
		}
	}
	// Not a digest MISMATCH in the VerifyAppCompose sense — no instance here claimed
	// to be this CVM. The likely causes are all locatable: the app_id names another
	// app, the record is stale, or this quote came from a replica the platform has
	// already retired. Naming what was offered is what lets a reader tell those apart.
	return nil, "", fmt.Errorf(
		"no instance of app %s at %s carries the app-compose this quote binds (compose_hash %x); offered %s",
		appID, base, composeHash, strings.Join(seen, ", "))
}

// composeCandidate is one field's bytes, named so a report and an error can say
// which field they came from. The bytes are as delivered — they are the digest
// preimage, so re-marshalling or re-indenting them anywhere in this path would break
// the very check they exist for.
type composeCandidate struct {
	field string
	raw   []byte
}

// cloudInstanceAppCompose returns every manifest this instance offers: what the CVM
// reported in tcb_info, and what the platform holds in compose_file.
//
// Both are returned rather than one being preferred, because the caller decides by
// DIGEST and the digest is a better judge than any priority rule here could be. The
// two fields are written by different halves of the platform and can legitimately
// disagree — mid-upgrade, the platform's record can be the compose the CVM has not
// booted yet — so a rule that always reads one field would miss a manifest that is
// sitting in the other and hashes correctly. Nothing is trusted either way: bytes
// that fail the digest are discarded whichever field carried them.
func cloudInstanceAppCompose(inst cloudInstance) ([]composeCandidate, error) {
	var out []composeCandidate
	raw, tcbErr := tcbInfoAppCompose(inst.TCBInfo)
	if tcbErr == nil {
		out = append(out, composeCandidate{field: "tcb_info.app_compose", raw: raw})
	}
	// Usually the two fields hold the same document; listing it twice would only pad
	// the "none of these matched" error with a repeated digest.
	if inst.ComposeFile != "" && (tcbErr != nil || !bytes.Equal(raw, []byte(inst.ComposeFile))) {
		out = append(out, composeCandidate{field: "compose_file", raw: []byte(inst.ComposeFile)})
	}
	if len(out) == 0 {
		// Report the tcb_info error rather than "this instance had nothing": it is the
		// specific one, and it distinguishes a stopped instance from an app that hides
		// its tcb_info.
		return nil, tcbErr
	}
	return out, nil
}

// tcbInfoAppCompose reads app_compose out of an instance's tcb_info, in whichever
// of the two shapes it arrived (see cloudInstance.TCBInfo).
func tcbInfoAppCompose(raw json.RawMessage) ([]byte, error) {
	if len(bytes.TrimSpace(raw)) == 0 {
		return nil, errors.New("no tcb_info (instance stopped, or the app hides it)")
	}
	doc, err := attest.UnwrapJSONString(raw)
	if err != nil {
		return nil, fmt.Errorf("decode tcb_info: %w", err)
	}
	trimmed := bytes.TrimSpace(doc)
	if len(trimmed) == 0 || bytes.Equal(trimmed, []byte("null")) {
		return nil, errors.New("empty tcb_info")
	}
	var tcb tcbInfo
	if err := json.Unmarshal(doc, &tcb); err != nil {
		return nil, fmt.Errorf("decode tcb_info: %w", err)
	}
	if tcb.AppCompose == "" {
		return nil, errors.New("tcb_info carries no app_compose")
	}
	return []byte(tcb.AppCompose), nil
}

// cloudAppComposeSource labels a successful cloud fetch for a report: the endpoint
// that answered plus which instance matched.
func cloudAppComposeSource(base, appID, instance string) string {
	if base == "" {
		base = DefaultCloudAPIBase
	}
	// No parentheses of its own: the instance label already carries the replica's name
	// in brackets, and wrapping it produced "(instance 1 of 1 (pc-gateway-staging-b))".
	return fmt.Sprintf("%s/apps/%s/attestations — %s", strings.TrimRight(base, "/"), appID, instance)
}
