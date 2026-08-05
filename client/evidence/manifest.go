package evidence

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
)

// manifestName is the bundle's checksum manifest, produced by `sha256sum` inside
// the CVM over every other published evidence file (dstack-ingress
// `evidence-lib.sh`, evidence_finalize). It is the file the quote's report_data
// binds, so it is the hinge of the whole bundle: hashing it reproduces the
// binding, and its entries pin the certificate chain.
const manifestName = "sha256sum.txt"

// quoteName is the cert-binding TDX quote, in the dstack GetQuote reply shape.
// It is deliberately NOT in the manifest — it is generated *from* the manifest's
// digest, so it cannot contain its own hash.
const quoteName = "quote.json"

// accountName is the ACME account document. It carries no private key (only the
// account URL and status) and is published on purpose; it is in the manifest, so
// omitting it from the fetch would leave a manifest entry unchecked.
const accountName = "acme-account.json"

// ManifestEntry is one `sha256sum` line: the expected digest of a named file.
type ManifestEntry struct {
	Name   string
	Digest [sha256.Size]byte
}

// parseManifest decodes `sha256sum.txt` into its entries.
//
// It accepts the two coreutils output modes — `<hex>  <name>` (text) and
// `<hex> *<name>` (binary) — and rejects everything else rather than guessing,
// because a misparsed name would silently drop a file from the checked set. In
// particular it rejects:
//
//   - a leading `\` on the line, which is how GNU sha256sum flags a filename
//     containing a newline or backslash (the name is then escaped, so taking it
//     literally would fetch the wrong path);
//   - any name that is not a plain basename. The names become URL path segments
//     under /evidences/, so `../` or an absolute path would let a hostile bundle
//     redirect a fetch elsewhere in the origin — and a bundle is untrusted input
//     until the report_data binding has been checked, which cannot happen until
//     after these fetches.
//
// Duplicate names are rejected too: two entries for one file make "the manifest
// matches" ambiguous.
func parseManifest(b []byte) ([]ManifestEntry, error) {
	var entries []ManifestEntry
	seen := make(map[string]struct{})
	for i, line := range strings.Split(string(b), "\n") {
		lineNo := i + 1
		// Tolerate CRLF and a trailing blank line; anything else blank mid-file is
		// still fine to skip, it carries no entry.
		line = strings.TrimRight(line, "\r")
		if strings.TrimSpace(line) == "" {
			continue
		}
		if strings.HasPrefix(line, "\\") {
			return nil, fmt.Errorf("%s line %d: escaped filename (contains a newline or backslash); refusing to guess", manifestName, lineNo)
		}
		// Exactly two fields: the digest and the name. SplitN keeps any spaces
		// inside the filename intact.
		hexDigest, rest, ok := strings.Cut(line, " ")
		if !ok {
			return nil, fmt.Errorf("%s line %d: not a sha256sum line: %q", manifestName, lineNo, line)
		}
		// coreutils writes two spaces in text mode and " *" in binary mode; either
		// way exactly one separator character remains after the Cut above.
		name, ok := strings.CutPrefix(rest, " ")
		if !ok {
			if name, ok = strings.CutPrefix(rest, "*"); !ok {
				return nil, fmt.Errorf("%s line %d: expected %q or %q between digest and name: %q",
					manifestName, lineNo, "  ", " *", line)
			}
		}

		raw, err := hex.DecodeString(hexDigest)
		if err != nil || len(raw) != sha256.Size {
			return nil, fmt.Errorf("%s line %d: %q is not a SHA-256 digest", manifestName, lineNo, hexDigest)
		}
		if err := checkBasename(name); err != nil {
			return nil, fmt.Errorf("%s line %d: %w", manifestName, lineNo, err)
		}
		if _, dup := seen[name]; dup {
			return nil, fmt.Errorf("%s: duplicate entry for %q", manifestName, name)
		}
		seen[name] = struct{}{}

		e := ManifestEntry{Name: name}
		copy(e.Digest[:], raw)
		entries = append(entries, e)
	}
	if len(entries) == 0 {
		return nil, fmt.Errorf("%s: no entries", manifestName)
	}
	return entries, nil
}

// checkBasename rejects any name that is not a single plain path component, so a
// manifest entry can only ever name a file inside /evidences/. See parseManifest
// for why this matters before the binding is verified.
func checkBasename(name string) error {
	switch {
	case name == "":
		return fmt.Errorf("empty filename")
	case strings.ContainsAny(name, "/\\"):
		return fmt.Errorf("filename %q is not a plain basename (contains a path separator)", name)
	case name == "." || name == "..":
		return fmt.Errorf("filename %q is not a plain basename", name)
	case strings.HasPrefix(name, "-"):
		// Not a security issue for us (we build URLs, not argv), but it is never a
		// name dstack-ingress produces, so treat it as a malformed bundle.
		return fmt.Errorf("filename %q starts with %q", name, "-")
	}
	return nil
}

// certName is the manifest entry holding the served certificate chain for domain
// — `cert-<domain>.pem` (dstack-ingress evidence_collect_cert). A bundle from a
// multi-domain ingress carries one such file per domain, so the check must look
// for this exact name rather than "the only cert in the bundle".
func certName(domain string) string { return "cert-" + domain + ".pem" }
