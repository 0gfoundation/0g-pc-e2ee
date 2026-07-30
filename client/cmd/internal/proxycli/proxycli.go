// Package proxycli holds the startup wiring shared by the two client-core
// binaries — the local sidecar (cmd/sidecar) and the cloud-TEE gateway
// (cmd/gateway). Both are the SAME client core wrapped as an OpenAI-compatible
// proxy; they differ only in how they listen (local vs enclave), whether they
// surface upstream error detail, and which operational routes they mount. The
// route-and-seal plumbing between those differences is identical, so it lives
// here once instead of being copied into each main.
//
// Each binary registers the shared flags with its own env prefix and default
// listen address, parses, then calls Build to get a wired *core.Client. Every
// parameter can be set two ways: an explicit command-line flag or a
// <PREFIX>_* environment variable used only as the flag's default, so
// precedence is: explicit flag > environment variable > built-in default. Env
// config is the primary path for the TEE/dstack deployment, where the compose
// file's `environment:` block is measured into the CVM attestation; flags stay
// convenient for local runs and one-off overrides.
package proxycli

import (
	"flag"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"

	"github.com/0gfoundation/0g-pc-e2ee/client/core"
	"github.com/0gfoundation/0g-pc-e2ee/client/dcap"
	"github.com/0gfoundation/0g-pc-e2ee/client/route"
	"github.com/0gfoundation/0g-pc-e2ee/protocol/attest"
	"github.com/0gfoundation/0g-pc-e2ee/protocol/wire"
)

// Flags holds the startup parameters common to both proxy binaries, populated
// by flag.Parse after RegisterFlags. Callers read Listen to bind their server
// and pass the rest to Build.
type Flags struct {
	Listen           *string
	RouterURL        *string
	sealFieldsCSV    *string
	unboundFieldsCSV *string
	attestOn         *bool
	attestEnforce    *bool
}

// RegisterFlags declares the six shared startup flags on fs and returns a Flags
// whose pointers are filled by fs.Parse. envPrefix (e.g. "ZG_GATEWAY",
// "ZG_SIDECAR") selects the environment variables consulted for each flag's
// default: <envPrefix>_LISTEN, _ROUTER_URL, _SEAL_FIELDS, _UNBOUND_FIELDS,
// _ATTEST, _ATTEST_ENFORCE. defaultListen is the built-in listen address used
// when neither the flag nor <envPrefix>_LISTEN is set.
func RegisterFlags(fs *flag.FlagSet, envPrefix, defaultListen string) *Flags {
	env := func(name string) string { return envPrefix + "_" + name }
	return &Flags{
		Listen:    fs.String("listen", envOr(env("LISTEN"), defaultListen), fmt.Sprintf("address to listen on (env %s)", env("LISTEN"))),
		RouterURL: fs.String("router-url", envOr(env("ROUTER_URL"), route.DefaultRouterURL), fmt.Sprintf("0G router base URL/domain (the route-preview path is appended) (env %s)", env("ROUTER_URL"))),
		sealFieldsCSV: fs.String("seal-fields", envOr(env("SEAL_FIELDS"), strings.Join(wire.DefaultSealedFields(), ",")),
			fmt.Sprintf("comma-separated request fields to seal (must include \"messages\") (env %s)", env("SEAL_FIELDS"))),
		unboundFieldsCSV: fs.String("unbound-fields", envOr(env("UNBOUND_FIELDS"), strings.Join(wire.DefaultUnboundFields(), ",")),
			fmt.Sprintf("comma-separated cleartext fields excluded from the AAD (intermediary-mutable, untrusted); empty binds everything (env %s)", env("UNBOUND_FIELDS"))),
		attestOn: fs.Bool("attest", envBool(env("ATTEST"), false),
			fmt.Sprintf("DCAP-verify each provider's TDX quote and seal only to the verified enc key (instead of trusting the router-supplied pubkey endpoint) (env %s)", env("ATTEST"))),
		attestEnforce: fs.Bool("attest-enforce", envBool(env("ATTEST_ENFORCE"), false),
			fmt.Sprintf("with -attest, reject a provider whose measurement is not in the allowlist instead of only warning; the audited-image allowlist is not wired yet (empty), so enforce currently rejects all providers (env %s)", env("ATTEST_ENFORCE"))),
	}
}

// Build validates the parsed flags and constructs the wired client core: a
// per-request route resolver (optionally DCAP-verifying each provider's TDX
// quote) feeding a core.Client that seals the configured fields. label is used
// only for the verifier's log line ("<label>: TDX quote verification ...") so
// the two binaries identify themselves. A redaction-safe debug logger is always
// attached (field names and byte lengths only, never plaintext or key
// material); it writes to the process log and never reaches the end user.
//
// It exits the process via log.Fatal on an invalid flag combination — the same
// fail-loud behavior both mains had inline — so a misconfigured proxy never
// starts with, say, an unsealed "messages" field or attestation silently off.
func (f *Flags) Build(label string) *core.Client {
	sealFields := parseCSV(*f.sealFieldsCSV)
	if err := wire.ValidateSealedFields(sealFields); err != nil {
		log.Fatalf("invalid -seal-fields: %v", err)
	}
	unboundFields := parseCSV(*f.unboundFieldsCSV)
	if err := wire.ValidateUnboundFields(unboundFields, sealFields); err != nil {
		log.Fatalf("invalid -unbound-fields: %v", err)
	}
	// Fail loudly rather than silently give NO attestation when the operator asked
	// for the strictest mode: -attest-enforce is meaningless without -attest.
	if *f.attestEnforce && !*f.attestOn {
		log.Fatalf("-attest-enforce requires -attest")
	}

	// Route per request: pick the provider via the router and derive its enc key +
	// signer from the broker, so no provider key is pinned up front. The router is
	// told to withhold exactly the sealed fields, so the prompt never reaches it in
	// cleartext even on the control-plane preview call. The service type is fixed
	// (route.New defaults to "chatbot"); it is not a startup choice.
	routeOpts := []route.Option{route.WithSensitiveFields(sealFields)}
	if *f.attestOn {
		routeOpts = append(routeOpts, route.WithQuoteVerification(newVerifier(label, *f.attestEnforce), nil))
	}
	router := route.New(*f.RouterURL, routeOpts...)
	return core.NewWithResolver(router,
		core.WithSealFields(sealFields),
		core.WithUnboundFields(unboundFields),
		core.WithDebugLogger(log.Default()),
	)
}

// newVerifier builds the per-request TDX quote verifier. Quote authenticity
// (genuine TDX + TCB UpToDate + report_data binding) is always enforced; only
// the measurement-allowlist decision is governed by enforce vs warn. The audited
// broker-image allowlist is not wired yet (empty), so warn is the usable interim
// (log an out-of-allowlist measurement but proceed) and enforce rejects all.
func newVerifier(label string, enforce bool) *attest.Verifier {
	mode := attest.ModeWarn
	if enforce {
		mode = attest.ModeEnforce
	}
	log.Printf("%s: TDX quote verification enabled (measurement enforce=%v, allowlist empty)", label, enforce)
	return attest.New(
		attest.Policy{}, // TODO: load the audited broker-image measurement allowlist
		attest.WithQuoteParser(dcap.NewQuoteParser(dcap.Config{})),
		attest.WithMeasurementMode(mode),
	)
}

// envOr returns the value of environment variable key, or def if it is unset.
// An explicitly-set-but-empty variable (e.g. ZG_GATEWAY_UNBOUND_FIELDS=) is
// honored as empty, which for CSV fields is a meaningful value (bind everything),
// so we branch on presence via LookupEnv rather than treating "" as unset.
func envOr(key, def string) string {
	if v, ok := os.LookupEnv(key); ok {
		return v
	}
	return def
}

// envBool parses a boolean environment variable (accepting the same forms as
// the -flag=bool syntax: 1/t/T/TRUE/true, 0/f/F/FALSE/false, etc.). An unset
// variable falls back to def; a set-but-unparseable value is fatal rather than
// silently defaulting, so a typo like ZG_GATEWAY_ATTEST=yes cannot quietly leave
// attestation off.
func envBool(key string, def bool) bool {
	v, ok := os.LookupEnv(key)
	if !ok {
		return def
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		log.Fatalf("invalid %s=%q: must be a boolean (true/false)", key, v)
	}
	return b
}

// parseCSV splits a comma-separated flag value into trimmed, non-empty parts.
func parseCSV(s string) []string {
	var out []string
	for _, part := range strings.Split(s, ",") {
		if p := strings.TrimSpace(part); p != "" {
			out = append(out, p)
		}
	}
	return out
}
