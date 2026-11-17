package clientip

import "strings"

// HeaderClient names the program the caller used (claude-code, codex, opencode,
// ...), for the router's usage attribution. The gateway sets it only next to a
// signed address (Stamp), after dropping any copy the caller sent, so the router
// believes it exactly when the address signature verifies. The raw User-Agent is
// never forwarded: its version, OS and runtime together fingerprint a user, and
// the router is not trusted with that.
const HeaderClient = "X-0G-Client"

// Client families. ClientUnknown is a request with no User-Agent; ClientOther is
// one no rule recognises. The router records "web" for a wallet session itself,
// whatever this header says.
const (
	ClientUnknown = "unknown"
	ClientOther   = "other"
)

// The rule tables below are a copy of the router's (0g-router
// backend/internal/service/client_attribution.go). testdata/client_vectors.json
// is shared byte for byte with the router's tests, so the two copies cannot drift
// without one side's tests failing: change both tables and the vector file
// together. Adding a family is safe; renaming one splits its history in two.

// clientTitleRules recognise coding tools built on a generic SDK by the
// OpenRouter-style app-attribution headers they send: X-Title (a prefix of the
// lowercased value, so "Decline Tracker" is not Cline) and HTTP-Referer (the
// tool's own domain). Checked before the User-Agent: Cline and Kilo send an
// OpenAI-SDK UA.
var clientTitleRules = []struct {
	titlePrefixes []string
	refererDomain string
	client        string
}{
	{[]string{"cline"}, "cline.bot", "cline"},
	{[]string{"kilo code", "kilocode"}, "kilocode.ai", "kilo"},
	{[]string{"roo code", "roocode", "roo-code"}, "roocode.com", "roo"},
	{[]string{"opencode"}, "opencode.ai", "opencode"},
	{[]string{"z code", "zcode"}, "zcode.z.ai", "zcode"},
	{[]string{"openclaw"}, "openclaw.ai", "openclaw"},
	{[]string{"cherry studio"}, "cherry-ai.com", "cherry-studio"},
	{[]string{"hermes agent"}, "hermes-agent.nousresearch.com", "hermes"},
	{[]string{"crush"}, "charm.land", "crush"},
	{[]string{"litellm"}, "litellm.ai", "litellm"},
	{[]string{"anythingllm"}, "anythingllm.com", "anythingllm"},
	{[]string{"lobehub", "lobechat"}, "lobehub.com", "lobehub"},
	// Tools that send only their SDK's default User-Agent to a custom endpoint:
	// recognised only once an integration we ship sends this X-Title (C-2).
	{[]string{"langflow"}, "langflow.org", "langflow"},
	{[]string{"n8n"}, "n8n.io", "n8n"},
	{[]string{"continue"}, "continue.dev", "continue"},
	{[]string{"dify"}, "dify.ai", "dify"},
	{[]string{"librechat"}, "librechat.ai", "librechat"},
	{[]string{"open webui", "openwebui", "open-webui"}, "openwebui.com", "open-webui"},
	{[]string{"goose"}, "goose-docs.ai", "goose"},
	{[]string{"tabby"}, "tabbyml.com", "tabby"},
}

// clientUARules match the lowercased User-Agent, first hit wins, so a specific
// rule comes before a generic one that also matches it.
var clientUARules = []struct {
	prefix bool // true: HasPrefix; false: Contains
	needle string
	client string
}{
	// claude-cli/ is decided in classifyUA (it splits on agent-sdk/).
	{true, "codex", "codex"}, // codex_cli_rs/, codex_exec/, "Codex Desktop/"
	{true, "opencode/", "opencode"},
	{true, "zcode/", "zcode"},
	{true, "pi (", "pi"}, // pi <= 1.4: "pi (win32 10.0.26200; x64)"
	{true, "pi/", "pi"},  // pi 1.5: "pi/1.5.0 (win32; bun/1.4.4; x64)"
	{true, "deepseek-harness/", "deepseek-harness"},
	{true, "kilo-code/", "kilo"},              // "Kilo-Code/7.8.27 ai-sdk/provider-utils/4.0.33 runtime/bun/1.4.4": before ai-sdk/
	{true, "roocode/", "roo"},                 // "RooCode/3.54.0"
	{true, "charm-crush/", "crush"},           // "Charm-Crush/<v> (https://charm.land/crush)"
	{true, "hermes-cli/", "hermes"},           // model list / connectivity calls; chat sends the OpenAI SDK UA
	{false, "litellm/", "litellm"},            // "litellm/1.106.2", "<partner>_litellm/<v>"
	{true, "magpie", "magpie"},                // "magpie/0.1.3161", or bare "magpie"
	{true, "lobehub/", "lobehub"},             // "lobehub/2.2.17"
	{true, "anythingllm/", "anythingllm"},     // "AnythingLLM/<v>"
	{true, "trustedrouter/", "trustedrouter"}, // a reseller gateway: "TrustedRouter/1.0"
	{false, "cherrystudio/", "cherry-studio"}, // Electron UA "... CherryStudio/1.9.12 ...": before mozilla/
	{true, "0g-pc-qa/", "0g-internal"},
	{true, "zgh/", "0g-internal"},
	{true, "claude0g-probe", "0g-internal"},
	{true, "langchain", "langchain"},
	{false, "ai-sdk/", "ai-sdk"},
	{false, "ai-sdk-provider-utils/", "ai-sdk"}, // newer: "ai-sdk-openai-compatible/3.0.78 ai-sdk-provider-utils/5.0.68 node.js/24"
	{true, "openai/", "openai-sdk"},
	{true, "asyncopenai/", "openai-sdk"},
	{true, "anthropic/", "anthropic-sdk"},
	{false, "chatboxapp", "chatbox"},
	{false, "google-apps-script", "apps-script"},
	{true, "mozilla/", "browser"},
	{true, "python-urllib", "python-http"},
	{true, "python-requests", "python-http"},
	{true, "python-httpx", "python-http"},
	{true, "python/", "python-http"}, // "Python/3.x aiohttp/3.x"
	{true, "aiohttp", "python-http"},
	{true, "node-fetch", "node-http"},
	{true, "undici", "node-http"},
	{true, "axios", "node-http"},
	{true, "deno/", "deno-http"},
	{true, "go-http-client", "go-http"},
	{true, "java-http-client", "java-http"},
	{true, "okhttp", "java-http"},
	{true, "curl/", "curl"},
	{true, "wget/", "curl"},
}

// Classify names the program behind a request from its User-Agent, X-Title and
// HTTP-Referer. Every input is self-reported: this is attribution for analysis,
// never a gate.
func Classify(userAgent, appTitle, referer string) string {
	title := strings.ToLower(strings.TrimSpace(appTitle))
	ref := strings.ToLower(referer)
	for _, r := range clientTitleRules {
		if ref != "" && strings.Contains(ref, r.refererDomain) {
			return r.client
		}
		for _, p := range r.titlePrefixes {
			if title != "" && strings.HasPrefix(title, p) {
				return r.client
			}
		}
	}
	return classifyUA(strings.ToLower(strings.TrimSpace(userAgent)))
}

func classifyUA(ua string) string {
	switch {
	case ua == "":
		return ClientUnknown
	case ua == "node": // the bare Node.js default, no version
		return "node-http"
	case strings.HasPrefix(ua, "claude-cli/"):
		// Claude Code and the Claude Agent SDK share the claude-cli UA; the SDK
		// adds "agent-sdk/<version>" in the parenthesised suffix, and an app
		// embedding the SDK may name itself there ("client-app/cherry-studio/2.1.7").
		if strings.Contains(ua, "client-app/cherry-studio") {
			return "cherry-studio"
		}
		if strings.Contains(ua, "agent-sdk/") {
			return "claude-agent-sdk"
		}
		return "claude-code"
	}
	for _, r := range clientUARules {
		if (r.prefix && strings.HasPrefix(ua, r.needle)) || (!r.prefix && strings.Contains(ua, r.needle)) {
			return r.client
		}
	}
	return ClientOther
}
