#!/usr/bin/env bash
#
# smoke-toolcall.sh — smoke-test the TOOL-CALL path through a deployed gateway.
#
# WHY THIS EXISTS ------------------------------------------------------------
# The gateway seals `messages` AND `tools` (wire.DefaultSealedFields), and the
# provider enclave seals `choices` back — which is where `tool_calls` live. So a
# chat smoke test that sends only a prompt exercises half of the sealed request
# set and none of the sealed tool path. This runs the other half, live.
#
# Four things can make a tool-call test quietly pass while proving nothing. None
# of them surface as an error; each is a check below:
#
#   1. THE TARGET MAY NOT BE A GATEWAY AT ALL. The router serves the same OpenAI
#      surface, so aiming this at router-api*.0g.ai answers every call happily
#      with NOTHING SEALED — the gateway is what seals, and the router is the
#      party it seals past. Preflight A probes /v1/gateway/identity, which only
#      the gateway serves, and says so in the summary if it is absent.
#
#   2. NOT EVERY MODEL SUPPORTS TOOLS. On the same fleet, 0GM-1.0-35B-A3B
#      advertises `tools`/`tool_choice` and 0GM-1.0-35B-A3B-SIA does not. Send
#      tools to the wrong one and it answers in prose — a green-looking run that
#      never made a tool call. Preflight B reads /v1/models and refuses to go on.
#      (A catalog in the bare OpenAI shape — `id` only, no supported_parameters —
#      cannot answer this; preflight says that rather than guessing.)
#
#   3. THE ROUTER CANNOT SEE THAT YOU NEED TOOLS. `tools` is a sealed field, so
#      the client strips it before asking the router to rank providers
#      (client/route/route.go, preview). The router ranks on what is left, which
#      says nothing about tool support. Preflight B therefore takes the address
#      of a tools-capable provider out of /v1/models and PINS it with
#      X-0G-Provider-Address; `--no-pin` opts out to test what unpinned routing
#      actually does.
#
#   4. STREAMING IS A DIFFERENT CODE PATH. Streaming assembles tool_calls from
#      per-frame deltas, and every frame is sealed and opened separately, in
#      order (SPEC §7). It is the likeliest thing to break and the one a
#      non-streaming test never touches. Check 3 reassembles the deltas.
#
# WHAT IT DOES NOT DO --------------------------------------------------------
# It cannot see the wire: the gateway seals on your behalf, so from out here the
# request and response are plaintext OpenAI JSON either way. That the fields are
# actually sealed is proven in-process by client/openaiproxy's tests, not here.
# What this proves is the live tool path works end to end THROUGH the sealing —
# a break in it shows up as a wrong or missing tool call, which is what these
# checks assert.
#
# USAGE ----------------------------------------------------------------------
#   ZG_API_KEY=sk-... ./scripts/smoke-toolcall.sh
#   ZG_API_KEY=sk-... ./scripts/smoke-toolcall.sh --model glm-5.2 --gateway my-gw.example
#   ZG_API_KEY=sk-... ./scripts/smoke-toolcall.sh --provider 0x4870… --no-stream
#
# Exit: 0 all checks passed, 1 a check failed, 2 bad usage / preflight refused.

set -euo pipefail

GATEWAY=${GATEWAY:-pc-gateway.0g.ai}
MODEL=${MODEL:-0GM-1.0-35B-A3B}
PROVIDER=${PROVIDER:-}
PIN=1
STREAM=1

# The header comment above IS the help text. Printed by walking it rather than a
# line range, so editing the header cannot silently truncate --help.
usage() {
	awk 'NR > 2 && /^#/ { sub(/^# ?/, ""); print; next } NR > 2 { exit }' "$0"
	exit "${1:-0}"
}

while [ $# -gt 0 ]; do
	case "$1" in
	--gateway) GATEWAY=$2; shift 2 ;;
	--model) MODEL=$2; shift 2 ;;
	--provider) PROVIDER=$2; shift 2 ;;
	--no-pin) PIN=0; shift ;;
	--no-stream) STREAM=0; shift ;;
	-h | --help) usage 0 ;;
	*) printf 'unknown argument: %s\n\n' "$1" >&2; usage 2 ;;
	esac
done

for bin in curl jq; do
	command -v "$bin" >/dev/null || { echo "need $bin on PATH" >&2; exit 2; }
done

# Accept a bare host or a full URL; normalize to a scheme-qualified base.
BASE=$GATEWAY
case "$BASE" in https://* | http://*) ;; *) BASE="https://$BASE" ;; esac
BASE=${BASE%/}

if [ -z "${ZG_API_KEY:-}" ]; then
	echo "warning: ZG_API_KEY is unset — the gateway forwards it as Authorization," >&2
	echo "         so the request goes upstream unauthenticated and will likely 401." >&2
fi

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

pass=0
fail=0
if [ -t 1 ]; then GREEN=$'\033[32m'; RED=$'\033[31m'; DIM=$'\033[2m'; OFF=$'\033[0m'
else GREEN=; RED=; DIM=; OFF=; fi

ok()   { pass=$((pass + 1)); printf '%s  PASS%s  %s\n' "$GREEN" "$OFF" "$1"; }
bad()  { fail=$((fail + 1)); printf '%s  FAIL%s  %s\n' "$RED" "$OFF" "$1"; }
note() { [ -n "$1" ] && printf '%s        %s%s\n' "$DIM" "$1" "$OFF"; return 0; }

# post <out-file> <header-file> <extra-curl-args...> — POST a chat completion and
# echo the HTTP status. The body arrives on stdin so the callers below can stay
# readable. A transport failure (no connection, timeout) echoes "000" rather than
# returning nonzero: under `set -e` that would abort the run at the assignment,
# losing both the FAIL line and every check after it.
post() {
	local out=$1 hdr=$2
	shift 2
	local args=(-sS -o "$out" -D "$hdr" -w '%{http_code}'
		-H 'Content-Type: application/json'
		-H "Authorization: Bearer ${ZG_API_KEY:-}"
		--max-time 120 --data-binary @-)
	[ "$PIN" = 1 ] && [ -n "$PROVIDER" ] && args+=(-H "X-0G-Provider-Address: $PROVIDER")
	local status
	status=$(curl "${args[@]}" "$@" "$BASE/v1/chat/completions") || true
	printf '%s' "${status:-000}"
}

# excerpt <file> [bytes] — a short, quotable slice of a response body, tolerant
# of the file being absent (a request that never got off the ground writes none).
excerpt() { head -c "${2:-400}" "$1" 2>/dev/null || true; }

# served <header-file> — the provider the gateway actually sealed this request
# to (X-Provider is originated by the gateway from the client's own pin, not
# relayed from upstream — see openaiproxy/proxy.go setProvider).
served() { tr -d '\r' <"$1" | sed -n 's/^[Xx]-[Pp]rovider: //p' | tail -1; }

# The tool the model is offered, shared by every check so a difference between
# checks is never the tool definition.
TOOLS='[{"type":"function","function":{
  "name":"get_current_weather",
  "description":"Get the current weather in a given city",
  "parameters":{"type":"object","properties":{
    "city":{"type":"string","description":"City name, e.g. Beijing"},
    "unit":{"type":"string","enum":["celsius","fahrenheit"]}},
  "required":["city"]}}}]'

echo "target   $BASE"
echo "model    $MODEL"

# ---------------------------------------------------------------------------
# Preflight A: is this a GATEWAY at all?
#
# Worth a request of its own, because the failure it catches is silent and total.
# The router speaks the same OpenAI surface as the gateway, so pointing this
# script at router-api*.0g.ai answers every chat call quite happily — with NO
# SEALING ANYWHERE, since sealing is the gateway's job and the router is the
# party it seals *past*. Every check below would still pass. Only the gateway
# serves /v1/gateway/identity (client/cmd/gateway/identity.go), so that is the
# tell. Not fatal — baselining the model against the router direct is a
# legitimate thing to want — but it must never be mistaken for a sealed run, so
# it is said loudly here and repeated in the summary.
# ---------------------------------------------------------------------------
SEALED=1
if [ "$(curl -sS --max-time 20 -o "$WORK/identity.json" -w '%{http_code}' \
	"$BASE/v1/gateway/identity" 2>/dev/null || echo 000)" = 200 ] &&
	jq -e . "$WORK/identity.json" >/dev/null 2>&1; then
	ok "target serves /v1/gateway/identity — this is a 0G gateway, so requests are sealed"
	note "$(jq -r '[(.instance_id // .app_id // empty), (.matched_release.tag // empty)] | join("  ") // ""' "$WORK/identity.json" 2>/dev/null || true)"
else
	SEALED=0
	bad "target does NOT serve /v1/gateway/identity — it is not a 0G gateway"
	note "if this is the router (router-api*.0g.ai), the chat calls below reach the"
	note "model but are NOT end-to-end encrypted: the gateway is what seals, and the"
	note "router is the party it seals past. The tool checks still mean something"
	note "about the MODEL; they mean nothing about E2EE. Point --gateway at the"
	note "gateway domain (e.g. pc-gateway.0g.ai) for a sealed run."
fi
echo

# ---------------------------------------------------------------------------
# Preflight B: does this model advertise tools, and on which provider?
#
# Catalog shapes differ. 0G's fleet listing carries model_id / canonical_id /
# address / supported_parameters, which is what the checks below want; a stock
# OpenAI /v1/models carries only `id`, and there is nothing to check tool support
# against. Tell those two apart rather than reporting the second as "no such
# model", which is what an empty capability filter looks like from the outside.
# ---------------------------------------------------------------------------
if curl -sS --max-time 30 -H "Authorization: Bearer ${ZG_API_KEY:-}" \
	"$BASE/v1/models" -o "$WORK/models.json" 2>/dev/null &&
	jq -e '.data | type == "array"' "$WORK/models.json" >/dev/null 2>&1; then

	total=$(jq '.data | length' "$WORK/models.json")
	# Does this catalog describe capabilities at all, or is it the bare shape?
	rich=$(jq '[.data[] | select(has("supported_parameters"))] | length' "$WORK/models.json")

	if [ "$total" = 0 ]; then
		note "preflight: the model catalog at $BASE/v1/models is empty"
		note "(a listing that needs a key returns this when ZG_API_KEY is unset or wrong)"
	elif [ "$rich" = 0 ]; then
		note "preflight: that catalog has $total entries but reports no supported_parameters,"
		note "so tool support cannot be checked here — it is the bare OpenAI /v1/models shape,"
		note "not 0G's fleet listing. Proceeding; check 1 is then the thing that tells you"
		note "whether this model does tool calls at all."
		jq -e --arg m "$MODEL" '[.data[] | select((.model_id // .canonical_id // .id) == $m)] | length > 0' \
			"$WORK/models.json" >/dev/null 2>&1 ||
			note "warning: \"$MODEL\" is not among them — $(jq -r '[.data[] | .model_id // .id // .canonical_id] | unique | join(", ")' "$WORK/models.json" | head -c 300)"
	else
		entries=$(jq -c --arg m "$MODEL" \
			'[.data[] | select(.model_id == $m or .canonical_id == $m or .id == $m)]' "$WORK/models.json")

		if [ "$(jq 'length' <<<"$entries")" = 0 ]; then
			bad "preflight: no model named \"$MODEL\" in this catalog"
			note "chat models it does list, tools-capable marked [tools]:"
			jq -r '[.data[] | select((.service_type // "chatbot") == "chatbot")
			        | (.model_id // .id // .canonical_id)
			          + (if (.supported_parameters // []) | index("tools") then "  [tools]" else "" end)]
			       | unique | .[] | "          " + .' "$WORK/models.json"
			exit 2
		fi

		# Prefer a healthy provider that actually advertises tools. This is both the
		# capability check and where the pin comes from — trap 1 and trap 2 have the
		# same answer, so they are resolved in one place.
		capable=$(jq -c '[.[] | select((.supported_parameters // []) | index("tools"))]
		                 | sort_by(.is_healthy != true) | first // empty' <<<"$entries")

		if [ -z "$capable" ]; then
			bad "preflight: \"$MODEL\" does not advertise \"tools\" on any provider"
			note "what it does advertise:"
			jq -r '.[] | "          " + (.address // "?") + "  " + ((.supported_parameters // []) | join(","))' <<<"$entries"
			note "pick a model whose supported_parameters contains \"tools\"."
			exit 2
		fi

		ok "preflight: \"$MODEL\" advertises tools and tool_choice"
		if [ -z "$PROVIDER" ]; then
			PROVIDER=$(jq -r '.address // ""' <<<"$capable")
			[ "$(jq -r '.is_healthy' <<<"$capable")" = true ] ||
				note "warning: that provider reports is_healthy=false"
		fi
	fi

	if [ -n "$PROVIDER" ] && [ "$PIN" = 1 ]; then
		note "pinning $PROVIDER (the router cannot rank on tools — see the header comment)"
	elif [ "$PIN" = 0 ]; then
		note "--no-pin: letting the router choose, which it does without seeing \"tools\""
	else
		note "no provider pin: a tools-incapable provider is possible (--provider sets one)"
	fi
else
	note "preflight skipped: could not read $BASE/v1/models"
	[ -n "$PROVIDER" ] || note "no --provider pin either; a tools-incapable provider is possible"
fi
echo

# ---------------------------------------------------------------------------
# Check 1 — non-streaming: the model asks for the tool.
# ---------------------------------------------------------------------------
code=$(post "$WORK/r1.json" "$WORK/r1.hdr" <<EOF
{"model": $(jq -Rn --arg m "$MODEL" '$m'),
 "messages": [
   {"role":"system","content":"You are a helpful assistant. Call a tool when it can answer the question."},
   {"role":"user","content":"What is the weather in Beijing right now? Use celsius."}],
 "tools": $TOOLS,
 "tool_choice": "auto",
 "temperature": 0.2,
 "max_tokens": 512}
EOF
)

CALL_ID=; CALL_ARGS=
if [ "$code" != 200 ]; then
	bad "non-streaming tool call: HTTP $code"
	note "$(excerpt "$WORK/r1.json")"
else
	name=$(jq -r '.choices[0].message.tool_calls[0].function.name // ""' "$WORK/r1.json")
	reason=$(jq -r '.choices[0].finish_reason // ""' "$WORK/r1.json")
	if [ "$name" = get_current_weather ]; then
		CALL_ID=$(jq -r '.choices[0].message.tool_calls[0].id // "call_1"' "$WORK/r1.json")
		CALL_ARGS=$(jq -r '.choices[0].message.tool_calls[0].function.arguments // "{}"' "$WORK/r1.json")
		ok "non-streaming: model called get_current_weather (finish_reason=$reason)"
		note "arguments: $CALL_ARGS"
		[ "$reason" = tool_calls ] ||
			note "warning: finish_reason is \"$reason\", expected \"tool_calls\""
	else
		bad "non-streaming: no tool call (finish_reason=$reason)"
		note "the model answered in prose instead: $(jq -r '.choices[0].message.content // "" | .[0:160]' "$WORK/r1.json")"
	fi
	# "sealed to" only when there is a gateway doing the sealing; otherwise this
	# header is just whoever answered.
	p=$(served "$WORK/r1.hdr")
	[ -n "$p" ] && { [ "$SEALED" = 1 ] && note "sealed to $p" || note "X-Provider: $p"; }
fi

# ---------------------------------------------------------------------------
# Check 2 — the tool result goes back up. This is the turn that matters: the
# assistant's tool_calls and the role:"tool" result both ride inside "messages",
# so they are sealed on the way to the enclave like any other prompt content.
# ---------------------------------------------------------------------------
if [ -n "$CALL_ID" ]; then
	code=$(post "$WORK/r2.json" "$WORK/r2.hdr" <<EOF
{"model": $(jq -Rn --arg m "$MODEL" '$m'),
 "messages": [
   {"role":"user","content":"What is the weather in Beijing right now? Use celsius."},
   {"role":"assistant","content":null,
    "tool_calls":[{"id": $(jq -Rn --arg s "$CALL_ID" '$s'),"type":"function",
      "function":{"name":"get_current_weather","arguments": $(jq -Rn --arg s "$CALL_ARGS" '$s')}}]},
   {"role":"tool","tool_call_id": $(jq -Rn --arg s "$CALL_ID" '$s'),
    "content":"{\"temp_c\":21,\"condition\":\"clear\"}"}],
 "tools": $TOOLS,
 "tool_choice": "auto",
 "max_tokens": 512}
EOF
	)
	if [ "$code" != 200 ]; then
		bad "tool result round trip: HTTP $code"
		note "$(excerpt "$WORK/r2.json")"
	else
		answer=$(jq -r '.choices[0].message.content // ""' "$WORK/r2.json")
		if printf '%s' "$answer" | grep -q 21; then
			ok "tool result round trip: model answered from the tool output"
			note "$(printf '%s' "$answer" | head -c 160)"
		else
			bad "tool result round trip: answer does not reflect the tool output (21C)"
			note "$(printf '%s' "$answer" | head -c 160)"
		fi
	fi
else
	note "skipping the tool-result turn: check 1 produced no tool call to answer"
fi

# ---------------------------------------------------------------------------
# Check 3 — streaming. Each SSE frame is sealed and opened on its own, in order,
# and the tool call arrives split across frames as deltas. Reassemble it.
# ---------------------------------------------------------------------------
if [ "$STREAM" = 1 ]; then
	code=$(post "$WORK/r3.sse" "$WORK/r3.hdr" -N <<EOF
{"model": $(jq -Rn --arg m "$MODEL" '$m'),
 "messages": [
   {"role":"system","content":"You are a helpful assistant. Call a tool when it can answer the question."},
   {"role":"user","content":"What is the weather in Beijing right now? Use celsius."}],
 "tools": $TOOLS,
 "tool_choice": "auto",
 "temperature": 0.2,
 "max_tokens": 512,
 "stream": true}
EOF
	)
	if [ "$code" != 200 ]; then
		bad "streaming tool call: HTTP $code"
		note "$(excerpt "$WORK/r3.sse")"
	else
		# One JSON object per line, [DONE] dropped, unparseable lines skipped.
		tr -d '\r' <"$WORK/r3.sse" | sed -n 's/^data: //p' | grep -v '^\[DONE\]$' |
			jq -c 'select(type == "object")' >"$WORK/r3.frames" 2>/dev/null || true

		frames=$(wc -l <"$WORK/r3.frames" | tr -d ' ')
		name=$(jq -rs '[.[] | .choices[0].delta.tool_calls[]? | .function.name? // empty] | first // ""' "$WORK/r3.frames")
		args=$(jq -rs '[.[] | .choices[0].delta.tool_calls[]? | .function.arguments? // empty] | add // ""' "$WORK/r3.frames")
		reason=$(jq -rs '[.[] | .choices[0].finish_reason? // empty] | last // ""' "$WORK/r3.frames")

		if [ "$name" = get_current_weather ]; then
			ok "streaming: reassembled get_current_weather from $frames frames (finish_reason=$reason)"
			note "arguments: $args"
			jq -e . >/dev/null 2>&1 <<<"$args" ||
				note "warning: the reassembled arguments are not valid JSON — frames may be lost or out of order"
		else
			bad "streaming: no tool call reassembled from $frames frames (finish_reason=$reason)"
			note "$(excerpt "$WORK/r3.sse" 240)"
		fi
	fi
fi

# ---------------------------------------------------------------------------
echo
printf '%d passed, %d failed\n' "$pass" "$fail"
# Repeated here because it is the line people read: a run against a non-gateway
# can look entirely green while proving nothing at all about sealing.
[ "$SEALED" = 1 ] ||
	printf '%sNOT A SEALED RUN — the target is not a 0G gateway, so nothing above was%s\n%sencrypted end to end. These results describe the model, not the E2EE path.%s\n' \
		"$RED" "$OFF" "$RED" "$OFF"
[ "$fail" = 0 ] || exit 1
