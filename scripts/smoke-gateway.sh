#!/usr/bin/env bash
#
# smoke-gateway.sh — smoke-test a deployed gateway end to end: is it a gateway, is it
# up, does it seal what it should and pass through what it should not, does a
# conversation stay on one provider, and what did it verify about that provider.
#
# WHAT IT CHECKS -------------------------------------------------------------
#   0. preflight  GET /v1/gateway/identity answers — only a gateway serves it; a bare
#                 router serves the same OpenAI surface and seals NOTHING, so a run
#                 aimed at one would otherwise look green. Prints compose_hash,
#                 os_image and matched_release.
#   1. health     /healthz 200 and /readyz 200 (503 = no provider ready).
#   2. auth       a chat request with no API key is refused 401 by the gateway.
#   3. sealed     a chat completion for --sealed-model: 200, X-0G-E2EE: sealed, an
#                 X-Provider, and a non-empty answer.
#   4. stream     the same, streamed: X-0G-E2EE: sealed, content deltas, [DONE].
#                 Every frame is sealed and opened separately (SPEC §7), so this is a
#                 different code path from 3.
#   5. passthru   a chat completion for --plain-model, a model the gateway does NOT
#                 seal: 200 and X-0G-E2EE: none. Skipped without --plain-model.
#   6. session    --turns sealed requests sharing one X-Session-Id (and
#                 X-Claude-Code-Session-Id): every one should land on the same
#                 X-Provider. Proves the stickiness only when the model has two or
#                 more providers; with one it passes trivially, and says so.
#   7. identity   GET /v1/providers/<X-Provider>/identity for the provider check 3
#                 used: quote_dcap pass, and the other verdicts printed
#                 (measurement, onchain_signer, runtime_release, compose_baseline).
#   8. pcverify   `pcverify -gateway <host>` when --pcverify names the binary: the
#                 independent check of the gateway itself — evidence bundle, quote,
#                 served certificate, code identity, OS image. Run it from an
#                 ordinary network: a TLS-intercepting proxy fails endpoint binding.
#
# WHAT IT DOES NOT DO --------------------------------------------------------
# It cannot see the wire: the gateway seals on your behalf, so out here request and
# response are plaintext OpenAI JSON either way. X-0G-E2EE is the gateway's own
# statement of which path a request took; that the sealed path really seals is
# proven by client/openaiproxy's tests. Tool calls have their own script
# (scripts/smoke-toolcall.sh).
#
# USAGE ----------------------------------------------------------------------
#   ZG_API_KEY=sk-... ./scripts/smoke-gateway.sh --gateway router-api-staging.0g.ai
#   ZG_API_KEY=sk-... ./scripts/smoke-gateway.sh --gateway router-api-staging.0g.ai \
#       --plain-model glm-5.2 --pcverify ./pcverify
#
#   --gateway HOST       gateway host or URL (env GATEWAY; required)
#   --sealed-model M     a model in the gateway's ZG_GATEWAY_SEAL_MODELS
#                        (env SEALED_MODEL; default 0GM-1.0-35B-A3B)
#   --plain-model M      a model it does not seal (env PLAIN_MODEL; check 5 skipped
#                        without one)
#   --turns N            session turns for check 6 (env TURNS; default 3)
#   --pcverify PATH      pcverify binary for check 8 (env PCVERIFY; skipped without)
#
# The API key is read from ZG_API_KEY only, never a flag, so it stays out of shell
# history and process listings.
#
# Exit: 0 all checks passed, 1 a check failed, 2 bad usage / preflight refused.

set -euo pipefail

GATEWAY=${GATEWAY:-}
SEALED_MODEL=${SEALED_MODEL:-0GM-1.0-35B-A3B}
PLAIN_MODEL=${PLAIN_MODEL:-}
TURNS=${TURNS:-3}
PCVERIFY=${PCVERIFY:-}

# The header comment above IS the help text.
usage() {
	awk 'NR > 2 && /^#/ { sub(/^# ?/, ""); print; next } NR > 2 { exit }' "$0"
	exit "${1:-0}"
}

while [ $# -gt 0 ]; do
	case "$1" in
	--gateway) GATEWAY=$2; shift 2 ;;
	--sealed-model) SEALED_MODEL=$2; shift 2 ;;
	--plain-model) PLAIN_MODEL=$2; shift 2 ;;
	--turns) TURNS=$2; shift 2 ;;
	--pcverify) PCVERIFY=$2; shift 2 ;;
	-h | --help) usage 0 ;;
	*) printf 'unknown argument: %s\n\n' "$1" >&2; usage 2 ;;
	esac
done

for bin in curl jq; do
	command -v "$bin" >/dev/null || { echo "need $bin on PATH" >&2; exit 2; }
done
[ -n "$GATEWAY" ] || { echo "--gateway is required" >&2; usage 2; }
[ -n "${ZG_API_KEY:-}" ] || { echo "ZG_API_KEY is required" >&2; exit 2; }
case "$TURNS" in '' | *[!0-9]*) echo "--turns must be a number" >&2; exit 2 ;; esac

BASE=$GATEWAY
case "$BASE" in https://* | http://*) ;; *) BASE="https://$BASE" ;; esac
BASE=${BASE%/}
HOST=${BASE#*://}
HOST=${HOST%%/*}

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

pass=0
fail=0
skip=0
if [ -t 1 ]; then GREEN=$'\033[32m'; RED=$'\033[31m'; DIM=$'\033[2m'; OFF=$'\033[0m'
else GREEN=; RED=; DIM=; OFF=; fi

ok()   { pass=$((pass + 1)); printf '%s  PASS%s  %s\n' "$GREEN" "$OFF" "$1"; }
bad()  { fail=$((fail + 1)); printf '%s  FAIL%s  %s\n' "$RED" "$OFF" "$1"; }
skp()  { skip=$((skip + 1)); printf '%s  SKIP  %s%s\n' "$DIM" "$1" "$OFF"; }
note() { [ -n "$1" ] && printf '%s        %s%s\n' "$DIM" "$1" "$OFF"; return 0; }

# jqr <jq args...> — read a value out of a response body, empty on any failure, so a
# body that is not JSON cannot abort the run under `set -e`.
jqr() { jq -r "$@" 2>/dev/null || true; }
excerpt() { head -c "${2:-300}" "$1" 2>/dev/null | tr '\n' ' ' || true; }

# header <file> <name> — a response header's value, case-insensitive, last one wins.
header() {
	awk -v n="$(printf '%s' "$2" | tr '[:upper:]' '[:lower:]')" '
		{ line = $0; sub(/\r$/, "", line); i = index(line, ":"); if (!i) next
		  k = tolower(substr(line, 1, i - 1)); v = substr(line, i + 1); sub(/^[ \t]+/, "", v)
		  if (k == n) out = v }
		END { print out }' "$1" 2>/dev/null || true
}

# get <out> <hdr> <path> — GET and echo the status ("000" on a transport failure).
get() {
	curl -sS -o "$1" -D "$2" -w '%{http_code}' --max-time 30 "$BASE$3" 2>/dev/null || printf '000'
}

# chat <out> <hdr> <model> <stream 0|1> [extra curl args...] — POST a chat completion
# and echo the status. The request carries a fixed, trivial prompt.
chat() {
	local out=$1 hdr=$2 model=$3 stream=$4
	shift 4
	local body
	body=$(jq -nc --arg m "$model" --argjson s "$([ "$stream" = 1 ] && echo true || echo false)" \
		'{model: $m, stream: $s, max_tokens: 32,
		  messages: [{role: "user", content: "Reply with the single word: pong"}]}')
	curl -sS -o "$out" -D "$hdr" -w '%{http_code}' --max-time 120 \
		-H 'Content-Type: application/json' -H "Authorization: Bearer $ZG_API_KEY" \
		"$@" --data-binary "$body" "$BASE/v1/chat/completions" 2>/dev/null || printf '000'
}

printf 'gateway  %s\n\n' "$BASE"

# 0. preflight -----------------------------------------------------------------
st=$(get "$WORK/id.json" "$WORK/id.h" /v1/gateway/identity)
if [ "$st" != 200 ] || [ -z "$(jqr 'keys[0]' "$WORK/id.json")" ]; then
	printf '%s  STOP%s  /v1/gateway/identity answered %s — this does not look like a gateway\n' \
		"$RED" "$OFF" "$st"
	note "$(excerpt "$WORK/id.json")"
	note "a bare router serves the same chat surface and seals nothing; refusing to go on"
	exit 2
fi
ok "preflight: /v1/gateway/identity answers"
note "compose_hash    $(jqr '.compose_hash // "null"' "$WORK/id.json")"
note "os_image        $(jqr '.os_image // "null"' "$WORK/id.json")"
note "matched_release $(jqr '.matched_release // "null"' "$WORK/id.json")"

# 1. health --------------------------------------------------------------------
for path in /healthz /readyz; do
	st=$(get "$WORK/h.out" "$WORK/h.h" "$path")
	if [ "$st" = 200 ]; then ok "health: $path 200"
	else bad "health: $path answered $st"; note "$(excerpt "$WORK/h.out")"; fi
done

# 2. auth ----------------------------------------------------------------------
body='{"model":"x","messages":[{"role":"user","content":"x"}]}'
st=$(curl -sS -o "$WORK/a.out" -w '%{http_code}' --max-time 30 -H 'Content-Type: application/json' \
	--data-binary "$body" "$BASE/v1/chat/completions" 2>/dev/null || printf '000')
if [ "$st" = 401 ]; then ok "auth: no API key -> 401"
else bad "auth: no API key answered $st, want 401"; note "$(excerpt "$WORK/a.out")"; fi

# 3. sealed --------------------------------------------------------------------
PROVIDER=
st=$(chat "$WORK/s.json" "$WORK/s.h" "$SEALED_MODEL" 0)
e2ee=$(header "$WORK/s.h" X-0G-E2EE)
PROVIDER=$(header "$WORK/s.h" X-Provider)
answer=$(jqr '.choices[0].message.content // empty' "$WORK/s.json")
if [ "$st" = 200 ] && [ "$e2ee" = sealed ] && [ -n "$PROVIDER" ] && [ -n "$answer" ]; then
	ok "sealed: $SEALED_MODEL -> 200, X-0G-E2EE: sealed"
	note "provider $PROVIDER; answer: $(printf '%s' "$answer" | head -c 80 | tr '\n' ' ')"
else
	bad "sealed: $SEALED_MODEL -> status $st, X-0G-E2EE '${e2ee:-<none>}', X-Provider '${PROVIDER:-<none>}', answer ${answer:+present}${answer:-empty}"
	note "$(excerpt "$WORK/s.json")"
fi

# 4. stream --------------------------------------------------------------------
st=$(chat "$WORK/st.out" "$WORK/st.h" "$SEALED_MODEL" 1)
e2ee=$(header "$WORK/st.h" X-0G-E2EE)
# Each stage tolerates "nothing to read": under pipefail a grep with no match would
# otherwise abort the run here, on exactly the failure this check exists to report.
deltas=$({ grep '^data: {' "$WORK/st.out" 2>/dev/null || true; } | sed 's/^data: //' |
	jqr -s '[.[] | .choices[0].delta.content // empty | select(. != "")] | length')
done_=$(grep -c '^data: \[DONE\]' "$WORK/st.out" 2>/dev/null || true)
if [ "$st" = 200 ] && [ "$e2ee" = sealed ] && [ "${deltas:-0}" -gt 0 ] && [ "${done_:-0}" -ge 1 ]; then
	ok "stream: $SEALED_MODEL -> 200, X-0G-E2EE: sealed, $deltas content deltas, [DONE]"
else
	bad "stream: status $st, X-0G-E2EE '${e2ee:-<none>}', ${deltas:-0} content deltas, [DONE] x${done_:-0}"
	note "$(excerpt "$WORK/st.out")"
fi

# 5. passthrough ---------------------------------------------------------------
if [ -z "$PLAIN_MODEL" ]; then
	skp "passthru: no --plain-model given"
else
	st=$(chat "$WORK/p.json" "$WORK/p.h" "$PLAIN_MODEL" 0)
	e2ee=$(header "$WORK/p.h" X-0G-E2EE)
	if [ "$st" = 200 ] && [ "$e2ee" = none ]; then
		ok "passthru: $PLAIN_MODEL -> 200, X-0G-E2EE: none"
	else
		bad "passthru: $PLAIN_MODEL -> status $st, X-0G-E2EE '${e2ee:-<none>}' (want none)"
		note "$(excerpt "$WORK/p.json")"
		[ "$e2ee" = sealed ] && note "it was SEALED: is $PLAIN_MODEL in ZG_GATEWAY_SEAL_MODELS?"
	fi
fi

# 6. session -------------------------------------------------------------------
sid="smoke-$(date +%s)-$$"
seen=()
errs=0
for _ in $(seq 1 "$TURNS"); do
	st=$(chat "$WORK/t.json" "$WORK/t.h" "$SEALED_MODEL" 0 \
		-H "X-Session-Id: $sid" -H "X-Claude-Code-Session-Id: $sid")
	if [ "$st" = 200 ]; then seen+=("$(header "$WORK/t.h" X-Provider)"); else errs=$((errs + 1)); fi
done
distinct=$(printf '%s\n' "${seen[@]:-}" | sort -u | grep -c . || true)
if [ "$errs" -gt 0 ]; then
	bad "session: $errs of $TURNS turns failed"
elif [ "$distinct" = 1 ]; then
	ok "session: $TURNS turns with one session id -> one provider (${seen[0]})"
	note "proves stickiness only if $SEALED_MODEL has 2+ providers; with one this passes trivially"
else
	bad "session: $TURNS turns with one session id landed on $distinct providers"
	note "$(printf '%s ' "${seen[@]}")"
	note "the router keeps a session on one provider by X-Session-Id; is the router on 0g-router#1024?"
fi

# 7. provider identity ---------------------------------------------------------
if [ -z "$PROVIDER" ]; then
	skp "identity: no X-Provider from check 3"
else
	st=$(get "$WORK/pi.json" "$WORK/pi.h" "/v1/providers/$PROVIDER/identity")
	dcap=$(jqr '.verdicts.quote_dcap' "$WORK/pi.json")
	if [ "$st" = 200 ] && [ "$dcap" = pass ]; then
		ok "identity: /v1/providers/$PROVIDER/identity -> quote_dcap pass"
	else
		bad "identity: status $st, quote_dcap '${dcap:-<none>}'"
		note "$(excerpt "$WORK/pi.json")"
	fi
	for v in measurement onchain_signer runtime_release compose_baseline; do
		note "$(printf '%-17s %s' "$v" "$(jqr ".verdicts.$v // \"<absent>\"" "$WORK/pi.json")")"
	done
	note "$(printf '%-17s %s' running_broker "$(jqr '.running_broker // "null"' "$WORK/pi.json")")"
fi

# 8. pcverify ------------------------------------------------------------------
if [ -z "$PCVERIFY" ]; then
	skp "pcverify: no --pcverify given"
else
	if "$PCVERIFY" -gateway "$HOST" >"$WORK/pv.out" 2>&1; then
		ok "pcverify: -gateway $HOST exit 0"
	else
		rc=$?
		bad "pcverify: -gateway $HOST exit $rc"
		grep -E '^(✗|-) ' "$WORK/pv.out" | while IFS= read -r line; do note "$line"; done
	fi
fi

printf '\n%d passed, %d failed, %d skipped\n' "$pass" "$fail" "$skip"
[ "$fail" -eq 0 ]
