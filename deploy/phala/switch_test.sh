#!/usr/bin/env bash
#
# switch_test.sh — offline tests for switch.sh.
#
# switch.sh talks to two things: the Cloudflare API and the gateway over HTTPS
# (the per-side probe, the public /healthz, and the served cert via openssl).
# This file puts a fake `curl` and a fake `openssl` first on PATH and models both
# from a small state directory, so every command can be driven end to end with no
# network and no token:
#
#   records.json   the delegation zone, as a JSON array of {id,type,name,content}
#   writes.log     one line per POST/PUT/DELETE the script sent
#   api.log        one line per record lookup (GET <name>)
#   health         lines of `<host> <path> <code> [<code>…]`; successive requests
#                  consume the codes in turn and the last one repeats
#   stale          if present, holds an app_id the public name keeps resolving to,
#                  standing in for a dstack gateway route cache that has not flushed
#
# The public name serves whichever app the traffic switch currently resolves to,
# read from records.json on every request, exactly as the dstack gateway would.
# A per-side probe host `<app_id>-443s.<base>` answers only when <base> is the
# cluster that app lives in (in1.phala.network unless `cluster.<app_id>` says
# otherwise) — a dstack gateway cannot route an app_id from another cluster.
#
# Run: ./deploy/phala/switch_test.sh   (needs bash, jq)
set -euo pipefail

HERE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
SWITCH="${HERE}/switch.sh"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

DOMAIN=router-api-tee.0g.ai
DZ=integratenetwork.work
BASE=in1.phala.network
ALIAS="${DOMAIN}.${DZ}"
ADDR_SWITCH="_dstack-app-address.${DOMAIN}.${DZ}"
ACME_SWITCH="_acme-challenge.${DOMAIN}.${DZ}"
addr_side() { echo "_dstack-app-address.${DOMAIN}.$1.${DZ}"; }
acme_side() { echo "_acme-challenge.${DOMAIN}.$1.${DZ}"; }

# ---------------------------------------------------------------------------
# Fakes
# ---------------------------------------------------------------------------
mkdir -p "$WORK/bin"

cat >"$WORK/bin/curl" <<'FAKE_CURL'
#!/usr/bin/env bash
set -euo pipefail
S="$FAKE_DIR"
method=GET url="" data="" wfmt=""
while [ $# -gt 0 ]; do
  case "$1" in
    -X) method="$2"; shift ;;
    --data) data="$2"; shift ;;
    -w) wfmt="$2"; shift ;;
    -H|-o|--max-time) shift ;;
    -*) ;;
    *) url="$1" ;;
  esac
  shift
done

# The app the public name currently lands on: follow the traffic switch CNAME to
# a per-side TXT, unless a stale route is pinned.
live_app() {
  if [ -f "$S/stale" ]; then cat "$S/stale"; return; fi
  local tgt
  tgt="$(jq -r --arg n "$FAKE_ADDR_SWITCH" '.[] | select(.name==$n and .type=="CNAME") | .content' "$S/records.json" | head -n1)"
  [ -n "$tgt" ] || return 0
  jq -r --arg n "$tgt" '.[] | select(.name==$n and .type=="TXT") | .content' "$S/records.json" \
    | head -n1 | sed 's/^"//; s/"$//; s/:.*//'
}

# Next scripted status for host+path, or the given default.
scripted() { # host path default
  local line codes n i
  line="$(awk -v h="$1" -v p="$2" '$1==h && $2==p {print; exit}' "$S/health" 2>/dev/null || true)"
  [ -n "$line" ] || { echo "$3"; return; }
  read -r -a codes <<<"$line"
  codes=("${codes[@]:2}")
  local f; f="$S/count.$(printf '%s' "$1$2" | tr -c 'A-Za-z0-9.-' '_')"
  n="$(cat "$f" 2>/dev/null || true)"; n="${n:-0}"
  echo $((n + 1)) >"$f"
  i=$(( n < ${#codes[@]} - 1 ? n : ${#codes[@]} - 1 ))
  echo "${codes[$i]}"
}

case "$url" in
  https://api.cloudflare.com/client/v4/*)
    path="${url#https://api.cloudflare.com/client/v4}"
    case "$method $path" in
      "GET /zones?"*)
        echo '{"success":true,"result":[{"id":"zone1"}]}' ;;
      "GET /zones/zone1/dns_records?"*)
        q="${path#*\?}"; name="${q#name=}"; name="${name%%&*}"
        echo "GET $name" >>"$S/api.log"
        jq -c --arg n "$name" '{success:true,result:[.[] | select(.name==$n)]}' "$S/records.json" ;;
      "POST /zones/zone1/dns_records")
        n="$(cat "$S/next_id" 2>/dev/null || echo 100)"; echo $((n + 1)) >"$S/next_id"
        id="rec$n"
        jq --arg id "$id" --argjson r "$data" '. + [$r + {id:$id} | {id,type,name,content}]' \
          "$S/records.json" >"$S/r.tmp" && mv "$S/r.tmp" "$S/records.json"
        echo "POST $(jq -r '.name + " " + .type + " " + .content' <<<"$data")" >>"$S/writes.log"
        echo '{"success":true,"result":{}}' ;;
      "PUT /zones/zone1/dns_records/"*)
        id="${path##*/}"
        jq --arg id "$id" --argjson r "$data" 'map(if .id==$id then ($r + {id:$id} | {id,type,name,content}) else . end)' \
          "$S/records.json" >"$S/r.tmp" && mv "$S/r.tmp" "$S/records.json"
        echo "PUT $(jq -r '.name + " " + .type + " " + .content' <<<"$data")" >>"$S/writes.log"
        echo '{"success":true,"result":{}}' ;;
      "DELETE /zones/zone1/dns_records/"*)
        id="${path##*/}"
        echo "DELETE $(jq -r --arg id "$id" '.[] | select(.id==$id) | .name + " " + .type + " " + .content' "$S/records.json")" >>"$S/writes.log"
        jq --arg id "$id" 'map(select(.id!=$id))' "$S/records.json" >"$S/r.tmp" && mv "$S/r.tmp" "$S/records.json"
        echo '{"success":true,"result":{}}' ;;
      *) echo '{"success":false,"errors":[{"message":"fake: unhandled '"$method $path"'"}]}' ;;
    esac
    ;;
  https://*)
    rest="${url#https://}"; host="${rest%%/*}"; hpath="/${rest#*/}"
    code=000
    if [ "$host" = "$FAKE_DOMAIN" ]; then
      app="$(live_app)"
      [ -n "$app" ] && code="$(scripted "public:$app" "$hpath" 200)"
    elif [[ "$host" == *-443s.* ]]; then
      app="${host%%-443s.*}"; base="${host#*-443s.}"
      home="$(cat "$S/cluster.$app" 2>/dev/null || echo in1.phala.network)"
      [ "$base" = "$home" ] && code="$(scripted "$host" "$hpath" 200)"
    fi
    echo "$(date +%s) $host$hpath $code" >>"$S/http.log"
    [ -n "$wfmt" ] && printf '%s' "$code"
    [ "$code" != 000 ] || exit 7
    ;;
  *) echo "fake curl: unexpected url '$url'" >&2; exit 2 ;;
esac
FAKE_CURL

# `echo | openssl s_client … | openssl x509 -fingerprint` — the served cert is
# identified by whichever app the public name currently lands on.
cat >"$WORK/bin/openssl" <<'FAKE_OPENSSL'
#!/usr/bin/env bash
set -euo pipefail
case "${1:-}" in
  s_client)
    cat >/dev/null
    if [ -f "$FAKE_DIR/stale" ]; then app="$(cat "$FAKE_DIR/stale")"
    else
      tgt="$(jq -r --arg n "$FAKE_ADDR_SWITCH" '.[] | select(.name==$n and .type=="CNAME") | .content' "$FAKE_DIR/records.json" | head -n1)"
      app="$(jq -r --arg n "$tgt" '.[] | select(.name==$n and .type=="TXT") | .content' "$FAKE_DIR/records.json" | head -n1 | sed 's/^"//; s/"$//; s/:.*//')"
    fi
    [ -n "$app" ] || exit 1
    echo "CERT $app" ;;
  x509)
    read -r _ app || exit 1
    echo "sha256 Fingerprint=FP:${app}" ;;
  *) exit 1 ;;
esac
FAKE_OPENSSL
chmod +x "$WORK/bin/curl" "$WORK/bin/openssl"

# ---------------------------------------------------------------------------
# Harness
# ---------------------------------------------------------------------------
PASS=0 FAIL=0 CUR=""
S=""

# A fresh zone: serving alias set, both sides published, traffic + issuance on a.
reset() {
  S="$WORK/state.$RANDOM$RANDOM"; mkdir -p "$S"
  : >"$S/writes.log"; : >"$S/health"; : >"$S/http.log"; : >"$S/api.log"; : >"$S/env"
  jq -n \
    --arg alias "$ALIAS" --arg base "_.${BASE}" \
    --arg as "$ADDR_SWITCH" --arg aa "$(addr_side a)" --arg ab "$(addr_side b)" \
    --arg cs "$ACME_SWITCH" --arg ca "$(acme_side a)" \
    '[{id:"r1",type:"CNAME",name:$alias,content:$base},
      {id:"r2",type:"TXT",name:$aa,content:"\"appa:443\""},
      {id:"r3",type:"TXT",name:$ab,content:"\"appb:443\""},
      {id:"r4",type:"CNAME",name:$as,content:$aa},
      {id:"r5",type:"CNAME",name:$cs,content:$ca}]' >"$S/records.json"
}

# Drop the record(s) at a name.
drop() { jq --arg n "$1" 'map(select(.name!=$n))' "$S/records.json" >"$S/r.tmp" && mv "$S/r.tmp" "$S/records.json"; }
health() { echo "$*" >>"$S/health"; }

# run [VAR=val …] -- switch.sh args…   → sets OUT and RC
run() {
  local envs=()
  while [ "$1" != "--" ]; do envs+=("$1"); shift; done
  shift
  set +e
  OUT="$(env -i PATH="$WORK/bin:$PATH" HOME="$WORK" \
    FAKE_DIR="$S" FAKE_DOMAIN="$DOMAIN" FAKE_ADDR_SWITCH="$ADDR_SWITCH" \
    CF_API_TOKEN=test PROBE_RETRIES=3 PROBE_INTERVAL=0 VERIFY_RETRIES=3 VERIFY_INTERVAL=0 \
    "${envs[@]}" bash "$SWITCH" --env-file "$S/env" "$@" 2>&1)"
  RC=$?
  # shellcheck disable=SC2001  # a regex, not a fixed string
  OUT="$(sed $'s/\033\\[[0-9;]*m//g' <<<"$OUT")"   # drop colour codes
  set -e
}

fail() { FAIL=$((FAIL + 1)); printf '  FAIL %s: %s\n' "$CUR" "$*"; printf '%s\n' "$OUT" | sed 's/^/      | /' | head -n 60; }
t() { CUR="$1"; reset; }
ok() { PASS=$((PASS + 1)); printf '  ok   %s\n' "$CUR"; }

expect_rc()       { [ "$RC" = "$1" ] || { fail "exit $RC, want $1"; return 1; }; }
expect_fail()     { [ "$RC" != 0 ] || { fail "exit 0, want failure"; return 1; }; }
expect_out()      { grep -qF -- "$1" <<<"$OUT" || { fail "output lacks: $1"; return 1; }; }
expect_no_out()   { ! grep -qF -- "$1" <<<"$OUT" || { fail "output has: $1"; return 1; }; }
expect_no_writes(){ [ ! -s "$S/writes.log" ] || { fail "unexpected writes: $(tr '\n' ';' <"$S/writes.log")"; return 1; }; }
expect_cname() { # name target
  local got; got="$(jq -r --arg n "$1" '.[] | select(.name==$n and .type=="CNAME") | .content' "$S/records.json")"
  [ "$got" = "$2" ] || { fail "$1 -> '${got}', want '$2'"; return 1; }
}
expect_first_write() { [ "$(head -n1 "$S/writes.log")" = "$1" ] || { fail "first write '$(head -n1 "$S/writes.log")', want '$1'"; return 1; }; }
expect_reads() { # name count — Cloudflare lookups of that name
  local n; n="$(grep -cxF "GET $1" "$S/api.log" || true)"
  [ "$n" = "$2" ] || { fail "$1 read ${n} times, want $2"; return 1; }
}
expect_probed()     { grep -qF -- " $1 " "$S/http.log" || { fail "never requested $1"; return 1; }; }
expect_not_probed() { ! grep -q -- "-443s\." "$S/http.log" || { fail "probed a side: $(grep -- '-443s\.' "$S/http.log" | head -n1)"; return 1; }; }

# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------
echo "switch.sh"

t "status: shows both switches, both sides and the live side"
run PLATFORM_BASE=$BASE -- status
expect_rc 0 && expect_out "-> _.${BASE}" && expect_out "[a]" \
  && expect_out "appa:443" && expect_out "appb:443" \
  && expect_out "https://appb-443s.${BASE}/readyz" && expect_out "live side       : a" \
  && expect_no_writes && ok

t "status: reads each side's app-address once"
run PLATFORM_BASE=$BASE -- status
expect_rc 0 && expect_reads "$(addr_side a)" 1 && expect_reads "$(addr_side b)" 1 && ok

t "status: warns when both sides publish the same app_id"
jq 'map(if .content=="\"appb:443\"" then .content="\"appa:443\"" else . end)' "$S/records.json" >"$S/r.tmp" && mv "$S/r.tmp" "$S/records.json"
run PLATFORM_BASE=$BASE -- status
expect_rc 0 && expect_out "both sides publish the same app_id" && ok

t "status: warns when the alias is not a _.<base> hop"
jq --arg n "$ALIAS" 'map(if .name==$n then .content="in1.phala.network" else . end)' "$S/records.json" >"$S/r.tmp" && mv "$S/r.tmp" "$S/records.json"
run PLATFORM_BASE=$BASE -- status
expect_rc 0 && expect_out "serving alias is not a gateway hop" && ok

t "status: warns when the alias and PLATFORM_BASE name different clusters"
run PLATFORM_BASE=prod5.phala.network -- status
expect_rc 0 && expect_out "name different clusters" && ok

t "setup: writes the serving alias as _.<PLATFORM_BASE>"
drop "$ALIAS"
run PLATFORM_BASE=$BASE -- setup --yes
expect_rc 0 && expect_cname "$ALIAS" "_.${BASE}" && ok

t "setup: accepts PLATFORM_BASE written with the _. prefix"
drop "$ALIAS"
run PLATFORM_BASE=_.$BASE -- setup --yes
expect_rc 0 && expect_cname "$ALIAS" "_.${BASE}" && ok

t "setup: refuses without PLATFORM_BASE"
drop "$ALIAS"
run -- setup --yes
expect_fail && expect_out "PLATFORM_BASE" && expect_no_writes && ok

t "setup: GATEWAY_DOMAIN is no longer read"
run GATEWAY_DOMAIN=_.prod5.phala.network -- setup --yes
expect_fail && expect_out "currently -> _.${BASE}" && expect_out "set PLATFORM_BASE" && expect_no_writes && ok

t "switch: moves issuance, then traffic, and verifies the new side"
run PLATFORM_BASE=$BASE -- switch b --yes
expect_rc 0 && expect_cname "$ADDR_SWITCH" "$(addr_side b)" && expect_cname "$ACME_SWITCH" "$(acme_side b)" \
  && expect_probed "appb-443s.${BASE}/readyz" && expect_out "now served by b (cert changed)" \
  && expect_first_write "PUT ${ACME_SWITCH} CNAME $(acme_side b)" && ok

t "switch: to the side already live is a no-op"
run PLATFORM_BASE=$BASE -- switch a --yes
expect_rc 0 && expect_out "already points at side a" && expect_no_writes && ok

t "switch: accepts blue/green as side names"
run PLATFORM_BASE=$BASE -- switch green --yes
expect_rc 0 && expect_cname "$ADDR_SWITCH" "$(addr_side b)" && ok

t "switch: refuses an unknown side"
run PLATFORM_BASE=$BASE -- switch c --yes
expect_fail && expect_out "unknown side 'c'" && expect_no_writes && ok

t "switch: gate 1 refuses a side that publishes no app-address"
drop "$(addr_side b)"
run PLATFORM_BASE=$BASE -- switch b --yes
expect_fail && expect_out "publishes no app-address TXT" && expect_no_writes && ok

t "switch: warns when both sides publish the same app_id"
jq 'map(if .content=="\"appa:443\"" then .content="\"appb:443\"" else . end)' "$S/records.json" >"$S/r.tmp" && mv "$S/r.tmp" "$S/records.json"
run PLATFORM_BASE=$BASE -- switch b --yes --no-verify
expect_rc 0 && expect_out "both sides publish the same app_id (appb:443)" && ok

t "switch: gate 2 refuses a side that never becomes ready"
health "appb-443s.${BASE} /readyz 503"
run PLATFORM_BASE=$BASE -- switch b --yes
expect_fail && expect_out "refusing to switch" && expect_no_writes && ok

t "switch: gate 2 waits out a side that becomes ready"
health "appb-443s.${BASE} /readyz 000 503 200"
run PLATFORM_BASE=$BASE -- switch b --yes
expect_rc 0 && expect_out "target-side probe OK" && expect_cname "$ADDR_SWITCH" "$(addr_side b)" && ok

t "switch: gate 2 falls back to /healthz on a side without /readyz"
health "appb-443s.${BASE} /readyz 404"
run PLATFORM_BASE=$BASE -- switch b --yes
expect_rc 0 && expect_out "predates readiness gating" && expect_probed "appb-443s.${BASE}/healthz" \
  && expect_cname "$ADDR_SWITCH" "$(addr_side b)" && ok

t "switch: an explicit --probe-url is respected on 404"
health "custom.example /readyz 404"
run PLATFORM_BASE=$BASE -- switch b --yes --probe-url https://custom.example/readyz
expect_fail && expect_no_out "predates readiness gating" && expect_no_writes && ok

t "switch: gate 2 refuses a side in another cluster"
echo "prod5.phala.network" >"$S/cluster.appb"
run PLATFORM_BASE=$BASE -- switch b --yes
expect_fail && expect_out "refusing to switch" && expect_no_writes && ok

t "switch: refuses without PLATFORM_BASE"
run -- switch b --yes
expect_fail && expect_out "set PLATFORM_BASE" && expect_not_probed && expect_no_writes && ok

t "switch: refuses without PLATFORM_BASE even with --probe-url"
run -- switch b --yes --probe-url https://custom.example/readyz
expect_fail && expect_out "set PLATFORM_BASE" && expect_no_writes && ok

t "switch: refuses when the serving alias is on another cluster"
run PLATFORM_BASE=prod5.phala.network -- switch b --yes
expect_fail && expect_out "is not on PLATFORM_BASE=prod5.phala.network" && expect_not_probed && expect_no_writes && ok

t "switch: runs before setup (no serving alias yet)"
drop "$ALIAS"
run PLATFORM_BASE=$BASE -- switch b --yes --no-verify
expect_rc 0 && expect_cname "$ADDR_SWITCH" "$(addr_side b)" && ok

t "switch: refuses when the traffic switch points at neither side"
jq --arg n "$ADDR_SWITCH" 'map(if .name==$n then .content="elsewhere.example" else . end)' "$S/records.json" >"$S/r.tmp" && mv "$S/r.tmp" "$S/records.json"
run PLATFORM_BASE=$BASE -- switch b --yes
expect_fail && expect_out "unrecognized target" && expect_no_writes && ok

t "switch: rolls back when the new side never turns healthy"
health "public:appb /healthz 500"
run PLATFORM_BASE=$BASE -- switch b --yes
expect_fail && expect_out "AUTO-ROLLBACK" && expect_out "never became healthy" \
  && expect_cname "$ADDR_SWITCH" "$(addr_side a)" && expect_cname "$ACME_SWITCH" "$(acme_side a)" && ok

t "switch: rolls back when the old cert keeps being served (route cache)"
echo appa >"$S/stale"
run PLATFORM_BASE=$BASE -- switch b --yes
expect_fail && expect_out "still serving a's cert" && expect_out "AUTO-ROLLBACK" \
  && expect_cname "$ADDR_SWITCH" "$(addr_side a)" && ok

t "switch: from no live side, a failed verify has nothing to roll back to"
drop "$ADDR_SWITCH"
health "public:appb /healthz 500"
run PLATFORM_BASE=$BASE -- switch b --yes
expect_fail && expect_out "no previous side to roll back to" && expect_cname "$ADDR_SWITCH" "$(addr_side b)" && ok

t "switch: from no live side, /healthz alone verifies"
drop "$ADDR_SWITCH"
run PLATFORM_BASE=$BASE -- switch b --yes
expect_rc 0 && expect_out "public health OK after switch to b" && ok

t "switch: --no-verify skips the post-switch check"
health "public:appb /healthz 500"
run PLATFORM_BASE=$BASE -- switch b --yes --no-verify
expect_rc 0 && expect_out "verification skipped" && expect_cname "$ADDR_SWITCH" "$(addr_side b)" && ok

t "switch: --dry-run changes nothing"
run PLATFORM_BASE=$BASE -- switch b --dry-run
expect_rc 0 && expect_out "[dry-run] update ${ADDR_SWITCH}" && expect_no_writes && ok

t "switch: refuses non-interactively without --yes"
run PLATFORM_BASE=$BASE -- switch b </dev/null
expect_fail && expect_out "without --yes" && expect_no_writes && ok

t "rollback: flips to the other side, read from DNS"
run PLATFORM_BASE=$BASE -- rollback --yes
expect_rc 0 && expect_out "rolling back: a -> b" && expect_cname "$ADDR_SWITCH" "$(addr_side b)" && ok

t "rollback: ignores --probe-url and probes the target side itself"
run PLATFORM_BASE=$BASE -- rollback --yes --probe-url https://custom.example/readyz
expect_rc 0 && expect_probed "appb-443s.${BASE}/readyz" && ok

t "rollback: refuses without PLATFORM_BASE"
run -- rollback --yes
expect_fail && expect_out "set PLATFORM_BASE" && expect_no_writes && ok

t "rollback: refuses when no side is live"
drop "$ADDR_SWITCH"
run PLATFORM_BASE=$BASE -- rollback --yes
expect_fail && expect_out "points at neither side" && expect_no_writes && ok

t "acme: moves only the issuance switch"
run -- acme b --yes
expect_rc 0 && expect_cname "$ACME_SWITCH" "$(acme_side b)" && expect_cname "$ADDR_SWITCH" "$(addr_side a)" \
  && expect_not_probed && ok

t "env file: values load, the real environment wins"
echo "PLATFORM_BASE=prod5.phala.network" >"$S/env"
echo "export TTL=30" >>"$S/env"
run PLATFORM_BASE=$BASE -- status
expect_rc 0 && expect_no_out "name different clusters" && expect_out "https://appb-443s.${BASE}/readyz" && ok

t "unknown command and flag are refused"
run -- frobnicate
if expect_fail && expect_out "unknown command"; then
  run -- status --frob
  expect_fail && expect_out "unknown flag" && ok
fi

echo
echo "passed: $PASS  failed: $FAIL"
[ "$FAIL" = 0 ]
