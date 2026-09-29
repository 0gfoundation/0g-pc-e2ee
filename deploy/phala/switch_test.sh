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
#   cluster.<app>  the cluster that app lives in (in1.phala.network if absent)
#   down.<base>    if present, that whole cluster is unreachable
#   cert.<app>     days of validity left on that app's cert (80 if absent)
#
# Routing follows dstack. A connection to the public name goes to the cluster the
# serving alias names (`_.<base>`); that cluster's gateway follows the traffic
# switch to a per-side TXT and can only route the app if it lives in that same
# cluster. A per-side probe host `<app_id>-443s.<base>` is routed by the app_id in
# the hostname, so it answers only when <base> is that app's cluster. Both are
# re-read from the state directory on every request.
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

# The routing model both fakes share, sourced by each.
cat >"$WORK/bin/fakeworld" <<'FAKE_WORLD'
S="$FAKE_DIR"
rec() { # name type -> first content at that name
  jq -r --arg n "$1" --arg t "$2" '.[] | select(.name==$n and .type==$t) | .content' "$S/records.json" | head -n1
}
home_of() { cat "$S/cluster.$1" 2>/dev/null || echo in1.phala.network; }
is_down() { [ -f "$S/down.$1" ]; }

# The app a connection to the public name reaches, or nothing: the serving alias
# picks the cluster, that cluster's gateway looks up the traffic switch, and it
# can only route an app that lives in its own cluster.
public_app() {
  local alias base tgt app
  alias="$(rec "$FAKE_ALIAS" CNAME)"; base="${alias#_.}"
  [ -n "$alias" ] && [ "$alias" != "$base" ] || return 0
  is_down "$base" && return 0
  if [ -f "$S/stale" ]; then app="$(cat "$S/stale")"
  else
    tgt="$(rec "$FAKE_ADDR_SWITCH" CNAME)"
    [ -n "$tgt" ] || return 0
    app="$(rec "$tgt" TXT | sed 's/^"//; s/"$//; s/:.*//')"
  fi
  [ -n "$app" ] && [ "$(home_of "$app")" = "$base" ] && echo "$app"
  return 0
}

# The app `<app_id>-443s.<base>` reaches: routed by the id in the hostname, so
# only the cluster has to match.
side_app() { # host
  local app="${1%%-443s.*}" base="${1#*-443s.}"
  is_down "$base" && return 0
  [ "$(home_of "$app")" = "$base" ] && echo "$app"
  return 0
}

app_for_host() { # host
  if [ "$1" = "$FAKE_DOMAIN" ]; then public_app
  elif [[ "$1" == *-443s.* ]]; then side_app "$1"
  fi
}
FAKE_WORLD

cat >"$WORK/bin/curl" <<'FAKE_CURL'
#!/usr/bin/env bash
set -euo pipefail
# shellcheck disable=SC1091
. "$(dirname "$0")/fakeworld"
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
    app="$(app_for_host "$host")"
    if [ -n "$app" ]; then
      if [ "$host" = "$FAKE_DOMAIN" ]; then code="$(scripted "public:$app" "$hpath" 200)"
      else code="$(scripted "$host" "$hpath" 200)"; fi
    fi
    echo "$(date +%s) $host$hpath $code" >>"$S/http.log"
    [ -n "$wfmt" ] && printf '%s' "$code"
    [ "$code" != 000 ] || exit 7
    ;;
  *) echo "fake curl: unexpected url '$url'" >&2; exit 2 ;;
esac
FAKE_CURL

# `echo | openssl s_client -connect <host>:443 … | openssl x509 …` — the cert is
# whichever app that host reaches. Its remaining validity is `cert.<app_id>`
# days (80 unless set), which is what -enddate prints and -checkend tests.
cat >"$WORK/bin/openssl" <<'FAKE_OPENSSL'
#!/usr/bin/env bash
set -euo pipefail
# shellcheck disable=SC1091
. "$(dirname "$0")/fakeworld"
case "${1:-}" in
  s_client)
    cat >/dev/null
    host=""
    while [ $# -gt 0 ]; do [ "$1" = -connect ] && host="${2%:*}"; shift; done
    app="$(app_for_host "$host")"
    [ -n "$app" ] || exit 1
    echo "CERT $app" ;;
  x509)
    read -r _ app || exit 1
    [ -n "${app:-}" ] || exit 1   # no certificate on stdin, as real openssl would fail
    days="$(cat "$S/cert.$app" 2>/dev/null || echo 80)"
    shift
    while [ $# -gt 0 ]; do
      case "$1" in
        -fingerprint) echo "sha256 Fingerprint=FP:${app}" ;;
        -enddate) echo "notAfter=in ${days} days (fake)" ;;
        -checkend) [ $((days * 86400)) -gt "$2" ] || { echo "Certificate will expire"; exit 1; }
                   echo "Certificate will not expire"; shift ;;
      esac
      shift
    done ;;
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
# Repoint the CNAME at a name.
point() { jq --arg n "$1" --arg c "$2" 'map(if .name==$n and .type=="CNAME" then .content=$c else . end)' "$S/records.json" >"$S/r.tmp" && mv "$S/r.tmp" "$S/records.json"; }
# Side b in a second cluster; X is the matching config.
BB=prod5.phala.network
X=("PLATFORM_BASE_A=$BASE" "PLATFORM_BASE_B=$BB")
cross() { echo "$BB" >"$S/cluster.appb"; }
# The state a completed cross-cluster move to b leaves.
on_b() { cross; point "$ADDR_SWITCH" "$(addr_side b)"; point "$ACME_SWITCH" "$(acme_side b)"; point "$ALIAS" "_.${BB}"; }
health() { echo "$*" >>"$S/health"; }

# run [VAR=val …] -- switch.sh args…   → sets OUT and RC
run() {
  local envs=()
  while [ "$1" != "--" ]; do envs+=("$1"); shift; done
  shift
  set +e
  OUT="$(env -i PATH="$WORK/bin:$PATH" HOME="$WORK" \
    FAKE_DIR="$S" FAKE_DOMAIN="$DOMAIN" FAKE_ADDR_SWITCH="$ADDR_SWITCH" FAKE_ALIAS="$ALIAS" \
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
expect_writes() { # expected write lines, in order, and nothing else
  local want; want="$(printf '%s\n' "$@")"
  [ "$(cat "$S/writes.log")" = "$want" ] || { fail "writes were: $(tr '\n' ';' <"$S/writes.log") want: $(tr '\n' ';' <<<"$want")"; return 1; }
}
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

t "status: shows each side's cluster and certificate"
cross
run "${X[@]}" -- status
expect_rc 0 && expect_out "cluster=${BASE}" && expect_out "cluster=${BB}" \
  && expect_out "probe=https://appb-443s.${BB}/readyz" && expect_out "cert  : OK   expires in 80 days" && ok

t "status: a standby cert close to expiry says how to renew it"
echo 10 >"$S/cert.appb"
run PLATFORM_BASE=$BASE -- status
expect_rc 0 && expect_out "cert  : SOON expires in 10 days" && expect_out "it cannot renew: issuance points at a" \
  && expect_out "acme b, wait for it to issue, then" && ok

t "status: the live side close to expiry points at its own renewal"
echo 10 >"$S/cert.appa"
run PLATFORM_BASE=$BASE -- status
expect_rc 0 && expect_out "it should be renewing" && ok

t "status: a side in a down cluster has an unreadable cert"
cross; touch "$S/down.${BB}"
run "${X[@]}" -- status
expect_rc 0 && expect_out "cert  : unreadable" && ok

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

t "status: warns when the alias is not on the live side's cluster (split state)"
run PLATFORM_BASE=prod5.phala.network -- status
expect_rc 0 && expect_out "split state: the serving alias ${ALIAS} -> _.${BASE}, but side a runs on _.prod5.phala.network" \
  && expect_out "failover a" && ok

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

t "switch: refuses when the serving alias is not on the live side's cluster"
run PLATFORM_BASE=prod5.phala.network -- switch b --yes
expect_fail && expect_out "side a is not reachable now" && expect_out "failover <a|b>" \
  && expect_not_probed && expect_no_writes && ok

t "switch: runs before setup, and creates the serving alias"
drop "$ALIAS"
run PLATFORM_BASE=$BASE -- switch b --yes --no-verify
expect_rc 0 && expect_cname "$ADDR_SWITCH" "$(addr_side b)" && expect_cname "$ALIAS" "_.${BASE}" && ok

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

t "switch: within one cluster, the serving alias is not written"
run PLATFORM_BASE=$BASE -- switch b --yes
expect_rc 0 && expect_writes "PUT ${ACME_SWITCH} CNAME $(acme_side b)" "PUT ${ADDR_SWITCH} CNAME $(addr_side b)" && ok

t "switch: refuses without a cluster for every side"
run PLATFORM_BASE_A=$BASE -- switch b --yes
expect_fail && expect_out "set PLATFORM_BASE" && expect_no_writes && ok

t "cross-cluster switch: probes b on its own cluster, then moves issuance, traffic, alias"
cross
run "${X[@]}" -- switch b --yes
expect_rc 0 && expect_probed "appb-443s.${BB}/readyz" && expect_out "cross-cluster: the serving alias moves _.${BASE} -> _.${BB}" \
  && expect_writes "PUT ${ACME_SWITCH} CNAME $(acme_side b)" "PUT ${ADDR_SWITCH} CNAME $(addr_side b)" "PUT ${ALIAS} CNAME _.${BB}" \
  && expect_out "now served by b (cert changed)" && ok

t "cross-cluster switch: gate 2 fails when b is not in the cluster configured for it"
cross
run PLATFORM_BASE=$BASE -- switch b --yes
expect_fail && expect_out "refusing to switch" && expect_no_writes && ok

t "cross-cluster switch: auto-rollback restores the serving alias too"
cross
health "public:appb /healthz 500"
run "${X[@]}" -- switch b --yes
expect_fail && expect_out "AUTO-ROLLBACK" && expect_cname "$ADDR_SWITCH" "$(addr_side a)" \
  && expect_cname "$ALIAS" "_.${BASE}" && expect_cname "$ACME_SWITCH" "$(acme_side a)" && ok

t "cross-cluster rollback: moves traffic and alias back to a"
on_b
run "${X[@]}" -- rollback --yes
expect_rc 0 && expect_cname "$ADDR_SWITCH" "$(addr_side a)" && expect_cname "$ALIAS" "_.${BASE}" && ok

t "switch: completes a move left split between its writes"
cross; point "$ADDR_SWITCH" "$(addr_side b)"   # traffic names b, alias still on a's cluster
run "${X[@]}" -- switch b --yes
expect_rc 0 && expect_out "split state" && expect_writes "PUT ${ACME_SWITCH} CNAME $(acme_side b)" "PUT ${ALIAS} CNAME _.${BB}" \
  && expect_no_out "AUTO-ROLLBACK" && ok

t "switch: refuses to leave a split state for the other side"
cross; point "$ALIAS" "_.${BB}"   # traffic on a, alias on b's cluster
run "${X[@]}" -- switch b --yes
expect_fail && expect_out "side a is not reachable now" && expect_no_writes && ok

t "setup: follows the live side's cluster"
cross; on_b; drop "$ALIAS"
run "${X[@]}" -- setup --yes
expect_rc 0 && expect_cname "$ALIAS" "_.${BB}" && ok

t "setup: refuses to point the alias away from the live side"
cross
run "${X[@]}" -- setup b --yes
expect_fail && expect_out "would strand it" && expect_no_writes && ok

t "setup: with no live side and two clusters, the side must be named"
cross; drop "$ADDR_SWITCH"; drop "$ALIAS"
run "${X[@]}" -- setup --yes
if expect_fail && expect_out "name the one to serve from"; then
  run "${X[@]}" -- setup b --yes
  expect_rc 0 && expect_cname "$ALIAS" "_.${BB}" && ok
fi

t "failover: to b while a's whole cluster is down"
cross; touch "$S/down.${BASE}"
run "${X[@]}" -- failover b --yes
expect_rc 0 && expect_out "verifying /healthz only" && expect_out "public health OK after switch to b" \
  && expect_cname "$ADDR_SWITCH" "$(addr_side b)" && expect_cname "$ALIAS" "_.${BB}" && expect_cname "$ACME_SWITCH" "$(acme_side b)" && ok

t "failover: a failed verify does not roll back"
cross; touch "$S/down.${BASE}"
health "public:appb /healthz 500"
run "${X[@]}" -- failover b --yes
expect_fail && expect_out "NOT rolling back" && expect_no_out "AUTO-ROLLBACK" \
  && expect_cname "$ADDR_SWITCH" "$(addr_side b)" && expect_cname "$ALIAS" "_.${BB}" && ok

t "failover: still refuses a target that is not ready"
cross; touch "$S/down.${BASE}"
health "appb-443s.${BB} /readyz 503"
run "${X[@]}" -- failover b --yes
expect_fail && expect_out "refusing to switch" && expect_no_writes && ok

t "failover: to the side already live and consistent is a no-op"
run "${X[@]}" -- failover a --yes
expect_rc 0 && expect_out "nothing to do" && expect_no_writes && ok

t "failover: overwrites an unrecognized traffic switch"
cross; point "$ADDR_SWITCH" "elsewhere.example"
run "${X[@]}" -- failover b --yes
expect_rc 0 && expect_out "overwriting it" && expect_cname "$ADDR_SWITCH" "$(addr_side b)" && ok

t "failover: same cluster, a still up — the cert check still applies"
run PLATFORM_BASE=$BASE -- failover b --yes
expect_rc 0 && expect_out "now served by b (cert changed)" && ok

t "failover: --dry-run changes nothing"
cross; touch "$S/down.${BASE}"
run "${X[@]}" -- failover b --dry-run
expect_rc 0 && expect_out "[dry-run] update ${ALIAS} CNAME -> _.${BB}" && expect_no_writes && ok

t "rollback: after a failover, refuses while a's cluster is still down"
on_b; touch "$S/down.${BASE}"
run "${X[@]}" -- rollback --yes
expect_fail && expect_out "refusing to switch" && expect_no_writes && ok

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
