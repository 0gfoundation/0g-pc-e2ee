#!/usr/bin/env bash
#
# deploy-side_test.sh — offline tests for deploy-side.sh.
#
# deploy-side.sh talks to Phala Cloud (the `phala` CLI), to the delegation zone's
# nameserver (`dig`), and to the new side over HTTPS (`curl`, `openssl`). This file
# puts fakes for all four first on PATH, modelled from a small state directory:
#
#   dns/<TYPE>/<name>  the answer the nameserver gives for that record
#   cvms.json          the account's CVMs, as `phala cvms list --json` items
#   deploy.args        written by the fake `phala deploy`: one argument per line
#   deploy.env         written by it too: the env file it was handed
#   deploy.cwd         and the files in the directory it ran in
#   cluster            the cluster a created CVM lands in (in1.phala.network if absent)
#   readyz             the status /readyz answers (200 if absent)
#   release            the tag /v1/gateway/identity reports as matched_release
#   cert_bad           if present, the side serves no valid certificate
#
# `phala deploy` stands in for the new CVM's ingress too: it publishes the side's
# app-address TXT and serving CNAME at once, as a booted ingress would.
#
# Run: ./deploy/phala/deploy-side_test.sh   (needs bash, jq)
set -euo pipefail

HERE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
DEPLOY="${HERE}/deploy-side.sh"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

DOMAIN=router-api.0g.ai
DZ=integratenetwork.work
BASE=in1.phala.network
OLD_A=1111111111111111111111111111111111111111
OLD_B=2222222222222222222222222222222222222222
NEW_APP=abcdefabcdefabcdefabcdefabcdefabcdefabcd

# ---------------------------------------------------------------------------
# Fakes
# ---------------------------------------------------------------------------
mkdir -p "$WORK/bin"

cat >"$WORK/bin/dig" <<'FAKE_DIG'
#!/usr/bin/env bash
# dig +short NS <zone>  |  dig +short @<ns> <TYPE> <name>
set -euo pipefail
args=()
for a in "$@"; do case "$a" in +short|@*) ;; *) args+=("$a") ;; esac; done
if [ "${args[0]}" = NS ]; then echo "ns1.fake-dns.test."; exit 0; fi
f="$FAKE_DIR/dns/${args[0]}/${args[1]}"
[ -f "$f" ] || exit 0
case "${args[0]}" in
  TXT)   printf '"%s"\n' "$(cat "$f")" ;;
  CNAME) printf '%s.\n' "$(cat "$f")" ;;
esac
FAKE_DIG

cat >"$WORK/bin/phala" <<'FAKE_PHALA'
#!/usr/bin/env bash
set -euo pipefail
S="$FAKE_DIR"
case "$1 ${2:-}" in
  "cvms list")
    search=""
    while [ $# -gt 0 ]; do [ "$1" = --search ] && search="$2"; shift; done
    jq --arg q "$search" '{success: true, items: [.[] | select((.cvmName | contains($q)) or (.appId | contains($q)))]}' "$S/cvms.json"
    ;;
  "deploy --json")
    printf '%s\n' "$@" >"$S/deploy.args"
    env=""; name=""
    while [ $# -gt 0 ]; do
      case "$1" in -e) env="$2" ;; -n) name="$2" ;; esac; shift
    done
    cp "$env" "$S/deploy.env"
    ls -A >"$S/deploy.cwd"
    app="${FAKE_NEW_APP}"
    jq --arg n "$name" --arg a "app_${app}" '. + [{appId: $a, cvmName: $n, status: "running"}]' \
      "$S/cvms.json" >"$S/cvms.tmp" && mv "$S/cvms.tmp" "$S/cvms.json"
    # The ingress, booting: it writes into the delegation zone it was given.
    dz="$(sed -n "s/^DELEGATION_ZONE='\(.*\)'$/\1/p" "$env")"
    dom="$(sed -n "s/^DOMAIN='\(.*\)'$/\1/p" "$env")"
    mkdir -p "$S/dns/TXT" "$S/dns/CNAME"
    echo "${app}:443" >"$S/dns/TXT/_dstack-app-address.${dom}.${dz}"
    echo "_.$(cat "$S/cluster" 2>/dev/null || echo in1.phala.network)" >"$S/dns/CNAME/${dom}.${dz}"
    echo "Provisioning CVM ${name}..."
    printf '{\n  "success": true,\n  "vm_uuid": "u-1",\n  "name": "%s",\n  "app_id": "app_%s"\n}\n' "$name" "$app"
    ;;
  *) echo "fake phala: unexpected: $*" >&2; exit 2 ;;
esac
FAKE_PHALA

cat >"$WORK/bin/curl" <<'FAKE_CURL'
#!/usr/bin/env bash
set -euo pipefail
S="$FAKE_DIR"
url="" wfmt=""
while [ $# -gt 0 ]; do
  case "$1" in -w) wfmt="$2"; shift ;; -o|--max-time) shift ;; -*) ;; *) url="$1" ;; esac
  shift
done
host="${url#https://}"; path="/${host#*/}"; host="${host%%/*}"
app="${host%%-443s.*}"; base="${host#*-443s.}"
cluster="$(cat "$S/cluster" 2>/dev/null || echo in1.phala.network)"
[ "$base" = "$cluster" ] || { [ -n "$wfmt" ] && printf 000; exit 0; }
case "$path" in
  /readyz) printf '%s' "$(cat "$S/readyz" 2>/dev/null || echo 200)" ;;
  /v1/gateway/identity)
    jq -n --arg a "$app" --arg r "$(cat "$S/release" 2>/dev/null || true)" \
      '{app_id: $a, compose_hash: "c0ffee", matched_release: (if $r == "" then null else {tag: $r} end)}' ;;
  *) printf 404 ;;
esac
FAKE_CURL

cat >"$WORK/bin/openssl" <<'FAKE_OPENSSL'
#!/usr/bin/env bash
set -euo pipefail
case "$1" in
  s_client) cat >/dev/null; echo "-----BEGIN CERTIFICATE-----" ;;
  x509)
    cat >/dev/null
    [ -f "$FAKE_DIR/cert_bad" ] && exit 1
    prev=""
    for a in "$@"; do
      [ "$prev" = -checkhost ] && echo "Hostname $a does match certificate"
      prev="$a"
    done ;;
esac
FAKE_OPENSSL
chmod +x "$WORK/bin/"*

# ---------------------------------------------------------------------------
# Harness
# ---------------------------------------------------------------------------
PASS=0 FAIL=0
S=""
COMPOSE="$WORK/docker-compose.release.yml"
cat >"$COMPOSE" <<'EOF'
services:
  gateway:
    image: ghcr.io/0gfoundation/0g-pc-e2ee-gateway@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
  cvm-identity:
    image: ghcr.io/0gfoundation/0g-pc-e2ee-gateway@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
EOF

record() { # TYPE name content
  mkdir -p "$S/dns/$1"; printf '%s\n' "$3" >"$S/dns/$1/$2"
}

# A deployment with a live on a and b's CVM already deleted: b's record still names
# its old app_id, and issuance has been aimed at b.
fresh() {
  S="$(mktemp -d "$WORK/state.XXXX")"
  record CNAME "_dstack-app-address.${DOMAIN}.${DZ}" "_dstack-app-address.${DOMAIN}.a.${DZ}"
  record CNAME "_acme-challenge.${DOMAIN}.${DZ}" "_acme-challenge.${DOMAIN}.b.${DZ}"
  record TXT "_dstack-app-address.${DOMAIN}.a.${DZ}" "${OLD_A}:443"
  record TXT "_dstack-app-address.${DOMAIN}.b.${DZ}" "${OLD_B}:443"
  echo "[{\"appId\": \"app_${OLD_A}\", \"cvmName\": \"gw-mainnet-a\", \"status\": \"running\"}]" >"$S/cvms.json"
  echo release-2026.10.28.1 >"$S/release"
  EXTRA_ENV=()
}

# Extra assignments for the next run (CVM_ENV_* keys, overrides); fresh clears them.
EXTRA_ENV=()

OUT="" ERR="" RC=0
run() { # args…
  RC=0
  OUT="$(env -i PATH="$WORK/bin:$PATH" HOME="$WORK" SECRETS_ENV=/nonexistent FAKE_DIR="$S" FAKE_NEW_APP="$NEW_APP" \
    DOMAIN="$DOMAIN" DELEGATION_ZONE="$DZ" PLATFORM_BASE="_.${BASE}" \
    CVM_NAME_PREFIX=gw-mainnet PHALA_INSTANCE_TYPE=tdx.4xlarge PHALA_NODE_ID=7 \
    CLOUDFLARE_API_TOKEN=cf-secret ZG_PROM_ENV=mainnet ZG_PROM_REMOTE_WRITE_URL=https://prom.test/w \
    ZG_PROM_REMOTE_WRITE_USERNAME=gw ZG_PROM_REMOTE_WRITE_PASSWORD='p#ss word' \
    "${EXTRA_ENV[@]}" POLL_INTERVAL=0 WAIT_PUBLISH=1 WAIT_READY=1 WAIT_IDENTITY=1 \
    bash "$DEPLOY" "$@" 2>"$WORK/err")" || RC=$?
  ERR="$(cat "$WORK/err")"
}

ok()  { PASS=$((PASS + 1)); printf 'ok   %s\n' "$1"; }
bad() { FAIL=$((FAIL + 1)); printf 'FAIL %s\n' "$1"; printf '  rc=%s\n  stdout: %s\n  stderr:\n%s\n' "$RC" "$OUT" "$ERR" | sed 's/^/    /'; }
check()       { local what="$1"; shift; if "$@"; then ok "$what"; else bad "$what"; fi; }
check_not()   { local what="$1"; shift; if "$@"; then bad "$what"; else ok "$what"; fi; }
err_has()     { grep -qF -- "$1" <<<"$ERR"; }
expect_rc()   { check "$1" [ "$RC" = "$2" ]; }
expect_err()  { if [ "$RC" != 0 ] && err_has "$2"; then ok "$1"; else bad "$1"; fi; }
not_created() { check "$1: nothing created" [ ! -f "$S/deploy.args" ]; }

# ---------------------------------------------------------------------------
# Preflight
# ---------------------------------------------------------------------------
fresh; run b --compose "$COMPOSE" --release release-2026.10.28.1 --dry-run
expect_rc "dry run on the standby passes" 0
not_created "dry run"
check "dry run shows the pinned node" err_has "--node-id 7"
check_not "dry run prints no secret value" grep -q 'cf-secret\|p#ss' <<<"$ERR$OUT"

fresh; run a --compose "$COMPOSE" --yes
expect_err "refuses the live side" "side a is live"
not_created "live side"

fresh; record CNAME "_dstack-app-address.${DOMAIN}.${DZ}" "elsewhere.example"
run b --compose "$COMPOSE" --yes
expect_err "refuses an unrecognized traffic switch" "unrecognized target"

fresh; echo '[{"appId": "app_9999999999999999999999999999999999999999", "cvmName": "gw-mainnet-b", "status": "stopped"}]' >"$S/cvms.json"
run b --compose "$COMPOSE" --yes
expect_err "refuses when a CVM with the side's name exists" "gw-mainnet-b app_id=9999"
not_created "existing name"

fresh; echo "[{\"appId\": \"app_${OLD_B}\", \"cvmName\": \"renamed-by-hand\", \"status\": \"running\"}]" >"$S/cvms.json"
run b --compose "$COMPOSE" --yes
expect_err "refuses when the side's published app_id still has a CVM" "renamed-by-hand app_id=${OLD_B}"
not_created "existing app_id"

fresh; record CNAME "_acme-challenge.${DOMAIN}.${DZ}" "_acme-challenge.${DOMAIN}.a.${DZ}"
run b --compose "$COMPOSE" --yes
expect_err "refuses when issuance does not point at the side" "run switch.sh acme b first"
not_created "issuance elsewhere"
run b --compose "$COMPOSE" --dry-run
expect_rc "…but a dry run only warns" 0

fresh; sed 's/@sha256:a*/:latest/' "$COMPOSE" >"$WORK/floating.yml"
run b --compose "$WORK/floating.yml" --yes
expect_err "refuses a compose with a floating gateway tag" "not pinned by digest"

fresh; run c --compose "$COMPOSE" --yes
expect_err "refuses side c without a cold cluster" "set PLATFORM_BASE_COLD"

fresh; EXTRA_ENV=(CVM_ENV_ZG_GATEWAY_NETWORK=testnet CVM_ENV_DNS_SETUP_MODE=wait)
run b --compose "$COMPOSE" --yes
expect_err "CVM_ENV_* cannot override a fixed key" "DNS_SETUP_MODE is set by this script"
not_created "override"

fresh; EXTRA_ENV=(CVM_ENV_GOMEMLIMIT=1GiB CVM_SECRET_ENV=$'GOMEMLIMIT=2GiB')
run b --compose "$COMPOSE" --yes
expect_err "CVM_SECRET_ENV cannot repeat a CVM_ENV_ key" "CVM_SECRET_ENV: GOMEMLIMIT is already set"
not_created "secret repeat"
fresh; EXTRA_ENV=(CVM_SECRET_ENV=$'DOMAIN=evil.example')
run b --compose "$COMPOSE" --yes
expect_err "CVM_SECRET_ENV cannot override a fixed key" "CVM_SECRET_ENV: DOMAIN is already set"
check_not "…and the error does not print the line" err_has "evil.example"

fresh; EXTRA_ENV=(CVM_REQUIRED_KEYS=ZG_GATEWAY_ROUTER_URL)
run b --compose "$COMPOSE" --dry-run
expect_err "a required key nothing sets is refused, even in a dry run" "ZG_GATEWAY_ROUTER_URL is required"
fresh; EXTRA_ENV=(CVM_REQUIRED_KEYS=ZG_GATEWAY_ROUTER_URL CVM_SECRET_ENV=ZG_GATEWAY_ROUTER_URL=https://hidden.test)
run b --compose "$COMPOSE" --dry-run
expect_rc "…and accepted once CVM_SECRET_ENV sets it" 0
fresh; EXTRA_ENV=(CVM_REQUIRED_KEYS=ZG_GATEWAY_ALLOWED_ORIGINS CVM_ENV_ZG_GATEWAY_ALLOWED_ORIGINS=)
run b --compose "$COMPOSE" --dry-run
expect_err "a required key mapped from an unset secret (empty) is refused" "ZG_GATEWAY_ALLOWED_ORIGINS is required"

fresh; EXTRA_ENV=(PHALA_INSTANCE_TYPE=CHANGEME CVM_ENV_ZG_GATEWAY_ROUTER_URL=CHANGEME)
run b --compose "$COMPOSE" --dry-run
expect_err "refuses placeholders, naming each" "still CHANGEME in the config: PHALA_INSTANCE_TYPE CVM_ENV_ZG_GATEWAY_ROUTER_URL"

fresh; run b --compose "$COMPOSE"
expect_err "refuses to create non-interactively without --yes" "without --yes"

# ---------------------------------------------------------------------------
# Create and wait
# ---------------------------------------------------------------------------
fresh; EXTRA_ENV=(CVM_ENV_ZG_GATEWAY_NETWORK=testnet CVM_ENV_GOMEMLIMIT=1GiB
  CVM_SECRET_ENV=$'# kept out of git\nZG_GATEWAY_ROUTER_URL=https://hidden.test')
run b --compose "$COMPOSE" --release release-2026.10.28.1 --yes
expect_rc "creates side b and waits for it" 0
check "prints app_id and url on stdout" \
  [ "$OUT" = $'app_id='"$NEW_APP"$'\nurl=https://'"$NEW_APP"'-443s.'"$BASE" ]
check "the env file has exactly the fixed keys, the CVM_ENV_ ones by name, then CVM_SECRET_ENV's" \
  [ "$(cut -d= -f1 "$S/deploy.env" | tr '\n' ' ')" = "DOMAIN DELEGATION_ZONE DNS_SETUP_MODE CLOUDFLARE_API_TOKEN ZG_PROM_ENV ZG_PROM_REMOTE_WRITE_URL ZG_PROM_REMOTE_WRITE_USERNAME ZG_PROM_REMOTE_WRITE_PASSWORD GOMEMLIMIT ZG_GATEWAY_NETWORK ZG_GATEWAY_ROUTER_URL " ]
check "DELEGATION_ZONE is the side's sub-zone" grep -qx "DELEGATION_ZONE='b.${DZ}'" "$S/deploy.env"
check "a CVM_SECRET_ENV value reaches the env file" grep -qx "ZG_GATEWAY_ROUTER_URL='https://hidden.test'" "$S/deploy.env"
check_not "…and is never printed" grep -q hidden.test <<<"$ERR$OUT"
check "DNS_SETUP_MODE is print" grep -qx "DNS_SETUP_MODE='print'" "$S/deploy.env"
check "a value with # and a space survives, quoted" grep -qx "ZG_PROM_REMOTE_WRITE_PASSWORD='p#ss word'" "$S/deploy.env"
check_not "ACME_STAGING is not passed" grep -q ACME_STAGING "$S/deploy.env"
check_not "never passes --cvm-id" grep -qx -- --cvm-id "$S/deploy.args"
check "runs the CLI from an empty directory" [ ! -s "$S/deploy.cwd" ]
check "names the CVM <prefix>-<side>" grep -qx gw-mainnet-b "$S/deploy.args"
check "with the configured shape" grep -qx tdx.4xlarge "$S/deploy.args"

fresh; echo in2.phala.network >"$S/cluster"
run b --compose "$COMPOSE" --yes
expect_err "fails at once when the side lands in another cluster" "want _.${BASE}"
check_not "…without waiting out the timeout" err_has "gave up after"

fresh; echo 503 >"$S/readyz"
run b --compose "$COMPOSE" --yes
expect_err "fails when /readyz never answers 200" "/readyz answered 503"

fresh; touch "$S/cert_bad"
run b --compose "$COMPOSE" --yes
expect_err "fails when the side has no certificate for DOMAIN" "no valid certificate"

fresh; echo release-2026.10.27.1 >"$S/release"
run b --compose "$COMPOSE" --release release-2026.10.28.1 --yes
expect_err "fails when the side matches a different release" "not release-2026.10.28.1"

fresh; : >"$S/release"
run b --compose "$COMPOSE" --release release-2026.10.28.1 --yes
expect_err "fails when matched_release never settles" "matched_release not reported"

# ---------------------------------------------------------------------------
# The checked-in config (env/*.env)
# ---------------------------------------------------------------------------
# Public files: a secret's key in one is a secret about to be committed. And every
# key must be one the scripts read, so a typo does not silently fall back to a
# default.
SECRET_KEYS=" CF_API_TOKEN CLOUDFLARE_API_TOKEN ZG_PROM_REMOTE_WRITE_URL ZG_PROM_REMOTE_WRITE_USERNAME ZG_PROM_REMOTE_WRITE_PASSWORD PHALA_CLOUD_API_KEY SMOKE_API_KEY CVM_SECRET_ENV CVM_ENV_ZG_GATEWAY_ALLOWED_ORIGINS "
KNOWN_KEYS=" CVM_REQUIRED_KEYS DOMAIN CF_ZONE DELEGATION_ZONE PLATFORM_BASE PLATFORM_BASE_COLD CVM_NAME_PREFIX PHALA_INSTANCE_TYPE PHALA_NODE_ID PHALA_NODE_ID_COLD PHALA_OS_IMAGE ZG_PROM_ENV SMOKE_SEALED_MODEL SMOKE_PLAIN_MODEL "
for f in "$HERE"/env/*.env; do
  name="env/$(basename "$f")"
  keys="$(sed -n 's/^[[:space:]]*\(export[[:space:]]\+\)\?\([A-Za-z_][A-Za-z0-9_]*\)=.*/\2/p' "$f")"
  leaked="" unknown=""
  for k in $keys; do
    [[ "$SECRET_KEYS" == *" $k "* ]] && leaked+=" $k"
    [[ "$KNOWN_KEYS" == *" $k "* || "$k" == CVM_ENV_?* ]] || unknown+=" $k"
  done
  check "${name} holds no secret${leaked:+ (has:$leaked)}" [ -z "$leaked" ]
  check "${name} sets only keys the scripts read${unknown:+ (unknown:$unknown)}" [ -z "$unknown" ]
  # Loaded the way the scripts load it, with nothing else in the environment.
  RC=0
  ERR="$(env -i PATH="$WORK/bin:$PATH" HOME="$WORK" SECRETS_ENV=/nonexistent bash "$DEPLOY" b --env-file "$f" \
    --compose "$COMPOSE" --dry-run 2>&1 >/dev/null)" || RC=$?
  if grep -qE "^[^#]*=CHANGEME$" "$f"; then
    expect_err "${name} loads, and its placeholders are refused" "still CHANGEME"
  else
    expect_err "${name} loads, and only the secrets are missing" "set CLOUDFLARE_API_TOKEN"
  fi
done

# A filled-in config file plus a local secrets.env is a complete configuration.
fresh
sed 's/=CHANGEME$/=filled.example/; s/^PLATFORM_BASE=.*/PLATFORM_BASE=in1.phala.network/' \
  "$HERE/env/mainnet.env" >"$WORK/filled.env"
printf '%s\n' CLOUDFLARE_API_TOKEN=cf-secret ZG_PROM_REMOTE_WRITE_URL=https://prom.test/w \
  ZG_PROM_REMOTE_WRITE_USERNAME=gw ZG_PROM_REMOTE_WRITE_PASSWORD=pw \
  "CVM_ENV_ZG_GATEWAY_ALLOWED_ORIGINS='https://a.test,https://*.b.test'" >"$WORK/secrets.env"
RC=0
ERR="$(env -i PATH="$WORK/bin:$PATH" HOME="$WORK" FAKE_DIR="$S" SECRETS_ENV="$WORK/secrets.env" \
  bash "$DEPLOY" b --env-file "$WORK/filled.env" --compose "$COMPOSE" --dry-run 2>&1 >/dev/null)" || RC=$?
expect_rc "a filled env file and secrets.env are enough for a dry run" 0
check "…and secrets.env was loaded" err_has "loading env from $WORK/secrets.env"

printf '\n%d passed, %d failed\n' "$PASS" "$FAIL"
[ "$FAIL" = 0 ]
