#!/usr/bin/env bash
#
# deploy-side.sh — create one blue/green side of the cloud-TEE gateway as a NEW
# Phala Cloud app from a release compose, and wait until it can serve. It moves no
# traffic: cutting over is still `switch.sh switch <side>`.
#
# WHY A NEW APP, AND WHY THIS SCRIPT REFUSES SO MUCH -------------------------
# A side is a separately CREATED app: that is what gives it its own app_id, and
# the traffic switch flips between app_ids (blue-green.md, "Why blue/green here is a
# DNS pointer flip"). An in-place upgrade keeps the app_id, so the switch record
# still names it and the platform spreads traffic across old and new instances — a
# silent half-cutover. `phala deploy` upgrades instead of creating whenever it is
# given --cvm-id or finds a phala.toml with a cvm_id in the working directory, so
# this script never passes the first and runs the CLI from an empty directory.
#
# Before creating anything it refuses when:
#   - the side is live (the traffic switch points at it);
#   - a CVM named <CVM_NAME_PREFIX>-<side> exists, or one with the app_id the side
#     currently publishes — the previous CVM of this side has not been deleted.
#     `switch.sh status` cannot tell this apart: a deleted CVM and a crashed one
#     both read as "unreachable", and only the second makes a new one unsafe;
#   - the issuance switch does not point at the side. The new side's ingress issues
#     its certificate on first boot, and a dns-01 challenge aimed at the other side
#     fails and burns the 5-failed-validations-per-hour budget, which is per
#     hostname and so shared with the live side (blue-green.md, fast path step 1).
#     Point it with `switch.sh acme <side>` first; the GitHub workflow does.
#   - the compose's gateway images are not pinned by digest (not a release asset).
#
# After creating it waits, all against the side directly and never the served name:
#   1. the side's ingress publishes _dstack-app-address.<DOMAIN>.<side>.<DZ> with
#      the NEW app_id (the old CVM's record stays until then);
#   2. the serving CNAME it publishes, <DOMAIN>.<side>.<DZ>, names the cluster this
#      side is configured for, _.<base> — a side in the wrong cluster is silent
#      under blue/green until the cutover fails (blue-green.md, "Where
#      GATEWAY_DOMAIN does and does not matter"), so this is checked, not eyeballed;
#   3. https://<app_id>-443s.<base> serves a certificate valid for DOMAIN and
#      answers /readyz 200 — the same gate `switch` applies before a cutover, so a
#      side that passes here will not be refused there for readiness;
#   4. /v1/gateway/identity reports the new app_id and, given --release, that
#      release as matched_release.
# A side that fails a check is left running for inspection; delete it before
# retrying.
#
# THE CVM'S ENVIRONMENT ------------------------------------------------------
# Phala builds allowed_envs — part of the measured app-compose — from the keys
# passed here, so the key set is fixed by this script, never by hand:
#   DOMAIN, DELEGATION_ZONE=<side>.<DZ>, DNS_SETUP_MODE=print, CLOUDFLARE_API_TOKEN,
#   ZG_PROM_ENV, ZG_PROM_REMOTE_WRITE_URL, ZG_PROM_REMOTE_WRITE_USERNAME,
#   ZG_PROM_REMOTE_WRITE_PASSWORD
# plus one key per CVM_ENV_<KEY> variable, passed as <KEY> (per-deployment gateway
# overrides: CVM_ENV_ZG_GATEWAY_ROUTER_URL=… reaches the CVM as
# ZG_GATEWAY_ROUTER_URL=…), in name order; and then one per line of
# CVM_SECRET_ENV (KEY=VALUE lines), for a value that should stay out of the
# repository — in the workflow it is a deploy-<target> secret. DNS_SETUP_MODE
# is not configurable: every blue/green side must run `print`, and under the
# default `wait` the ingress blocks on a one-hop CNAME check that never passes.
# The values are encrypted to the CVM by the CLI, written to a 0600 temp file
# only, and never printed.
#
# WHERE CONFIG COMES FROM ----------------------------------------------------
# Everything that is not a secret is checked in, one file per deployment:
# env/staging.env, env/mainnet.env. None of it is confidential — the hostnames and
# clusters are in public DNS, the CVM's shape and image are in its public quote —
# and in git every change is reviewed and diffable between deployments. The
# secrets (CLOUDFLARE_API_TOKEN, the three ZG_PROM_REMOTE_WRITE_*, PHALA_CLOUD_API_KEY)
# come from the environment only: in the workflow, from the deploy-<target>
# Environment; locally, from `secrets.env` next to this script (git-ignored, see
# secrets.env.example; SECRETS_ENV names another path), loaded after the config
# file, or exported. A value still reading CHANGEME is refused.
#
# Usage:
#   ./deploy-side.sh b --env-file env/mainnet.env --compose docker-compose.release.yml \
#       --release release-2026.10.28.1        # secrets in ./secrets.env, or exported
#   ./deploy-side.sh b --env-file … --compose … --dry-run   # preflight only
#
# Flags:
#   --compose PATH   the release's docker-compose.release.yml (required)
#   --release TAG    the release it came from; checked against matched_release
#   --dry-run        run the preflight and print what would be created
#   --yes            do not prompt for confirmation
#   --env-file PATH  load config from PATH instead of ./deploy.env next to this script
#
# Config (env or env file; the real environment wins over the file):
#   DOMAIN               served hostname (required — no default, so a staging run
#                        cannot fall through to mainnet's)
#   DELEGATION_ZONE      base delegation zone        (default: integratenetwork.work)
#   PLATFORM_BASE        main cluster, sides a and b (required for a and b)
#   PLATFORM_BASE_COLD   cold standby's cluster      (required for c)
#   CVM_NAME_PREFIX      CVM name is <prefix>-<side> (required)
#   PHALA_INSTANCE_TYPE  e.g. tdx.4xlarge            (required: the shape is fixed at
#                        create time and GOMEMLIMIT depends on it — README, "CVM shape")
#   PHALA_NODE_ID        node for sides a and b      (optional: auto-selected, then
#   PHALA_NODE_ID_COLD   node for side c              check 2 catches a wrong cluster)
#   PHALA_OS_IMAGE       OS image                    (optional: auto-selected)
#   PHALA_CLOUD_API_KEY  read by the CLI itself
#   PHALA                CLI command                 (default: phala)
#   CLOUDFLARE_API_TOKEN, ZG_PROM_*, CVM_ENV_*, CVM_SECRET_ENV   the CVM's environment, above
#   CVM_REQUIRED_KEYS    keys the CVM must get with a non-empty value, space-
#                        separated (optional): for one that comes from a secret, so
#                        a missing secret fails here instead of the compose default
#                        silently taking over
#   WAIT_PUBLISH         seconds for checks 1–2      (default: 1800; image pull + boot)
#   WAIT_READY           seconds for check 3         (default: 900; cert + cold warmer sweep)
#   WAIT_IDENTITY        seconds for check 4         (default: 600)
#   POLL_INTERVAL        seconds between polls       (default: 15)
#
# On success it prints two lines on stdout, for callers to capture:
#   app_id=<40 hex>
#   url=https://<app_id>-443s.<base>
# Everything else goes to stderr.
if [ -z "${BASH_VERSION:-}" ]; then exec bash "$0" "$@"; fi

set -euo pipefail

DRY_RUN=0
ASSUME_YES=0
COMPOSE=""
RELEASE=""
ENV_FILE=""
SIDE=""

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
# Colour only on a terminal: the deploy workflow captures this output into the run
# summary, which is Markdown.
if [ -t 2 ] && [ -z "${NO_COLOR:-}" ]; then
  c_red=$'\033[31m'; c_grn=$'\033[32m'; c_yel=$'\033[33m'; c_rst=$'\033[0m'
else
  c_red=''; c_grn=''; c_yel=''; c_rst=''
fi
info() { printf '%s==>%s %s\n' "$c_grn" "$c_rst" "$*" >&2; }
warn() { printf '%swarn:%s %s\n' "$c_yel" "$c_rst" "$*" >&2; }
die()  { printf '%serror:%s %s\n' "$c_red" "$c_rst" "$*" >&2; exit 1; }
# For the checks wait_for polls: they run in a subshell, where `die` would only end
# the subshell and read as "not yet". This status tells wait_for to stop.
stop() { printf '%serror:%s %s\n' "$c_red" "$c_rst" "$*" >&2; exit 3; }

need() { command -v "$1" >/dev/null 2>&1 || die "missing required command: $1"; }

# Same loader as switch.sh: KEY=VALUE lines, the real environment wins.
load_env_file() { # path
  local f="$1" line key
  [ -f "$f" ] || die "env file not found: $f"
  info "loading env from $f"
  while IFS= read -r line || [ -n "$line" ]; do
    line="${line%$'\r'}"
    line="${line#"${line%%[![:space:]]*}"}"
    case "$line" in ''|'#'*) continue ;; esac
    line="${line#export }"
    key="${line%%=*}"
    [ "$key" = "$line" ] && continue
    case "$key" in ''|*[!A-Za-z0-9_]*) continue ;; esac
    printenv "$key" >/dev/null 2>&1 && continue
    eval "export $line"
  done < "$f"
}

confirm() {
  [ "$ASSUME_YES" = 1 ] && return 0
  [ -t 0 ] || die "refusing to proceed non-interactively without --yes"
  local reply
  read -r -p "$1 [y/N] " reply
  [[ "$reply" =~ ^[Yy]$ ]]
}

usage() {
  awk 'NR==1{next} /^[^#]/{exit} {sub(/^# ?/,""); print}' "$0"
  exit "${1:-0}"
}

side_base() { case "$1" in a|b) echo "$PLATFORM_BASE" ;; c) echo "$PLATFORM_BASE_COLD" ;; esac; }
side_node() { case "$1" in a|b) echo "${PHALA_NODE_ID:-}" ;; c) echo "${PHALA_NODE_ID_COLD:-}" ;; esac; }
addr_target() { echo "_dstack-app-address.${DOMAIN}.$1.${DELEGATION_ZONE}"; }
acme_target() { echo "_acme-challenge.${DOMAIN}.$1.${DELEGATION_ZONE}"; }

# Strip the CLI's `app_` prefix and lowercase, so ids from the CLI, DNS and the
# identity route compare equal.
norm_app_id() { local a="${1#app_}"; printf '%s' "${a,,}"; }

# ---------------------------------------------------------------------------
# DNS — asked of the delegation zone's own nameserver, not a recursive resolver:
# the records polled here change during the run, and a resolver would answer from
# a cache for up to a TTL. Read-only, so no Cloudflare token is needed.
# ---------------------------------------------------------------------------
AUTH_NS=""
resolve_ns() {
  AUTH_NS="$(dig +short NS "$DELEGATION_ZONE" | head -n1)"
  AUTH_NS="${AUTH_NS%.}"
  [ -n "$AUTH_NS" ] || die "could not find a nameserver for ${DELEGATION_ZONE}"
}
dns() { # type name -> first answer, trailing dot and TXT quotes stripped
  local v
  v="$(dig +short @"$AUTH_NS" "$1" "$2" 2>/dev/null | head -n1 || true)"
  v="${v%.}"; v="${v#\"}"; v="${v%\"}"
  printf '%s' "$v"
}

# Which side a switch-layer CNAME target names: a|b|c, "" if unset, "?" if neither.
which_side() { # target kind(addr|acme)
  local s
  [ -n "$1" ] || { echo ""; return; }
  for s in a b c; do
    [ "$1" = "$("${2}_target" "$s")" ] && { echo "$s"; return; }
  done
  echo "?"
}

# ---------------------------------------------------------------------------
# Phala
# ---------------------------------------------------------------------------
# CVMs whose name or app_id matches exactly. `--search` is a substring match, so
# it only narrows the page; the comparison is done here.
cvms_matching() { # name app_id
  local out q
  for q in "$1" ${2:+"$2"}; do
    out="$("$PHALA" cvms list --search "$q" --page-size 100 --json)" \
      || die "phala cvms list failed (is PHALA_CLOUD_API_KEY set?)"
    jq -r --arg n "$1" --arg a "${2:-}" '
      .items[]? | (.appId // "" | ltrimstr("app_") | ascii_downcase) as $id
      | select(.cvmName == $n or ($a != "" and $id == $a))
      | "\(.cvmName) app_id=\($id) status=\(.status)"' <<<"$out"
  done | sort -u
}

cvm_status() { # app_id -> status, or empty
  "$PHALA" cvms list --search "$1" --page-size 100 --json 2>/dev/null \
    | jq -r --arg a "$1" '.items[]? | select((.appId // "" | ltrimstr("app_") | ascii_downcase) == $a) | .status' \
    | head -n1 || true
}

# ---------------------------------------------------------------------------
# The CVM's environment
# ---------------------------------------------------------------------------
ENV_KEYS=()
SET_KEYS=()  # the subset with a non-empty value

# Write KEY='VALUE' lines to $1: the fixed keys in a fixed order, then the
# CVM_ENV_* ones by name, then CVM_SECRET_ENV's lines in order. Neither may
# override a fixed key — that would be a second, unreviewed place to set
# DNS_SETUP_MODE or DELEGATION_ZONE — nor set a key twice. Single quotes, because
# the CLI's dotenv parser takes an unquoted `#` as a comment; so a value may not
# contain one, nor a newline.
write_env() { # path
  local f="$1" v k line
  emit() {
    case "$2" in *"'"*|*$'\n'*) die "the value of $1 contains a single quote or a newline; the env file cannot carry it" ;; esac
    printf "%s='%s'\n" "$1" "$2" >>"$f"
    ENV_KEYS+=("$1")
    if [ -n "$2" ]; then SET_KEYS+=("$1"); fi
  }
  : >"$f"; ENV_KEYS=(); SET_KEYS=()
  emit DOMAIN "$DOMAIN"
  emit DELEGATION_ZONE "${SIDE}.${DELEGATION_ZONE}"
  emit DNS_SETUP_MODE print
  emit CLOUDFLARE_API_TOKEN "$CLOUDFLARE_API_TOKEN"
  emit ZG_PROM_ENV "$ZG_PROM_ENV"
  emit ZG_PROM_REMOTE_WRITE_URL "$ZG_PROM_REMOTE_WRITE_URL"
  emit ZG_PROM_REMOTE_WRITE_USERNAME "$ZG_PROM_REMOTE_WRITE_USERNAME"
  emit ZG_PROM_REMOTE_WRITE_PASSWORD "$ZG_PROM_REMOTE_WRITE_PASSWORD"
  for v in $(compgen -v CVM_ENV_ | LC_ALL=C sort); do
    k="${v#CVM_ENV_}"
    [ -n "$k" ] || die "CVM_ENV_ names no key"
    [[ " ${ENV_KEYS[*]} " == *" $k "* ]] && die "${v}: ${k} is set by this script; it cannot be overridden"
    emit "$k" "${!v}"
  done
  # Errors name the key only: the line is a secret.
  while IFS= read -r line || [ -n "$line" ]; do
    line="${line%$'\r'}"
    line="${line#"${line%%[![:space:]]*}"}"
    case "$line" in ''|'#'*) continue ;; esac
    k="${line%%=*}"
    if [ "$k" = "$line" ] || ! [[ "$k" =~ ^[A-Za-z_][A-Za-z0-9_]*$ ]]; then
      die "CVM_SECRET_ENV: a line is not KEY=VALUE"
    fi
    [[ " ${ENV_KEYS[*]} " == *" $k "* ]] && die "CVM_SECRET_ENV: ${k} is already set (fixed, a CVM_ENV_ key, or twice)"
    emit "$k" "${line#*=}"
  done <<<"${CVM_SECRET_ENV:-}"
}

# ---------------------------------------------------------------------------
# Checks after create
# ---------------------------------------------------------------------------
http_status() { # url -> HTTP status, 000 if unreachable
  curl -sSk -o /dev/null -w '%{http_code}' --max-time 10 "$1" 2>/dev/null || true
}

# The side's certificate, read through its -443s host (routed by app_id). 0 if it
# covers DOMAIN and is valid for another week, 1 otherwise.
side_cert_ok() { # host
  local pem
  pem="$(echo | openssl s_client -servername "$1" -connect "${1}:443" 2>/dev/null || true)"
  openssl x509 -noout -checkend $((7 * 86400)) <<<"$pem" >/dev/null 2>&1 || return 1
  openssl x509 -noout -checkhost "$DOMAIN" <<<"$pem" 2>/dev/null | grep -q 'does match'
}

# Run $2 (a function) every POLL_INTERVAL until it succeeds or $1 seconds pass. The
# function prints a one-line progress note and returns 1 while it is not there yet,
# or calls `stop` when waiting cannot help.
wait_for() { # seconds fn what
  local deadline=$((SECONDS + $1)) note rc
  while :; do
    rc=0; note="$("$2")" || rc=$?
    case "$rc" in 0) return 0 ;; 1) ;; *) exit 1 ;; esac
    [ "$SECONDS" -ge "$deadline" ] && die "gave up after ${1}s waiting for ${3}: ${note}"
    info "waiting for ${3}: ${note}"
    sleep "$POLL_INTERVAL"
  done
}

check_published() {
  local addr alias st
  addr="$(dns TXT "$(addr_target "$SIDE")")"
  if [ "$(norm_app_id "${addr%%:*}")" != "$APP_ID" ]; then
    st="$(cvm_status "$APP_ID")"
    echo "$(addr_target "$SIDE") = ${addr:-<none>} (CVM status: ${st:-unknown})"
    return 1
  fi
  alias="$(dns CNAME "${DOMAIN}.${SIDE}.${DELEGATION_ZONE}")"
  if [ -z "$alias" ]; then
    echo "${DOMAIN}.${SIDE}.${DELEGATION_ZONE} not published yet"
    return 1
  fi
  # Published but wrong is not going to fix itself: stop waiting.
  [ "$alias" = "_.${BASE}" ] || stop "side ${SIDE} published ${DOMAIN}.${SIDE}.${DELEGATION_ZONE} -> ${alias}, want _.${BASE}: it is running in another cluster, or the platform exported a doubled _. prefix (blue-green.md, \"Where GATEWAY_DOMAIN does and does not matter\"). Delete it, and set PHALA_NODE_ID to a node in ${BASE}."
}

check_ready() {
  local code
  side_cert_ok "$HOST" || { echo "no valid certificate for ${DOMAIN} at ${HOST} yet"; return 1; }
  code="$(http_status "https://${HOST}/readyz")"
  case "$code" in
    2*) return 0 ;;
    404) stop "${HOST}/readyz answered 404: this build predates /readyz, or the -443s route reaches something else" ;;
    *) echo "/readyz answered ${code}"; return 1 ;;
  esac
}

identity() { curl -sSk --max-time 10 "https://${HOST}/v1/gateway/identity" 2>/dev/null || true; }
check_identity() {
  local doc id
  doc="$(identity)"
  id="$(jq -r '.app_id // empty' <<<"$doc" 2>/dev/null || true)"
  [ -n "$id" ] || { echo "app_id not reported yet"; return 1; }
  [ "$(norm_app_id "$id")" = "$APP_ID" ] \
    || stop "${HOST} reports app_id ${id}, not ${APP_ID}: the -443s route reached another app"
  [ -z "$RELEASE" ] && return 0
  # Null while the lookup is pending, and for good when the release is older than
  # the last 5 the gateway compares against (README, "Gateway self-description").
  jq -e '.matched_release != null' <<<"$doc" >/dev/null 2>&1 \
    || { echo "matched_release not reported (yet)"; return 1; }
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
POSITIONAL=()
while [ $# -gt 0 ]; do
  case "$1" in
    --dry-run)    DRY_RUN=1 ;;
    --yes|-y)     ASSUME_YES=1 ;;
    --compose)    COMPOSE="${2:?--compose needs a path}"; shift ;;
    --compose=*)  COMPOSE="${1#*=}" ;;
    --release)    RELEASE="${2:?--release needs a tag}"; shift ;;
    --release=*)  RELEASE="${1#*=}" ;;
    --env-file)   ENV_FILE="${2:?--env-file needs a path}"; shift ;;
    --env-file=*) ENV_FILE="${1#*=}" ;;
    -h|--help)    usage 0 ;;
    -*)           die "unknown flag: $1 (try --help)" ;;
    *)            POSITIONAL+=("$1") ;;
  esac
  shift
done
[ "${#POSITIONAL[@]}" -eq 1 ] || usage 1
case "${POSITIONAL[0]}" in
  a|b|c) SIDE="${POSITIONAL[0]}" ;;
  *) die "unknown side '${POSITIONAL[0]}' (want: a|b|c)" ;;
esac

if [ -n "$ENV_FILE" ]; then
  load_env_file "$ENV_FILE"
elif [ -f "${SCRIPT_DIR}/deploy.env" ]; then
  load_env_file "${SCRIPT_DIR}/deploy.env"
fi
SECRETS_ENV="${SECRETS_ENV:-${SCRIPT_DIR}/secrets.env}"
if [ -f "$SECRETS_ENV" ]; then load_env_file "$SECRETS_ENV"; fi

DELEGATION_ZONE="${DELEGATION_ZONE:-integratenetwork.work}"
PLATFORM_BASE="${PLATFORM_BASE:-}"; PLATFORM_BASE="${PLATFORM_BASE#_.}"
PLATFORM_BASE_COLD="${PLATFORM_BASE_COLD:-}"; PLATFORM_BASE_COLD="${PLATFORM_BASE_COLD#_.}"
PHALA="${PHALA:-phala}"
WAIT_PUBLISH="${WAIT_PUBLISH:-1800}"
WAIT_READY="${WAIT_READY:-900}"
WAIT_IDENTITY="${WAIT_IDENTITY:-600}"
POLL_INTERVAL="${POLL_INTERVAL:-15}"

# A checked-in env file holds CHANGEME until someone fills it in.
placeholders=()
for v in DOMAIN DELEGATION_ZONE PLATFORM_BASE PLATFORM_BASE_COLD CVM_NAME_PREFIX \
  PHALA_INSTANCE_TYPE PHALA_NODE_ID PHALA_NODE_ID_COLD PHALA_OS_IMAGE ZG_PROM_ENV \
  $(compgen -v CVM_ENV_ || true); do
  [ "${!v:-}" = CHANGEME ] && placeholders+=("$v")
done
[ "${#placeholders[@]}" -eq 0 ] || die "still CHANGEME in the config: ${placeholders[*]}"
: "${DOMAIN:?set DOMAIN (the served hostname)}"
: "${CVM_NAME_PREFIX:?set CVM_NAME_PREFIX (the CVM is named <prefix>-<side>)}"
: "${PHALA_INSTANCE_TYPE:?set PHALA_INSTANCE_TYPE (README, \"CVM shape\")}"
: "${CLOUDFLARE_API_TOKEN:?set CLOUDFLARE_API_TOKEN (the token the CVM uses, scoped to ${DELEGATION_ZONE})}"
: "${ZG_PROM_ENV:?set ZG_PROM_ENV}"
: "${ZG_PROM_REMOTE_WRITE_URL:?set ZG_PROM_REMOTE_WRITE_URL}"
: "${ZG_PROM_REMOTE_WRITE_USERNAME:?set ZG_PROM_REMOTE_WRITE_USERNAME}"
: "${ZG_PROM_REMOTE_WRITE_PASSWORD:?set ZG_PROM_REMOTE_WRITE_PASSWORD}"
[ -n "$COMPOSE" ] || die "--compose is required"
[ -f "$COMPOSE" ] || die "compose file not found: $COMPOSE"
COMPOSE="$(cd -- "$(dirname -- "$COMPOSE")" && pwd)/$(basename -- "$COMPOSE")"

BASE="$(side_base "$SIDE")"
[ -n "$BASE" ] || die "side ${SIDE} has no cluster: set $([ "$SIDE" = c ] && echo PLATFORM_BASE_COLD || echo PLATFORM_BASE)"
NODE="$(side_node "$SIDE")"
NAME="${CVM_NAME_PREFIX}-${SIDE}"
[[ "$NAME" =~ ^[A-Za-z][A-Za-z0-9-]{4,62}$ ]] || die "CVM name '${NAME}' is not 5-63 letters, digits or hyphens starting with a letter"

need "$PHALA"; need dig; need curl; need jq; need openssl

# --- preflight ---------------------------------------------------------------
# The release workflow pins both gateway image lines by digest; a compose that does
# not is the floating development one, whose measured text names a moving tag.
if grep -E '^[[:space:]]*image:[[:space:]]*[^[:space:]]*-gateway[@:]' "$COMPOSE" | grep -qv '@sha256:'; then
  die "${COMPOSE} has a gateway image that is not pinned by digest; deploy a release's docker-compose.release.yml"
fi
grep -qE '^[[:space:]]*image:[[:space:]]*[^[:space:]]*-gateway@sha256:' "$COMPOSE" \
  || die "${COMPOSE} has no digest-pinned gateway image; is it the gateway compose?"
COMPOSE_SHA="$(sha256sum "$COMPOSE" | cut -d' ' -f1)"

resolve_ns
live_tgt="$(dns CNAME "_dstack-app-address.${DOMAIN}.${DELEGATION_ZONE}")"
live="$(which_side "$live_tgt" addr)"
acme_tgt="$(dns CNAME "_acme-challenge.${DOMAIN}.${DELEGATION_ZONE}")"
acme="$(which_side "$acme_tgt" acme)"
old_addr="$(dns TXT "$(addr_target "$SIDE")")"
old_app="$(norm_app_id "${old_addr%%:*}")"

info "side ${SIDE} (${NAME}) in ${BASE}; traffic -> ${live:-none}, issuance -> ${acme:-none}"
[ "$live" = "?" ] && die "the traffic switch points at an unrecognized target (${live_tgt}); resolve it with switch.sh status first"
[ "$live" = "$SIDE" ] && die "side ${SIDE} is live: deploy the other side, or switch away first"

existing="$(cvms_matching "$NAME" "$old_app")"
if [ -n "$existing" ]; then
  die "side ${SIDE} still has a CVM — delete it first (phala cvms delete <name>), or pick the other side:
${existing}"
fi
[ -n "$old_app" ] && info "side ${SIDE}'s record still names ${old_app}, which no longer exists — fine, the new CVM rewrites it"

if [ "$acme" != "$SIDE" ]; then
  [ "$DRY_RUN" = 1 ] || die "the issuance switch points at ${acme:-nothing}, not side ${SIDE}: run switch.sh acme ${SIDE} first, or the new side's certificate request fails (and spends the hourly failed-validation budget the live side shares)"
  warn "the issuance switch points at ${acme:-nothing}; a real run requires switch.sh acme ${SIDE} first"
fi

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
( umask 077; : >"$TMP/cvm.env" )
write_env "$TMP/cvm.env"
# Non-empty, not just present: a workflow maps an unset secret to an empty value.
for k in ${CVM_REQUIRED_KEYS:-}; do
  [[ " ${SET_KEYS[*]} " == *" $k "* ]] \
    || die "${k} is required for this deployment (CVM_REQUIRED_KEYS) but nothing sets it to a value — is its secret configured?"
done

args=(deploy --json -n "$NAME" -c "$COMPOSE" -e "$TMP/cvm.env" -t "$PHALA_INSTANCE_TYPE")
[ -n "$NODE" ] && args+=(--node-id "$NODE")
[ -n "${PHALA_OS_IMAGE:-}" ] && args+=(--image "$PHALA_OS_IMAGE")

info "compose     : ${COMPOSE} (sha256 ${COMPOSE_SHA})${RELEASE:+, release ${RELEASE}}"
info "instance    : ${PHALA_INSTANCE_TYPE}, node ${NODE:-auto}, image ${PHALA_OS_IMAGE:-auto}"
[ -n "$NODE" ] || warn "no node pinned: the platform picks one, and a side outside ${BASE} is caught only after it boots"

if [ "$DRY_RUN" = 1 ]; then
  info "dry run: would run ${PHALA} ${args[*]}"
  exit 0
fi
confirm "Create CVM ${NAME} as side ${SIDE}?" || die "aborted"

# --- create --------------------------------------------------------------------
# From an empty directory, so no phala.toml there can turn this into an upgrade.
# With --json the CLI writes its error to stdout too, as a JSON object, so on
# failure that output IS the reason: print it. It holds no env value (the env is
# encrypted before it leaves this machine).
rc=0
out="$(cd "$TMP" && mkdir -p cwd && cd cwd && "$PHALA" "${args[@]}")" || rc=$?
[ "$rc" = 0 ] || die "phala deploy failed (exit ${rc}):
${out:-<no output>}
Check \`phala cvms ls\` before retrying: if a CVM named ${NAME} was created, delete it first."
# Progress lines come before the JSON object on stdout; take the object.
APP_ID="$(sed -n '/^{/,$p' <<<"$out" | jq -r '.app_id // empty' 2>/dev/null || true)"
APP_ID="$(norm_app_id "$APP_ID")"
[[ "$APP_ID" =~ ^[0-9a-f]{40}$ ]] || die "could not read an app_id from phala deploy's output:
${out}"
[ "$APP_ID" != "$old_app" ] || die "the new CVM has the old app_id ${APP_ID}: that is an upgrade, not a new side"
HOST="${APP_ID}-443s.${BASE}"
info "created ${NAME}: app_id ${APP_ID}"

# --- wait ----------------------------------------------------------------------
wait_for "$WAIT_PUBLISH" check_published "side ${SIDE}'s records"
info "published: $(addr_target "$SIDE") -> ${APP_ID}, ${DOMAIN}.${SIDE}.${DELEGATION_ZONE} -> _.${BASE}"
wait_for "$WAIT_READY" check_ready "https://${HOST}/readyz"
info "ready: https://${HOST}/readyz"
wait_for "$WAIT_IDENTITY" check_identity "/v1/gateway/identity"
IDENTITY="$(identity)"
if [ -n "$RELEASE" ]; then
  matched="$(jq -r '.matched_release.tag // empty' <<<"$IDENTITY")"
  [ "$matched" = "$RELEASE" ] \
    || die "the side reports matched_release ${matched:-<none>}, not ${RELEASE}: the compose deployed is not that release's"
fi
info "identity: app_id ${APP_ID}, compose_hash $(jq -r '.compose_hash // "?"' <<<"$IDENTITY"), release ${RELEASE:-not checked}"

info "side ${SIDE} is ready. Cut over with: switch.sh switch ${SIDE}"
printf 'app_id=%s\nurl=https://%s\n' "$APP_ID" "$HOST"
