#!/usr/bin/env bash
#
# deploy.sh — provision one gateway CVM on Phala Cloud (dstack).
#
# WHY THIS EXISTS ------------------------------------------------------------
# Two thirds of a release were already scripted and one third was not.
# `.github/workflows/release.yml` produces the attested artifact (a
# digest-pinned `docker-compose.release.yml`), `switch.sh` moves traffic between
# two CVMs — and in between sat a dashboard form with eight secret fields, a
# node picker and an instance-type dropdown, none of which is written down
# anywhere a reviewer can read. Every one of those choices ends up in the
# MEASURED app-compose (allowed_envs, public_logs, public_sysinfo,
# public_tcbinfo, secure_time, KMS), so a hand-filled form is not a convenience
# gap: it is an unrecorded input to app_id. This script is that record.
#
# WHAT IT DOES NOT DO --------------------------------------------------------
# It never moves traffic. Deploying a side and cutting over to it stay separate
# commands on purpose (`switch.sh`), so a deploy can be verified against the
# live side before anything points at it. It also never edits DNS — it only
# READS it, to catch the two mistakes that fail silently (see `preflight`).
#
# ORDER OF A RELEASE ---------------------------------------------------------
#   ./switch.sh acme b                 # 1. aim issuance at the side about to be built
#   ./deploy.sh deploy --side b …      # 2. this script: build the side, wait for /readyz
#   ./switch.sh switch b               # 3. cut traffic over (probes b first, rolls back itself)
#   ./deploy.sh verify                 # 4. full pcverify gate on the served domain
#   phala cvms delete --cvm-id <a>     # 5. retire the old side
# Step 1 comes first for a reason (blue-green.md "About the certificate"): a
# side whose ACME challenge still points at its sibling burns the
# 5-failed-validations-per-hour budget for the HOSTNAME, which blocks the live
# side's renewal too.
#
# CONFIG ---------------------------------------------------------------------
# From the environment or an env file, exactly like switch.sh: `deploy.env` next
# to this script is loaded automatically (git-ignored — it holds the Cloudflare
# token and the Prometheus password), the real environment wins over the file,
# and --env-file points elsewhere. See deploy.env.example for the full list.
#
# Usage:
#   ./deploy.sh preflight --side b                 # checks only, changes nothing
#   ./deploy.sh deploy --side b --release latest   # deploy the newest release asset
#   ./deploy.sh deploy --side b --release release-2026.08.30.1
#   ./deploy.sh deploy --side b --compose ./docker-compose.release.yml
#   ./deploy.sh status                             # app_id / instance / probe URL
#   ./deploy.sh verify                             # pcverify gate against DOMAIN
#
# Flags:
#   --side a|b          which blue/green side this CVM is (sets DELEGATION_ZONE)
#   --release TAG       take docker-compose.release.yml from that GitHub release
#                       ("latest" for the newest); its sha256 is checked against
#                       the one the release notes publish
#   --compose PATH      deploy a local manifest instead (must be digest-pinned)
#   --name NAME         CVM name (default: 0g-pc-gateway-<ZG_PROM_ENV>-<side>).
#                       MEASURED — it is a field of the app-compose, so it is part of
#                       app_id; see check_name_free() below before choosing one.
#   --env-file PATH     load config from PATH instead of ./deploy.env
#   --dry-run           print the phala command (secrets redacted), do nothing
#   --yes               do not prompt
#   --no-probe          skip the post-deploy readiness wait
#   --skip-acme-check   deploy even though issuance is not aimed at this side
#   --allow-duplicate-name  deploy even though a CVM already carries this name
#   --allow-floating-tag  deploy a manifest with an unpinned gateway image
#                       (development only — it voids the attestation, see
#                       README "Pin the image digest")
#
# This is a bash script; re-exec under bash if started with `sh deploy.sh`.
if [ -z "${BASH_VERSION:-}" ]; then exec bash "$0" "$@"; fi

set -euo pipefail

DRY_RUN=0
ASSUME_YES=0
NO_PROBE=0
SKIP_ACME_CHECK=0
ALLOW_FLOATING=0
ALLOW_DUP_NAME=0
SIDE=""
RELEASE=""
COMPOSE_ARG=""
NAME_ARG=""
ENV_FILE=""

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd -- "$SCRIPT_DIR/../.." && pwd)"
GH_API="https://api.github.com"
GH_REPO="0gfoundation/0g-pc-e2ee"
RELEASE_ASSET="docker-compose.release.yml"

# ---------------------------------------------------------------------------
# Helpers (same shape as switch.sh, so the two read alike)
# ---------------------------------------------------------------------------
c_red=$'\033[31m'; c_grn=$'\033[32m'; c_yel=$'\033[33m'; c_dim=$'\033[2m'; c_rst=$'\033[0m'
log()  { printf '%s\n' "$*" >&2; }
info() { printf '%s==>%s %s\n' "$c_grn" "$c_rst" "$*" >&2; }
warn() { printf '%swarn:%s %s\n' "$c_yel" "$c_rst" "$*" >&2; }
die()  { printf '%serror:%s %s\n' "$c_red" "$c_rst" "$*" >&2; exit 1; }
ok()   { printf '  %s✓%s %s\n' "$c_grn" "$c_rst" "$*" >&2; }
bad()  { printf '  %s✗%s %s\n' "$c_red" "$c_rst" "$*" >&2; }

need() { command -v "$1" >/dev/null 2>&1 || die "missing required command: $1"; }

confirm() {
  [ "$DRY_RUN" = 1 ] && return 0
  [ "$ASSUME_YES" = 1 ] && return 0
  [ -t 0 ] || die "refusing to proceed non-interactively without --yes"
  local reply
  read -r -p "$1 [y/N] " reply
  [[ "$reply" =~ ^[Yy]$ ]]
}

# TWO ENVIRONMENTS, AND THEY MUST NOT BLEED INTO EACH OTHER -------------------
# deploy.env holds both kinds of setting — how this script behaves (INSTANCE_TYPE,
# PROBE_*, CVM_NAME) and what the CVM's containers are given (DOMAIN, the tokens,
# the ZG_PROM_* values). They are separated in two directions:
#
#   deploy.env -> the CVM   an explicit allowlist, written by build_env_file. A
#                           name it does not list cannot reach a container, no
#                           matter what the file says. That is deliberate: the
#                           compose interpolates a fixed set of ${…} references
#                           and the app's allowed_envs is MEASURED, so "just add
#                           a variable" is a change to app_id, not to config.
#   deploy.env -> children  this loader. Values become shell variables of THIS
#                           script and, by default, nothing more.
#
# That second one is why this loader is no longer identical to switch.sh's, which
# exports everything. switch.sh's children are curl and openssl; ours include the
# phala CLI, which has an env contract of its own (`phala help envs`:
# PHALA_CLOUD_API_KEY, PRIVATE_KEY, ETH_RPC_URL, DEBUG …). Exporting the whole
# file would put the Cloudflare token and the Prometheus password in the
# environment of every child process, and would let an innocuous-looking
# `DEBUG=1` in deploy.env change what the CLI does — `DEBUG=phala::api-client`
# makes it print every HTTP request, bodies included. So only the names below,
# which a child genuinely needs, are exported.
TOOL_ENV_EXPORTS="PHALA_CLOUD_API_KEY PHALA_CLOUD_API_PREFIX PRIVATE_KEY ETH_RPC_URL"

# Names the compose actually interpolates from the CVM's environment. Anything
# else beginning ZG_GATEWAY_ is a silent no-op — those settings are spelled out
# literally in the measured compose text, so changing one means editing that file
# (and getting a new app_id), never setting a variable here.
CVM_ZG_GATEWAY_VARS="ZG_GATEWAY_ROUTER_URL ZG_GATEWAY_ALLOWED_ORIGINS"

LOADED_KEYS=""

# Only point it at a file you trust — the values are assigned through the shell.
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
    key="${key%"${key##*[![:space:]]}"}"
    case "$key" in ''|*[!A-Za-z0-9_]*) continue ;; esac
    LOADED_KEYS="$LOADED_KEYS $key"
    # The real environment wins, so a one-off `FOO=… ./deploy.sh` still overrides.
    [ -n "${!key+set}" ] && continue
    # A plain assignment, not an export: inside a function with no `local` for
    # this name, it lands in the shell's global scope and stays out of every
    # child's environment.
    eval "$line"
    case " $TOOL_ENV_EXPORTS " in *" $key "*) export "$key" ;; esac
  done < "$f"
}

# Settings in deploy.env that do nothing, and would take a deploy to discover.
check_env_namespaces() {
  local key
  for key in $LOADED_KEYS; do
    case "$key" in
      ZG_GATEWAY_*)
        case " $CVM_ZG_GATEWAY_VARS " in
          *" $key "*) ;;
          *) warn "$key is set here but the compose does not reference it — the gateway's other settings are literal, measured text. Edit docker-compose.yml (and take the new app_id) instead." ;;
        esac ;;
      DEBUG)
        warn "DEBUG is set here. It is NOT passed on — the phala CLI reads it (DEBUG=phala::api-client prints every request body), which is not something a config file should switch on by accident." ;;
    esac
  done
}

# ---------------------------------------------------------------------------
# Compose manifest: obtaining it, and refusing an unpinned one
# ---------------------------------------------------------------------------
# The one anchor for "this line references the gateway image", copied verbatim
# from release.yml so the guard here and the guard that PRODUCES the artifact
# cannot disagree about what a gateway-image line looks like.
GW_IMAGE_RE='^[[:space:]]*image:[[:space:]]*ghcr\.io/0gfoundation/0g-pc-e2ee-gateway'

# Every gateway-image line must carry a digest, and the SAME digest: `gateway`
# and `cvm-identity` run two binaries out of one artifact, and pinning only the
# first leaves the root-privileged init container floating on :latest — the exact
# hole the pinning exists to close. A bare `image: …-gateway` counts as floating,
# since docker reads it as :latest.
check_compose_pinned() { # file
  local f="$1" digests n_gw
  n_gw="$(grep -cE "${GW_IMAGE_RE}(:|@|[[:space:]]|\$)" "$f" || true)"
  [ "${n_gw:-0}" -ge 2 ] || die "$f: found ${n_gw:-0} gateway-image line(s), expected at least 2 (gateway + cvm-identity)"

  if grep -qE "${GW_IMAGE_RE}(:|[[:space:]]|\$)" "$f"; then
    if [ "$ALLOW_FLOATING" = 1 ]; then
      warn "gateway image is on a FLOATING TAG. compose_hash — and so app_id and the"
      warn "quote — stay identical while the code that sees plaintext prompts changes"
      warn "underneath them. Development only; never for an attested deploy."
    else
      die "$f: gateway image is on a floating tag, not a digest.
    Deploy the release asset (--release latest) or pass --allow-floating-tag for a dev CVM.
    See README 'Pin the image digest'."
    fi
  else
    digests="$(grep -E "${GW_IMAGE_RE}@" "$f" | sed -E 's/.*@//' | tr -d ' \t' | sort -u)"
    [ "$(printf '%s\n' "$digests" | wc -l)" -eq 1 ] \
      || die "$f: gateway-image lines carry DIFFERENT digests — gateway and cvm-identity must share one build:
$digests"
    ok "gateway image pinned on $n_gw line(s): $digests"
  fi

  # Any other image on a tag is a weaker version of the same problem: it is
  # measured by name, and the name's contents can be republished. Upstream
  # images are pinned in the checked-in compose, so this only fires on a hand-edit.
  local floating
  floating="$(grep -nE '^[[:space:]]*image:' "$f" | grep -v '@sha256:' | grep -vE "${GW_IMAGE_RE}" || true)"
  [ -z "$floating" ] || warn "image line(s) not pinned by digest:
$floating"
}

# Download the release asset and check it against the sha256 the release notes
# publish. Both come from the same release, so this is an integrity check on the
# TRANSFER, not a trust anchor — what makes the bytes authoritative is that
# pcverify compares them against the CVM's own app-compose afterwards.
fetch_release_compose() { # tag ("latest" or a tag name) -> path on stdout
  local tag="$1" api out body url want got
  out="$WORKDIR/$RELEASE_ASSET"
  if [ "$tag" = latest ]; then api="$GH_API/repos/$GH_REPO/releases/latest"
  else api="$GH_API/repos/$GH_REPO/releases/tags/$tag"; fi

  local -a auth=()
  [ -n "${GITHUB_TOKEN:-}" ] && auth=(-H "Authorization: Bearer $GITHUB_TOKEN")

  body="$(curl -sSfL "${auth[@]}" -H 'Accept: application/vnd.github+json' "$api")" \
    || die "cannot read release '$tag' from $GH_REPO — private repo or rate limited? set GITHUB_TOKEN"

  tag="$(printf '%s' "$body" | jq -r '.tag_name')"
  url="$(printf '%s' "$body" | jq -r --arg n "$RELEASE_ASSET" '.assets[]? | select(.name==$n) | .browser_download_url')"
  [ -n "$url" ] && [ "$url" != null ] || die "release $tag has no $RELEASE_ASSET asset"

  curl -sSfL "${auth[@]}" -o "$out" "$url" || die "download failed: $url"

  # Two independent statements of what the asset should hash to: the API's own
  # `digest` field, and the `| Release compose sha256 | <hex> |` row the workflow
  # writes into the notes. Prefer the first, fall back to the second. Neither is
  # a trust anchor — both come from the same release — so this is a check on the
  # TRANSFER; what authenticates these bytes is pcverify comparing them against
  # the CVM's own app-compose afterwards. Absent is a warning, not a failure.
  want="$(printf '%s' "$body" | jq -r --arg n "$RELEASE_ASSET" \
    '.assets[]? | select(.name==$n) | .digest // "" | sub("^sha256:";"")' | grep -oiE '^[0-9a-f]{64}$' || true)"
  [ -n "$want" ] || want="$(printf '%s' "$body" | jq -r '.body // ""' \
    | grep -io 'Release compose sha256[^|]*|[^|]*' | grep -oiE '[0-9a-f]{64}' | head -1 || true)"
  got="$(sha256sum "$out" | awk '{print $1}')"
  if [ -n "$want" ]; then
    [ "$want" = "$got" ] || die "release $tag: $RELEASE_ASSET sha256 $got != $want published in the notes"
    ok "release $tag asset sha256 matches the release notes: $got"
  else
    warn "release $tag publishes no compose sha256 in its notes; downloaded sha256 $got"
  fi
  RELEASE_TAG="$tag"
  printf '%s\n' "$out"
}

# ---------------------------------------------------------------------------
# DNS reads — the two prerequisites that fail without a useful log line
# ---------------------------------------------------------------------------
cname_of() { # name -> the CNAME target it resolves to (trailing dot stripped), or empty
  command -v dig >/dev/null 2>&1 || return 0
  dig +short CNAME "$1" 2>/dev/null | head -1 | sed 's/\.$//'
}

# The serving alias is the one record neither this script nor the CVM maintains:
# `<DOMAIN>.<DELEGATION_ZONE>` CNAME -> GATEWAY_DOMAIN, created once by
# `switch.sh setup`. It names the CLUSTER, so a CVM deployed to a different
# cluster than the alias points at is unreachable under the served domain no
# matter how healthy it is — the failure mode of a cluster migration.
check_serving_alias() {
  local got want
  want="${GATEWAY_DOMAIN#_.}"
  got="$(cname_of "${DOMAIN}.${DELEGATION_ZONE}")"
  if [ -z "$got" ]; then
    warn "serving alias ${DOMAIN}.${DELEGATION_ZONE} does not resolve (dig missing, or not created yet)"
    warn "  create it once: GATEWAY_DOMAIN=${GATEWAY_DOMAIN} ./switch.sh setup"
  elif [ "${got#_.}" = "$want" ]; then
    ok "serving alias ${DOMAIN}.${DELEGATION_ZONE} -> $got"
  else
    bad "serving alias ${DOMAIN}.${DELEGATION_ZONE} -> $got, but GATEWAY_DOMAIN is ${GATEWAY_DOMAIN}"
    warn "  this CVM will be deployed to a cluster the served domain does not point at."
    warn "  Repoint it with: GATEWAY_DOMAIN=${GATEWAY_DOMAIN} ./switch.sh setup"
  fi
}

# Issuance must already be aimed at the side being built, or its first ACME run
# validates against the sibling's challenge record: 5 failed validations per hour,
# per HOSTNAME, so it blocks the live side's renewal too.
check_acme_aimed_here() {
  local got want
  want="_acme-challenge.${DOMAIN}.${SIDE_ZONE}"
  got="$(cname_of "_acme-challenge.${DOMAIN}.${DELEGATION_ZONE}")"
  if [ -z "$got" ]; then
    warn "cannot read the issuance switch (dig missing, or the record does not exist yet)"
    return 0
  fi
  if [ "$got" = "$want" ]; then
    ok "issuance switch points at side ${SIDE}"
    return 0
  fi
  bad "issuance switch points at $got, not $want"
  if [ "$SKIP_ACME_CHECK" = 1 ]; then
    warn "continuing anyway (--skip-acme-check)"
    return 0
  fi
  die "aim it first:  ./switch.sh acme ${SIDE}     (or pass --skip-acme-check)"
}

# ---------------------------------------------------------------------------
# Phala CLI
# ---------------------------------------------------------------------------
# `phala deploy` replaced `phala cvm create`; `--vcpu`/`--memory` are deprecated
# in favour of `--instance-type`. Fail on an old CLI rather than on a flag the
# error message will not explain.
check_cli() {
  need phala
  local v
  v="$(phala --version 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1 || true)"
  [ -n "$v" ] || die "cannot read 'phala --version'"
  phala deploy --help >/dev/null 2>&1 \
    || die "phala CLI $v has no 'deploy' command — upgrade (npm i -g phala)"
  ok "phala CLI $v"
  if phala whoami >/dev/null 2>&1 || phala status >/dev/null 2>&1; then
    ok "authenticated ($(phala whoami 2>/dev/null | head -1 || echo 'see phala status'))"
  else
    die "not authenticated — run 'phala login' or set PHALA_CLOUD_API_KEY"
  fi
}

# THE CVM NAME IS MEASURED. dstack's app-compose carries a `name` field (dstack-types
# AppCompose), and compose_hash is the SHA-256 of that manifest — so the name is inside
# app_id, exactly like the compose text and allowed_envs. `pcverify -gateway` prints it
# as `app name`, read out of the manifest the quote anchors. Three consequences:
#
#   * A name is not a label you can fix later. Renaming means a different app_id, which
#     means a different CVM and a re-audit, not an edit.
#   * Two sides with the SAME image but different names are different app_ids. That is
#     what keeps a staging CVM and a production one from colliding into a single app —
#     nothing else in the manifest distinguishes them, since DOMAIN and the router URL
#     are `${…}` references whose values are never measured.
#   * Replicas of ONE side must share the name, or they are not replicas: dstack load
#     balances within an app_id, and a differently-named CVM is a different app.
#
# It is also the CLI's handle — `--cvm-id` accepts a name — which is what makes a
# collision worth refusing below rather than discovering later.
check_name_free() {
  if ! phala cvms get --cvm-id "$CVM_NAME" --json >/dev/null 2>&1; then
    ok "no CVM named ${CVM_NAME} yet"
    return 0
  fi
  bad "a CVM named ${CVM_NAME} already exists"
  if [ "$ALLOW_DUP_NAME" = 1 ]; then
    warn "continuing anyway (--allow-duplicate-name); '--cvm-id ${CVM_NAME}' is now ambiguous"
    return 0
  fi
  die "retire it first (phala cvms delete --cvm-id ${CVM_NAME}), or pass --name for a new one.
    Updating that CVM in place is a different operation and this script does not do it:
    'phala deploy --cvm-id ${CVM_NAME}' replaces the app on the SAME CVM, which is not a
    blue/green release — the point of a release here is a second CVM to cut over to and
    roll back from. --allow-duplicate-name overrides, at the cost of a name that no
    longer addresses one CVM."
}

# app_id / instance_id out of whatever shape the CLI's JSON has this version:
# scan every object for a key named like the one we want and take the first
# 40-hex value. Keyed lookup at a fixed path is what breaks on a CLI upgrade,
# and the value's shape is unambiguous.
json_id() { # json key-substring -> first 40-hex value under a matching key
  printf '%s' "$1" | jq -r --arg k "$2" '
    [.. | objects | to_entries[] | select(.key|ascii_downcase|contains($k)) | .value
     | select(type=="string") | ascii_downcase | sub("^0x";"")
     | select(test("^[0-9a-f]{40}$"))] | first // empty' 2>/dev/null || true
}

http_status() { curl -sSk -o /dev/null -w '%{http_code}' --max-time 10 "$1" 2>/dev/null || true; }
http_ok() { # -k on purpose: this reaches a side by app-id, where the served cert
  # is legitimately for another name. Cert validity is the evidence bundle's job.
  local code; code="$(curl -sSk -o /dev/null -w '%{http_code}' --max-time 10 "$1" 2>/dev/null || echo 000)"
  [[ "$code" =~ ^2[0-9][0-9]$ ]]
}

# Reach one specific CVM before any traffic points at it: <app_id>-443s is TLS
# passthrough routed by the app-id in the hostname, independent of the custom
# domain's _dstack-app-address (blue-green.md "Health-checking the standby").
probe_url() { # app_id [path] -> url
  [ -n "$PLATFORM_BASE" ] || return 0
  printf 'https://%s-443s.%s%s\n' "$1" "$PLATFORM_BASE" "${2:-/readyz}"
}

# /readyz, not /healthz: the question is whether it can SERVE — at least one
# provider quote DCAP-verified and its on-chain signer read and agreeing — which
# means waiting out a cold warmer sweep. Minutes, not one DNS TTL.
wait_ready() { # app_id
  local url health i
  url="$(probe_url "$1")"
  health="$(probe_url "$1" /healthz)"
  if [ -z "$url" ]; then
    warn "PLATFORM_BASE unset — skipping the readiness probe; this CVM is unverified"
    return 0
  fi
  info "waiting for $url (up to $((PROBE_RETRIES * PROBE_INTERVAL))s)"
  for ((i = 1; i <= PROBE_RETRIES; i++)); do
    if http_ok "$url"; then ok "ready after $(( (i-1) * PROBE_INTERVAL ))s"; return 0; fi
    if [ $((i % 6)) = 0 ]; then
      log "  ${c_dim}$(( (i-1) * PROBE_INTERVAL ))s: /readyz $(http_status "$url"), /healthz $(http_status "$health")${c_rst}"
    fi
    sleep "$PROBE_INTERVAL"
  done
  bad "not ready after $((PROBE_RETRIES * PROBE_INTERVAL))s (/readyz $(http_status "$url"), /healthz $(http_status "$health"))"
  warn "a serving process that is not READY usually means no provider passed the"
  warn "enforced checks — ZG_GATEWAY_ATTEST_ENFORCE / ZG_GATEWAY_ONCHAIN_ENFORCE are"
  warn "fail-closed, so an unreachable PCCS, router or chain RPC looks exactly like this."
  warn "Logs:  phala logs --cvm-id ${CVM_NAME}"
  return 1
}

# ---------------------------------------------------------------------------
# Config resolution
# ---------------------------------------------------------------------------
resolve_config() {
  # Serving domain + delegation (same four the compose declares `${VAR:?…}`).
  DOMAIN="${DOMAIN:-router-api-tee.0g.ai}"
  GATEWAY_DOMAIN="${GATEWAY_DOMAIN:-}"
  DELEGATION_ZONE="${DELEGATION_ZONE:-integratenetwork.work}"

  [ -n "$GATEWAY_DOMAIN" ] || die "set GATEWAY_DOMAIN (the cluster's dstack gateway, e.g. _.dstack-pha-in2.phala.network)"
  case "$GATEWAY_DOMAIN" in _.*) ;; *) die "GATEWAY_DOMAIN must start with '_.' (got '$GATEWAY_DOMAIN')" ;; esac

  # PLATFORM_BASE is GATEWAY_DOMAIN without the wildcard label, and deriving it
  # is what stops the two drifting apart across a cluster move — the failure
  # would be silent: probes aimed at the OLD cluster, which answers nothing for
  # a new app_id, read as "the standby is broken".
  PLATFORM_BASE="${PLATFORM_BASE:-${GATEWAY_DOMAIN#_.}}"
  [ "$PLATFORM_BASE" = "${GATEWAY_DOMAIN#_.}" ] \
    || die "PLATFORM_BASE ($PLATFORM_BASE) and GATEWAY_DOMAIN ($GATEWAY_DOMAIN) name different clusters"

  SIDE_A_LABEL="${SIDE_A_LABEL:-a}"
  SIDE_B_LABEL="${SIDE_B_LABEL:-b}"

  PROBE_RETRIES="${PROBE_RETRIES:-30}"
  PROBE_INTERVAL="${PROBE_INTERVAL:-10}"

  # CVM shape. INSTANCE_TYPE is required rather than defaulted: GOMEMLIMIT in the
  # compose is hardcoded to 24GiB, derived by hand from a 32 GiB CVM, and nothing
  # in the manifest can check the shape it was actually given. A default here
  # would be a silent claim about memory the CVM may not have.
  INSTANCE_TYPE="${INSTANCE_TYPE:-}"
  NODE_ID="${NODE_ID:-}"
  OS_IMAGE="${OS_IMAGE:-}"
  DISK_SIZE="${DISK_SIZE:-40G}"
  KMS="${KMS:-}"

  # app-compose flags — MEASURED, so both blue/green sides must set them alike.
  #   public_logs   off: container logs are readable from outside the CVM, and
  #                 this one handles sealed prompts.
  #   public_sysinfo off: nothing needs it and it widens what the host exposes.
  #   public_tcbinfo ON: pcverify fetches app-compose.json from the guest agent
  #                 through it; off, code identity must be supplied by hand.
  PUBLIC_LOGS="${PUBLIC_LOGS:-false}"
  PUBLIC_SYSINFO="${PUBLIC_SYSINFO:-false}"
  PUBLIC_TCBINFO="${PUBLIC_TCBINFO:-true}"
  SECURE_TIME="${SECURE_TIME:-false}"
  LISTED="${LISTED:-false}"

  # Container env. DNS_SETUP_MODE=print because each side lives under its own
  # sub-zone while the served CNAMEs stay pinned at the base zone, so the
  # default `wait`'s strict one-hop pre-check never matches and the side would
  # block until DNS_SETUP_TIMEOUT and restart without a certificate.
  DNS_SETUP_MODE="${DNS_SETUP_MODE:-print}"
  ACME_STAGING="${ACME_STAGING:-false}"
}

# The variables the compose interpolates, written to a mode-600 file rather than
# passed as `-e KEY=VALUE`: an argv is world-readable in `ps` for the life of the
# call, and four of these are secrets. Every name here must also be in the app's
# allowed_envs or dstack drops it silently — allowed_envs is itself measured, so
# adding a name is a new app_id, not a config tweak.
build_env_file() { # -> path
  local f="$WORKDIR/cvm.env" missing=()
  local v
  for v in CLOUDFLARE_API_TOKEN ZG_PROM_ENV ZG_PROM_REMOTE_WRITE_URL \
           ZG_PROM_REMOTE_WRITE_USERNAME ZG_PROM_REMOTE_WRITE_PASSWORD; do
    [ -n "${!v:-}" ] || missing+=("$v")
  done
  [ "${#missing[@]}" -eq 0 ] || die "missing required config: ${missing[*]} (see deploy.env.example)"

  case "$ZG_PROM_ENV" in staging|mainnet) ;; *) die "ZG_PROM_ENV must be 'staging' or 'mainnet' (got '$ZG_PROM_ENV')" ;; esac

  umask 077
  {
    printf 'DOMAIN=%s\n' "$DOMAIN"
    printf 'GATEWAY_DOMAIN=%s\n' "$GATEWAY_DOMAIN"
    printf 'DELEGATION_ZONE=%s\n' "$SIDE_ZONE"
    printf 'CLOUDFLARE_API_TOKEN=%s\n' "$CLOUDFLARE_API_TOKEN"
    printf 'DNS_SETUP_MODE=%s\n' "$DNS_SETUP_MODE"
    printf 'ACME_STAGING=%s\n' "$ACME_STAGING"
    printf 'ZG_PROM_ENV=%s\n' "$ZG_PROM_ENV"
    printf 'ZG_PROM_REMOTE_WRITE_URL=%s\n' "$ZG_PROM_REMOTE_WRITE_URL"
    printf 'ZG_PROM_REMOTE_WRITE_USERNAME=%s\n' "$ZG_PROM_REMOTE_WRITE_USERNAME"
    printf 'ZG_PROM_REMOTE_WRITE_PASSWORD=%s\n' "$ZG_PROM_REMOTE_WRITE_PASSWORD"
    # Optional overrides: emitted only when set, so the compose default applies
    # otherwise. Their VALUES are invisible to app_id (the measured text is the
    # ${…} reference), which is why staging and production can share one build.
    # `if`, not `[ … ] && printf`: a trailing AND-list that evaluates false makes
    # this whole group exit 1, which `set -e` turns into a silent abort here.
    if [ -n "${ZG_GATEWAY_ROUTER_URL:-}" ]; then
      printf 'ZG_GATEWAY_ROUTER_URL=%s\n' "$ZG_GATEWAY_ROUTER_URL"
    fi
    if [ -n "${ZG_GATEWAY_ALLOWED_ORIGINS:-}" ]; then
      printf 'ZG_GATEWAY_ALLOWED_ORIGINS=%s\n' "$ZG_GATEWAY_ALLOWED_ORIGINS"
    fi
  } > "$f"
  printf '%s\n' "$f"
}

# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------
print_plan() {
  cat >&2 <<EOF
${c_dim}--------------------------------------------------------------------${c_rst}
  CVM name        ${CVM_NAME}
  side            ${SIDE}   (DELEGATION_ZONE=${SIDE_ZONE})
  served domain   ${DOMAIN}
  cluster         ${GATEWAY_DOMAIN}   (probes via ${PLATFORM_BASE})
  compose         ${COMPOSE_FILE}${RELEASE_TAG:+   (release ${RELEASE_TAG})}
  compose sha256  $(sha256sum "$COMPOSE_FILE" | awk '{print $1}')
  instance type   ${INSTANCE_TYPE:-<auto-selected by the platform>}
  node / image    ${NODE_ID:-<auto>} / ${OS_IMAGE:-<auto>}
  disk            ${DISK_SIZE}
  kms             ${KMS:-<CLI default>}
  measured flags  public_logs=${PUBLIC_LOGS} public_sysinfo=${PUBLIC_SYSINFO} public_tcbinfo=${PUBLIC_TCBINFO} secure_time=${SECURE_TIME}
  acme            ACME_STAGING=${ACME_STAGING}   DNS_SETUP_MODE=${DNS_SETUP_MODE}
  prometheus      env=${ZG_PROM_ENV} -> ${ZG_PROM_REMOTE_WRITE_URL}
${c_dim}--------------------------------------------------------------------${c_rst}
EOF
}

cmd_preflight() {
  require_side
  info "preflight for side ${SIDE}"
  check_cli
  resolve_compose
  check_compose_pinned "$COMPOSE_FILE"
  check_serving_alias
  check_acme_aimed_here
  check_name_free
  [ -n "$INSTANCE_TYPE" ] || warn "INSTANCE_TYPE unset — the platform picks the shape, and GOMEMLIMIT=24GiB in the compose assumes 32 GiB (README 'CVM shape')"
  build_env_file >/dev/null && ok "all required environment values present"
  warn "two prerequisites this script CANNOT check:"
  warn "  1. Phala must allowlist the SNI suffix ${DOMAIN} on ${PLATFORM_BASE}."
  warn "     Until they do, the handshake is dropped before the dstack gateway sees it —"
  warn "     DNS and the certificate both look fine and the client sees a bare TLS error."
  warn "  2. The OS image this cluster boots must have an entry in"
  warn "     client/evidence/osimages.json, or 'pcverify -gateway' FAILS the os-image"
  warn "     check for every user. Read it off the deployed CVM and add it before cutover."
}

cmd_deploy() {
  require_side
  check_cli
  resolve_compose
  check_compose_pinned "$COMPOSE_FILE"
  check_serving_alias
  check_acme_aimed_here
  check_name_free

  local envfile; envfile="$(build_env_file)"

  local -a args=(deploy
    --name "$CVM_NAME"
    --compose "$COMPOSE_FILE"
    -e "$envfile"
    --disk-size "$DISK_SIZE"
    --wait --json)
  [ -n "$INSTANCE_TYPE" ] && args+=(--instance-type "$INSTANCE_TYPE")
  [ -n "$NODE_ID" ]       && args+=(--node-id "$NODE_ID")
  [ -n "$OS_IMAGE" ]      && args+=(--image "$OS_IMAGE")
  [ -n "$KMS" ]           && args+=(--kms "$KMS")
  # Booleans are --flag / --no-flag pairs, and each one is measured.
  [ "$PUBLIC_LOGS" = true ]    && args+=(--public-logs)    || args+=(--no-public-logs)
  [ "$PUBLIC_SYSINFO" = true ] && args+=(--public-sysinfo) || args+=(--no-public-sysinfo)
  [ "$PUBLIC_TCBINFO" = true ] && args+=(--public-tcbinfo) || args+=(--no-public-tcbinfo)
  [ "$SECURE_TIME" = true ]    && args+=(--secure-time)    || args+=(--no-secure-time)
  [ "$LISTED" = true ]         && args+=(--listed)         || args+=(--no-listed)
  # Never --dev-os: it requires an SSH key, i.e. interactive root inside the CVM,
  # which makes every measurement below it meaningless for this workload.

  print_plan
  if [ "$DRY_RUN" = 1 ]; then
    info "dry run — would execute:"
    printf 'phala %s\n' "${args[*]}" >&2
    printf '%s(%s holds DOMAIN, GATEWAY_DOMAIN, DELEGATION_ZONE, CLOUDFLARE_API_TOKEN, DNS_SETUP_MODE, ACME_STAGING and the four ZG_PROM_* values — mode 600, deleted on exit)%s\n' \
      "$c_dim" "$envfile" "$c_rst" >&2
    return 0
  fi
  confirm "Create CVM ${CVM_NAME} on ${PLATFORM_BASE}?" || { warn "aborted"; exit 1; }

  info "phala deploy …"
  local out
  out="$(phala "${args[@]}")" || die "phala deploy failed"
  printf '%s\n' "$out" > "$WORKDIR/deploy.json"

  APP_ID="$(json_id "$out" app_id)"
  # Not every CLI version returns the ids from deploy; ask for them explicitly.
  if [ -z "$APP_ID" ]; then
    out="$(phala cvms get --cvm-id "$CVM_NAME" --json 2>/dev/null || true)"
    APP_ID="$(json_id "$out" app_id)"
  fi
  [ -n "$APP_ID" ] || die "deployed, but could not read app_id — 'phala cvms get --cvm-id $CVM_NAME --json'"
  INSTANCE_ID="$(json_id "$out" instance_id)"

  info "app_id      ${APP_ID}"
  [ -n "$INSTANCE_ID" ] && info "instance_id ${INSTANCE_ID}"
  info "probe       $(probe_url "$APP_ID")"

  [ "$NO_PROBE" = 1 ] || wait_ready "$APP_ID"

  cat >&2 <<EOF

${c_grn}==>${c_rst} side ${SIDE} is up. Next:

  # confirm the side publishes its app-address record, then cut traffic over
  ./switch.sh status
  ./switch.sh switch ${SIDE}

  # then the full attestation gate against the served domain
  ./deploy.sh verify

  # and retire the old side once ${SIDE} is confirmed live
  phala cvms delete --cvm-id <old-side>
EOF
}

# The gate. -expect-compose-file is the strongest form: the CVM's own
# app-compose (anchored by the quote's compose_hash) must embed byte-for-byte
# the manifest this script deployed. -strict makes every check mandatory, so a
# check that could not RUN fails instead of being reported as advisory.
cmd_verify() {
  resolve_compose
  local -a v=(-gateway "$DOMAIN" -pccs-url "${PCCS_URL:-https://pccs.phala.network}"
              -expect-compose-file "$COMPOSE_FILE" -strict)
  # A staging certificate is correctly bound by the quote and deliberately signed
  # by an untrusted CA, so chain trust fails on purpose. It narrows the claim to
  # "a genuine TEE minted this certificate" — fine for a deployment you operate,
  # never for auditing one you do not.
  [ "${ACME_STAGING:-false}" = true ] && v+=(-allow-untrusted-cert)
  info "pcverify ${v[*]}"
  ( cd "$REPO_ROOT/client" && go run ./cmd/pcverify "${v[@]}" )
}

cmd_status() {
  check_cli
  local out app
  out="$(phala cvms get --cvm-id "$CVM_NAME" --json 2>/dev/null || true)"
  [ -n "$out" ] || die "no CVM named ${CVM_NAME} (try: phala cvms list)"
  app="$(json_id "$out" app_id)"
  printf 'cvm name    : %s\n' "$CVM_NAME"
  printf 'app_id      : %s\n' "${app:-<unreadable>}"
  printf 'instance_id : %s\n' "$(json_id "$out" instance_id)"
  printf 'cluster     : %s\n' "$PLATFORM_BASE"
  if [ -n "$app" ]; then
    printf 'probe       : %s  -> %s\n' "$(probe_url "$app")" "$(http_status "$(probe_url "$app")")"
    printf 'health      : %s  -> %s\n' "$(probe_url "$app" /healthz)" "$(http_status "$(probe_url "$app" /healthz)")"
  fi
  printf 'public      : https://%s%s -> %s\n' "$DOMAIN" "/healthz" "$(http_status "https://${DOMAIN}/healthz")"
}

require_side() {
  [ -n "$SIDE" ] || die "--side a|b is required (it sets the CVM's DELEGATION_ZONE; see blue-green.md)"
}

resolve_compose() {
  [ -n "${COMPOSE_FILE:-}" ] && return 0
  if [ -n "$COMPOSE_ARG" ]; then
    [ -f "$COMPOSE_ARG" ] || die "compose file not found: $COMPOSE_ARG"
    COMPOSE_FILE="$(cd -- "$(dirname -- "$COMPOSE_ARG")" && pwd)/$(basename -- "$COMPOSE_ARG")"
  elif [ -n "$RELEASE" ]; then
    COMPOSE_FILE="$(fetch_release_compose "$RELEASE")"
  else
    die "pass --release <tag|latest> (the attested artifact) or --compose <path>"
  fi
}

usage() {
  awk 'NR==1{next} /^[^#]/{exit} {sub(/^# ?/,""); print}' "$0"
  exit "${1:-0}"
}

# ---------------------------------------------------------------------------
# Arg parsing
# ---------------------------------------------------------------------------
POSITIONAL=()
while [ $# -gt 0 ]; do
  case "$1" in
    --side)      SIDE="${2:?--side needs a|b}"; shift ;;
    --side=*)    SIDE="${1#*=}" ;;
    --release)   RELEASE="${2:?--release needs a tag or 'latest'}"; shift ;;
    --release=*) RELEASE="${1#*=}" ;;
    --compose)   COMPOSE_ARG="${2:?--compose needs a path}"; shift ;;
    --compose=*) COMPOSE_ARG="${1#*=}" ;;
    --name)      NAME_ARG="${2:?--name needs a value}"; shift ;;
    --name=*)    NAME_ARG="${1#*=}" ;;
    --env-file)  ENV_FILE="${2:?--env-file needs a path}"; shift ;;
    --env-file=*) ENV_FILE="${1#*=}" ;;
    --dry-run)   DRY_RUN=1 ;;
    --yes|-y)    ASSUME_YES=1 ;;
    --no-probe)  NO_PROBE=1 ;;
    --skip-acme-check) SKIP_ACME_CHECK=1 ;;
    --allow-floating-tag) ALLOW_FLOATING=1 ;;
    --allow-duplicate-name) ALLOW_DUP_NAME=1 ;;
    -h|--help)   usage 0 ;;
    -*)          die "unknown flag: $1 (try --help)" ;;
    *)           POSITIONAL+=("$1") ;;
  esac
  shift
done
set -- "${POSITIONAL[@]+"${POSITIONAL[@]}"}"

need curl; need jq; need sha256sum

[ -n "$ENV_FILE" ] && load_env_file "$ENV_FILE"
[ -z "$ENV_FILE" ] && [ -f "$SCRIPT_DIR/deploy.env" ] && load_env_file "$SCRIPT_DIR/deploy.env"
check_env_namespaces

resolve_config

case "$SIDE" in
  ''|a|b) ;;
  *) die "--side must be 'a' or 'b' (got '$SIDE')" ;;
esac
if [ -n "$SIDE" ]; then
  [ "$SIDE" = a ] && SIDE_LABEL="$SIDE_A_LABEL" || SIDE_LABEL="$SIDE_B_LABEL"
  SIDE_ZONE="${SIDE_LABEL}.${DELEGATION_ZONE}"
else
  SIDE_LABEL=""; SIDE_ZONE=""
fi
# Default: 0g-pc-gateway-<env>-<side>, e.g. 0g-pc-gateway-staging-b. The env comes
# from ZG_PROM_ENV, which is already required and already means exactly this, so
# there is one place to state which deployment a CVM belongs to. Both parts earn
# their place in a MEASURED field: without the env, a staging CVM and a mainnet
# one on the same build would share app_id.
CVM_NAME="${NAME_ARG:-${CVM_NAME:-0g-pc-gateway${ZG_PROM_ENV:+-$ZG_PROM_ENV}${SIDE:+-$SIDE}}}"
RELEASE_TAG=""
APP_ID=""; INSTANCE_ID=""

# Everything transient — the downloaded manifest and the env file with the
# tokens in it — lives in one 0700 directory that is removed on any exit.
WORKDIR="$(mktemp -d "${TMPDIR:-/tmp}/0g-pc-deploy.XXXXXX")"
chmod 700 "$WORKDIR"
trap 'rm -rf "$WORKDIR"' EXIT

cmd="${1:-}"
case "$cmd" in
  preflight) cmd_preflight ;;
  deploy)    cmd_deploy ;;
  verify)    cmd_verify ;;
  status)    cmd_status ;;
  ""|-h|--help|help) usage 0 ;;
  *) die "unknown command '$cmd' (want: preflight | deploy | verify | status)" ;;
esac
