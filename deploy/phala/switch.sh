#!/usr/bin/env bash
#
# switch.sh — blue/green traffic switch for the cloud-TEE gateway.
#
# WHY THIS EXISTS ------------------------------------------------------------
# The gateway runs in a dstack CVM whose app_id = SHA-256(app-compose), so a new
# gateway image is a *different app_id* — a separate, separately-attested CVM
# (see deploy/phala/README.md "Pin the image digest"). dstack only load-balances
# *within one app_id*; two different images are two unrelated apps. So a
# blue/green release is not "shift weight on a load balancer" — it is flipping a
# single DNS pointer, `_dstack-app-address.<DOMAIN>`, from the blue app_id to the
# green one. This script flips that pointer safely and reversibly.
#
# WHERE THE SWITCH LIVES -----------------------------------------------------
# The served zone (0g.ai) is operator-delegated and we may not hold a token for
# it, so nothing here touches it. Its three CNAMEs already point into the
# delegation zone and never change. All switching happens inside the delegation
# zone (integratenetwork.work), which the deploy token controls. Each side runs
# with its own delegation sub-zone so their auto-managed records never collide:
#
#   served zone 0g.ai (static, never touched):
#     _dstack-app-address.<DOMAIN>  CNAME -> _dstack-app-address.<DOMAIN>.<DZ>
#     _acme-challenge.<DOMAIN>      CNAME -> _acme-challenge.<DOMAIN>.<DZ>
#     <DOMAIN>                      CNAME -> <DOMAIN>.<DZ>
#
#   delegation zone <DZ>=integratenetwork.work — the SWITCH LAYER (this script):
#     _dstack-app-address.<DOMAIN>.<DZ>  CNAME -> _dstack-app-address.<DOMAIN>.a.<DZ>  | .b.<DZ>   <-- traffic
#     _acme-challenge.<DOMAIN>.<DZ>      CNAME -> _acme-challenge.<DOMAIN>.a.<DZ>      | .b.<DZ>   <-- issuance
#     <DOMAIN>.<DZ>                      CNAME -> <GATEWAY_DOMAIN>  (static; set once, not by this script)
#
#   delegation zone <DZ> — PER-SIDE records, written by each CVM's dstack-ingress:
#     a side (DELEGATION_ZONE=a.<DZ>):  _dstack-app-address.<DOMAIN>.a.<DZ> TXT = <app_id_a>:443
#     b side (DELEGATION_ZONE=b.<DZ>):  _dstack-app-address.<DOMAIN>.b.<DZ> TXT = <app_id_b>:443
#
# So `switch a|b` just repoints the two switch-layer CNAMEs at the chosen side's
# per-side records. dstack-ingress on the Cloudflare provider resolves the
# longest parent zone it can access, so a.<DZ>/b.<DZ> need NOT be real Cloudflare
# zones — one token scoped to <DZ> covers them.
#
# See deploy/phala/blue-green.md for the full runbook (one-time setup, migration
# from a single instance, certificate issuance, and the standby-probe options).
#
# ---------------------------------------------------------------------------
# Config comes from the environment or an env file. Put your token + any
# overrides in `switch.env` next to this script (see switch.env.example) and it
# is loaded automatically; the real environment still wins over the file, so
# `CF_API_TOKEN=… ./switch.sh …` overrides it for a one-off. `switch.env` is
# git-ignored (it holds the Cloudflare token). Point elsewhere with --env-file.
#
# Usage:
#   ./switch.sh status                               # (reads switch.env if present)
#   ./switch.sh switch b                             # flip traffic (+ acme) to side b
#   ./switch.sh rollback                             # flip back to the previous side
#   ./switch.sh acme b                               # point ONLY the issuance switch at b
#   CF_API_TOKEN=... ./switch.sh status              # or supply config via the environment
#
# Common flags:
#   --dry-run        show the Cloudflare changes without applying them
#   --yes            do not prompt for confirmation
#   --probe-url URL  health-check the *target* side directly before switching
#                    (must return HTTP 200; see blue-green.md for how to obtain one)
#   --no-verify      skip the post-switch public /healthz check + auto-rollback
#   --env-file PATH  load config from PATH instead of ./switch.env
#
# Config (env or env file, with defaults for the current production deployment):
#   CF_API_TOKEN     (required) Cloudflare token that can edit the delegation zone
#   CF_ZONE          delegation zone name           (default: integratenetwork.work)
#   DOMAIN           served hostname                (default: router-api-tee.0g.ai)
#   DELEGATION_ZONE  base delegation zone           (default: same as CF_ZONE)
#   SIDE_A_LABEL     sub-zone label for side a      (default: a)
#   SIDE_B_LABEL     sub-zone label for side b      (default: b)
#   TXT_PREFIX       app-address record prefix      (default: _dstack-app-address)
#   HEALTH_PATH      public health path             (default: /healthz)
#   TTL              CNAME TTL in seconds           (default: 60)
#   VERIFY_RETRIES   post-switch health attempts    (default: 10)
#   VERIFY_INTERVAL  seconds between attempts       (default: 6)
#
set -euo pipefail

# ---------------------------------------------------------------------------
# State set during arg parsing / config resolution (see the bottom of the file).
# Config values (CF_ZONE, DOMAIN, …) are resolved AFTER the env file is loaded,
# so a `switch.env` next to this script can supply them.
# ---------------------------------------------------------------------------
DRY_RUN=0
ASSUME_YES=0
PROBE_URL=""
NO_VERIFY=0
ENV_FILE=""

CF_API="https://api.cloudflare.com/client/v4"
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
c_red=$'\033[31m'; c_grn=$'\033[32m'; c_yel=$'\033[33m'; c_dim=$'\033[2m'; c_rst=$'\033[0m'
log()  { printf '%s\n' "$*" >&2; }
info() { printf '%s==>%s %s\n' "$c_grn" "$c_rst" "$*" >&2; }
warn() { printf '%swarn:%s %s\n' "$c_yel" "$c_rst" "$*" >&2; }
die()  { printf '%serror:%s %s\n' "$c_red" "$c_rst" "$*" >&2; exit 1; }

need() { command -v "$1" >/dev/null 2>&1 || die "missing required command: $1"; }

# Load KEY=VALUE lines from an env file (like a .env). The real environment wins,
# so `CF_API_TOKEN=… ./switch.sh` still overrides a value in the file. Lines may
# be blank, `# comments`, or `export KEY=VALUE`; values may be quoted. This runs
# the file's assignments via the shell, so only point it at a file you trust.
load_env_file() { # path
  local f="$1" line key
  [ -f "$f" ] || die "env file not found: $f"
  info "loading env from $f"
  while IFS= read -r line || [ -n "$line" ]; do
    line="${line#"${line%%[![:space:]]*}"}"          # strip leading whitespace
    case "$line" in ''|'#'*) continue ;; esac
    line="${line#export }"
    key="${line%%=*}"
    [ "$key" = "$line" ] && continue                 # no '=' on the line
    case "$key" in ''|*[!A-Za-z0-9_]*) continue ;; esac
    printenv "$key" >/dev/null 2>&1 && continue       # already in the environment
    eval "export $line"
  done < "$f"
}

# side label helpers ---------------------------------------------------------
side_label() { # a|b|blue|green -> configured label
  case "$1" in
    a|A|blue)  echo "$SIDE_A_LABEL" ;;
    b|B|green) echo "$SIDE_B_LABEL" ;;
    *) die "unknown side '$1' (want: a|b, or blue|green)" ;;
  esac
}
side_name() { case "$1" in a|A|blue) echo "a";; b|B|green) echo "b";; *) echo "$1";; esac; }
other_side() { case "$(side_name "$1")" in a) echo b;; b) echo a;; esac; }

# per-side target names for a side label
addr_target() { echo "${TXT_PREFIX}.${DOMAIN}.$(side_label "$1").${DELEGATION_ZONE}"; }
acme_target() { echo "_acme-challenge.${DOMAIN}.$(side_label "$1").${DELEGATION_ZONE}"; }

# ---------------------------------------------------------------------------
# Cloudflare API
# ---------------------------------------------------------------------------
cf() { # method path [json-body]
  local method="$1" path="$2" body="${3:-}"
  local args=(-sS -X "$method" "${CF_API}${path}"
    -H "Authorization: Bearer ${CF_API_TOKEN}"
    -H "Content-Type: application/json")
  [ -n "$body" ] && args+=(--data "$body")
  local resp
  resp="$(curl "${args[@]}")" || die "cloudflare request failed: $method $path"
  if [ "$(jq -r '.success' <<<"$resp")" != "true" ]; then
    die "cloudflare API error on $method $path: $(jq -c '.errors' <<<"$resp")"
  fi
  printf '%s' "$resp"
}

ZONE_ID=""
resolve_zone_id() {
  [ -n "$ZONE_ID" ] && return 0
  local resp
  resp="$(cf GET "/zones?name=${CF_ZONE}&status=active")"
  ZONE_ID="$(jq -r '.result[0].id // empty' <<<"$resp")"
  [ -n "$ZONE_ID" ] || die "no active Cloudflare zone named '${CF_ZONE}' visible to this token"
}

# echo "<id>\t<type>\t<content>" for every record at a name (may be empty)
cf_records_at() { # name
  resolve_zone_id
  cf GET "/zones/${ZONE_ID}/dns_records?name=$1&per_page=100" \
    | jq -r '.result[] | [.id, .type, .content] | @tsv'
}

# Upsert a CNAME at $name -> $target, removing any conflicting records first.
put_cname() { # name target
  local name="$1" target="$2"
  resolve_zone_id
  local existing cname_id="" conflicts=()
  existing="$(cf_records_at "$name")"
  while IFS=$'\t' read -r id type content; do
    [ -z "${id:-}" ] && continue
    if [ "$type" = "CNAME" ]; then
      if [ "$content" = "$target" ]; then
        info "$name already CNAME -> $target (no change)"
        return 0
      fi
      cname_id="$id"
    else
      conflicts+=("$id:$type:$content")
    fi
  done <<<"$existing"

  local payload
  payload="$(jq -nc --arg n "$name" --arg t "$target" --argjson ttl "$TTL" \
    '{type:"CNAME",name:$n,content:$t,ttl:$ttl,proxied:false}')"

  if [ "$DRY_RUN" = 1 ]; then
    for c in "${conflicts[@]:-}"; do [ -n "$c" ] && log "  ${c_dim}[dry-run] delete ${c%%:*} (${c#*:})${c_rst}"; done
    if [ -n "$cname_id" ]; then log "  ${c_dim}[dry-run] update $name CNAME -> $target${c_rst}"
    else log "  ${c_dim}[dry-run] create $name CNAME -> $target${c_rst}"; fi
    return 0
  fi

  # A CNAME cannot coexist with other record types at the same name.
  for c in "${conflicts[@]:-}"; do
    [ -z "$c" ] && continue
    warn "removing conflicting record at $name (${c#*:})"
    cf DELETE "/zones/${ZONE_ID}/dns_records/${c%%:*}" >/dev/null
  done

  if [ -n "$cname_id" ]; then
    cf PUT "/zones/${ZONE_ID}/dns_records/${cname_id}" "$payload" >/dev/null
    info "updated $name CNAME -> $target"
  else
    cf POST "/zones/${ZONE_ID}/dns_records" "$payload" >/dev/null
    info "created $name CNAME -> $target"
  fi
}

# Current CNAME target of a switch-layer name (empty if unset / not a CNAME).
current_cname() { # name
  cf_records_at "$1" | awk -F'\t' '$2=="CNAME"{print $3; exit}'
}

# Which side (a|b) a switch-layer CNAME currently points at ("" / "?" if neither).
which_side() { # current-target
  local t="$1"
  [ -z "$t" ] && { echo ""; return; }
  case "$t" in
    "$(addr_target a)"|"$(acme_target a)") echo a ;;
    "$(addr_target b)"|"$(acme_target b)") echo b ;;
    *) echo "?" ;;
  esac
}

# ---------------------------------------------------------------------------
# DNS + HTTP checks
# ---------------------------------------------------------------------------
# The app_id:port a side currently publishes, read straight from the delegation
# zone (authoritative, no public-DNS propagation lag). Each side's dstack-ingress
# writes this per-side TXT itself; we only read it.
side_app_addr() { # a|b
  cf_records_at "$(addr_target "$1")" \
    | awk -F'\t' '$2=="TXT"{print $3; exit}' | sed 's/^"//; s/"$//'
}

http_ok() { # url -> 0 if HTTP 2xx
  local code
  code="$(curl -sS -o /dev/null -w '%{http_code}' --max-time 10 "$1" 2>/dev/null || echo 000)"
  [[ "$code" =~ ^2[0-9][0-9]$ ]]
}

public_health_ok() { http_ok "https://${DOMAIN}${HEALTH_PATH}"; }

confirm() {
  [ "$DRY_RUN" = 1 ] && return 0        # dry-run changes nothing; never prompt
  [ "$ASSUME_YES" = 1 ] && return 0
  [ -t 0 ] || die "refusing to proceed non-interactively without --yes"
  local reply
  read -r -p "$1 [y/N] " reply
  [[ "$reply" =~ ^[Yy]$ ]]
}

# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------
cmd_status() {
  resolve_zone_id
  local addr_now acme_now addr_side acme_side
  addr_now="$(current_cname "$ADDR_SWITCH")"
  acme_now="$(current_cname "$ACME_SWITCH")"
  addr_side="$(which_side "$addr_now")"
  acme_side="$(which_side "$acme_now")"

  printf 'delegation zone : %s (zone id %s)\n' "$CF_ZONE" "$ZONE_ID"
  printf 'served domain   : %s\n\n' "$DOMAIN"

  printf 'traffic switch  : %s\n' "${TXT_PREFIX}.${DOMAIN}"
  printf '   -> %s  [%s]\n' "${addr_now:-<unset>}" "${addr_side:-none}"
  printf 'issuance switch : _acme-challenge.%s\n' "$DOMAIN"
  printf '   -> %s  [%s]\n\n' "${acme_now:-<unset>}" "${acme_side:-none}"

  local s app_a app_b
  app_a="$(side_app_addr a || true)"
  app_b="$(side_app_addr b || true)"
  for s in a b; do
    printf 'side %s : app-address %-24s app_id=%s\n' \
      "$s" "$(addr_target "$s")" "$(side_app_addr "$s" || true)"
  done
  if [ -n "$app_a" ] && [ "$app_a" = "$app_b" ]; then
    warn "both sides publish the same app_id — same build, so the switch cannot"
    warn "select between them (dstack treats them as replicas). Use two images."
  fi
  printf '\n'

  if public_health_ok; then
    printf 'public health   : %sOK%s  https://%s%s\n' "$c_grn" "$c_rst" "$DOMAIN" "$HEALTH_PATH"
  else
    printf 'public health   : %sFAIL%s https://%s%s\n' "$c_red" "$c_rst" "$DOMAIN" "$HEALTH_PATH"
  fi

  if [ "$addr_side" = a ] || [ "$addr_side" = b ]; then
    printf '\nlive side       : %s%s%s\n' "$c_grn" "$addr_side" "$c_rst"
  fi
}

move_switches() { # target-side  [--acme-only]
  local target="$1" acme_only="${2:-}"
  local tgt_addr tgt_acme
  tgt_addr="$(addr_target "$target")"
  tgt_acme="$(acme_target "$target")"

  if [ "$acme_only" != "--acme-only" ]; then
    put_cname "$ADDR_SWITCH" "$tgt_addr"
  fi
  put_cname "$ACME_SWITCH" "$tgt_acme"
}

cmd_switch() {
  [ -n "${1:-}" ] || die "usage: $0 switch <a|b>"
  local target; target="$(side_name "$1")"
  resolve_zone_id

  local cur_target cur_side
  cur_target="$(current_cname "$ADDR_SWITCH")"
  cur_side="$(which_side "$cur_target")"

  info "current live side: ${cur_side:-<none>}  ->  target: ${target}"
  if [ "$cur_side" = "$target" ]; then
    warn "traffic switch already points at side ${target}; nothing to do"
    exit 0
  fi

  # Gate 1: the target side must actually be publishing an app-address.
  local tgt_addr; tgt_addr="$(side_app_addr "$target")"
  if [ -z "$tgt_addr" ]; then
    die "side ${target} publishes no app-address TXT at $(addr_target "$target") — is that CVM up and did its ingress publish?"
  fi
  info "side ${target} publishes app_id: ${tgt_addr}"

  # A side's identity is its app_id, which comes from the gateway image digest.
  # If both sides publish the SAME app_id they are the same build — dstack treats
  # them as replicas of one app and routes to either, so the switch cannot
  # isolate the target. That defeats the purpose; make it loud.
  local other_addr; other_addr="$(side_app_addr "$(other_side "$target")")"
  if [ -n "$other_addr" ] && [ "$other_addr" = "$tgt_addr" ]; then
    warn "both sides publish the same app_id (${tgt_addr}) — they are the same"
    warn "build, so dstack treats them as replicas and this switch cannot select"
    warn "between them. Blue/green needs two DIFFERENT gateway images."
  fi

  # Gate 2: optional direct probe of the target side before we send it traffic.
  if [ -n "$PROBE_URL" ]; then
    info "probing target side directly: $PROBE_URL"
    http_ok "$PROBE_URL" || die "target-side probe failed ($PROBE_URL) — refusing to switch"
    info "target-side probe OK"
  else
    warn "no --probe-url given: cannot health-check side ${target} before cutover (see blue-green.md)"
  fi

  confirm "Switch traffic ${cur_side:-<none>} -> ${target} for ${DOMAIN}?" || { warn "aborted"; exit 1; }

  # Record the side we are leaving, so `rollback` knows where to go.
  local statedir="${TMPDIR:-/tmp}"
  [ "$DRY_RUN" = 1 ] || printf '%s\n' "${cur_side:-}" > "${statedir}/.gw-switch-prev-${DOMAIN}" 2>/dev/null || true

  move_switches "$target"

  if [ "$DRY_RUN" = 1 ]; then info "dry-run complete; no changes applied"; exit 0; fi

  if [ "$NO_VERIFY" = 1 ]; then
    info "switched to ${target} (post-switch verification skipped)"; exit 0
  fi

  # Verify the public endpoint recovers; auto-rollback if it does not.
  info "waiting for public endpoint to serve from ${target} (TTL ${TTL}s)..."
  local i
  for ((i=1; i<=VERIFY_RETRIES; i++)); do
    if public_health_ok; then
      info "public health OK after switch to ${target} (attempt ${i})"
      info "done. rollback with:  $0 switch ${cur_side:-<other>}"
      exit 0
    fi
    log "  attempt ${i}/${VERIFY_RETRIES}: not healthy yet, sleeping ${VERIFY_INTERVAL}s"
    sleep "$VERIFY_INTERVAL"
  done

  warn "public endpoint did not become healthy after switching to ${target}"
  if [ -n "$cur_side" ]; then
    warn "AUTO-ROLLBACK: restoring traffic to ${cur_side}"
    move_switches "$cur_side"
    die "rolled back to ${cur_side}. Investigate side ${target} before retrying."
  fi
  die "no previous side to roll back to; the switch now points at ${target} but /healthz is failing"
}

cmd_rollback() {
  resolve_zone_id
  local cur_side prev
  cur_side="$(which_side "$(current_cname "$ADDR_SWITCH")")"
  local statedir="${TMPDIR:-/tmp}"
  prev="$(cat "${statedir}/.gw-switch-prev-${DOMAIN}" 2>/dev/null || true)"
  if [ -z "$prev" ] || [ "$prev" = "?" ]; then
    # No recorded previous side: fall back to "the other side".
    if [ -z "$cur_side" ] || [ "$cur_side" = "?" ]; then
      die "cannot determine a side to roll back to; use: $0 switch <a|b>"
    fi
    prev="$(other_side "$cur_side")"
    warn "no recorded previous side; rolling back to the other side: ${prev}"
  fi
  info "rolling back: ${cur_side:-<none>} -> ${prev}"
  cmd_switch "$prev"
}

cmd_acme() {
  [ -n "${1:-}" ] || die "usage: $0 acme <a|b>"
  local target; target="$(side_name "$1")"
  info "pointing issuance switch (_acme-challenge.${DOMAIN}) at side ${target}"
  info "this lets side ${target}'s dstack-ingress answer the ACME dns-01 challenge"
  confirm "Point _acme-challenge for ${DOMAIN} at side ${target}?" || { warn "aborted"; exit 1; }
  move_switches "$target" --acme-only
  info "done. Remember to point it back at the live side once side ${target} has its cert,"
  info "so the live side can keep renewing:  $0 acme <live-side>"
}

usage() {
  # Print the header comment block (everything up to `set -euo pipefail`),
  # stripping the leading "# ".
  awk 'NR==1{next} /^set -euo pipefail/{exit} {sub(/^# ?/,""); print}' "$0"
  exit "${1:-0}"
}

# ---------------------------------------------------------------------------
# Arg parsing
# ---------------------------------------------------------------------------
POSITIONAL=()
while [ $# -gt 0 ]; do
  case "$1" in
    --dry-run)   DRY_RUN=1 ;;
    --yes|-y)    ASSUME_YES=1 ;;
    --no-verify) NO_VERIFY=1 ;;
    --probe-url) PROBE_URL="${2:?--probe-url needs a URL}"; shift ;;
    --probe-url=*) PROBE_URL="${1#*=}" ;;
    --env-file)  ENV_FILE="${2:?--env-file needs a path}"; shift ;;
    --env-file=*) ENV_FILE="${1#*=}" ;;
    -h|--help)   usage 0 ;;
    -*)          die "unknown flag: $1 (try --help)" ;;
    *)           POSITIONAL+=("$1") ;;
  esac
  shift
done
set -- "${POSITIONAL[@]:-}"

# Load config from an env file before resolving defaults. Precedence:
#   real environment  >  --env-file / $ENV_FILE  >  ./switch.env next to script
# The real environment always wins (load_env_file skips keys already set).
if [ -n "$ENV_FILE" ]; then
  load_env_file "$ENV_FILE"
elif [ -f "${SCRIPT_DIR}/switch.env" ]; then
  load_env_file "${SCRIPT_DIR}/switch.env"
fi

# ---------------------------------------------------------------------------
# Config (env / env-file, with defaults for the current production deployment)
# ---------------------------------------------------------------------------
CF_ZONE="${CF_ZONE:-integratenetwork.work}"
DOMAIN="${DOMAIN:-router-api-tee.0g.ai}"
DELEGATION_ZONE="${DELEGATION_ZONE:-$CF_ZONE}"
SIDE_A_LABEL="${SIDE_A_LABEL:-a}"
SIDE_B_LABEL="${SIDE_B_LABEL:-b}"
TXT_PREFIX="${TXT_PREFIX:-_dstack-app-address}"
HEALTH_PATH="${HEALTH_PATH:-/healthz}"
TTL="${TTL:-60}"
VERIFY_RETRIES="${VERIFY_RETRIES:-10}"
VERIFY_INTERVAL="${VERIFY_INTERVAL:-6}"

# Switch-layer record names (in the delegation zone) that this script owns.
ADDR_SWITCH="${TXT_PREFIX}.${DOMAIN}.${DELEGATION_ZONE}"
ACME_SWITCH="_acme-challenge.${DOMAIN}.${DELEGATION_ZONE}"

need curl; need jq
: "${CF_API_TOKEN:?set CF_API_TOKEN (Cloudflare token for ${CF_ZONE}); put it in ${SCRIPT_DIR}/switch.env or export it}"

cmd="${1:-status}"
case "$cmd" in
  status)   cmd_status ;;
  switch)   cmd_switch "${2:-}" ;;
  rollback) cmd_rollback ;;
  acme)     cmd_acme "${2:-}" ;;
  ""|-h|--help|help) usage 0 ;;
  *) die "unknown command '$cmd' (want: status | switch <a|b> | rollback | acme <a|b>)" ;;
esac
