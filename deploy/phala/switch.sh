#!/usr/bin/env bash
#
# switch.sh — blue/green traffic switch for the cloud-TEE gateway.
#
# WHY THIS EXISTS ------------------------------------------------------------
# The gateway runs in a dstack CVM, and under a KMS key provider (what Phala
# Cloud runs) that CVM's app_id is assigned when the app is CREATED and kept for
# its life — it is NOT derived from the compose text, so two CVMs created as
# separate *apps* are two unrelated apps whatever their compose says, while a CVM
# created under an existing app_id joins that app as an instance, and an in-place
# upgrade keeps the app_id too. (`truncate(compose_hash, 20)` is the fallback for
# the local-key-provider case; see the app_id note in blue-green.md.) dstack only
# load-balances *within one app_id*. So a blue/green release is not "shift weight
# on a load balancer" — it is flipping a single DNS pointer,
# `_dstack-app-address.<DOMAIN>`, from the blue app_id to the green one. This
# script flips that pointer safely and reversibly.
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
#   ./switch.sh setup                                # one-time: static serving alias
#                                                    # (derived from PLATFORM_BASE)
#   ./switch.sh switch b                             # flip traffic (+ acme) to side b
#   ./switch.sh rollback                             # flip to the other side (live side read from DNS; stateless)
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
#   PLATFORM_BASE    dstack platform base domain    (e.g. in1.phala.network) — enables the
#                    per-side app-id probe before a switch (<app_id>-443s.<PLATFORM_BASE>),
#                    and `setup` derives GATEWAY_DOMAIN from it as _.<PLATFORM_BASE>.
#                    Either spelling is accepted; a leading `_.` is stripped on read.
#   GATEWAY_DOMAIN   cluster dstack gateway         (used only by `setup`; defaults to
#                    _.<PLATFORM_BASE>, and a missing `_.` is added — the alias must
#                    name the gateway's wildcard hop. Setting both to different
#                    clusters is refused; they are two spellings of one value and
#                    nothing else cross-checks them. `status` warns if the live alias
#                    drifts from PLATFORM_BASE or is not a `_.<base>` hop.)
#   SIDE_A_LABEL     sub-zone label for side a      (default: a)
#   SIDE_B_LABEL     sub-zone label for side b      (default: b)
#   TXT_PREFIX       app-address record prefix      (default: _dstack-app-address)
#   HEALTH_PATH      public health path             (default: /healthz — post-switch check)
#   PROBE_PATH       standby readiness path         (default: /readyz — pre-switch gate 2)
#   TTL              CNAME TTL in seconds           (default: 60)
#   VERIFY_RETRIES   post-switch health attempts    (default: 20; window must outlast the route cache)
#   VERIFY_INTERVAL  seconds between attempts       (default: 6)
#   PROBE_RETRIES    pre-switch target probe tries  (default: 30, PROBE_INTERVAL apart)
#   PROBE_INTERVAL   seconds between probe attempts (default: 10)
#
# The two probes measure different things on purpose. The post-switch check
# (HEALTH_PATH + VERIFY_*) asks "did traffic land on the new side yet", so its
# window is sized to the DNS TTL and the dstack gateway's route cache. The
# pre-switch gate (PROBE_PATH + PROBE_*) asks "can the standby actually serve",
# which means waiting out its first warmer sweep — provider quotes DCAP-verified
# one at a time, collateral fetched cold, each provider's on-chain signer read — so
# its window is minutes, not one TTL. Sharing a knob between them would tie a
# provider-readiness timeout to a DNS timescale.
#
# This is a bash script (arrays, [[ ]], ${BASH_SOURCE}). If it was started with a
# POSIX shell — `sh switch.sh` runs under dash on Debian/Ubuntu/WSL and chokes on
# `set -o pipefail` — re-exec under bash so it works either way.
if [ -z "${BASH_VERSION:-}" ]; then exec bash "$0" "$@"; fi

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
    line="${line%$'\r'}"                             # tolerate CRLF (Windows/WSL) files
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
# Normalize a side to a|b. Die (don't echo it back) on anything else, so a typo
# like `switch c` fails at the argument instead of flowing into a record name.
side_name() { case "$1" in a|A|blue) echo "a";; b|B|green) echo "b";; *) die "unknown side '$1' (want: a|b, or blue|green)";; esac; }
other_side() { case "$(side_name "$1")" in a) echo b;; b) echo a;; esac; }

# per-side target names for a side label. side_label's die runs in the `$(...)`
# subshell, so it can't abort us directly; check its status with `|| return 1`
# and return non-zero (emitting nothing) rather than echo a malformed name with an
# empty label. Callers assign this via `$(...)` from a directly-called function
# (e.g. move_switches), where that non-zero status does trip set -e.
addr_target() { local l; l="$(side_label "$1")" || return 1; echo "${TXT_PREFIX}.${DOMAIN}.${l}.${DELEGATION_ZONE}"; }
acme_target() { local l; l="$(side_label "$1")" || return 1; echo "_acme-challenge.${DOMAIN}.${l}.${DELEGATION_ZONE}"; }

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

http_status() { # url -> the HTTP status code, or 000 if unreachable
  # `-w` prints 000 itself when the request never got a response, so the exit code
  # is swallowed rather than handled: `|| echo 000` would APPEND a second one and
  # the caller would compare against "000\n000".
  curl -sSk -o /dev/null -w '%{http_code}' --max-time 10 "$1" 2>/dev/null || true
}

http_ok() { # url -> 0 if HTTP 2xx. -k: we check reachability/health, not cert
  # validity (that is covered by the evidence bundle and the fingerprint check),
  # and staging/per-side endpoints legitimately serve a cert for another name.
  local code
  code="$(curl -sSk -o /dev/null -w '%{http_code}' --max-time 10 "$1" 2>/dev/null || echo 000)"
  [[ "$code" =~ ^2[0-9][0-9]$ ]]
}

# A per-side READINESS URL that reaches THAT side directly, by app-id, via the
# dstack gateway's platform hostname (<app_id>-443s.<PLATFORM_BASE>). The `s` = TLS
# passthrough to the side's own ingress; routing is by the app-id in the hostname,
# independent of the custom domain's _dstack-app-address, so it hits the target
# side even before any traffic points at it. Empty if PLATFORM_BASE is unset.
#
# It probes PROBE_PATH (/readyz), not HEALTH_PATH (/healthz): the question before a
# cutover is not "is that process up" but "can it serve" — with on-chain grounding
# enforced, a side that cannot read the chain answers nothing, and traffic must stay
# on the live side, which is still serving from a warm cache. Point --probe-url at
# /healthz to fall back to the weaker liveness-only gate.
platform_probe_url() { # a|b [path] -> defaults to PROBE_PATH
  [ -n "$PLATFORM_BASE" ] || return 0
  local addr; addr="$(side_app_addr "$1")"   # "<app_id>:443"
  [ -n "$addr" ] || return 0
  echo "https://${addr%%:*}-443s.${PLATFORM_BASE}${2:-$PROBE_PATH}"
}

public_health_ok() { http_ok "https://${DOMAIN}${HEALTH_PATH}"; }

# SHA-256 fingerprint of the TLS cert currently served at $DOMAIN:443, or empty.
# Each side runs its OWN dstack-ingress and issues its OWN cert, so the served
# fingerprint identifies WHICH side answered — used to confirm a switch actually
# took effect rather than being fooled by a cached routing lookup on the gateway.
served_cert_fp() {
  command -v openssl >/dev/null 2>&1 || return 0
  echo | openssl s_client -servername "$DOMAIN" -connect "${DOMAIN}:443" 2>/dev/null \
    | openssl x509 -noout -fingerprint -sha256 2>/dev/null | sed 's/.*=//'
}

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

  local alias_now; alias_now="$(current_cname "$SERVING_ALIAS" || true)"
  printf 'serving alias   : %s\n' "$SERVING_ALIAS"
  printf '   -> %s\n' "${alias_now:-<unset>}"
  # The serving alias and PLATFORM_BASE are two hand-typed spellings of one
  # cluster, and nothing else cross-checks them: a mismatch means the standby
  # probe health-checks a side on one cluster while traffic goes to another, so
  # `switch` would pass its gate and then cut over to an unreachable side.
  if [ -n "$PLATFORM_BASE" ] && [ -n "$alias_now" ] &&
     [ "${alias_now#_.}" != "${PLATFORM_BASE#_.}" ]; then
    warn "serving alias and PLATFORM_BASE name different clusters:"
    warn "  alias -> ${alias_now} vs PLATFORM_BASE=${PLATFORM_BASE}"
    warn "  the pre-switch probe would test a side the live path cannot reach."
  fi
  # Right cluster, wrong form: the alias must name the gateway's wildcard hop.
  # A bare base domain is not one, and the cluster check above cannot see it
  # because it compares the two with `_.` stripped.
  if [ -n "$alias_now" ] && [ "$alias_now" = "${alias_now#_.}" ]; then
    warn "serving alias is not a gateway hop (wants _.<base>): ${alias_now}"
    warn "  traffic will not reach a dstack gateway, and pcverify cannot derive"
    warn "  a base domain from this chain. Re-run 'setup' to rewrite it."
  fi
  printf 'traffic switch  : %s\n' "${TXT_PREFIX}.${DOMAIN}"
  printf '   -> %s  [%s]\n' "${addr_now:-<unset>}" "${addr_side:-none}"
  printf 'issuance switch : _acme-challenge.%s\n' "$DOMAIN"
  printf '   -> %s  [%s]\n\n' "${acme_now:-<unset>}" "${acme_side:-none}"

  local s app_a app_b
  app_a="$(side_app_addr a || true)"
  app_b="$(side_app_addr b || true)"
  for s in a b; do
    printf 'side %s : app_id=%-45s probe=%s\n' \
      "$s" "$(side_app_addr "$s" || true)" "$(platform_probe_url "$s" || true)"
  done
  if [ -n "$app_a" ] && [ "$app_a" = "$app_b" ]; then
    warn "both sides publish the same app_id — dstack treats them as instances of"
    warn "ONE app and routes to either, so the switch cannot select between them."
    warn "Usually one side was created under the other's app_id (an instance or an"
    warn "in-place upgrade) instead of as its own app; a stale record left by a"
    warn "replaced CVM does it too. Each side must be a separately created app —"
    warn "adding instances to a side is scaling, not a second side."
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

  # Order matters: the traffic switch is written LAST. A cf failure aborts the
  # whole script (cf -> die), so if that happened between two writes with traffic
  # first, traffic would be left pointing at the unverified target with neither
  # the verify loop nor the auto-rollback reached. Writing issuance first means
  # any failure before the final, single-PUT traffic flip leaves traffic on the
  # current side.
  put_cname "$ACME_SWITCH" "$tgt_acme"
  if [ "$acme_only" != "--acme-only" ]; then
    put_cname "$ADDR_SWITCH" "$tgt_addr"
  fi
}

cmd_switch() {
  [ -n "${1:-}" ] || die "usage: $0 switch <a|b>"
  local target; target="$(side_name "$1")"
  resolve_zone_id

  local cur_target cur_side
  cur_target="$(current_cname "$ADDR_SWITCH")"
  cur_side="$(which_side "$cur_target")"

  # "?" = the traffic switch points at something that is neither side's record.
  # Refuse rather than proceed: auto-rollback would have no valid side to restore.
  if [ "$cur_side" = "?" ]; then
    die "traffic switch points at an unrecognized target (${cur_target}); resolve it manually (./switch.sh status) before switching"
  fi

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

  # A side's identity is its app_id, which is assigned when the app is CREATED,
  # not derived from the compose text — so two sides created as separate apps are
  # distinct even when byte-identical, and conversely a CVM created UNDER an
  # existing app_id joins that app as an instance. Both sides publishing the SAME
  # app_id therefore means one app is behind both records, and dstack will route
  # to either instance, so the switch cannot isolate the target. That defeats the
  # purpose; make it loud.
  local other_addr; other_addr="$(side_app_addr "$(other_side "$target")")"
  if [ -n "$other_addr" ] && [ "$other_addr" = "$tgt_addr" ]; then
    warn "both sides publish the same app_id (${tgt_addr}) — one app is behind"
    warn "both records, so dstack treats them as its instances and this switch"
    warn "cannot select between them. Check that each side was created as its OWN"
    warn "app rather than under the other's app_id, and that neither record is a"
    warn "leftover from a replaced CVM."
  fi

  # Gate 2: verify the TARGET side can actually SERVE before we send it any
  # traffic — /readyz, not /healthz (see platform_probe_url). Prefer an explicit
  # --probe-url; otherwise, if PLATFORM_BASE is set, probe the target's own app-id
  # endpoint, which reaches it directly regardless of where traffic currently points.
  #
  # The window (PROBE_RETRIES x PROBE_INTERVAL, ~5min by default) is sized to a COLD
  # FIRST WARMER SWEEP on the standby, not to a DNS TTL: that sweep DCAP-verifies
  # each provider's quote one at a time, fetches Intel collateral cold, and reads
  # each provider's on-chain signer. A fresh side is legitimately not-ready for a
  # while, and cutting the wait short here would just switch to a side that has not
  # finished proving it can serve anyone.
  local probe="$PROBE_URL"
  [ -z "$probe" ] && probe="$(platform_probe_url "$target")"
  if [ -n "$probe" ]; then
    info "probing target side ${target} directly: $probe"
    info "  (up to ${PROBE_RETRIES} attempts ${PROBE_INTERVAL}s apart — a cold side must finish its first warmer sweep)"
    local pi probe_ok=0 status fell_back=0
    for ((pi=1; pi<=PROBE_RETRIES; pi++)); do
      status="$(http_status "$probe")"
      case "$status" in
        2*) probe_ok=1; break ;;
        404)
          # A side that PREDATES readiness gating does not serve PROBE_PATH at all: the
          # path falls through its catch-all to the router, which answers about itself.
          # That must not read as "not ready" — the target of a ROLLBACK is an older
          # image by definition, and the emergency path is the worst place to be strict.
          # Checked on EVERY attempt, not once up front: a standby that has not finished
          # booting answers 000, and a single early probe would miss the 404 entirely and
          # then burn the whole window on an image that was never going to serve it.
          # A 503 is different — the route exists and says not-ready, a real verdict.
          if [ -n "$PROBE_URL" ]; then break; fi   # operator chose this URL; respect it
          # Fall back ONCE. The immediate retry below skips the interval on purpose, so
          # re-entering this arm every attempt would spend the whole PROBE_RETRIES budget
          # in a tight loop — the ~5min window collapsing into about a second, and the
          # three warnings printed once per attempt. Past the first fallback a 404 is an
          # ordinary failure of HEALTH_PATH (a custom HEALTH_PATH that side does not
          # serve, say), so it falls through to the interval sleep and keeps waiting.
          if [ "$fell_back" = 1 ]; then
            log "  probe attempt ${pi}/${PROBE_RETRIES} got 404 on the ${HEALTH_PATH} fallback too"
          else
            fell_back=1
            warn "side ${target} does not serve ${PROBE_PATH} (404) — it predates readiness gating"
            warn "falling back to ${HEALTH_PATH}: this only checks the process is up, NOT that it can"
            warn "serve. It cannot tell you whether that side can reach providers or the chain."
            probe="$(platform_probe_url "$target" "$HEALTH_PATH")"
            continue   # retry immediately against the fallback, without burning an interval
          fi
          ;;
      esac
      if [ "$pi" -lt "$PROBE_RETRIES" ]; then
        log "  probe attempt ${pi}/${PROBE_RETRIES} got ${status}, retrying in ${PROBE_INTERVAL}s"
        sleep "$PROBE_INTERVAL"
      fi
    done
    [ "$probe_ok" = 1 ] || die "target-side probe failed after ${PROBE_RETRIES} attempts ($probe) — refusing to switch"
    info "target-side probe OK"
  else
    warn "no --probe-url and no PLATFORM_BASE: cannot health-check side ${target} before cutover (see blue-green.md)"
  fi

  confirm "Switch traffic ${cur_side:-<none>} -> ${target} for ${DOMAIN}?" || { warn "aborted"; exit 1; }

  # Fingerprint the cert the live side is serving BEFORE we flip. After the flip
  # we wait for the served fingerprint to CHANGE — proof the gateway is now
  # routing to ${target} and not answering our health check from a cached route
  # to the old side. Only meaningful when switching between two live sides and
  # openssl is present.
  local cert_before=""
  if [ -n "$cur_side" ]; then
    # `|| true`: a plain `var=$(cmd)` under `set -e` aborts if cmd exits non-zero
    # (unlike `local var=$(cmd)`, where local's own status masks it). served_cert_fp
    # returns non-zero on a transient TLS read failure (pipefail), which must fall
    # through to the degradation below, not kill the script.
    cert_before="$(served_cert_fp || true)"
    if [ -z "$cert_before" ]; then
      if command -v openssl >/dev/null 2>&1; then
        warn "could not read the current served cert; will verify /healthz only"
      else
        warn "openssl not found: verifying /healthz only — a cached gateway route to ${cur_side} could satisfy it (install openssl for cache-proof verification)"
      fi
    fi
  fi

  move_switches "$target"

  if [ "$DRY_RUN" = 1 ]; then info "dry-run complete; no changes applied"; exit 0; fi

  if [ "$NO_VERIFY" = 1 ]; then
    info "switched to ${target} (post-switch verification skipped)"; exit 0
  fi

  # Verify the public endpoint recovers AND is actually being served by ${target}
  # (cert fingerprint changed); auto-rollback if it does not within the window.
  # The window must exceed the gateway's routing-cache TTL or a slow cache flush
  # reads as a failure — see VERIFY_RETRIES/VERIFY_INTERVAL.
  info "waiting for the public endpoint to serve from ${target} (record TTL ${TTL}s)..."
  local i cert_now healthz_seen=0
  for ((i=1; i<=VERIFY_RETRIES; i++)); do
    if public_health_ok; then
      healthz_seen=1
      # `|| true`: never let a transient openssl/TLS hiccup abort mid-verify-loop —
      # traffic is already switched, so aborting here would skip the auto-rollback.
      # An empty cert_now just means "not confirmed yet", handled by the else below.
      cert_now="$(served_cert_fp || true)"
      if [ -z "$cert_before" ]; then
        # No baseline to compare (no prior side, or no openssl): /healthz is all we have.
        info "public health OK after switch to ${target} (attempt ${i})"
        info "done. rollback with:  $0 switch ${cur_side:-<other>}"
        exit 0
      elif [ -n "$cert_now" ] && [ "$cert_now" != "$cert_before" ]; then
        info "verified: ${DOMAIN} now served by ${target} (cert changed) and /healthz OK"
        info "done. rollback with:  $0 switch ${cur_side:-<other>}"
        exit 0
      else
        log "  attempt ${i}/${VERIFY_RETRIES}: /healthz OK but still the old cert — gateway route cache not flushed yet, waiting ${VERIFY_INTERVAL}s"
      fi
    else
      log "  attempt ${i}/${VERIFY_RETRIES}: not healthy yet, sleeping ${VERIFY_INTERVAL}s"
    fi
    # Don't sleep after the final attempt — go straight to the failure path.
    if [ "$i" -lt "$VERIFY_RETRIES" ]; then sleep "$VERIFY_INTERVAL"; fi
  done

  # Two distinct failure modes, handled differently:
  if [ "$healthz_seen" = 1 ]; then
    warn "after ${VERIFY_RETRIES} attempts ${DOMAIN} /healthz is OK but still serving ${cur_side}'s cert"
    warn "— the gateway route cache has not flushed to ${target} within the verify window."
    warn "This usually means the window is shorter than the cache, not that ${target} is broken;"
    warn "raise VERIFY_RETRIES (or lower TTL) and re-run before concluding the switch failed."
  else
    warn "after ${VERIFY_RETRIES} attempts ${DOMAIN} /healthz never became healthy on ${target}"
  fi
  if [ -n "$cur_side" ]; then
    warn "AUTO-ROLLBACK: restoring traffic to ${cur_side}"
    move_switches "$cur_side"
    die "rolled back to ${cur_side}. Investigate side ${target} (or the cache window) before retrying."
  fi
  die "no previous side to roll back to; the switch points at ${target} but was not confirmed"
}

cmd_rollback() {
  resolve_zone_id
  # Stateless by design: with two sides, "roll back" is just "switch to the other
  # one", and which side is live is read from the shared switch record — not a
  # local file. So every operator, on any machine, computes the same target and
  # there is no stale per-machine state to get it wrong.
  local cur_side
  cur_side="$(which_side "$(current_cname "$ADDR_SWITCH")")"
  if [ -z "$cur_side" ] || [ "$cur_side" = "?" ]; then
    die "traffic switch points at neither side; nothing to roll back — use: $0 switch <a|b>"
  fi
  local target; target="$(other_side "$cur_side")"
  info "rolling back: ${cur_side} -> ${target} (live side read from DNS)"
  # A --probe-url passed to `rollback` would be for the wrong side (it names some
  # specific endpoint, not ${target}); drop it so gate 2 uses ${target}'s own
  # app-id probe instead of validating the rollback against an unrelated URL.
  PROBE_URL=""
  cmd_switch "$target"
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

cmd_setup() {
  resolve_zone_id
  local cur; cur="$(current_cname "$SERVING_ALIAS")"
  # One cluster, two operator-side spellings: GATEWAY_DOMAIN for the serving
  # alias here, and PLATFORM_BASE for the standby probe
  # (`<app_id>-443s.<PLATFORM_BASE>`). The CVMs no longer take a hand-typed
  # cluster at all, so these are the last two that can drift apart — and drifting
  # is not harmless: the probe would health-check a side on one cluster while the
  # serving alias hands traffic to another. So derive one from the other when
  # only PLATFORM_BASE is set, and refuse when both are set and disagree.
  # PLATFORM_BASE is already normalised to the bare base where it is read; the
  # `#_.` here is a fuse, and the one on GATEWAY_DOMAIN does the real work since
  # that one is not normalised until after this comparison.
  if [ -z "$GATEWAY_DOMAIN" ] && [ -n "$PLATFORM_BASE" ]; then
    GATEWAY_DOMAIN="_.${PLATFORM_BASE#_.}"
    info "GATEWAY_DOMAIN unset; derived from PLATFORM_BASE -> ${GATEWAY_DOMAIN}"
  elif [ -n "$GATEWAY_DOMAIN" ] && [ -n "$PLATFORM_BASE" ] &&
       [ "${GATEWAY_DOMAIN#_.}" != "${PLATFORM_BASE#_.}" ]; then
    info "GATEWAY_DOMAIN : ${GATEWAY_DOMAIN}"
    info "PLATFORM_BASE  : ${PLATFORM_BASE}"
    die "these name different clusters — the serving alias and the standby probe would disagree"
  fi
  if [ -z "$GATEWAY_DOMAIN" ]; then
    # Help the operator "freeze" whatever the single-instance container wrote.
    if [ -n "$cur" ]; then
      info "serving alias ${SERVING_ALIAS} currently -> ${cur}"
      die "set GATEWAY_DOMAIN to pin it (e.g. GATEWAY_DOMAIN=${cur} $0 setup)"
    fi
    die "set PLATFORM_BASE (<cluster>.phala.network) and it is derived, or set GATEWAY_DOMAIN (_.<cluster>.phala.network) directly"
  fi
  # Normalise the FORM, not just the cluster. The check above strips `_.` from
  # both sides on purpose — it asks "same cluster?" — so a GATEWAY_DOMAIN given
  # without the prefix agrees with PLATFORM_BASE and would otherwise be written
  # bare. Bare is not a harmless variant: the alias must name the gateway's
  # wildcard hop, this hop carries traffic in the single-instance layout, and
  # `pcverify` rejects a CNAME chain that does not end at `_.<base>`
  # (client/evidence/appcompose.go, deriveBaseDomain). Idempotent on a value that
  # already has it.
  GATEWAY_DOMAIN="_.${GATEWAY_DOMAIN#_.}"
  info "one-time setup: the static serving alias in the delegation zone"
  info "  ${SERVING_ALIAS}  CNAME ->  ${GATEWAY_DOMAIN}"
  info "the two switch records are created by 'acme'/'switch'; the per-side"
  info "records are written by each CVM's dstack-ingress — none are set here."
  confirm "Create/point ${SERVING_ALIAS} at ${GATEWAY_DOMAIN}?" || { warn "aborted"; exit 1; }
  put_cname "$SERVING_ALIAS" "$GATEWAY_DOMAIN"
  info "done. Next: point issuance at a side and deploy it (see blue-green.md fast path)."
}

usage() {
  # Print the header comment block: skip the shebang, then print comment lines and
  # stop at the first NON-comment line (the bash re-exec guard, then `set -euo
  # pipefail`) — so no code leaks into --help.
  awk 'NR==1{next} /^[^#]/{exit} {sub(/^# ?/,""); print}' "$0"
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
GATEWAY_DOMAIN="${GATEWAY_DOMAIN:-}"   # dstack gateway of the cluster; needed only by `setup`
PLATFORM_BASE="${PLATFORM_BASE:-}"     # dstack platform base domain (e.g. in1.phala.network) for per-side app-id probes
# Normalise to the BARE base once, here, because platform_probe_url interpolates
# this value straight into `<app_id>-443s.${PLATFORM_BASE}` and a `_.` in it makes
# an unresolvable host — a failure that only shows up as gate 2 timing out for
# PROBE_RETRIES x PROBE_INTERVAL (~5 min by default) and then refusing, on
# `switch` AND on `rollback`. Accepting the `_.` form is deliberate: `setup`
# derives GATEWAY_DOMAIN from this, and the two are one cluster written two ways.
# The `#_.` in setup/status stays as a fuse, but this is what actually holds.
PLATFORM_BASE="${PLATFORM_BASE#_.}"
SIDE_A_LABEL="${SIDE_A_LABEL:-a}"
SIDE_B_LABEL="${SIDE_B_LABEL:-b}"
TXT_PREFIX="${TXT_PREFIX:-_dstack-app-address}"
HEALTH_PATH="${HEALTH_PATH:-/healthz}"
TTL="${TTL:-60}"
VERIFY_RETRIES="${VERIFY_RETRIES:-20}"   # ~2x TTL by default, to outlast the gateway route cache
VERIFY_INTERVAL="${VERIFY_INTERVAL:-6}"
PROBE_PATH="${PROBE_PATH:-/readyz}"      # standby readiness path (gate 2); /healthz is liveness only
PROBE_RETRIES="${PROBE_RETRIES:-30}"     # pre-switch target probe attempts before refusing to switch
PROBE_INTERVAL="${PROBE_INTERVAL:-10}"   # seconds between them: 30x10s ≈ 5min, enough for a cold first sweep

# Switch-layer record names (in the delegation zone) that this script owns.
SERVING_ALIAS="${DOMAIN}.${DELEGATION_ZONE}"           # static -> GATEWAY_DOMAIN (set by `setup`)
ADDR_SWITCH="${TXT_PREFIX}.${DOMAIN}.${DELEGATION_ZONE}"
ACME_SWITCH="_acme-challenge.${DOMAIN}.${DELEGATION_ZONE}"

need curl; need jq
: "${CF_API_TOKEN:?set CF_API_TOKEN (Cloudflare token for ${CF_ZONE}); put it in ${SCRIPT_DIR}/switch.env or export it}"

cmd="${1:-status}"
case "$cmd" in
  status)   cmd_status ;;
  setup)    cmd_setup ;;
  switch)   cmd_switch "${2:-}" ;;
  rollback) cmd_rollback ;;
  acme)     cmd_acme "${2:-}" ;;
  ""|-h|--help|help) usage 0 ;;
  *) die "unknown command '$cmd' (want: setup | status | switch <a|b> | rollback | acme <a|b>)" ;;
esac
