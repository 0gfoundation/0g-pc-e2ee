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
#     <DOMAIN>.<DZ>                      CNAME -> _.<live side's cluster>                             <-- serving alias
#
#   delegation zone <DZ> — PER-SIDE records, written by each CVM's dstack-ingress:
#     a side (DELEGATION_ZONE=a.<DZ>):  _dstack-app-address.<DOMAIN>.a.<DZ> TXT = <app_id_a>:443
#     b side (DELEGATION_ZONE=b.<DZ>):  _dstack-app-address.<DOMAIN>.b.<DZ> TXT = <app_id_b>:443
#
# So `switch a|b` repoints the two switch-layer CNAMEs at the chosen side's
# per-side records, and the serving alias at that side's cluster — which is a
# no-op unless the sides run in different clusters (PLATFORM_BASE_A/_B). dstack-ingress on the Cloudflare provider resolves the
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
#   ./switch.sh setup [a|b]                          # one-time: serving alias -> the live
#                                                    # (or named) side's cluster
#   ./switch.sh switch b                             # flip traffic (+ acme, + alias) to side b;
#                                                    # auto-rollback if b does not verify
#   ./switch.sh failover b                           # same flip when the live side is gone:
#                                                    # no rollback, old side need not answer
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
#   PLATFORM_BASE    dstack platform base domain    (e.g. in1.phala.network) — the cluster
#                    both sides run in. Required by setup, switch, failover and
#                    rollback, unless PLATFORM_BASE_A and PLATFORM_BASE_B are both set.
#   PLATFORM_BASE_A  side a's / side b's cluster    (default: PLATFORM_BASE) — set them
#   PLATFORM_BASE_B  when the sides run in different clusters. A side's cluster is
#                    where its pre-switch probe goes (<app_id>-443s.<base>) and what
#                    the serving alias names (_.<base>) while it is live. A leading
#                    `_.` is accepted and stripped on read.
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
#   CERT_WARN_DAYS   `status` flags a side cert valid for fewer days (default: 21)
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

# The cluster (dstack platform base domain) a side runs in, and the serving-alias
# value that sends traffic to that cluster's gateway: its wildcard hop `_.<base>`,
# never the bare base — `pcverify` rejects a CNAME chain that does not end at
# `_.<base>` (client/evidence/appcompose.go, deriveBaseDomain).
side_base() { case "$(side_name "$1")" in a) echo "$PLATFORM_BASE_A" ;; b) echo "$PLATFORM_BASE_B" ;; esac; }
side_gateway() { local b; b="$(side_base "$1")" || return 1; [ -n "$b" ] && echo "_.${b}"; }

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
# writes this per-side TXT itself; we only read it — so within one run it cannot
# change under us, and load_side_addrs reads both once. It must be called
# directly, not in `$(...)`, for the cache to reach the caller; side_app_addr
# still works uncached if it was not.
SIDE_ADDRS_LOADED=0 SIDE_ADDR_a="" SIDE_ADDR_b=""
read_side_app_addr() { # a|b
  cf_records_at "$(addr_target "$1")" \
    | awk -F'\t' '$2=="TXT"{print $3; exit}' | sed 's/^"//; s/"$//'
}
load_side_addrs() {
  [ "$SIDE_ADDRS_LOADED" = 1 ] && return 0
  SIDE_ADDR_a="$(read_side_app_addr a)"
  SIDE_ADDR_b="$(read_side_app_addr b)"
  SIDE_ADDRS_LOADED=1
}
side_app_addr() { # a|b
  if [ "$SIDE_ADDRS_LOADED" != 1 ]; then read_side_app_addr "$1"; return; fi
  case "$(side_name "$1")" in a) echo "$SIDE_ADDR_a" ;; b) echo "$SIDE_ADDR_b" ;; esac
}

# Warn when both sides publish the same app_id. A side's identity is its app_id,
# which is assigned when the app is CREATED, not derived from the compose text —
# so two sides created as separate apps are distinct even when byte-identical,
# and conversely a CVM created UNDER an existing app_id joins that app as an
# instance. Both sides publishing the SAME app_id therefore means one app is
# behind both records, and dstack will route to either instance, so the switch
# cannot isolate the target. That defeats the purpose; make it loud.
warn_if_same_app_id() {
  local app_a app_b
  app_a="$(side_app_addr a)"; app_b="$(side_app_addr b)"
  [ -n "$app_a" ] && [ "$app_a" = "$app_b" ] || return 0
  warn "both sides publish the same app_id (${app_a}) — dstack treats them as instances"
  warn "of ONE app and routes to either, so the switch cannot select between them."
  warn "Usually one side was created under the other's app_id (an instance or an"
  warn "in-place upgrade) instead of as its own app; a stale record left by a"
  warn "replaced CVM does it too. Each side must be a separately created app —"
  warn "adding instances to a side is scaling, not a second side."
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
  [[ "$(http_status "$1")" =~ ^2[0-9][0-9]$ ]]
}

# A per-side READINESS URL that reaches THAT side directly, by app-id, via the
# dstack gateway's platform hostname (<app_id>-443s.<that side's base>). The `s` =
# TLS passthrough to the side's own ingress; routing is by the app-id in the
# hostname, independent of the custom domain's _dstack-app-address, so it hits the
# target side even before any traffic points at it. It must be the side's OWN
# cluster: a gateway only routes app_ids it hosts. Empty if that base is unset.
#
# It probes PROBE_PATH (/readyz), not HEALTH_PATH (/healthz): the question before a
# cutover is not "is that process up" but "can it serve" — with on-chain grounding
# enforced, a side that cannot read the chain answers nothing, and traffic must stay
# on the live side, which is still serving from a warm cache. Point --probe-url at
# /healthz to fall back to the weaker liveness-only gate.
platform_probe_url() { # a|b [path] -> defaults to PROBE_PATH
  local base; base="$(side_base "$1")"
  [ -n "$base" ] || return 0
  local addr; addr="$(side_app_addr "$1")"   # "<app_id>:443"
  [ -n "$addr" ] || return 0
  echo "https://${addr%%:*}-443s.${base}${2:-$PROBE_PATH}"
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

# A side's own certificate, read through its `-443s` platform hostname (routed
# by app_id, so this reaches a standby too; the ingress presents the cert it
# holds for DOMAIN whatever the SNI). Prints its notAfter date and returns 0 if
# it is valid for more than CERT_WARN_DAYS, 1 if it expires sooner, 2 if it
# could not be read (side or cluster down, no openssl, no cluster configured).
#
# This is the check that matters for a standby: only the side the issuance
# switch points at can renew, so a side kept in reserve ages until its cert runs
# out, and a failover onto it would then serve an expired certificate.
side_cert_expiry() { # a|b
  command -v openssl >/dev/null 2>&1 || return 2
  local base addr host pem end
  base="$(side_base "$1")"; addr="$(side_app_addr "$1")"
  [ -n "$base" ] && [ -n "$addr" ] || return 2
  host="${addr%%:*}-443s.${base}"
  pem="$(echo | openssl s_client -servername "$host" -connect "${host}:443" 2>/dev/null || true)"
  end="$(openssl x509 -noout -enddate <<<"$pem" 2>/dev/null || true)"
  end="${end#notAfter=}"
  [ -n "$end" ] || return 2
  echo "$end"
  openssl x509 -noout -checkend $((CERT_WARN_DAYS * 86400)) <<<"$pem" >/dev/null 2>&1 || return 1
}

confirm() {
  [ "$DRY_RUN" = 1 ] && return 0        # dry-run changes nothing; never prompt
  [ "$ASSUME_YES" = 1 ] && return 0
  [ -t 0 ] || die "refusing to proceed non-interactively without --yes"
  local reply
  read -r -p "$1 [y/N] " reply
  [[ "$reply" =~ ^[Yy]$ ]]
}

# Commands that move traffic need both sides' clusters: the target's builds its
# pre-switch probe (gate 2) and is what the serving alias moves to, and the live
# side's is what a rollback moves the alias back to.
need_side_bases() {
  [ -n "$PLATFORM_BASE_A" ] && [ -n "$PLATFORM_BASE_B" ] ||
    die "set PLATFORM_BASE (<cluster>.phala.network) — or PLATFORM_BASE_A and PLATFORM_BASE_B when the sides run in different clusters. They build the pre-switch probe and the serving alias."
}

# "" if the serving alias sends traffic to side $1's cluster, else a one-line
# reason. With the traffic switch on that side, a mismatch means the live
# path is broken: that cluster's gateway is handed an app_id it does not host.
alias_mismatch() { # side alias-now
  local want; want="$(side_gateway "$1")"
  if [ -z "$2" ]; then echo "the serving alias ${SERVING_ALIAS} is unset (want ${want})"
  elif [ "$2" != "$want" ]; then echo "the serving alias ${SERVING_ALIAS} -> $2, but side $1 runs on ${want}"
  fi
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
  # Traffic goes to the alias's cluster, and that cluster's gateway can only
  # route the live side if the live side runs there. A mismatch is a split state
  # (a cutover interrupted between its writes, or a hand edit): live traffic is
  # failing right now.
  if { [ "$addr_side" = a ] || [ "$addr_side" = b ]; } && [ -n "$(side_base "$addr_side")" ]; then
    local split; split="$(alias_mismatch "$addr_side" "$alias_now")"
    if [ -n "$split" ]; then
      warn "split state: ${split}."
      warn "  That cluster's gateway does not host side ${addr_side}'s app_id, so live traffic fails."
      warn "  Repair: $0 failover ${addr_side}  (or failover to the side the alias's cluster hosts)"
    fi
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

  local s end rc
  load_side_addrs
  for s in a b; do
    printf 'side %s : app_id=%-45s cluster=%s\n' \
      "$s" "$(side_app_addr "$s")" "$(side_base "$s")"
    printf '         probe=%s\n' "$(platform_probe_url "$s")"
    rc=0; end="$(side_cert_expiry "$s")" || rc=$?
    case "$rc" in
      0) printf '         cert  : %sOK%s   expires %s\n' "$c_grn" "$c_rst" "$end" ;;
      1) printf '         cert  : %sSOON%s expires %s\n' "$c_red" "$c_rst" "$end"
         if [ "$acme_side" = "$s" ]; then
           warn "side ${s}'s cert expires within ${CERT_WARN_DAYS} days although issuance points at it — it should be renewing; check its dstack-ingress log."
         else
           warn "side ${s}'s cert expires within ${CERT_WARN_DAYS} days and it cannot renew: issuance points at ${acme_side:-no side}."
           warn "  Renew it: $0 acme ${s}, wait for it to issue, then $0 acme ${acme_side:-<live side>}."
         fi ;;
      *) printf '         cert  : unreadable\n' ;;
    esac
  done
  warn_if_same_app_id
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

  # Order matters. Issuance first: a cf failure aborts the whole script (cf ->
  # die), and one before the traffic records are touched leaves traffic where it
  # was. Then the traffic switch, then the serving alias — a no-op unless the
  # target runs in another cluster. Alias last because a cluster's gateway caches
  # the app_id it looked up: written first, the alias would send clients to the
  # target's gateway while the switch still names the old side, and that gateway
  # would cache the old app_id (which it cannot route) for every client it
  # serves. Written last, only clients still holding the old alias fail, and only
  # once the old cluster's gateway refreshes — see blue-green.md, "Cross-cluster".
  # A failure between the two leaves them split; `status` flags it and re-running
  # the same command repairs it.
  put_cname "$ACME_SWITCH" "$tgt_acme"
  if [ "$acme_only" != "--acme-only" ]; then
    local gw; gw="$(side_gateway "$target" || true)"
    [ -n "$gw" ] || die "no cluster known for side ${target} (PLATFORM_BASE unset?)"
    put_cname "$ADDR_SWITCH" "$tgt_addr"
    put_cname "$SERVING_ALIAS" "$gw"
  fi
}

# Refuse (die) unless side $1 can take traffic: gate 1 — it publishes an
# app-address — and gate 2 — it answers its readiness probe.
gate_target() { # target-side
  local target="$1"
  load_side_addrs
  # Gate 1: the target side must actually be publishing an app-address.
  local tgt_addr; tgt_addr="$(side_app_addr "$target")"
  if [ -z "$tgt_addr" ]; then
    die "side ${target} publishes no app-address TXT at $(addr_target "$target") — is that CVM up and did its ingress publish?"
  fi
  info "side ${target} publishes app_id: ${tgt_addr}"
  warn_if_same_app_id

  # Gate 2: verify the TARGET side can actually SERVE before we send it any
  # traffic — /readyz, not /healthz (see platform_probe_url). Prefer an explicit
  # --probe-url; otherwise probe the target's own app-id endpoint on PLATFORM_BASE,
  # which reaches it directly regardless of where traffic currently points.
  #
  # The window (PROBE_RETRIES x PROBE_INTERVAL, ~5min by default) is sized to a COLD
  # FIRST WARMER SWEEP on the standby, not to a DNS TTL: that sweep DCAP-verifies
  # each provider's quote one at a time, fetches Intel collateral cold, and reads
  # each provider's on-chain signer. A fresh side is legitimately not-ready for a
  # while, and cutting the wait short here would just switch to a side that has not
  # finished proving it can serve anyone.
  local probe="$PROBE_URL"
  [ -z "$probe" ] && probe="$(platform_probe_url "$target")"
  [ -n "$probe" ] || die "no probe URL for side ${target} (PLATFORM_BASE unset?)"
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
}

# Wait for the public endpoint to be served by side $1. Returns 0 once verified,
# 1 if /healthz never turned healthy, 2 if it did but the old side's cert
# ($2, the fingerprint read before the flip) kept being served.
verify_switched() { # target-side cert-before
  local target="$1" cert_before="$2"
  # Verify the public endpoint recovers AND is actually being served by ${target}
  # (cert fingerprint changed) within the window.
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
        return 0
      elif [ -n "$cert_now" ] && [ "$cert_now" != "$cert_before" ]; then
        info "verified: ${DOMAIN} now served by ${target} (cert changed) and /healthz OK"
        return 0
      else
        log "  attempt ${i}/${VERIFY_RETRIES}: /healthz OK but still the old cert — gateway route cache not flushed yet, waiting ${VERIFY_INTERVAL}s"
      fi
    else
      log "  attempt ${i}/${VERIFY_RETRIES}: not healthy yet, sleeping ${VERIFY_INTERVAL}s"
    fi
    # Don't sleep after the final attempt — go straight to the failure path.
    if [ "$i" -lt "$VERIFY_RETRIES" ]; then sleep "$VERIFY_INTERVAL"; fi
  done

  [ "$healthz_seen" = 1 ] && return 2
  return 1
}

# Explain a failed verify ($3: verify_switched's status), restore traffic to the
# previous side $2 if there was one, and die either way.
auto_rollback() { # target-side previous-side verdict
  local target="$1" cur_side="$2" verdict="$3"
  # Two distinct failure modes, handled differently:
  if [ "$verdict" = 2 ]; then
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

# Report a failed verify WITHOUT restoring anything, and die. `failover` ends
# here: the side it left is presumed unreachable, so there is nowhere to go back to.
fail_forward() { # target-side verdict
  local target="$1" verdict="$2"
  if [ "$verdict" = 2 ]; then
    warn "after ${VERIFY_RETRIES} attempts ${DOMAIN} /healthz is OK but the cert never changed —"
    warn "clients may still be served by the old side through a cached route."
  else
    warn "after ${VERIFY_RETRIES} attempts ${DOMAIN} /healthz never became healthy on ${target}"
  fi
  warn "NOT rolling back: failover leaves traffic pointed at ${target}."
  die "failover to ${target} not confirmed. Check '$0 status' and side ${target}; DNS caches can take up to ${TTL}s past the window."
}

# The cutover `switch` and `failover` share: gate the target, flip the records,
# verify. On a failed verify, `rollback` restores the previous side (switch) and
# `stay` leaves traffic on the target and reports it (failover).
cutover() { # target-side previous-side rollback|stay
  local target="$1" cur_side="$2" on_fail="$3"

  gate_target "$target"

  local from_gw to_gw
  from_gw="$(current_cname "$SERVING_ALIAS")"
  to_gw="$(side_gateway "$target")"
  if [ -n "$from_gw" ] && [ "$from_gw" != "$to_gw" ]; then
    warn "cross-cluster: the serving alias moves ${from_gw} -> ${to_gw}."
    warn "  New connections from clients still holding the old alias fail once the old"
    warn "  cluster's gateway refreshes its app-address, until their DNS cache (TTL ${TTL}s)"
    warn "  expires. Open connections are unaffected. See blue-green.md, \"Cross-cluster\"."
  fi

  if [ "$on_fail" = stay ]; then
    confirm "Fail over traffic ${cur_side:-<none>} -> ${target} for ${DOMAIN}, with NO automatic rollback?" || { warn "aborted"; exit 1; }
  else
    confirm "Switch traffic ${cur_side:-<none>} -> ${target} for ${DOMAIN}?" || { warn "aborted"; exit 1; }
  fi

  # Fingerprint the cert the live side is serving BEFORE we flip. After the flip
  # we wait for the served fingerprint to CHANGE — proof the gateway is now
  # routing to ${target} and not answering our health check from a cached route
  # to the old side. Only meaningful when switching between two live sides and
  # openssl is present; on a failover the old side is usually not answering, and
  # /healthz is all there is.
  local cert_before=""
  if [ -n "$cur_side" ] && [ "$cur_side" != "$target" ]; then
    # `|| true`: a plain `var=$(cmd)` under `set -e` aborts if cmd exits non-zero
    # (unlike `local var=$(cmd)`, where local's own status masks it). served_cert_fp
    # returns non-zero on a transient TLS read failure (pipefail), which must fall
    # through to the degradation below, not kill the script.
    cert_before="$(served_cert_fp || true)"
    if [ -z "$cert_before" ]; then
      if ! command -v openssl >/dev/null 2>&1; then
        warn "openssl not found: verifying /healthz only — a cached gateway route to ${cur_side} could satisfy it (install openssl for cache-proof verification)"
      elif [ "$on_fail" = stay ]; then
        info "side ${cur_side} is not serving a cert (expected if it is down); verifying /healthz only"
      else
        warn "could not read the current served cert; will verify /healthz only"
      fi
    fi
  fi

  move_switches "$target"

  if [ "$DRY_RUN" = 1 ]; then info "dry-run complete; no changes applied"; exit 0; fi

  if [ "$NO_VERIFY" = 1 ]; then
    info "switched to ${target} (post-switch verification skipped)"; exit 0
  fi

  local verdict=0
  verify_switched "$target" "$cert_before" || verdict=$?
  if [ "$verdict" = 0 ]; then
    info "done. rollback with:  $0 switch ${cur_side:-<other>}"
    exit 0
  fi
  if [ "$on_fail" = stay ]; then fail_forward "$target" "$verdict"; fi
  auto_rollback "$target" "$cur_side" "$verdict"
}

cmd_switch() {
  [ -n "${1:-}" ] || die "usage: $0 switch <a|b>"
  local target; target="$(side_name "$1")"
  resolve_zone_id
  need_side_bases

  local cur_target cur_side
  cur_target="$(current_cname "$ADDR_SWITCH")"
  cur_side="$(which_side "$cur_target")"

  # "?" = the traffic switch points at something that is neither side's record.
  # Refuse rather than proceed: auto-rollback would have no valid side to restore.
  if [ "$cur_side" = "?" ]; then
    die "traffic switch points at an unrecognized target (${cur_target}); resolve it manually (./switch.sh status), or force a state with: $0 failover <a|b>"
  fi

  info "current live side: ${cur_side:-<none>}  ->  target: ${target}"
  local alias_now split=""
  alias_now="$(current_cname "$SERVING_ALIAS")"

  if [ "$cur_side" = "$target" ]; then
    split="$(alias_mismatch "$target" "$alias_now")"
    if [ -z "$split" ]; then
      warn "traffic switch already points at side ${target}; nothing to do"
      exit 0
    fi
    # Traffic already names the target but the alias does not follow it — a
    # cutover interrupted between its two writes. Finish it; there is no earlier
    # consistent state to roll back to, so it runs like a failover.
    warn "split state: ${split}. Completing the move to ${target}."
    cutover "$target" "$target" stay
  fi

  # Auto-rollback restores the previous side's records, so they must describe a
  # working state to begin with. An alias that does not exist yet (before
  # `setup`) is not a broken state: the cutover creates it.
  [ -n "$cur_side" ] && [ -n "$alias_now" ] && split="$(alias_mismatch "$cur_side" "$alias_now")"
  if [ -n "$split" ]; then
    die "${split}, so side ${cur_side} is not reachable now and a rollback would restore a broken state. Force a state with: $0 failover <a|b>"
  fi

  cutover "$target" "$cur_side" rollback
}

# Like `switch`, but for when the live side is gone: no auto-rollback (there is
# nothing to roll back to), no check that the previous records were consistent,
# and no need for the old side to answer. The target still has to pass gates 1
# and 2 — failing over to a side that cannot serve helps no one.
cmd_failover() {
  [ -n "${1:-}" ] || die "usage: $0 failover <a|b>"
  local target; target="$(side_name "$1")"
  resolve_zone_id
  need_side_bases

  local cur_target cur_side
  cur_target="$(current_cname "$ADDR_SWITCH")"
  cur_side="$(which_side "$cur_target")"
  if [ "$cur_side" = "?" ]; then
    warn "traffic switch points at an unrecognized target (${cur_target}); overwriting it"
    cur_side=""
  fi
  info "failover: current live side ${cur_side:-<none>}  ->  target: ${target}"

  if [ "$cur_side" = "$target" ] && [ -z "$(alias_mismatch "$target" "$(current_cname "$SERVING_ALIAS")")" ]; then
    warn "traffic already points at side ${target} and the serving alias follows it; nothing to do"
    exit 0
  fi
  cutover "$target" "$cur_side" stay
}

cmd_rollback() {
  resolve_zone_id
  need_side_bases
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

cmd_setup() { # [side]
  resolve_zone_id
  local cur; cur="$(current_cname "$SERVING_ALIAS")"
  local live; live="$(which_side "$(current_cname "$ADDR_SWITCH")")"
  # Which side's cluster the alias should name: the one asked for, else the live
  # side's. With both sides in one cluster it makes no difference.
  local side="${1:-}"
  if [ -n "$side" ]; then side="$(side_name "$side")"
  elif [ "$PLATFORM_BASE_A" = "$PLATFORM_BASE_B" ]; then side=a
  elif [ "$live" = a ] || [ "$live" = b ]; then side="$live"
  else die "the sides run in different clusters and neither is live; name the one to serve from: $0 setup <a|b>"
  fi
  local gateway; gateway="$(side_gateway "$side" || true)"
  if [ -z "$gateway" ]; then
    # Show where the alias points today, so the cluster can be read off it.
    [ -n "$cur" ] && info "serving alias ${SERVING_ALIAS} currently -> ${cur}"
    die "set PLATFORM_BASE (<cluster>.phala.network, read off a CVM's kms_info.gateway_app_url), or PLATFORM_BASE_A / PLATFORM_BASE_B for side ${side}"
  fi
  # Pointing the alias away from the live side's cluster takes the service down:
  # that cluster's gateway cannot route the live app_id. Moving traffic across
  # clusters is `switch`/`failover`, which move the alias and the traffic switch
  # together.
  if { [ "$live" = a ] || [ "$live" = b ]; } && [ "$gateway" != "$(side_gateway "$live" || true)" ]; then
    die "side ${live} is live and runs on $(side_gateway "$live" || echo '<unknown>'); pointing the alias at ${gateway} would strand it. Use: $0 switch ${side}  (or failover)"
  fi
  info "one-time setup: the serving alias in the delegation zone"
  info "  ${SERVING_ALIAS}  CNAME ->  ${gateway}"
  info "the two switch records are created by 'acme'/'switch'; the per-side"
  info "records are written by each CVM's dstack-ingress — none are set here."
  confirm "Create/point ${SERVING_ALIAS} at ${gateway}?" || { warn "aborted"; exit 1; }
  put_cname "$SERVING_ALIAS" "$gateway"
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
PLATFORM_BASE="${PLATFORM_BASE:-}"     # dstack platform base domain (e.g. in1.phala.network) for per-side app-id probes
# Normalise to the BARE base once, here, because platform_probe_url interpolates
# this value straight into `<app_id>-443s.${PLATFORM_BASE}` and a `_.` in it makes
# an unresolvable host — a failure that only shows up as gate 2 timing out for
# PROBE_RETRIES x PROBE_INTERVAL (~5 min by default) and then refusing, on
# `switch` AND on `rollback`. Accepting the `_.` form is deliberate: it is how
# the serving alias spells the same cluster, and operators copy it from there.
PLATFORM_BASE="${PLATFORM_BASE#_.}"
# Per-side clusters, for sides that run in different ones; each defaults to
# PLATFORM_BASE, so a same-cluster deployment sets only that.
PLATFORM_BASE_A="${PLATFORM_BASE_A:-$PLATFORM_BASE}"; PLATFORM_BASE_A="${PLATFORM_BASE_A#_.}"
PLATFORM_BASE_B="${PLATFORM_BASE_B:-$PLATFORM_BASE}"; PLATFORM_BASE_B="${PLATFORM_BASE_B#_.}"
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
CERT_WARN_DAYS="${CERT_WARN_DAYS:-21}"   # `status` warns when a side's cert is valid for fewer days than this

# Switch-layer record names (in the delegation zone) that this script owns.
SERVING_ALIAS="${DOMAIN}.${DELEGATION_ZONE}"           # -> _.<live side's cluster> (`setup`, and moved by `switch`/`failover`)
ADDR_SWITCH="${TXT_PREFIX}.${DOMAIN}.${DELEGATION_ZONE}"
ACME_SWITCH="_acme-challenge.${DOMAIN}.${DELEGATION_ZONE}"

need curl; need jq
: "${CF_API_TOKEN:?set CF_API_TOKEN (Cloudflare token for ${CF_ZONE}); put it in ${SCRIPT_DIR}/switch.env or export it}"

cmd="${1:-status}"
case "$cmd" in
  status)   cmd_status ;;
  setup)    cmd_setup "${2:-}" ;;
  switch)   cmd_switch "${2:-}" ;;
  failover) cmd_failover "${2:-}" ;;
  rollback) cmd_rollback ;;
  acme)     cmd_acme "${2:-}" ;;
  ""|-h|--help|help) usage 0 ;;
  *) die "unknown command '$cmd' (want: setup [a|b] | status | switch <a|b> | failover <a|b> | rollback | acme <a|b>)" ;;
esac
