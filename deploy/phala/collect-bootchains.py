#!/usr/bin/env python3
"""Inventory the boot chains of the provider fleet, ahead of turning hop 3 on.

WHAT THIS IS FOR. `ZG_GATEWAY_ATTEST_ENFORCE` compares each provider's boot chain
(MRTD + RTMR1 + RTMR2) against `attest.BootChainPolicy`, and that allowlist is
empty today, so enforce would reject every provider. Before it can be filled and
switched on somebody has to know what is actually out there: how many distinct
boot chains the fleet runs, which providers share one, and which of them are
already the image the gateway itself runs. That census is what this script
produces, from either of the two places the values are already available:

  --log       the gateway's own "boot chain is not in the allowlist" WARN lines,
              which carry all three registers precisely so an operator can record
              an entry from them. No network, no credentials, whole fleet at once.
  --endpoint  a live GET of the provider's /v1/quote, which additionally yields
              RTMR0, mr_config_id (compose hash / app_id) and the reply's
              vm_config provenance — the image name and os_image_hash an
              allowlist entry wants recorded beside the registers.

WHAT THIS IS *NOT*. An observation is not an audit. Every value here was reported
by the machine being asked about, so on its own it says "this is what the fleet
currently claims", never "this is the image we trust". An allowlist entry is only
meaningful once the same three registers have been recomputed independently —
`dstack-mr` over the published guest-OS release, per client/evidence/osimages.json's
header — and found to agree with what a live quote reports. This script gives you
the second half of that comparison and the worklist for the first; it deliberately
writes its JSON draft with every entry marked unconfirmed.

Nor does it verify anything: --endpoint mode parses the quote structurally, by
fixed offset, exactly like attest.ParseTDXQuoteBody, and skips the DCAP signature
chain entirely (the gateway and `pcverify -provider` do that). Values collected
this way are inputs to a human decision, never to a trust decision.

USAGE

  # census from a gateway log (or stdin)
  ./collect-bootchains.py --log gateway.log
  kubectl logs deploy/gateway | ./collect-bootchains.py --log -

  # live, one provider or many
  ./collect-bootchains.py --endpoint https://compute-network-20.example.work
  ./collect-bootchains.py --endpoints-file endpoints.txt --jobs 8

  # emit a draft allowlist next to the table
  ./collect-bootchains.py --log gateway.log --json bootchains.json

Sources combine: pass --log and --endpoint together and the census covers both.

Exit status is 0 when at least one boot chain was collected, 1 when none was, and
2 on a usage error — so a cron wrapper can tell "the fleet is uniform" (a table
with one row) from "we learned nothing" (no rows at all).
"""

from __future__ import annotations

import argparse
import binascii
import collections
import concurrent.futures
import hashlib
import json
import re
import sys
import urllib.error
import urllib.parse
import urllib.request

# ---------------------------------------------------------------------------
# TDX v4 quote layout. ABSOLUTE offsets into the whole quote (48-byte header +
# TD Quote Body), mirroring protocol/attest/tdxquote.go — keep the two in step.
# ---------------------------------------------------------------------------
REG_LEN = 48
MIN_QUOTE_LEN = 632  # header(48) + body through report_data
OFF = {
    "mrtd": 184,
    "mr_config_id": 232,
    "rtmr0": 376,
    "rtmr1": 424,
    "rtmr2": 472,
    "rtmr3": 520,
}
REPORT_DATA_OFF, REPORT_DATA_LEN = 568, 64

# report_data layout (SPEC §4.2, protocol/attest/reportdata.go): enc_pub(32) ‖
# signer_addr(20) ‖ version(4, big-endian) ‖ reserved(8, zero).
RD_SIGNER_OFF, RD_SIGNER_LEN = 32, 20
RD_VERSION_OFF = 52
RD_VERSION = 1

# The three registers an entry is keyed on. RTMR0 (VM shape) and RTMR3
# (per-instance app events) are excluded — see attest.BootChain for why.
BOOT_REGS = ("mrtd", "rtmr1", "rtmr2")

DEFAULT_TIMEOUT = 20
MAX_QUOTE_BODY = 4 << 20  # bound the /v1/quote read, like pcverify does

# One WARN line from client/route/route.go's measurement-miss log. Fields are
# matched by name rather than position so a future added field cannot silently
# shift the parse.
WARN_RE = re.compile(
    r'boot chain is not in the allowlist'
    r'(?=.*\bquote_url="?(?P<quote_url>[^"\s]+)"?)'
    r'(?=.*\bmrtd=(?P<mrtd>[0-9a-fA-F]{96})\b)'
    r'(?=.*\brtmr1=(?P<rtmr1>[0-9a-fA-F]{96})\b)'
    r'(?=.*\brtmr2=(?P<rtmr2>[0-9a-fA-F]{96})\b)'
    r'(?:(?=.*\bsigner_addr=(?P<signer>0x[0-9a-fA-F]{40})\b))?'
)


class Observation:
    """One provider, as one source reported it."""

    def __init__(self, quote_url, regs, signer=None, source="", vm=None, app=None):
        self.quote_url = quote_url
        self.regs = regs  # dict of register name -> lowercase hex
        self.signer = (signer or "").lower() or None
        self.source = source
        self.vm = vm or {}      # UNAUTHENTICATED vm_config provenance
        self.app = app or {}    # compose_hash / app_id, from mr_config_id

    @property
    def boot_chain(self):
        return tuple(self.regs[r] for r in BOOT_REGS)

    @property
    def host(self):
        try:
            return urllib.parse.urlparse(self.quote_url).hostname or self.quote_url
        except ValueError:
            return self.quote_url


# ---------------------------------------------------------------------------
# Source 1: gateway logs
# ---------------------------------------------------------------------------
def observations_from_log(stream, label):
    """Yield an Observation per matching WARN line.

    The gateway re-logs a provider on every quote-cache miss, so the same
    (provider, boot chain) recurs; dedup is the caller's job (dedupe()), not
    this parser's, because a *changed* boot chain for one provider is a real
    event — a broker upgrade — and must not be collapsed away here.
    """
    for lineno, line in enumerate(stream, 1):
        m = WARN_RE.search(line)
        if not m:
            continue
        regs = {r: m.group(r).lower() for r in BOOT_REGS}
        yield Observation(
            quote_url=m.group("quote_url"),
            regs=regs,
            signer=m.group("signer"),
            source=f"{label}:{lineno}",
        )


# ---------------------------------------------------------------------------
# Source 2: a live /v1/quote
# ---------------------------------------------------------------------------
def quote_url_for(endpoint):
    """Derive a provider's quote URL, matching client/route deriveQuoteURL.

    A serving endpoint, a /v1 base, and a chat-completions URL all reduce to the
    same quote URL. A URL that is ALREADY a quote URL is taken as given — the
    census is fed from gateway logs, whose quote_url field is exactly that, so
    round-tripping one must not append a second /v1/quote.
    """
    u = urllib.parse.urlparse(endpoint if "://" in endpoint else "https://" + endpoint)
    if not u.scheme or not u.netloc:
        raise ValueError(f"{endpoint!r} is not an absolute URL")
    path = u.path.rstrip("/")
    if not path.endswith("/quote"):
        if path.endswith("/chat/completions"):
            path = path[: -len("/chat/completions")]
        elif not path.endswith("/v1"):
            path += "/v1"
        path += "/quote"
    return f"{u.scheme.lower()}://{u.netloc.lower()}{path}?legacy=false"


def fetch_quote_reply(url, timeout):
    req = urllib.request.Request(url, headers={"Accept": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        body = resp.read(MAX_QUOTE_BODY + 1)
    if len(body) > MAX_QUOTE_BODY:
        raise ValueError(f"quote reply larger than {MAX_QUOTE_BODY} bytes")
    return json.loads(body)


def unwrap_json_string(value):
    """dstack delivers tcb_info/vm_config as an object OR as a JSON string
    wrapping one; accept both (attest.UnwrapJSONString does the same)."""
    if isinstance(value, str):
        try:
            return json.loads(value)
        except json.JSONDecodeError:
            return {}
    return value if isinstance(value, dict) else {}


def parse_quote_body(raw):
    """Structural extraction only — no signature check. See module docstring."""
    if len(raw) < MIN_QUOTE_LEN:
        raise ValueError(f"quote too short: {len(raw)} bytes, need >= {MIN_QUOTE_LEN}")
    regs = {name: raw[off : off + REG_LEN].hex() for name, off in OFF.items()}
    rd = raw[REPORT_DATA_OFF : REPORT_DATA_OFF + REPORT_DATA_LEN]
    signer = None
    if int.from_bytes(rd[RD_VERSION_OFF : RD_VERSION_OFF + 4], "big") == RD_VERSION:
        signer = "0x" + rd[RD_SIGNER_OFF : RD_SIGNER_OFF + RD_SIGNER_LEN].hex()
    return regs, signer


def compose_identity(mr_config_id_hex):
    """Read the dstack compose hash out of mr_config_id, when the layout exposes
    it. Only v1 (`0x01 ‖ compose_hash(32) ‖ zeros`) carries it in the clear; v2/v3
    commit to it inside a digest, so they yield nothing rather than a guess
    (attest.ComposeHashFromMRConfigID)."""
    b = bytes.fromhex(mr_config_id_hex)
    version = b[0]
    if version != 1 or any(b[33:]):
        return {"mr_config_version": version}
    compose_hash = b[1:33]
    if not any(compose_hash):
        return {"mr_config_version": version}
    return {
        "mr_config_version": version,
        "compose_hash": compose_hash.hex(),
        "app_id": compose_hash[:20].hex(),
    }


def observe_endpoint(endpoint, timeout):
    """Fetch and parse one provider's quote. Returns (Observation, None) or
    (None, error-string) — a fetch failure is per-provider news, not a reason to
    abandon the census."""
    try:
        url = quote_url_for(endpoint)
    except ValueError as e:
        return None, f"{endpoint}: {e}"
    try:
        reply = fetch_quote_reply(url, timeout)
        quote_hex = reply.get("quote") or ""
        if not quote_hex:
            raise ValueError('reply has no "quote" field')
        raw = binascii.unhexlify(quote_hex.removeprefix("0x"))
        regs, signer = parse_quote_body(raw)
    except (urllib.error.URLError, OSError, ValueError, binascii.Error,
            json.JSONDecodeError) as e:
        return None, f"{url}: {type(e).__name__}: {e}"

    # vm_config is NOT signed by Intel — it is the reply's own account of itself.
    # Collected as provenance for the allowlist entry's `name`/`os_image_hash`
    # fields, which are never matched on, and printed as a claim.
    vm = unwrap_json_string(reply.get("vm_config"))
    provenance = {
        k: vm[k]
        for k in ("image", "os_image_hash", "qemu_single_pass_add_pages",
                  "num_gpus", "gpus", "vcpu", "memory")
        if k in vm
    }
    app = compose_identity(regs["mr_config_id"])
    tcb = unwrap_json_string(reply.get("tcb_info"))
    if isinstance(tcb.get("app_compose"), str):
        app["app_compose_sha256"] = hashlib.sha256(
            tcb["app_compose"].encode()
        ).hexdigest()
    return Observation(url, regs, signer, source="live", vm=provenance, app=app), None


# ---------------------------------------------------------------------------
# Census
# ---------------------------------------------------------------------------
def dedupe(observations):
    """Collapse repeats of the same (provider, boot chain) — the gateway logs one
    per cache miss — keeping the richest record for each and preserving first-seen
    order. A provider that reported TWO different boot chains keeps both rows: that
    is a broker upgrade (or a rotation mid-window), and hiding it would erase the
    one event this census exists to catch."""
    best = {}
    for o in observations:
        key = (o.quote_url, o.boot_chain)
        prior = best.get(key)
        if prior is None or (not prior.vm and o.vm):
            best[key] = o
    return list(best.values())


def builtin_gateway_images(path):
    """Load client/evidence/osimages.json, so the census can say which boot chains
    are already the gateway's own audited image. It is the ONLY allowlist in the
    repo today, and it is the gateway's — the provider verifier is wired with an
    empty policy — so a match here is a useful signal, not a pass."""
    try:
        with open(path, encoding="utf-8") as f:
            doc = json.load(f)
    except (OSError, json.JSONDecodeError):
        return []
    out = []
    for img in doc.get("images", []):
        try:
            out.append((
                img["name"],
                tuple(img[r].strip().lower() for r in BOOT_REGS),
                img.get("os_image_hash", ""),
            ))
        except KeyError:
            continue
    return out


def short(hex_str, keep=12):
    return hex_str[:keep] + "…"


def render(groups, gateway_images, out):
    known = {bc: (name, h) for name, bc, h in gateway_images}
    gw_mrtd = {bc[0] for _, bc, _ in gateway_images}
    gw_rtmr1 = {bc[1] for _, bc, _ in gateway_images}

    print(f"\n{len(groups)} distinct boot chain(s) across "
          f"{sum(len(g) for g in groups.values())} provider(s)\n", file=out)
    for i, (bc, obs) in enumerate(groups.items(), 1):
        mrtd, rtmr1, rtmr2 = bc
        match = known.get(bc)
        if match:
            verdict = f"== gateway allowlist entry {match[0]!r}"
        else:
            hints = []
            if mrtd in gw_mrtd:
                hints.append("MRTD matches the gateway's image")
            if rtmr1 in gw_rtmr1:
                hints.append("RTMR1 (kernel) matches the gateway's image")
            verdict = "NOT in any allowlist" + (
                f" ({', '.join(hints)})" if hints else "")
        print(f"[{i}] {len(obs)} provider(s) — {verdict}", file=out)
        print(f"    mrtd   {mrtd}", file=out)
        print(f"    rtmr1  {rtmr1}", file=out)
        print(f"    rtmr2  {rtmr2}", file=out)
        images = sorted({o.vm.get("image", "") for o in obs} - {""})
        hashes = sorted({o.vm.get("os_image_hash", "") for o in obs} - {""})
        if images or hashes:
            print(f"    claims image={','.join(images) or '?'} "
                  f"os_image_hash={','.join(short(h, 16) for h in hashes) or '?'}"
                  "   (unauthenticated vm_config)", file=out)
        rtmr0s = sorted({o.regs["rtmr0"] for o in obs if "rtmr0" in o.regs})
        if len(rtmr0s) > 1:
            print(f"    rtmr0  {len(rtmr0s)} distinct VM shapes in this group "
                  "(excluded from the entry by design)", file=out)
        for o in sorted(obs, key=lambda o: o.host):
            extra = ""
            if o.app.get("app_id"):
                extra = f"  app_id={o.app['app_id']}"
            elif o.app.get("mr_config_version") not in (None, 1):
                extra = f"  mr_config v{o.app['mr_config_version']}"
            print(f"      {o.host:<52} {o.signer or '-'}{extra}", file=out)
        print(file=out)


def draft_json(groups, gateway_images):
    """A draft in client/evidence/osimages.json's shape — the shape a provider-side
    allowlist would reuse. Every entry is marked unconfirmed on purpose: these are
    values a machine reported about itself, and they become an allowlist only after
    dstack-mr recomputes them from the published release."""
    known = {bc: name for name, bc, _ in gateway_images}
    images = []
    for bc, obs in groups.items():
        claimed = sorted({o.vm.get("image", "") for o in obs} - {""})
        hashes = sorted({o.vm.get("os_image_hash", "") for o in obs} - {""})
        images.append({
            "name": known.get(bc) or (claimed[0] if claimed else "UNIDENTIFIED"),
            "os_image_hash": hashes[0] if hashes else "",
            "mrtd": bc[0],
            "rtmr1": bc[1],
            "rtmr2": bc[2],
            "_observed_on": sorted(o.host for o in obs),
            "_confirmed_by_dstack_mr": False,
            "_matches_gateway_allowlist": bc in known,
        })
    images.sort(key=lambda e: (-len(e["_observed_on"]), e["name"]))
    return {
        "_comment": [
            "DRAFT — collected by deploy/phala/collect-bootchains.py from live",
            "providers and/or gateway logs. Every value here was reported by the",
            "machine being verified, so it is an inventory, NOT an allowlist. Before",
            "any entry is used: recompute mrtd/rtmr1/rtmr2 with dstack-mr from the",
            "published guest-OS release (client/evidence/osimages.json's header has",
            "the procedure), confirm they equal what a live quote reports, then clear",
            "_confirmed_by_dstack_mr. Entries named UNIDENTIFIED had no vm_config to",
            "read (log-only census) — resolve the release before recording them.",
        ],
        "images": images,
    }


def main(argv):
    ap = argparse.ArgumentParser(
        description="Inventory provider boot chains (MRTD/RTMR1/RTMR2) ahead of "
                    "enabling ZG_GATEWAY_ATTEST_ENFORCE.",
        epilog="An observation is not an audit — see the script header.")
    ap.add_argument("--log", action="append", default=[], metavar="FILE",
                    help='gateway log to harvest WARN lines from ("-" for stdin); repeatable')
    ap.add_argument("--endpoint", action="append", default=[], metavar="URL",
                    help="provider endpoint to GET /v1/quote from; repeatable")
    ap.add_argument("--endpoints-file", metavar="FILE",
                    help="file of provider endpoints, one per line (# comments ok)")
    ap.add_argument("--jobs", type=int, default=6, metavar="N",
                    help="concurrent quote fetches (default 6)")
    ap.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT, metavar="SEC",
                    help=f"per-fetch timeout (default {DEFAULT_TIMEOUT}s)")
    ap.add_argument("--json", metavar="FILE",
                    help='write a draft allowlist ("-" for stdout)')
    ap.add_argument("--osimages", metavar="FILE",
                    default="client/evidence/osimages.json",
                    help="gateway allowlist to cross-reference (default %(default)s)")
    args = ap.parse_args(argv)

    endpoints = list(args.endpoint)
    if args.endpoints_file:
        try:
            with open(args.endpoints_file, encoding="utf-8") as f:
                endpoints += [ln.split("#", 1)[0].strip() for ln in f]
        except OSError as e:
            ap.error(f"--endpoints-file: {e}")
    endpoints = [e for e in endpoints if e]

    if not args.log and not endpoints:
        ap.error("nothing to do: pass --log and/or --endpoint/--endpoints-file")

    observations, errors = [], []
    for path in args.log:
        try:
            if path == "-":
                observations += list(observations_from_log(sys.stdin, "stdin"))
            else:
                with open(path, encoding="utf-8", errors="replace") as f:
                    observations += list(observations_from_log(f, path))
        except OSError as e:
            errors.append(f"--log {path}: {e}")

    if endpoints:
        with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, args.jobs)) as pool:
            for obs, err in pool.map(
                lambda ep: observe_endpoint(ep, args.timeout), endpoints
            ):
                (observations.append(obs) if obs else errors.append(err))

    observations = dedupe(observations)
    groups = collections.OrderedDict()
    for o in sorted(observations, key=lambda o: o.host):
        groups.setdefault(o.boot_chain, []).append(o)
    # Biggest fleet first: that is the entry worth computing before the others.
    groups = collections.OrderedDict(
        sorted(groups.items(), key=lambda kv: -len(kv[1])))

    gateway_images = builtin_gateway_images(args.osimages)
    render(groups, gateway_images, sys.stdout)

    if errors:
        print(f"{len(errors)} source(s) yielded nothing:", file=sys.stderr)
        for e in errors:
            print(f"  {e}", file=sys.stderr)

    if args.json:
        doc = json.dumps(draft_json(groups, gateway_images), indent=2) + "\n"
        if args.json == "-":
            sys.stdout.write(doc)
        else:
            with open(args.json, "w", encoding="utf-8") as f:
                f.write(doc)
            print(f"draft allowlist written to {args.json} "
                  "(every entry unconfirmed — see its _comment)", file=sys.stderr)

    return 0 if groups else 1


if __name__ == "__main__":
    try:
        sys.exit(main(sys.argv[1:]))
    except KeyboardInterrupt:
        sys.exit(130)
