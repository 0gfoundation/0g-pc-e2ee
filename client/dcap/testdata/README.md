# dcap test fixtures

This directory will hold the fixtures for the **hermetic full-verification test**
of `NewQuoteParser` — a real quote plus the DCAP collateral captured for it, so
`verify.RawTdxQuote` runs entirely offline and deterministically.

It is not committed yet because collateral must be captured from a network the CI
sandbox cannot reach (Intel PCS / Phala PCCS). The verifier and its offline
*negative* tests ship now; the positive hermetic test lands once these files
exist.

## What to capture

DCAP collateral is time-sensitive (TCB Info / QE Identity carry `issueDate` /
`nextUpdate`), so the hermetic test must pin `Config.Now` to the capture time.

Run this on a host with outbound network (e.g. the deployed gateway):

```bash
# 1) Save the FULL quote hex (the "quote" field of /v1/quote?legacy=false — the
#    complete one with the trailing ECDSA signature + PCK cert chain).
#    quote.hex = that hex string.

# 2) FMSPC + CA type (local, no network):
dcap-qvl decode  --hex --fmspc quote.hex     # -> fmspc, e.g. 90c06f000000
dcap-qvl pckinfo --hex        quote.hex       # -> ca: platform | processor

# 3) Fetch collateral from Phala's hosted PCCS (or api.trustedservices.intel.com):
BASE=https://pccs.phala.network
curl -D tcb.hdr "$BASE/tdx/certification/v4/tcb?fmspc=<FMSPC>"                -o tcb_info.json
curl -D qe.hdr  "$BASE/tdx/certification/v4/qe/identity?update=standard"     -o qe_identity.json
curl -D crl.hdr "$BASE/sgx/certification/v4/pckcrl?ca=<CA>&encoding=der"      -o pck_crl.der
curl            "$BASE/sgx/certification/v4/rootcacrl"                        -o root_ca_crl.der
# the *.hdr files hold the *-Issuer-Chain response headers (URL-encoded PEM).
```

Also record the capture timestamp (UTC) — it becomes the test's frozen
`Config.Now`.

## How the test will use it

The hermetic test injects a `trust.HTTPSGetter` that maps the PCS/PCCS URLs above
to these captured bytes (body + issuer-chain headers), sets `Config.Now` to the
capture time, verifies the full quote, and asserts the extracted measurement and
report_data equal the known values (the same enc_pub / signer as the
protocol/attest real-vector KAT).
