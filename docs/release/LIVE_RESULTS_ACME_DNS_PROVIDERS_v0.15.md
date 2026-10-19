# Live validation W27-26: ACME dns-01 per DNS provider + wildcard - v0.15

Harness: `tests/live/acme-dns-providers/run.sh` (README there lists every variable and permission).
Status: **the harness is built and its RFC2136 + wildcard + long-wait paths were run for real against a local BIND + Pebble.
Every Let's Encrypt staging and every cloud-provider cell is PENDING-RUN**: this machine has no DNS-provider accounts,
zones or credentials, so nothing below is claimed for them.

## Run metadata

| Field | Value |
|---|---|
| Date of local run | 2026-10-16 |
| Base commit | 5ffaaf75 (branch kk/w27-b) plus the W27-26 harness commit |
| Host | macOS arm64, podman machine (applehv), Go toolchain from the repo |
| Local ACME CA | Pebble `ghcr.io/letsencrypt/pebble@sha256:7b1fdd61a6d05bcb56e0f8fefe66c18c6281dbed152aad2e071c2b0d9dc6fae8` (not Let's Encrypt) |
| Local DNS | BIND 9 (Ubuntu 24.04 package) built from `bind.Containerfile`, zone `uat.test`, TSIG hmac-sha256, key generated per run |
| Directory used (operator legs) | PENDING-RUN (default `https://acme-staging-v02.api.letsencrypt.org/directory`) |
| Zones used (operator legs) | PENDING-RUN |
| Propagation mode (operator legs) | PENDING-RUN (record `auto`/`doh`/`authoritative`) |

## Results

| Leg | Result | Renewal seconds | TXT left | Secret occurrences (log+audit) | Issuer | Served fp == new_fingerprint |
|---|---|---|---|---|---|---|
| route53 | PENDING-RUN (needs `KK_R53_CRED_FILE`, `KK_R53_ZONE`) | PENDING-RUN | PENDING-RUN | PENDING-RUN | PENDING-RUN | PENDING-RUN |
| azure | PENDING-RUN (needs `KK_AZ_CRED_FILE`, `KK_AZ_ZONE`, `KK_AZ_RESOURCE_GROUP`) | PENDING-RUN | PENDING-RUN | PENDING-RUN | PENDING-RUN | PENDING-RUN |
| gcp | PENDING-RUN (needs `KK_GCP_CRED_FILE`, `KK_GCP_ZONE`, `KK_GCP_PROJECT`) | PENDING-RUN | PENDING-RUN | PENDING-RUN | PENDING-RUN | PENDING-RUN |
| rfc2136 vs Let's Encrypt staging | PENDING-RUN (needs a publicly delegated zone and a TSIG-updatable server: `KK_RFC2136_SERVER`, `KK_RFC2136_TSIG_FILE`, `KK_RFC2136_ZONE`) | PENDING-RUN | PENDING-RUN | PENDING-RUN | PENDING-RUN | PENDING-RUN |
| cname (acme-dns delegation) | PENDING-RUN (needs `KK_CNAME_ZONE`, `KK_CNAME_CRED_FILE`, and the `_acme-challenge.<name>` CNAME) | PENDING-RUN | PENDING-RUN | PENDING-RUN | PENDING-RUN | PENDING-RUN |
| wildcard vs Let's Encrypt staging | PENDING-RUN (first runnable provider) | PENDING-RUN | PENDING-RUN | PENDING-RUN | PENDING-RUN | PENDING-RUN |
| route53-long-wait (170 s) | PENDING-RUN | PENDING-RUN | PENDING-RUN | PENDING-RUN | PENDING-RUN | PENDING-RUN |
| Cloudflare | not in this ticket: W20-29, `tests/live/acme-upstream/run.sh`, `LIVE_RESULTS_ACME_UPSTREAM_v0.9.3.md` | - | - | - | - | - |

### Local stand-ins (real output, 2026-10-16)

`KK_RFC2136_LOCAL=1 bash tests/live/acme-dns-providers/run.sh all rfc2136-long-wait` (exit 2 only because the cloud legs skipped; every leg that ran PASSED):

| Leg | Result | Renewal seconds | TXT left | Secret occurrences (log+audit) | Issuer | Served fp == new_fingerprint |
|---|---|---|---|---|---|---|
| rfc2136 (local BIND + Pebble) | PASS | 0 | 0 | 0 | `CN=Pebble Intermediate CA 55c771` | yes |
| wildcard `*.wild-<stamp>.uat.test` (local BIND + Pebble) | PASS | 0 | 0 | 0 | `CN=Pebble Intermediate CA 55c771` | yes (SAN `DNS:*.wild-...` present) |
| rfc2136-long-wait (propagation none, 170 s) | PASS | 171 | 0 | 0 | `CN=Pebble Intermediate CA 55c771` | yes |

What this proves: the hub's RFC2136 adapter (`connector_acme_dns01_rfc2136.go`) authenticates with TSIG, publishes and then
removes the `_acme-challenge` TXT (BIND's update log shows 1 add and 1 delete per name, and an independent `dig` finds no TXT
afterwards; a planted record proves that check can fail); Pebble validated dns-01 by querying that BIND; a wildcard order
(`*.wild-...` validated at `_acme-challenge.wild-...`) issued; the hub log and full audit trail contain the TSIG secret 0
times (a planted canary proves the scanner can fail); nginx served the renewed certificate (fingerprint equals `new_fingerprint`).
The long-wait row answered a JSON 200 after 171 s in the handler, so the 3-minute case behind "Run 2" of the ACME upstream
results no longer drops the response when the wait is a fixed delay.

What it does not prove: acceptance by Let's Encrypt staging, public DNS propagation, or any cloud provider API. The
`route53-long-wait` row above stays PENDING-RUN because it exercises the Route53 adapter and a real zone.

Findings from building it (not fixed here, out of scope):
* `golang.org/x/crypto/acme` (used by the connector) takes the order URL for a not-yet-valid order from the `Location` header of the
  finalize response (`CreateOrderCert` -> `WaitOrder(o.URI)`). Pebble answers finalize with status `processing` and no `Location`,
  so the hub fails with `acme finalize: Post "": egress: destination blocked: scheme ""`. Let's Encrypt (Boulder) sends the header.
  The harness puts a TLS front (`pebble-proxy.py`) in front of Pebble that adds only that header. If a customer CA behaves like Pebble,
  the connector breaks on it; a product fallback (re-use `order.URI` when the finalize response has no `Location`) would fix it.
* The ISC `bind9` image is amd64-only and segfaults under qemu on Apple Silicon; the harness builds BIND from the Ubuntu package instead.

## Steps for the operator (the owner)

Credentials live outside the repo, e.g. `$HOME/.config/kryptkeeper-lab/` (mode 600). Field names are in the README. Each run uses a fresh name,
so staging rate limits are not a concern. Fill the PENDING-RUN cells from the printed table (`KK_EVIDENCE_DIR=<dir>` also writes
`results.md` and, only when the secret count is 0, the hub log and audit per leg).

1. Route53 + wildcard + long wait, one hub:
   `KK_R53_CRED_FILE=~/.config/kryptkeeper-lab/r53.json KK_R53_ZONE=<test zone> KK_EVIDENCE_DIR=$PWD/ev bash tests/live/acme-dns-providers/run.sh route53 wildcard route53-long-wait`
   (add `KK_DNS_PROPAGATION=doh` if outbound :53 is filtered; record the mode in the table header above).
2. Azure: `KK_AZ_CRED_FILE=... KK_AZ_ZONE=... KK_AZ_RESOURCE_GROUP=... bash tests/live/acme-dns-providers/run.sh azure`
3. GCP: `KK_GCP_CRED_FILE=<service-account key> KK_GCP_ZONE=<dns name> KK_GCP_PROJECT=... bash tests/live/acme-dns-providers/run.sh gcp`
4. RFC2136 (needs the server reachable from the hub container, and a zone delegated from the public DNS so Let's Encrypt can see it):
   `KK_RFC2136_SERVER=<host:53> KK_RFC2136_TSIG_FILE=... KK_RFC2136_ZONE=... bash tests/live/acme-dns-providers/run.sh rfc2136`
5. CNAME delegation: register an acme-dns account, create `_acme-challenge.kk-uat-cname.<zone>. CNAME <fulldomain>.`, then
   `KK_CNAME_ZONE=<zone> KK_CNAME_CRED_FILE=... bash tests/live/acme-dns-providers/run.sh cname`
6. Exit 0 = pass; paste the per-leg rows (and the `FAIL:` text of any failed leg) into the table. A FAIL stays FAIL.
