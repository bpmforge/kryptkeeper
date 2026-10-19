# Live DNS-provider UAT (W27-26)

Renews a throwaway certificate through the hub at a real ACME CA, solving dns-01 in a real
DNS provider, for Route53, Azure DNS, GCP Cloud DNS, RFC2136 and CNAME delegation (acme-dns),
plus a wildcard. Cloudflare is W20-29 (`tests/live/acme-upstream/run.sh`) and is not repeated.
Results go in `docs/release/LIVE_RESULTS_ACME_DNS_PROVIDERS_v0.15.md`.

```
bash tests/live/acme-dns-providers/run.sh [leg ...]
  legs: route53 azure gcp rfc2136 cname wildcard route53-long-wait | all (default)
        rfc2136-long-wait (opt-in: local stand-in for the long wait)
```

Exit 0 = every selected leg passed, 1 = a leg failed, 2 = something was skipped and nothing
failed. A leg without its prerequisites prints `SKIP: <leg> needs <VAR>` and is recorded
SKIPPED, never PASS. With no environment set, `all` prints one SKIP per leg and exits 2.

Every secret variable below is a **file path**. A Python helper reads it and posts it to the hub;
nothing secret is put in argv, echoed or `set -x`-traced. Keep the files under
`$HOME/.config/kryptkeeper-lab/` (mode 600), never in the repo.

## Per-leg environment

| Leg | Variables | File contents (hub credential `dns` object, exactly these field names) |
|---|---|---|
| route53 | `KK_R53_CRED_FILE`, `KK_R53_ZONE` (optional `KK_R53_ZONE_ID`) | JSON `{"access_key_id","secret_access_key","session_token"?,"hosted_zone_id"?}` |
| azure | `KK_AZ_CRED_FILE`, `KK_AZ_ZONE`, `KK_AZ_RESOURCE_GROUP` | JSON `{"tenant_id","client_id","client_secret","subscription_id"}`; the harness adds `resource_group` |
| gcp | `KK_GCP_CRED_FILE`, `KK_GCP_ZONE`, `KK_GCP_PROJECT` | the raw service-account key JSON; sent as `service_account_json`, with `project_id` added |
| rfc2136 | `KK_RFC2136_SERVER` (host:port), `KK_RFC2136_TSIG_FILE`, `KK_RFC2136_ZONE` | JSON `{"tsig_key_name","tsig_secret"(base64),"tsig_algorithm"?}`; the harness adds `nameserver`, `zone` |
| cname | `KK_CNAME_ZONE`, `KK_CNAME_CRED_FILE` (optional `KK_CNAME_NAME`) | JSON `{"base_url","accounts":{"<zone>":{"username","password","subdomain","fulldomain"}}}` (acme-dns) |

These are the field names read from `internal/bootstrap/connector_acme_dns01_{route53,azure,gcp,rfc2136,delegated}.go`.
The connector itself is `config_json {"directory_url","challenge":"dns-01","dns_provider":"route53|azure|gcp|rfc2136|delegated"}`
(**CNAME delegation is `dns_provider: "delegated"`**), with the file above under the credential's `dns` key.

Common: `KK_ACME_DIRECTORY` (default Let's Encrypt **staging**), `KK_EVIDENCE_DIR` (copies responses, served
cert, audit, hub log and `results.md` there; hub log and audit only when the secret count is 0),
`KK_DNS_PROPAGATION` / `KK_DNS_DOH_URL` (default `auto`; use `doh` where outbound :53 is filtered,
see the Run 1 root cause in `LIVE_RESULTS_ACME_UPSTREAM_v0.9.3.md`), `KK_FRESH_HUB=1` (fresh hub data dir per leg),
`KK_WILDCARD_LEG` (which provider the wildcard uses; default the first runnable of route53, azure, gcp, rfc2136),
`KK_PROPAGATION_DELAY` (default `170s`, the long-wait leg).

Minimum permissions: DNS record edit on the one test zone only (Route53 `route53:ChangeResourceRecordSets`,
`ListResourceRecordSets`, `ListHostedZonesByName`; Azure "DNS Zone Contributor" on the zone; GCP `dns.admin`-equivalent
limited to the zone; RFC2136 a TSIG key allowed to update only `_acme-challenge` names; acme-dns an account).
Use a throwaway zone or subdomain you can delete afterwards.

## What each leg does

Name `kk-uat-<UTC stamp>-<leg>.<zone>` (fresh per run; LE staging limits). Steps: import a self-signed unmanaged cert
-> provider credential -> ACME connector -> takeover -> SSH credential + nginx target (the fixture from
`tests/live/ssh-install`, hub reaches it by container name) -> `POST /api/v1/renewal/execute` (`CURL_MAX=900`; needs
200 and `installed_verified`) -> nginx serves `new_fingerprint`, issuer matches, SAN matches -> the **provider's own API**
(`txtleft.py`; `dig` for RFC2136) shows no `_acme-challenge` TXT left (a failed query is FAIL, not PASS) -> hub log + audit
contain each secret value 0 times (counts printed; a planted canary proves the scanner can fail).

* **wildcard**: `*.wild-<stamp>.<zone>` on the first runnable provider; also asserts `DNS:*.wild-...` in the SAN.
* **route53-long-wait**: Route53 with `dns_propagation:"none"`, `dns_propagation_delay:"170s"`, so the request spends about
  three minutes in `handlers_renewal_execute.go`; PASS needs a JSON 200 (not `curl: (52)`). Extra row, not a replacement.
* **cname**: acme-dns keeps its TXT by design (no delete), so the cleanup check is "no TXT in the customer zone and the
  operator's CNAME untouched". Create the delegation once: `_acme-challenge.kk-uat-cname.<zone>. CNAME <fulldomain from the
  acme-dns registration>.` (or choose the name with `KK_CNAME_NAME`). The name is fixed, not per run, because the CNAME is
  operator-owned.

## Local RFC2136 + Pebble (no account needed)

`KK_RFC2136_LOCAL=1 bash run.sh rfc2136 wildcard rfc2136-long-wait` runs the RFC2136 leg against a throwaway BIND 9
(`bind.Containerfile`, TSIG key generated per run, zone `uat.test`) and Pebble
(`ghcr.io/letsencrypt/pebble:2.10.1@sha256:ddf23064... (multi-arch index)`, pinned) validating dns-01 by querying that BIND. The hub trusts Pebble's CA via
`SSL_CERT_FILE`. Pebble answers finalize with
"processing" and no `Location` header; the hub's ACME connector copes (it keeps the order URL from `AuthorizeOrder`, W27-38), so
the hub talks to Pebble directly with no proxy. The issuer check is `Pebble` there,
not `(STAGING)`. This proves the TSIG/dynamic-update code path and the harness, **not** Let's Encrypt staging acceptance;
the RFC2136 acceptance row for LE staging still needs a publicly delegated zone served by a TSIG-updatable server.

## Cleanup and cost

Staging certificates are free. The harness itself never writes to a provider zone (the hub does), so it deletes nothing; if a
TXT is reported left behind, the FAIL line names the record to remove by hand. Containers, network and images created by the run
(`kk-uat-<stamp>-*`) are removed on exit; nothing else is touched.
