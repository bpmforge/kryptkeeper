# Live validation W20-29: ACME upstream (LE staging, dns-01, Cloudflare) - v0.9.3

Date: 2026-10-15. Base: origin/main 6561651f (detached). Harness: `tests/live/acme-upstream/run.sh`, unmodified.
Host: macOS arm64, podman, GOTOOLCHAIN=go1.26.9. Directory: LE STAGING. Zone: kryptkeeper.io. Test name: `kk-uat-20261015135010.kryptkeeper.io`.

## Verdict: FAIL (blocked at dns-01 propagation check) - NOT validated

The renewal never reached the CA challenge/finalize step, so issuance, install and the served cert are UNVERIFIED.

## Steps

| Step | Result | Evidence |
|---|---|---|
| Build hub + nginx/sshd fixture | PASS | fixture up, placeholder served (sha256 6e80e905...) |
| Hub up | PASS | healthz ok |
| Import unmanaged cert for test name | PASS | fp 523b44eb...f04591 |
| Cloudflare credential, ACME connector (LE staging), takeover | PASS | token never printed |
| SSH credential + nginx target | PASS | |
| Renew via ACME dns-01 | **FAIL** | see below |
| Order/authorization status at CA | UNVERIFIED | not logged; failure occurred before challenge acceptance |
| TXT publish | UNVERIFIED directly (hub reaches waitForTXT only after Present succeeded, so it was created) | |
| TXT removal | PASS | harness check: no `_acme-challenge.<name>` TXT in zone afterwards |
| Issuing CA "(STAGING)" | UNVERIFIED | nginx still served `CN=placeholder.kk-uat.local` |
| Installed cert served by nginx (subject/issuer/notAfter) | FAIL/UNVERIFIED | placeholder still served, not replaced |
| Token absent from hub log + audit | PASS | |
| Hub audit | certificate.renew_execute outcome=failure at 13:53:20Z; import/credential/connector/takeover/target all success |

Exact error (hub log; harness got no JSON, see bug 2):
`renewal execute failed: upstream renewal via connector conn-95b11f7a2c4aeb885ec2f6f5799397dd: dns-01: _acme-challenge.kk-uat-20261015135010.kryptkeeper.io not visible at pat.ns.cloudflare.com, elijah.ns.cloudflare.com before the deadline`
Harness: `curl: (52) Empty reply from server` -> `FAIL: renewal -> 000 ...`.

## Root cause 1 (environment, verified): outbound port 53 to non-local resolvers is blocked on this network
`internal/bootstrap/connector_acme_dns01.go:144-175` (`lookupTXTAt`/`waitForTXT`) queries each authoritative NS directly on `:53` and has no override; the 3-minute deadline is at `internal/bootstrap/connector_acme.go:449`.
Verified: from the host, `dig TXT kryptkeeper.io @pat.ns.cloudflare.com`, `@elijah.ns.cloudflare.com` and `@1.1.1.1` all time out over UDP and TCP; from an alpine container `nslookup ... 173.245.58.1` times out, while the default gateway resolver (169.254.1.1) answers. The NS-name lookup itself succeeded (names appear in the error), so Cloudflare publish was not the issue. Consequence: dns-01 cannot complete on any network that only permits recursive DNS (corporate/home egress filtering). Not fixable in the harness; a rerun needs a network with unfiltered outbound :53. Possible product follow-up (not done, out of scope): fall back to the system resolver / DoH, or make the propagation check configurable.

## Bug 2 (product, observed + code-read): empty reply when the ACME wait outlasts the per-request write deadline
`internal/bootstrap/handlers_renewal_execute.go:~160` sets a 180s read/write deadline sized for k8s push retries (135s). The dns-01 propagation wait alone is 3 min (`connector_acme.go:449`) plus ACME order time, so the failure was logged and audited at 13:53:20 (~182s after the request) but the response was dropped: callers see `curl: (52) Empty reply from server` instead of the error JSON. It will also drop a success response if propagation takes ~3 min. Suggest a deadline of at least dns wait + order + install (e.g. 300s+).

## Zone safety
DNS record names/types before and after the run are identical (CNAME apex, CNAME www, MX x3, TXT cf2024-1._domainkey, TXT apex); no `_acme-challenge` leftovers; no other record touched.

## Cleanup
Harness trap removed hub/nginx containers, network and images; verified no `kk-uat-acmeup*` containers, networks or images remain. No product code or harness change was made.

---

# Run 2 (kk/acme-dns-propagation)

Date: 2026-10-15. Code under test: origin/kk/acme-dns-propagation e68c5584 (detached). Same host, same network (outbound :53 filtered), LE STAGING, zone kryptkeeper.io. Test name: `kk-uat-20261015142217.kryptkeeper.io`. Connector `config_json` was left at the harness default (no `dns_propagation` set, i.e. `auto`).
Harness: `tests/live/acme-upstream/run.sh` with one minimal, additive change (this commit): when `KK_EVIDENCE_DIR` is set, copy the renew/execute response, hub log, audit dump, served-cert details and certificate list there before cleanup. No behavioural change to any step or check.

## Verdict: PASS (harness: ALL STEPS PASSED, exit 0)

Method used: `auto` fell back from `authoritative` to `doh` (hub log below). The renewal completed in 71s per the harness.

| Step | Result | Evidence |
|---|---|---|
| Build hub + nginx/sshd fixture | PASS | placeholder served, sha256 6e80e905...7a7ef |
| Hub up | PASS | |
| Import unmanaged cert | PASS | fp 85700622...57f02cb |
| Cloudflare credential, ACME connector (LE staging, default propagation), takeover | PASS | token never printed |
| SSH credential + nginx target | PASS | |
| Renew via ACME dns-01 | **PASS** | `installed_verified verified=True`, 71s |
| Propagation method (auto) | **PASS** | hub log, below |
| Renew/execute HTTP response is JSON (not empty) | **PASS** | HTTP 200, body below (Run 1 bug 2 not reproduced on this run) |
| Order/authorization status at CA | UNVERIFIED directly | not logged by the hub; issuance by the CA implies it completed |
| Issuing CA contains "(STAGING)" | **PASS** | `issuer=C=US, O=Let's Encrypt, CN=(STAGING) Baloney Bulgur YE2` |
| Cert served by nginx is the renewed cert | **PASS** | served sha256 == `new_fingerprint` 14a001ec...3c84973f7 |
| SAN contains test name | PASS | harness check |
| TXT removed from zone | PASS | harness check; independent post-run zone listing shows no `_acme-challenge` |
| Token absent from hub log + audit | PASS | harness check |

## Evidence

Hub log (propagation lines; timestamps are the hub's, UTC):
```
2026/10/15 14:23:31 acme connector conn-69e37aefd93ed7f045545ad4f0820b21: dns-01 authoritative check got no DNS answer; falling back
2026/10/15 14:23:31 acme connector conn-69e37aefd93ed7f045545ad4f0820b21: dns-01 propagation checked via doh
```
The hub started at 14:22:26; the harness created the connector at 14:22:27. The fallback line is 14:23:31, so the authoritative attempt consumed roughly one minute before falling back (the exact start of the renewal call was not logged; UNVERIFIED beyond that bound).

renew/execute response (HTTP 200):
```
{"data":{"predecessor_fingerprint":"85700622afa0b3eb1b7d40b3f26f00c15f8bf3576c97c9eaf56eb193157f02cb","new_fingerprint":"14a001ec13cae412e69ae30f00238951181ff97346d7ee8dd922a53ac84973f7","renewed":true,"install_outcome":"installed_verified","verified":true}}
```

Served by nginx (openssl s_client, after renewal):
```
subject=CN=kk-uat-20261015142217.kryptkeeper.io
issuer=C=US, O=Let's Encrypt, CN=(STAGING) Baloney Bulgur YE2
notBefore=Oct 15 13:25:03 2026 GMT
notAfter=Dec 18 13:25:02 2026 GMT
sha256 Fingerprint=14:A0:01:EC:13:CA:E4:12:E6:9A:E3:0F:00:23:89:51:18:1F:F9:73:46:D7:EE:8D:D9:22:A5:3A:C8:49:73:F7
```

Hub records: `/api/v1/certificates` lists both the new cert (14a001ec...) and the imported predecessor (85700622...). Audit (UTC): 14:22:27 certificate.import, credential.create x2, connector.create, estate.takeover, target.create all success; 14:23:38 `certificate.renew_execute` outcome=success (resource = predecessor fingerprint).

## Zone safety
Cloudflare zone record names/types listed before and after the run via API (names/types only): identical. CNAME kryptkeeper.io, CNAME www, MX kryptkeeper.io x3, TXT cf2024-1._domainkey, TXT kryptkeeper.io (apex SPF). Zero `_acme-challenge` records after the run. No other record touched (listed names/types only; record contents were not compared).

## Cleanup
Harness trap removed the hub and nginx containers, the network and the two run images. Verified afterwards: no `kk-uat-acmeup*` containers, networks or images, and no `/tmp/kk-uat-acmeup.*` work dir remain. (Unrelated older `kk-uat-autopilot-*`, `kk-uat-agent-*`, `kk-uat-ssh*` images pre-existed and were not touched.)

## Notes
- Port 53 blocking was not re-measured in Run 2; the `authoritative check got no DNS answer` log line is consistent with it still being blocked.
- Run 1 bug 2 (empty reply after the write deadline) did not occur here, but this run finished in 71s, well under the old 180s deadline, so Run 2 does not exercise the 15m budget change. UNVERIFIED for waits near 3 minutes.
