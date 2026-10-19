# Live validation W26-05: ACME EAB, ARI, provisioners, dns-01 with certbot and lego - v0.14

Date: 2026-10-16. Hub commit: 2d210c08 (branch kk/w26-a) plus the harness flag fixes in this commit. Harness: `tests/live/acme/fg2-run.sh`.
certbot: 5.8.0. lego: 5.5.2 linux/arm64 (`docker.io/goacme/lego:latest`). pebble-challtestsrv: `ghcr.io/letsencrypt/pebble-challtestsrv@sha256:12ce21884def456bcf9786542113949e1f19dc7738d2c70e156c2d0c38a1405b` (latest at run time, image 7324c0dd5360).
Host: macOS arm64 (M-series), podman 6.1.3, hub built linux/arm64 CGO_ENABLED=0. Run log: `<scratch>`.
Original `tests/live/acme/run.sh` re-run 2026-10-16 by the lead on the same branch: `=== RESULT: 28 passed, 0 failed ===`, exit 0.

## Verdict: PASS - `=== RESULT: 53 passed, 0 failed ===` (exit 0)

First run: 29 passed, 7 failed. All 7 failures were harness bugs, none a hub defect:
the lego 5.5.2 CLI renamed `--kid/--hmac` to `--eab.kid/--eab.hmac` (the lego
issue, renew (new account registration), revoke, dns-01 and ARI-issue steps all
died with "flag provided but not defined: -kid", then the later lego steps
reported externalAccountRequired because no account had been registered); and
certbot prints only the problem detail text, so the assertion for the
RFC 8555 problem type now reads certbot's debug log (`urn:ietf:params:acme:error:externalAccountRequired`)
instead of its console output. lego 5.x has no `renew` subcommand: `lego run` is
get-or-renew and ARI-aware, so the not-yet control now runs for real instead of
being skipped. No assertion was weakened; the hub answered correctly throughout.

## Board acceptance

| # | Acceptance | Named PASS lines | Result |
|---|---|---|---|
| 1 | certbot and lego each issue, renew, revoke with EAB; no-EAB order refused `externalAccountRequired` | "certbot (EAB): obtain/renew/revoke", "lego (EAB): obtain certificate / renew / revoke", "certbot register without EAB ...: externalAccountRequired" (default and provisioner directory) | PASS |
| 2 | dns-01 (server-side resolver) issue by certbot or lego | "certbot dns-01: certificate for dns-web.internal", "lego dns-01 (--dns exec): certificate for dns-lego.internal" (provisioner offers dns-01 only) | PASS |
| 3 | lego renews on ARI; revoked cert answers OCSP revoked on the first request | "lego renewed the revoked certificate because ARI said renew now (no --renew-force, no --days)", "OCSP reports revoked on the first request" (certbot, lego, ARI cert) | PASS |
| 4 | out-of-allow-list name is `rejectedIdentifier` | "certbot: example.com (outside *.internal) is rejectedIdentifier / not permitted"; "no certificate was issued for example.com" | PASS |

## Steps

| Step | Result | Evidence |
|---|---|---|
| EAB keys minted; hmac_key only in the 201, never in GET | PASS | 4 keys minted; GET lists none of the hmac keys |
| provisioners internal-tls and internal-dns created | PASS | http-01+dns-01 and dns-01-only, allow `*.internal` |
| no-EAB register refused on default and provisioner directory | PASS | urn:ietf:params:acme:error:externalAccountRequired in certbot debug log, both directories |
| audit `acme.eab.reject` | PASS | 2 rows |
| certbot EAB obtain, chain, inventory source=acme | PASS | chains to "UAT Root CA"; inventory fp matched |
| certbot renew, then pre-revoke OCSP good | PASS | post-renewal chain OK; OCSP good, signature verified |
| certbot revoke, OCSP revoked (first request), CRL lists serial | PASS | |
| lego EAB obtain, chain, inventory source=acme | PASS | |
| lego renew (new fingerprint), pre-revoke OCSP good | PASS | `lego run --renew-force --ari-disable` on the stored EAB account |
| lego revoke, OCSP revoked (first request), CRL lists serial | PASS | `lego certificates revoke --eab ...` |
| allow-list: example.com refused, no cert issued | PASS | |
| certbot dns-01 on internal-dns (dns-01 only) | PASS | chain + inventory source=acme |
| lego dns-01 on internal-dns | PASS | `--dns exec`, `--dns.resolvers 10.91.26.53:53 --dns.propagation.wait 5s` |
| ARI live cert: 200, window end in the future | PASS | |
| ARI mangled certID == unknown serial, byte-identical 404 | PASS | |
| ARI control: lego does not renew before the window | PASS | `lego run` on the existing cert left the fingerprint unchanged |
| admin-API revoke, ARI window closes at once, OCSP revoked | PASS | admin revoke 200; window end now/past |
| lego renews because of ARI, no `--renew-force` | PASS | new fingerprint, chains to UAT Root CA |

## Notes

- "Inside the ARI window" is proven through the revocation-driven renew-now
  window (the hub issues long-lived ACME certificates), as the spec decided.
- dns-01 is shown by a provisioner that offers dns-01 only, so a success cannot
  have used http-01 (the hub does not log successful challenges).
- `FEATURE_VALIDATION_v0.9.md` row "ACME EAB" moves UNIT-ONLY to LIVE in a
  follow-up edit outside this ticket.
