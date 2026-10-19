# Screenshot tour: setup and data readiness

How to stand up a hub that screenshots well, and which pages need more than
the demo seed. Reviewed on `ux/v1-review` (2026-10-17) at 1440px light/dark
and 375px light.

## Recipe

1. Build: `go build -o dist/kryptkeeper ./cmd/kryptkeeper` and
   `npm --prefix ui run build`.
2. Start the hub with the same providers `docker-compose.yml` uses, plus
   SPIFFE so Machine Identities has data:
   `APP_NOTIFICATION_PROVIDER=delivery APP_DISCOVERY_PROVIDER=db
   SPIFFE_TRUST_DOMAIN=acme.test KRYPTKEEPER_TLS_DISABLE=true`, password login
   as in `scripts/dev/local-review-env.sh`. The bare-binary default
   notification provider serves three canned deliveries dated 2026-04-07;
   never screenshot with it.
3. Seed once on a fresh data dir:
   `BASE_URL=http://127.0.0.1:<port> TOKEN=<bootstrap token> bash scripts/dev/seed-demo.sh`.
   Re-runs are safe but probing by hand leaves duplicates; reset the data dir
   before the final capture.
4. Sign in through `/login` as the named admin and approve one code-signing
   and one wildcard request (the bootstrap token may not approve). Leave the
   rest pending so the inbox has content.
5. Serve the production bundle with `node scripts/dev/serve-real.mjs`
   (`KK_REVIEW_API`, `KK_REVIEW_PORT`). Never review `npm run dev`: it answers
   from MSW fixtures.
6. Capture `/search?q=acme`, not `/search`.

## Pages that screenshot well after the seed

Dashboard, Certificates (+ detail), Certificate Authorities (+ detail),
Templates, Issuance policies, Approvals inbox, My requests, Discovery
(+ endpoint), Crypto Posture, PQC Migration, Algorithm Sunset, Expiry
Timeline, Revocation Activity, Change Audit, Audit Evidence (+ detail),
Compliance Evidence, CA Health, SSH certificates, Code Signing, Keys, Key
Ceremonies, Users, Roles, Access Review, ACME, Enrollment Protocols,
Integrations, Inventory Sources, Target Setup, Renewal Policy, Machine
Identities, Issue certificate (capture a later wizard step).

## Pages that need more than the seed

| Page | What it needs | Lab hardware or external service? |
|---|---|---|
| Agents, Automation, Rollout Groups | A satellite agent that heartbeats and a target it can deploy to; one renewal run | Local container or lab host; no cloud |
| Alerts (+ delivery detail) | Real deliveries: an SMTP sink or webhook receiver so the delivery provider records sends | Local mail/webhook sink is enough |
| Cloud Keys | AWS KMS / Azure Key Vault / GCP KMS credentials | External cloud (LocalStack can stand in for AWS) |
| CT Findings | CT monitor polling real logs for a domain you own | External (public CT logs) |
| Anomalies | The scheduled anomaly scan to run after a burst of issuance | Software only; wait for the scan |
| SLOs | The SLO sweeper to run for a window | Software only; time |
| Issuance Velocity, Posture trend | Issuance and snapshots spread over days; a fresh seed puts everything on one day | Software only; time or backdated data |
| SPIFFE | `SPIFFE_SIGNING_CA_ID` plus a workload minting SVIDs | Software only |
| Tenants | `MULTI_TENANCY=on` and a restart | Config only |
| Delivery Plugins | A signed WASM plugin | Build artifact |
| Migration | An exported AD CS / other-CA dataset | AD CS export file |
| Blast Radius | Paste a fingerprint with deployments; capture the result | Software only |
| CA storage on HSM | SoftHSM or a real HSM for a non-software key store | SoftHSM works without hardware |
| Settings (K8s, SaaS, SIEM, evidence delivery) | Config values; evidence delivery needs SMTP | Config, local SMTP sink |

## Known demo-data quirks (not UI bugs)

- Requester shows as `bootstrap` on seeded approvals and change-audit rows;
  sign in as a named user to create the hero-shot rows.
- The legacy/contoso certs are imported on purpose (expired, weak, external)
  so posture and sunset pages have findings.
