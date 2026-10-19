# Ceremony and dual-control UAT: run record

Real run of `tests/live/ceremony/run.sh` on the developer Mac (hub built from
the checkout, Postgres 16 in podman). Output below is `run-record.txt`
verbatim. The commit shown is the W23-08 parent of the commit that adds this
harness; the hub code under test is identical. Negative proof: with
`KRYPTKEEPER_KEY_DUAL_CONTROL=false` forced in the base hub env, leg B goes
red (DELETE answers 204, not 202) and the run exits non-zero.

Setup note: `KRYPTKEEPER_BOOTSTRAP_CREATE_ROOT=true` is set because the hub
refuses to start with no CA configured; the ceremony CAs under test are
separate parked roots.

```
W23-09 ceremony + dual-control UAT
date:    2026-10-15T23:18:02Z
commit:  3928081b (internal/v2.2.0-1597-g3928081b)
machine: Darwin 27.0.0 arm64, go1.27.1, podman 6.1.3

=== build hub and start Postgres ===
PASS: hub built from this checkout
PASS: postgres ready on 127.0.0.1:55439
PASS: hub up with APP_API_KEYS_JSON identities alice, bob, carol (pki-admin) and agent (mcp-agent)

=== A. 2-of-3 ceremony ===
PASS: start ceremony quorum 1 refused -> 400
PASS: start ceremony quorum 4 (more than approvers) refused -> 400
PASS: start 2-of-3 ceremony (alice) -> 201
PASS: CA is parked: status=pending_ceremony
PASS: issuance from the parked CA refused -> 409
PASS: bootstrap token approval refused (not an eligible approver) -> 400
PASS: mcp-agent approval refused (not admin role) -> 403
PASS: alice approves (1 of 2) -> 200
PASS: issuance still refused before quorum -> 409
PASS: alice approving twice refused -> 400
PASS: bob approves (2 of 2) -> 200
PASS: ceremony status=completed
PASS: issuance after the Mth approval -> 201
PASS: openssl verify of the leaf against the ceremony CA chain: OK
PASS: carol approving a completed ceremony refused -> 400
PASS: start second ceremony -> 201
PASS: alice aborts it -> 200
PASS: ceremony status=aborted
PASS: aborted ceremony's CA refuses issuance (409)

=== B. dual control on key operations ===
PASS: alice creates key uat-dc-1 -> 201
PASS: alice DELETE uat-dc-1 is only proposed -> 202
PASS: key still readable while the delete is pending -> 200
PASS: proposer (alice) cannot approve her own delete -> 403
PASS: bootstrap token cannot approve -> 403
PASS: mcp-agent cannot approve -> 403
PASS: bob (a different human) approves -> 200
PASS: key is gone after the approval -> 404
PASS: alice creates key uat-dc-2 -> 201
PASS: alice export is only proposed -> 202
PASS: bob approves the export grant -> 200
PASS: carol (different human) cannot redeem alice's grant -> 403
PASS: alice redeems her approved grant -> 200
PASS: redeemed export returned an encrypted PEM
PASS: redeeming the same grant again refused (single use) -> 403

=== C. approval queue unreachable fails closed ===
PASS: alice creates key uat-dc-3 -> 201
PASS: postgres stopped
PASS: key DELETE with the queue down -> 503
PASS: postgres restarted and healthy
PASS: key uat-dc-3 still exists (nothing was deleted) -> 200

=== D. opt-out is loud ===
PASS: hub log carries the dual-control WARNING

ALL STEPS PASSED
```
