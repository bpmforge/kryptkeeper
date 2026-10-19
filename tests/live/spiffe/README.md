# Live SPIFFE Workload API conformance (W29-01)

Boots a real hub process with the Workload API on a Unix socket and drives it
with the real `go-spiffe/v2/workloadapi` client.

    bash tests/live/spiffe/run.sh      # needs go, curl, python3; no containers

The script runs the hub twice on one data dir: phase 1 creates the signing CA
(`POST /api/v1/cas`, `ECDSA-P256`), phase 2 restarts with
`SPIFFE_TRUST_DOMAIN=kk.test SPIFFE_SIGNING_CA_ID=<id> SPIFFE_SVID_TTL=20s
SPIFFE_WORKLOAD_SOCKET=<sock>`, then runs `go test ./tests/live/spiffe/...`.

Env consumed by the tests (all set by run.sh; tests skip unless
`KK_LIVE_SPIFFE=1`): `KK_SPIFFE_HUB_BASE`, `KK_SPIFFE_TOKEN`,
`KK_SPIFFE_SOCKET`, `KK_SPIFFE_TRUST_DOMAIN`, `KK_SPIFFE_TTL`.

| Test | Proves |
|---|---|
| `TestGoSpiffeUnregisteredUIDDenied` | unbound UID gets `PermissionDenied` (runs before the bind) |
| `TestGoSpiffeFetchX509SVID` | SVID has the registered ID, TTL <= 24h, chain validates against `/api/v1/spiffe/bundle` |
| `TestGoSpiffeRotatesAtHalfLife` | an `X509Source` receives a new leaf at or before 50% of lifetime, no restart |
| `TestSharedUIDWorkloadsGetSameSPIFFEID` | two clients with one UID get the same ID |
| `TestNHILiveSelfApprovalRefused` | proposer approving its own NHI gets 403 |
| `TestNHILiveMCPAgentCannotApprove` | an `mcp-agent` key cannot approve (403) |
| `TestNHILiveRedeemOnce` | second redeem of a join token is 401 |
| `TestNHILiveExpiredSVIDRejected` | an SVID stops verifying after NotAfter |
| `TestNHILiveRevokedCannotMint` | revoked NHI's unredeemed token is dead; repeat revoke is 204 |
| `TestNHILiveAuditTrail` | `nhi.propose` / `nhi.approve` / `nhi.revoke` rows (and the self-approval failure) are in the audit log |

run.sh provisions two named administrators (`KK_SPIFFE_PROPOSER_TOKEN`,
`KK_SPIFFE_APPROVER_TOKEN`) through `APP_API_KEYS_JSON`: keys minted with the
bootstrap token are setup credentials and can never approve.

Last run (2026-10-16, macOS, hub built from this branch): 10 passed, 0 failed (4 go-spiffe + 6 NHI).

Known limitation (by design, do not weaken): attestation is by kernel peer UID
(SO_PEERCRED), so workloads sharing a UID cannot be told apart and receive the
same SPIFFE ID. Use one UID per identity.
