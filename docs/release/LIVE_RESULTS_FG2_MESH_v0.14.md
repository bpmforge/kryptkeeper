# Live validation W26-19: hub-rooted workload identities on kind - v0.14

Date: 2026-10-16 (18:19:57Z). Hub commit: 20c44d1a. Harness: `tests/live/istio-mtls/run.sh`.
kind node image: `docker.io/kindest/node@sha256:a1ed56cfb0e7b93589bdf97c8cd566405a265939e3620fc4f5de89adff580ae5`
(single node, podman provider). Kubernetes version: v1.37.0.
go-spiffe: v2.8.1. Istio: not used.

Source log: real run by the lead on 2026-10-16, ends `ALL STEPS PASSED`, exit 0.

## Verdict: Path S PASS - validated live on 2026-10-16; Path I not attempted

| Path | Status |
|---|---|
| Path S (SPIFFE SVIDs from the hub Workload API) | PASS (M1-M7) |
| Path I (Istio `cacerts`) | NOT_ATTEMPTED (optional per spec; needs a CA-capable template with an exportable key and istioctl). PENDING-RUN |

| Field | Value |
|---|---|
| `openssl verify -CAfile <hub bundle> <client leaf>` output | `leaf.pem: OK` |
| Hub root sha256 | `b59529632872cd9126fc293ec0ec5afd16be94fe3c1c9d1183ed3b3e38dd9125` |
| uid 2003 refusal message | PermissionDenied: `uid 2003 is not a registered workload` |
| `spiffe.workload_attest` audit rows (success / denied) | 2 / 1 (recorded, not asserted) |

## Steps

| Row | Step | Result | Evidence |
|---|---|---|---|
| M1 | hub Pod up, Workload API listening on the hostPath socket, status enabled | PASS | Pod Ready twice (root CA 9f1c1900-43cb-4835-b431-e92be5c92c74 unchanged after restart with SPIFFE_SIGNING_CA_ID); log "Workload API listening on the hostPath socket"; `/api/v1/spiffe/status` enabled=true, trust domain kk-uat.example |
| M2 | selectors UID 2001 / 2002 registered (201), registry lists 2 | PASS | 2001 -> spiffe://kk-uat.example/ns/uat/sa/server, 2002 -> .../sa/client; registry lists 2 |
| M3 | svid-server and svid-client obtain SVIDs (registered selectors) | PASS | server got SVID and listens; client completed the call |
| M4 | mTLS: PEER id and CHAIN_OK on both sides, data flows | PASS | server saw .../sa/client, client saw .../sa/server, CHAIN_OK both sides, application data flowed |
| M5 | independent `openssl verify` to the hub root; bundle root == hub root | PASS | `leaf.pem: OK`; leaf SAN URI:spiffe://kk-uat.example/ns/uat/sa/client; Workload API bundle root sha256 equals hub root |
| M6 | unregistered uid 2003 refused with PermissionDenied | PASS | `uid 2003 is not a registered workload` |
| M7 | audit holds `spiffe.selector_bind` rows | PASS | 2 `spiffe.selector_bind` success rows; `spiffe.workload_attest` success=2 denied=1 |

## Findings

- Socket chmod sidecar: the run log does not show whether the root chmod sidecar
  (`manifests/hub.yaml`, widens the socket to 0666) was actually needed. It was
  always present in the manifest, and no run without it was made. The 0755 socket
  mode remains a code-reading expectation, not an observed result (PENDING-RUN:
  needs a run without the sidecar).
- go-spiffe v2.8.1 `X509Source` worked against the hub Workload API as used by the
  svidclient (M3, M4).
- Path I (Istio `cacerts`) was not attempted; PENDING-RUN.
