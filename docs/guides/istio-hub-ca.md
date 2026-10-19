# Hub-rooted workload identities for Istio and SPIFFE workloads

> Status: Path S (SPIFFE SVIDs from the hub Workload API) was validated live on
> 2026-10-16: rows M1-M7 of `docs/release/LIVE_RESULTS_FG2_MESH_v0.14.md` read
> PASS (harness `tests/live/istio-mtls/run.sh`). Path I (Istio plugged-in CA
> `cacerts`) remains UNVALIDATED: it was not attempted and is not described here.
> Each section names the results row that backs its claims.

## What this gives you

Two workloads on the same node obtain short-lived X.509 SVIDs from the hub,
chaining to the hub's CA, and authenticate each other with mutual TLS by SPIFFE
ID. Evidence: rows M3, M4, M5.

## 1. Enable SPIFFE on the hub (row M1)

Run the hub with the CA provider and set:

```
SPIFFE_TRUST_DOMAIN=example.org
SPIFFE_SIGNING_CA_ID=<ca-id>            # the CA that signs SVIDs
SPIFFE_SVID_TTL=1h                      # default
SPIFFE_WORKLOAD_SOCKET=/run/spiffe/api.sock
```

The signing CA must already exist when the hub starts, so on a fresh install start
once to create the root, read its id from `GET /api/v1/cas`, then restart with
`SPIFFE_SIGNING_CA_ID` set. `GET /api/v1/spiffe/status` reports `enabled: true`.
See also `docs/guides/spiffe.md`.

## 2. Share the socket with workloads (row M1)

The Workload API is a Unix-domain socket, not a network service: workloads must
reach the socket through the node filesystem (a `hostPath` volume on Kubernetes).
The hub attests callers by the kernel-reported peer UID. The harness found it
necessary to widen the socket's permissions (a connecting UID needs write access
to the socket); see the results doc Findings for the measured behaviour.

## 3. Register workload selectors (row M2)

Bind each workload UID to a SPIFFE ID inside the trust domain (approver role):

```bash
curl -s -X POST -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"uid":2001,"spiffe_id":"spiffe://example.org/ns/prod/sa/server"}' \
  https://hub.example.com/api/v1/spiffe/workload-selectors
```

A workload cannot name its own identity; it receives only the identity bound to
its UID. A UID with no binding is refused with gRPC `PermissionDenied` and
receives no certificate (row M6).

## 4. Fetch SVIDs and run mTLS (rows M3-M5)

Workloads use a standard SPIFFE library pointed at the socket, for example
go-spiffe `workloadapi.NewX509Source` with `workloadapi.WithAddr("unix:///run/spiffe/api.sock")`,
then `tlsconfig.MTLSServerConfig` / `MTLSClientConfig` with `tlsconfig.AuthorizeID`.
The harness client (`tests/live/istio-mtls/svidclient`) is a working example.
Only `FetchX509SVID` is implemented by the hub (no rotation push, no JWT SVIDs).

## 5. Verify the chain to the hub root (row M5)

`GET /api/v1/spiffe/bundle` returns the trust bundle as PEM:

```bash
openssl verify -CAfile bundle.pem leaf.pem
```

## 6. Audit (row M7)

Selector bindings are audited as `spiffe.selector_bind`; attestations as
`spiffe.workload_attest` (see `GET /api/v1/audit?action=...`).

## Not covered

Istio with a hub-rooted `cacerts` secret, istiod acting as a hub-signed CA via
the CSR API, SVID rotation push, multi-node clusters (the socket is per node).
