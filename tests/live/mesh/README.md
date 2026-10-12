# W19-09 — service-mesh discovery UAT (Istio/Linkerd on kind)

Proves (and disproves) the hub's mesh discovery
(`internal/discovery/servicemesh.go`, scheduled by
`internal/bootstrap/mesh_discovery_wiring.go`'s `MeshDiscoveryScheduler`)
against a REAL Istio and Linkerd control plane on a kind cluster.

## What this actually tests (read the code first)

Mesh discovery is **not** reachable through `POST /api/v1/discovery/scans`
the way `k8s-certmanager` is (W19-17) — `scan_jobs.type`'s CHECK constraint
has no mesh scan type, and adding one would need a migration, out of this
ticket's scope. The only production path is
`MeshDiscoveryScheduler`, wired unconditionally in `cmd/kryptkeeper/main.go`
whenever `NewMeshDiscoveryFromEnv()` sees `KRYPTKEEPER_MESH_K8S_URL` set. It
sweeps on a timer (`KRYPTKEEPER_MESH_SWEEP_MINUTES`, default 60) with **no
immediate first tick** — this fixture sets it to `1` and polls up to ~100s.

`MeshDiscovery.Discover` probes, independently:

- every `kubernetes.io/tls` Secret cluster-wide (`k8s-tls-secret`)
- `istio-system/istio-ca-secret` and `istio-system/cacerts` (`istio-mesh`)
- `linkerd/linkerd-identity-issuer` (`linkerd-mesh`)

Results flow into the SAME `endpoints`/`certificates` tables network
scanning uses (a deliberate W12-04 decision: "same tables, same dedupe, no
parallel store"), visible via `GET /api/v1/discovery/endpoints` when the hub
runs with `APP_DISCOVERY_PROVIDER=db` (scanner-mode is in-memory and would
never see a scheduler-written SQL row).

## Topology

- podman only (`KIND_EXPERIMENTAL_PROVIDER=podman`), reusing the kind
  cluster **pattern** from `tests/live/k8s/run.sh` (same cluster name,
  same RBAC/token/CA-export shape) without modifying that fixture, per
  W19-09's write_scope.
- Real Linkerd (`brew install linkerd`) and real Istio (`brew install
  istioctl`) control planes on ONE kind cluster. Both fit together in this
  Mac's 8GiB podman machine — Istio was not skipped as best-effort.
- Two ServiceAccounts: `kk-uat-mesh-reader` (get/list secrets in both
  `linkerd` and `istio-system`) and `kk-uat-mesh-reader-neg` (`istio-system`
  only, no `linkerd` access) — the negative RBAC case.
- The hub runs on the host, as every other `tests/live/*` fixture.

## Run

```
bash tests/live/mesh/run.sh
```

Idempotent, PASS/FAIL per step, non-zero exit on any FAIL, cleans up the
kind cluster and hub processes on exit via `trap`. No real key material is
committed — the cluster CA, SA tokens, and mesh-issued certs are generated
by Linkerd's/Istio's own installers at run time and live only in the
ephemeral cluster and a `mktemp` work dir.

## Gated Go live test

`mesh_live_test.go` is skipped unless `KK_LIVE_MESH=1`. It's a thin wrapper
around `run.sh` (same shape as `tests/live/pkcs11/pkcs11_live_test.go` and
`tests/live/ad-ldap/adldap_live_test.go`) — the actual orchestration needs
process lifecycle management (`kind`, `linkerd`, `istioctl`) a Go test would
just re-implement `os/exec` calls around.

## Result: partial (2026-09-11) — see `docs/STATUS.md` for full detail

**What's proven real and correct:**

- Real Linkerd (`edge-26.6.3`) issuer secret and real Istio (`istioctl
  1.31.0`) `istio-ca-secret` both read successfully through the K8s API,
  with SHA-256 fingerprints matching independent `kubectl get secret |
  openssl x509 -fingerprint` ground truth.
- Real RBAC: the two-SA split confirmed directly against the apiserver
  (positive SA gets 200 on `linkerd/linkerd-identity-issuer`, negative SA
  gets 403).
- **A real hub defect found and FIXED on this branch (W19-20):**
  `MeshDiscovery.k8sGet` used `http.DefaultClient` with no CA-trust field —
  any cluster with a private API-server CA (every kind cluster; every real
  production cluster) failed every call with "x509: certificate signed by
  unknown authority". Fixed by mirroring
  `internal/certmanager/connector.go`'s CA-trust pattern
  (`MeshConfig.CACert`, `KRYPTKEEPER_MESH_K8S_CA_CERT`/`_FILE`); this
  fixture's hub startup uses that fix and the K8s calls succeed.

**What's still broken (found, NOT fixed here — W19-21, ticketed):**

The Linkerd/Istio certs never reach `/api/v1/discovery/endpoints`. The
hub log shows the scheduler running and reaching the K8s API successfully,
then:

```
mesh discovery: persist failed: upsert endpoint istio-system/istio-ca-secret:0:
constraint failed: CHECK constraint failed: port BETWEEN 1 AND 65535 (275)
```

Root cause, precisely:

- `internal/discovery/servicemesh.go`'s `meshEndpoint()` (called for the
  `k8s-tls-secret`/`istio-mesh`/`linkerd-mesh` protocols) never sets `Port`
  — these sources are identified by a K8s object name
  (`namespace/secret-name`), not a network address, so `Port` defaults to
  `0`.
- `internal/db/migrations/{sqlite,postgres}/000003_discovery_endpoints.up.sql:30`'s
  `endpoints` table requires `port INTEGER NOT NULL CHECK (port BETWEEN 1
  AND 65535)`.
- `internal/bootstrap/discovery_db_provider.go`'s `upsertScanResults`
  inserts every non-error result in ONE transaction and returns
  immediately on the first SQL error (no partial persistence) — so the
  moment any port-0 result appears (Istio's, in this run), the CHECK
  constraint aborts the ENTIRE transaction, and
  `mesh_discovery_wiring.go`'s `tick()` logs "persist failed" and returns
  early, discarding the whole sweep — including the Linkerd result that
  would otherwise have persisted cleanly.

This means mesh discovery has **never actually landed anything in
inventory against a real cluster**, for any cluster, since it was wired
(W7-06/W12-04) — masked until now because no prior test exercised the real
`sqliteDiscoveryStore` against its actual schema constraints with a
K8s-secret-shaped (port-less) result.

The negative case (RBAC without `linkerd` → a clear permission error, not
a silent empty result) is consequently **untestable**, blocked by the same
defect: `tick()` returns before ever reaching its own
`result.ErrorCount > 0` log line whenever persistence fails first, and
separately, `discovery_db_provider.go`'s `if ep.Error != "" { continue }`
means an error-carrying endpoint is never persisted at all, even on a
sweep that otherwise commits.

Not fixed here deliberately: this needs a schema migration in both
dialects (SQLite CHECK-constraint changes require a full table rebuild,
not an in-place `ALTER`) plus either per-row error isolation in
`upsertScanResults` or a documented decision to route port-less discovery
sources through the `scan_jobs.results_summary` path the way
`k8s-certmanager` already does (see `internal/bootstrap/k8s_discovery.go`'s
comment on exactly this class of problem for cloud/cert-manager sources).
Larger than "small and safe" for a UAT-fixture-scope ticket — see
**W19-21** in `docs/board/plan.json`.

## Gate

`go build ./... && go test ./...` — 36 packages ok (includes W19-20's two
new tests: `TestNewMeshDiscoveryTrustsConfiguredCACert`,
`TestNewMeshDiscoveryFailsClosedWithoutCACert`). `make lint` — 0 issues.
