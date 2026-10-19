# W26-18 - cert-manager external issuer on kind

Proves the `kryptkeeper-certmanager` external issuer (`Dockerfile.certmanager`,
`charts/kryptkeeper-certmanager-issuer`) against a REAL cert-manager on a real
kind cluster (podman provider) and a hub built from this checkout. Needs
W26-17 (watch reconcile, `Denied` / `PendingApproval` conditions).

## Run

```
bash tests/live/certmanager/run.sh
```

Prerequisites: `kind helm kubectl podman openssl curl python3 go`; a running
podman machine (it is shared with CI: run serially). Network access to pull
`cert-manager.yaml` and `docker.io/curlimages/curl`.

| Env | Default | Meaning |
|---|---|---|
| `HUB_PORT` | `8197` | host port of the hub (plain HTTP, `0.0.0.0`) |
| `CLUSTER` | `kk-uat-cm` | kind cluster name |
| `CERT_MANAGER_VERSION` | `v1.17.2` (pinned) | cert-manager release applied |
| `HUB_HOST_ADDR` | auto | address pods use to reach the host; else tries `host.containers.internal`, the podman-machine gateway (macOS), the host's primary address |
| `KEEP_CLUSTER` | `0` | `1` leaves the cluster and temp dirs for debugging |

Cleanup is a trap: kind cluster, image, hub process, `/tmp/kk-uat-cm-hub`,
temp dir. No secrets are committed; the bearer token is random per run and is
only passed with `kubectl create secret --from-literal` from a variable.

## What each step proves

1. Issue: Certificate `ok-N` Ready < 60 s, in `GET /api/v1/certificates?q=` < 120 s,
   `tls.crt` verifies with `openssl verify` against the hub root (EST cacerts).
2. Denial: a name outside the template `name_policy` (`.kk-uat.example`) yields a
   CertificateRequest with `Denied=True` (and `Ready=False`), reason `Denied`,
   message `policy_violation: ... name policy ...`; no inventory row.
3. Outage: hub killed -> `Ready=False`, reason `Pending`, message
   `hub unreachable...`; hub restarted (same data dir) -> request completes
   without touching the cluster, within 420 s (backoff caps at 5 min). Records
   whether `ALERT certmanager.issuer.unreachable` fired (needs 5 consecutive
   failures).

The script ends `ALL STEPS PASSED` and prints `MEASURE key=value` lines; copy
them into `docs/release/LIVE_RESULTS_FG2_CERTMANAGER_v0.14.md`.

## Notes

- The issuer approves its own requests (Approved=True on issue, Denied=True on a
  policy violation); the chart keeps `certManager.approverRBAC=false` so
  cert-manager's built-in approver cannot pre-approve (cert-manager forbids
  Denied on an approved request). Do not install approver-policy.
- The chart's `crds/` registers the `Issuer`/`ClusterIssuer` kinds so cert-manager's
  webhook accepts the signer; no Issuer object is created.
- Certificates request ECDSA P-256: the hub Baseline policy rejects RSA-2048.
- Fresh names per run (`ok-$RANDOM`) so `kubectl wait` never sees an old Ready.
