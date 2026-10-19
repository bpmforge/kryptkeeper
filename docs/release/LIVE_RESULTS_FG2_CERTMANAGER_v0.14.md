# Live validation W26-18: cert-manager external issuer on kind - v0.14

Date: 2026-10-16. Hub commit: 4235029f (plus the issuer/chart fixes in the W26-18 commit).
Harness: `tests/live/certmanager/run.sh`. Log: `<scratch>`.
cert-manager: v1.17.2. kind node image: `docker.io/kindest/node@sha256:a1ed56cfb0e7b93589bdf97c8cd566405a265939e3620fc4f5de89adff580ae5`.
Kubernetes version: v1.37.0 (kind, podman provider). Pod-to-host hub address: `host.containers.internal:8197`.

## Verdict: PASS - `ALL STEPS PASSED`

| Field | Value |
|---|---|
| Certificate Ready after apply (limit 60 s) | 0 s (whole-second timer; sub-second) |
| Inventory row after apply (limit 120 s) | 0 s (whole-second timer; sub-second) |
| Denied condition message (pasted) | `policy_violation: ca issuance failed: template policy violation: policy violation [dns_names]: DNS name "evil21.example.com" is not permitted by the template's name policy (template tpl-uat-certmanager-1792174445274584000)` |
| Recovery after hub restart (limit 420 s) | 13 s |
| Recovery after apply (incl. outage) | 34 s |
| `certmanager.issuer.unreachable` alert fired | No (4 consecutive failure logs, threshold 5) |

## Steps

| Step | Result | Evidence |
|---|---|---|
| hub up, root CA, template with name_policy | PASS | root CA b590a347-..., template tpl-uat-certmanager-... |
| kind + pinned cert-manager Available, CRDs usable | PASS | v1.17.2 |
| issuer image built and loaded | PASS | |
| pod reaches host hub | PASS | host.containers.internal |
| helm install, deployment rolled out | PASS | |
| A. Certificate Ready < 60 s | PASS | 0 s |
| A. inventory < 120 s | PASS | 0 s |
| A. tls.crt chains to hub root | PASS | `openssl verify`: OK |
| B. Denied=True with policy_violation and name-policy text | PASS | message above, reason `Denied` |
| B. Ready=False alongside Denied | PASS | |
| B. no inventory row for denied name | PASS | |
| C. outage: Ready=False / Pending / "hub unreachable" | PASS | `connect: connection refused` |
| C. recovery without manual action < 420 s | PASS | 13 s after hub restart |

## Findings (product and harness bugs the live run exposed, all fixed)

1. `spec.request` holds a base64 of the PEM CSR, not DER. The issuer wrapped it in a
   second PEM block, so the hub rejected every CSR ("signature invalid or unsupported
   key type"). Fixed: `csrToPEM` passes PEM through and wraps bare DER.
2. cert-manager's webhook rejects any status update on a request whose signer type
   is unknown ("referenced signer resource does not exist"). The chart now ships
   `Issuer` and `ClusterIssuer` CRDs (group `certmanager.kryptkeeper.io`) in `crds/`.
3. The webhook forbids `Denied` on an Approved request and `Approved` changes need
   `approve` on the signer. The issuer is now the approver for its own signer: it
   adds `Approved=True` on successful issuance and `Denied=True` on a policy
   violation; the chart grants it `approve` on `issuers/clusterissuers.certmanager.kryptkeeper.io`.
   cert-manager's built-in approver is not granted the signer (`certManager.approverRBAC=false`).
   A request already approved elsewhere gets `Ready=False/Denied` instead of a 403 retry loop.
4. The hub's `POST /api/v1/certificates` returns the inventory item (fingerprint), not
   `certificate_pem`. The issuer now downloads the PEM chain from
   `/api/v1/certificates/{fp}/download?format=pem&include_chain=true`.
5. Harness: cert-manager's default RSA-2048 key violates the hub Baseline policy;
   the Certificates now request ECDSA P-256 (the assertions are unchanged).

The Ready and inventory timers are whole seconds, so 0 s means under one second.
