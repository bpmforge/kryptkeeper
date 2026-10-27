# Incident Response Runbook

Ticket **S-01** (G-8, kin D-051/D-087/FR-P13/FR-P49). This runbook covers
**CA-compromise response** — the scenario the project's
[security principles](../design/SECURITY_PRINCIPLES.md) treat as trust-core: "a CA signing key is compromised or suspected compromised."
It documents the **manual sequence of existing primitives** an operator
executes today. There is not yet a single "declare compromise, do everything"
API — the dedicated per-key ACL + auto-rotate + one-call compromise workflow
is tracked as **FR-P49/D-087** and is still `todo` on the board as of this
ticket. This runbook exists so a real incident does not depend on someone
improvising that sequence under pressure for the first time.

## Severity: why a CA compromise is different from a leaf-cert compromise

A compromised leaf certificate/key affects one identity — revoke it, reissue
it, done. A compromised **CA** key affects every certificate it has ever
issued (and, if it's an intermediate whose parent is not compromised,
requires the parent to revoke *it*). Treat any of the following as a
suspected CA compromise and start this runbook rather than a single-cert
response:

- Key material for a CA (software-store file, HSM slot, KMS key, Vault
  transit key) was accessed, exported, or exists somewhere it shouldn't.
- A certificate was observed in the wild that this CA did not knowingly
  issue (chains to it, isn't in `/api/v1/certificates`).
- The host/process holding a software-backed CA's keystore passphrase was
  itself compromised.

## Roles

- **Incident lead** — runs this runbook, owns the timeline.
- **Approver** — a *different* principal from whoever proposes the bulk
  revoke (see step 3). Kryptkeeper enforces proposer≠approver at the API
  layer (`POST /api/v1/pending-actions/{id}/approve` returns `403` if the
  proposer tries to self-approve) — this is not a process nicety, it's
  mechanically gated, matching the "proposer is not approver" rule.

## Procedure

### 1. Contain — suspend the CA immediately

```bash
curl -X POST "$KRYPTKEEPER_API/api/v1/cas/$CA_ID/suspend" \
  -H "Authorization: Bearer $ADMIN_TOKEN"
```
`internal/ca/engine.go` refuses new issuance and renewal against a
non-`active` CA (`"CA %s is not active"`) — suspend is the fastest way to
stop **Kryptkeeper itself** from signing anything else with the suspected
key. It does **not** stop an attacker who exfiltrated the raw key material
from forging certificates entirely outside this system — suspend is
containment inside Kryptkeeper, not a fix for key material that has already
left its boundary. If that has happened, this is also a
"private key material never leaves its boundary" incident in its own right;
handle the exfiltration path (rotate credentials to whatever exposed it,
etc.) in parallel with this runbook, not after it.

`POST /api/v1/cas/{id}/suspend` returns `409` if the CA is already
suspended — treat that as informational, not a failure, if two responders
race to contain the same CA.

### 2. Assess blast radius

```bash
curl "$KRYPTKEEPER_API/api/v1/certificates?ca_id=$CA_ID&status=active&limit=100" \
  -H "Authorization: Bearer $ADMIN_TOKEN"
```
Paginate with `cursor` (100 per page max) to get the full count. This
number — not a guess — is what you report as blast radius, and it's the
input to step 3.

Also check whether `$CA_ID` is a **root** or an **intermediate**
(`GET /api/v1/cas/{id}` → `type`). That determines whether step 5 is
reachable through this API at all:
- **Intermediate**: its own certificate is signed by a parent CA this
  system may also manage. See step 5.
- **Root**: nothing in Kryptkeeper (or any PKI software) can revoke a root
  from above it. See step 5's root case — this is an out-of-band,
  human-communication step, not an API call.

### 3. Propose the bulk revoke — do not self-approve

Revoking every certificate a compromised CA issued is exactly what the
`bulk_revoke` pending-action type exists for
(`internal/bootstrap/pending_action_exec.go`) — it takes a `ca_id` directly
(rather than requiring you to enumerate fingerprints yourself) and goes
through the same approval gate as an MCP-proposed action:

```bash
curl -X POST "$KRYPTKEEPER_API/api/v1/pending-actions" \
  -H "Authorization: Bearer $PROPOSER_TOKEN" -H "Content-Type: application/json" \
  -d '{
    "action_type": "bulk_revoke",
    "params": {"ca_id": "'"$CA_ID"'", "reason_code": 2, "reason_text": "CA key compromise — incident <id>"},
    "rationale": "Suspected/confirmed compromise of CA '"$CA_ID"' — see incident <id>"
  }'
```
`reason_code: 2` is RFC 5280's `cACompromise` — use it here rather than `1`
(`keyCompromise`, which is correct for a single compromised leaf key) so the
revocation reason correctly records that the *issuer's* key was the
problem, not the individual leaf keys.

A **different** principal than the proposer approves:
```bash
curl -X POST "$KRYPTKEEPER_API/api/v1/pending-actions/$ACTION_ID/approve" \
  -H "Authorization: Bearer $APPROVER_TOKEN"
```
This executes the revoke server-side. Response
(`internal/bootstrap/handlers_pending_actions.go`):
```json
{"data": {"status": "approved", "result": {"revoked": N, "failed": N, "ca_id": "..."}}}
```
`result` is `executePendingAction`'s raw JSON output, nested under
`data.result` — pipe `jq .data.result.revoked`, not `jq .revoked`.
**`bulk_revoke` caps at 500 certificates per action** (`maxBulkRevoke`,
matching the direct `/certificates/bulk-revoke` API's own cap) — if step 2's
count exceeds 500, `data.result.total_matched`/`truncated_at` will show you
missed some; propose additional
`bulk_revoke` actions (or fall back to the direct
`POST /api/v1/certificates/bulk-revoke` endpoint with explicit fingerprint
pages) until the count from step 2 is fully covered. Do not stop after the
first action reports success without checking `total_matched`.

Every step here emits an audit event — `action.propose` on the
`POST /api/v1/pending-actions` call above, `action.approve` on the approval,
`certificate.revoke`/`certificate.bulk_revoke` for the actual revocations
(`internal/bootstrap/handlers_pending_actions.go`,
`internal/bootstrap/handlers_bulk.go`). This is the append-only record
the security principles require; it is what step 7's postmortem timeline is reconstructed
from, not memory of what happened.

### 4. Decide: re-key in place, or retire this CA identity entirely

Two options once containment (steps 1–3) is done — pick based on whether the
compromise vector is understood and closed:

- **Re-key in place** (same CA identity, new key) — only if you are
  confident the vector that led to compromise (e.g., a specific host, a
  specific credential) has been closed. Reactivate, then rotate
  immediately — see step 5. Anyone who pinned the CA's certificate directly
  needs the new certificate pushed to them; there is no cross-signing
  overlap chain (see `docs/ops/KEY_ROTATION.md`).
- **Retire this CA identity, mint a fresh one** — the safer default when the
  compromise vector is not fully understood, or when you don't want an
  incident-tainted CA ID to remain in the trust chain at all. Leave this CA
  suspended permanently, create a new CA via `POST /api/v1/cas`, and have
  every certificate holder re-request against the new CA — `bulk-reissue`
  (step 5's alternative) does **not** apply here, since
  `RenewCertificate` reissues under the **same** `ca_id` as the original
  cert (`internal/bootstrap/certificate_ca_provider.go`) — it cannot retarget
  a different CA. Re-enrollment against a new CA is a manual/scripted
  per-holder operation, not a bulk API call.

### 5. If re-keying in place: reactivate, then rotate — back to back

```bash
curl -X POST "$KRYPTKEEPER_API/api/v1/cas/$CA_ID/activate" -H "Authorization: Bearer $ADMIN_TOKEN"
curl -X POST "$KRYPTKEEPER_API/api/v1/cas/$CA_ID/rotate-key" \
  -H "Authorization: Bearer $ADMIN_TOKEN" -H "Content-Type: application/json" -d '{}'
```
`RotateCA` (`internal/ca/rotation.go`) refuses a non-`active` CA, so
reactivation must happen first — **there is a real window between these two
calls where the CA is active under the still-compromised key.** Run them
back to back, scripted, not as two manually-timed steps, and have someone
watching `GET /api/v1/audit?action=certificate.issue` live during that
window in case the compromised credential is used to issue something before
rotation completes. See `docs/ops/KEY_ROTATION.md` for the full rotation
contract (response shape, the `ErrCARotationInconsistent` failure mode, and
why you must not retry a rotation call that returns it).

**Intermediate CA case**: the CA's certificate *before* rotation is still
trusted by its parent unless separately revoked there. Capture
`certificate_fingerprint_sha256` from `GET /api/v1/cas/{id}` **before**
rotating (rotation replaces it), then revoke that fingerprint via
`POST /api/v1/certificates/{fingerprint}/revoke` if the parent CA tracks its
child's certificate as a revocable certificate record. **This is not
verified against a real parent/child revocation test as part of this
ticket** — treat it as the documented intent, confirm against your actual
parent-CA setup before relying on it in a real incident, and file a gap
ticket if the parent doesn't track the child's cert as revocable.

**Root CA case**: there is no revocation authority above a root. The only
real mitigation is manual, out-of-band trust-store removal/replacement
communicated to every relying party — this cannot be scripted against
Kryptkeeper's API and is the reason a root-CA compromise is a
business-continuity event, not just an ops procedure.

### 6. Reissue

For holders who still need a valid certificate under the (now re-keyed) CA:
```bash
curl -X POST "$KRYPTKEEPER_API/api/v1/certificates/bulk-reissue" \
  -H "Authorization: Bearer $ADMIN_TOKEN" -H "Content-Type: application/json" \
  -d '{"fingerprints": ["<old-fp-1>", "<old-fp-2>", ...]}'
```
Capped at 200 fingerprints per call (`internal/bootstrap/handlers_bulk.go`).
Each reissue is a fresh CSR-based issuance under the CA's *current* key —
run this only after step 5's rotation has completed, or you reissue under
the still-compromised key.

### 7. Post-incident

- Pull the full timeline from the audit log:
  `GET /api/v1/audit?action=ca.rotate_key`,
  `?action=certificate.bulk_revoke`, `?action=action.approve`, and
  `/api/v1/reports/change-audit` for a broader view. The audit log is
  append-only (security principle 5) — this is the authoritative record, not chat logs
  or memory of who did what.
- Confirm no certificate issued by the compromised key remains `active`:
  re-run step 2's query and expect `0`.
- If key material genuinely left its boundary (a raw key file, an HSM
  export, credentials to either), that is a separate incident under
  the "private key material never leaves its boundary" rule — file
  it, don't fold it silently into this CA-compromise writeup.
- Write up what happened, when, and the exact sequence executed, referencing
  the audit-log query results above rather than reconstructing from memory.

## Related runbooks

- `docs/ops/KEY_ROTATION.md` — the rotation contract used in step 5, for
  *planned* rotation outside an incident.
- `docs/ops/RESTORE_DRILL.md` / `docs/ops/DR_RUNBOOK.md` — if step 5's
  rotation fails mid-way (`ErrCARotationInconsistent`), recovery is a
  restore from a pre-rotation backup, not a retry.
- `docs/ops/OIDC_JWKS_RUNBOOK.md` — covers a *different* compromise class:
  a compromised OIDC/JWKS signing key for authentication, not a PKI CA. Use
  that runbook instead if the incident is about who can log in, not what
  certificates are trusted.
