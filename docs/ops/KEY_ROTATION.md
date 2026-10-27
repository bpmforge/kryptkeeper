# Key Rotation Runbook

Ticket **S-01** (G-8, kin D-051/D-087/FR-P13/FR-P49). Covers *planned,
routine* key rotation — a CA nearing its recommended cryptoperiod, or a
scheduled algorithm upgrade. For rotation forced by a suspected or confirmed
compromise, use `docs/ops/INCIDENT_RESPONSE.md`'s CA-compromise procedure
instead — it layers suspend + bulk-revoke + this same rotate step together
under time pressure, in a different order than a calm scheduled rotation.

## What rotation does and doesn't do

`POST /api/v1/cas/{id}/rotate-key` (`ca.Engine.RotateCA`,
`internal/ca/rotation.go`) re-keys a CA **in place**:

- Generates a new key under the CA's existing keystore ID (the old key is
  **retired, not deleted** — `keystore.Store.RotateKey`'s existing
  semantics).
- Re-issues the CA's own certificate under the new public key — self-signed
  for a root, parent-signed for an intermediate.
- Preserves the CA's original validity **window length** (not the original
  `NotAfter`) — the new key gets a fresh full term starting now. This is
  deliberate: a re-key is normally performed to replace an aging/compromised
  key with a fresh one, not to inherit whatever term happened to remain.
- Records the event in the `ca_key_rotations` ledger.

**What it does NOT do**: there is no cross-signing / overlap chain between
the old and new CA certificate (cross-signing is a separate, not-yet-landed
scope). Relying parties that pinned or distributed the **old** CA
certificate will need to be updated out-of-band once you rotate — this is
inherent to re-key-without-cross-sign, not a bug. Plan the "who trusts this
CA's old cert directly" inventory *before* rotating, not after.

## When to rotate (scheduled)

NIST SP 800-57 Part 1 recommends a CA signing-key cryptoperiod of roughly
1–3 years depending on key strength and risk tolerance; SOC 2/ISO 27001
auditors expect documented evidence of a rotation schedule being followed,
not just capability to rotate. Treat a CA approaching that window (or an
algorithm your posture reporting flags for sunset — see
`/api/v1/reports/algorithm-sunset`) as the trigger for the procedure below,
on your own cadence rather than waiting for an incident.

## Authorization

- **Admin role required**, gated on top of the normal tenant-visibility
  check for the CA (`internal/bootstrap/handlers_cas.go`'s `/rotate-key`
  handler) — a deliberately stricter combination than most other CA
  mutations, because re-keying is more consequential than any other CA
  operation: it generates new key material and immediately re-issues the
  CA's own certificate.
- Every call emits an audit event (`ca.rotate_key`, outcomes `success` /
  `denied` / `failure`) via `emitAuditEvent`/`emitAuditEventDetail` — the
  audit log is the append-only record of who rotated what and when (see
  [SECURITY_PRINCIPLES.md](../design/SECURITY_PRINCIPLES.md), rule 5).

> **Contract gap, not fixed here**: `/api/v1/cas/{id}/rotate-key` is live in
> code (`internal/bootstrap/handlers_cas.go`) but is not yet documented in
> `docs/openapi.yaml`. `docs/openapi.yaml` is outside this ticket's
> `write_scope`; flagging it here rather than silently patching the contract
> doc as a drive-by. The request/response shapes below are read directly
> from the handler and `ca_engine_provider.go`, not guessed.

## Procedure

1. **Inventory who trusts this CA's current certificate directly** (pinned
   clients, distributed root/intermediate bundles, cross-signed relying
   parties). Rotation has no overlap chain — anything that trusts the old
   cert stops trusting the new one the moment you rotate, unless you push
   the new cert to them first.
2. **Confirm the CA is `active`.** `RotateCA` refuses a CA that isn't
   (`CA %s is not active (status=%s)`) — a suspended CA must be reactivated
   (or rotation deliberately deferred) before this step.
3. **Call the rotate endpoint:**
   ```bash
   curl -X POST "$KRYPTKEEPER_API/api/v1/cas/$CA_ID/rotate-key" \
     -H "Authorization: Bearer $ADMIN_TOKEN" \
     -H "Content-Type: application/json" \
     -d '{"algorithm":"ECDSA-P256"}'   # omit "algorithm" to keep the CA's current algorithm
   ```
   Response (`{"data": <CAKeyRotationResult>}`, matching every other CA
   mutation's envelope in `handlers_cas.go`):
   ```json
   {
     "data": {
       "id": "<ca-id>",
       "status": "active",
       "key_id": "<unchanged keystore key id>",
       "rotated_at": "<RFC3339 timestamp>",
       "ledger_id": "<ca_key_rotations row id>",
       "ledger_persisted": true
     }
   }
   ```
   `ledger_persisted: false` means the key rotation and certificate
   re-issuance **already succeeded and are already in effect** — only the
   audit-ledger write failed. Do not retry in that case (see step 5).
4. **Distribute the new CA certificate** to whatever the inventory in step 1
   turned up, before (or immediately after, if timing is tight)
   communicating that the old certificate is retiring.
5. **If the call returns an error naming `ErrCARotationInconsistent`**
   (`internal/ca/rotation.go`): the keystore mutation already happened (new
   key live, old key retained on disk) but a later step — loading the new
   signer, generating a serial number, computing the SKI, or the CA-store
   write — failed. **Do NOT retry the rotation call.** Retrying generates
   *another* new key on top of an already-inconsistent CA. Instead inspect
   the CA directly; if its certificate no longer matches its keystore key,
   recover it from a pre-rotation backup via `docs/ops/RESTORE_DRILL.md` /
   `docs/ops/DR_RUNBOOK.md` rather than rotating again. This is the same
   irreversibility class the boot-time `ca.CheckKeyConsistency` scan
   (G-78, `cmd/kryptkeeper/main.go`) exists to catch after a raw process
   crash in this same window — S-01's drill in `RESTORE_DRILL.md`
   reproduced that exact check firing (for a different reason: a
   mid-restore gap, not a rotation crash) and confirmed it is advisory on
   `/readyz` (logged, not fatal) so an operator sees it rather than the
   hub silently serving a broken CA.
6. **Verify**: `GET /api/v1/cas/{id}` shows the new
   `certificate_fingerprint_sha256`; issue a real certificate from the CA
   and confirm `chain_complete: true, chain_trusted: true` in the response
   (same shape as `RESTORE_DRILL.md`'s drill, step 8).

## Rotating a non-CA key

Raw keystore keys that do **not** back a CA (e.g. a standalone
software-store key) rotate via `POST /api/v1/keys/{id}/rotate` instead —
this is a separate, less consequential route with its own admin gating. The
handler (`internal/bootstrap/handlers_keys.go`) explicitly **refuses** to
rotate a key that backs a CA through this endpoint
(`ca.KeyInUseByCA`, W9-04/G-35) — you'll get an error directing you to
`/api/v1/cas/{id}/rotate-key` instead. This guard exists because rotating a
CA's key through the raw keystore route (bypassing certificate re-issuance)
would silently leave the CA's certificate embedding the *old* public key —
the exact footgun `RotateCA`'s design exists to prevent.

## OCSP for the rotated-out issuer (W23-19)

A relying party that still holds the OLD anchor sends OCSP requests whose
CertID names the old issuer. While the retired key (`<id>-retired-<ts>`)
exists, the responder answers them: it recognises the old issuer by key hash,
signs with the OLD key (the response verifies against the old certificate, as
RFC 6960 requires) and reads status from the same revocation store under the
re-keyed CA's id. The old certificate is stored in the `ca_key_rotations`
ledger (`old_cert_pem`, migration 000129), so this survives restarts and works
on every replica. Rotations recorded before that migration have no stored
certificate and are not answered. Once `RetireRotatedKeys` destroys the
retired key (after `KRYPTKEEPER_CA_OLD_KEY_GRACE`, default 90 days) the old
issuer is no longer served and the responder answers `unauthorized` (RFC 6960
section 2.3), as for any issuer it does not serve. Responses signed by a
retired key are never cached.

## Rollback

There is no "undo rotation" operation — the old key is retained on disk
(retired, not deleted) but `RotateCA` does not expose reinstating it as the
active key. If a rotation was performed in error, the recovery path is the
same as for `ErrCARotationInconsistent` above: restore the CA from a
pre-rotation backup via `docs/ops/RESTORE_DRILL.md`, not a second rotation
call.
