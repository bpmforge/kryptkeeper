# Key Destruction and Residual Copies

Ticket **W23-24** (FR-P47). What `DELETE /api/v1/keys/{id}` does, how a cloud
deletion is cancelled, and, most important for an auditor, **what still exists
after a key is destroyed**. Destroying a key in Kryptkeeper does not, by
itself, make every copy of it unrecoverable.

## What destroy does

`DELETE /api/v1/keys/{id}` (admin role; dual control on by default, so a second
administrator approves). A key that backs an active CA is refused with 409.

| Backend | Effect |
|---|---|
| Software / file | Cached key zeroized, encrypted key file removed. Unrecoverable from this keystore. |
| PKCS#11 HSM | Token object destroyed. |
| Vault transit | `deletion_allowed` set on the key, then the key (all versions) deleted. |
| AWS KMS | `ScheduleKeyDeletion`, 7-day pending window (provider range 7-30). Key is `PendingDeletion` and cannot sign. |
| GCP KMS | Key version `destroy` -> `DESTROY_SCHEDULED` (default 24 h). |
| Azure Key Vault | Key deleted into soft-delete retention (default 90 d); purge removes it for good. |

Cloud keys stay recoverable at the provider until the window ends; this is the
safety net and also a residual (below).

## Cancel

`POST /api/v1/keys/{id}/cancel-deletion` (admin role) restores a cloud key still
inside its window to Enabled.

- Dual control on: files a proposal; a different administrator approves; the
  cancel runs on approval. Dual control off: runs immediately.
- Only cloud-KMS keys with a recorded deletion can be cancelled, and only before
  the provider window ends. Anything else is a 409.
- **AWS:** `CancelKeyDeletion` leaves the key *Disabled*, so the cancel is
  followed by `EnableKey`. The sequence is retry-safe: if the enable step fails,
  repeating the cancel finds the key Disabled and only enables it.
- Local (file, HSM, Vault) keys cannot be cancelled; destroy is final.
- Verified against the moto AWS emulator by `tests/live/kms-aws`
  (`TestAWSKMSDeletionPendingAndCancel`): PendingDeletion with the 7-day date,
  Enabled after cancel, second cancel refused. Real-provider timing and IAM are
  not covered by the emulator.

## Residual after destroy

Destroy removes the key from the live keystore and the provider's active set.
These copies are **not** touched and must be handled separately:

1. **Backups.** Bundles from `POST /api/v1/admin/backup` and any filesystem or
   volume backup of the keystore directory still hold the key (encrypted) until
   those artefacts expire or are deleted. Restoring one resurrects the key.
2. **Snapshots.** VM, disk/volume and Postgres snapshots or PITR archives taken
   before the destroy contain the encrypted key files or key references and
   persist for their retention period.
3. **Escrow and export bundles.** Dual-custody escrow bundles (`/keys/escrow`)
   and BYOK/KMS export bundles remain recoverable by their custodians. Destroy
   does **not** revoke escrow. Delete the escrow bundle and have the custodians
   destroy their shares as a separate step, recorded separately.

Also remember cloud keys inside the provider window (above), and any
certificate or CSR already issued: destroying the CA key does not revoke what it
signed.

A destruction is complete only when the key is gone from (a) the live store,
(b) the provider window, (c) every backup and snapshot generation that holds it,
and (d) escrow.

## Audit evidence

- `key.delete` (outcomes: proposed, success, failure) for the destroy request.
- `key.destroy_cancel` (success, denied, failure) for each cancel attempt,
  including refused ones.

The product design also names `key.destroy` and `key.destroy_provider_failed`
(`docs/v1-vision/02-DETAIL-FG1-ca-core-keys.md`); at this commit the handlers emit
`key.delete`, so search for that action.
