# Kryptkeeper v0.11.0

This release finishes the CA and key core: a 9-algorithm CA matrix, external
and offline roots, cross-signed rollover with rollback, CA revocation, key
compromise handling, template enrollment permissions, scalable revocation
(DB-backed CRL numbers, delta CRLs, CRL shards) and a proven two-replica HA
setup. It is feature group W23 of the v1.0 release train.

## Upgrade notes (read first)

- **Unsupported CA algorithm is now 400, not 422.** `POST /cas` with an
  algorithm outside the matrix answers 400 with `supported_algorithms`.
  A backend that cannot hold the algorithm (Ed25519 on PKCS#11 or cloud KMS)
  still answers 422.
- **CA re-key is dual-controlled.** `POST /cas/{id}/rotate-key` returns 202
  with an `action_id` when `KRYPTKEEPER_KEY_DUAL_CONTROL` is on (the default);
  a second admin approves, then the proposer retries with
  `approved_action_id`. Scheduled CA-key rotation now files a pending action
  (`ca_key_rotate_scheduled`) instead of rotating on its own.
- **CA revoke and delete.** `POST /cas/{id}/revoke` is always dual-controlled.
  `DELETE /cas/{id}` now removes only revoked or expired CAs (422 for an
  active CA, 409 while it has certificates or child CAs); an imported keyless
  root is soft-removed under dual control.
- **Key owner ACL.** Once a key has a policy (`PUT /keys/{id}/policy`), rotate,
  delete and export are refused (403) for admins not on its ACL.
- **Protocol template gates.** Setting `KRYPTKEEPER_ACME_TEMPLATE`,
  `KRYPTKEEPER_EST_TEMPLATE` or `KRYPTKEEPER_SCEP_TEMPLATE` makes that
  protocol enforce the template's `enrollment_permissions`; a missing or
  inactive template then denies. Unset keeps today's behaviour. Internal
  callers with no role are denied on restricted templates.
- **CRL numbers live in the database.** They now continue across restarts and
  are shared by replicas (RFC 5280 monotonic). The first CRL after upgrade
  starts the DB sequence at 1 per CA.
- **Helm.** The chart sets `APP_TEMPLATE_FILE` to
  `<persistence.mountPath>/data/templates.json`; before this, template writes
  failed with 503 on the read-only root filesystem.
- **Ceremonies expire** after `KRYPTKEEPER_CEREMONY_TTL` (default 72h).
- **OCSP** responses carry `Cache-Control: max-age=14400` by default
  (`KRYPTKEEPER_OCSP_MAX_AGE`, clamped to the response's validity).
- Migrations 000120-000129 run on upgrade (both engines).

## New

- **CA algorithms:** ECDSA-P256/P384, RSA-2048/3072/4096, Ed25519,
  ML-DSA-44/65/87. RSA-3072 works on every keystore backend.
- **External and offline roots:** `POST /cas/import` (dual-controlled),
  issuing-CA CSR generation and signed-certificate completion that checks key
  match, issuer signature, path length and validity.
- **Per-CA key backends:** one hub can mix software, PKCS#11 and KMS keys
  (`KRYPTKEEPER_KEY_BACKENDS`).
- **Rollover:** `rotate-key?mode=cross-sign` returns a bridge certificate;
  failed rotations roll back; OCSP keeps answering for leaves under the old
  key until it is retired.
- **CA revocation** puts the CA on its parent's CRL, marks child leaves
  revoked over OCSP and refuses ACME, EST, SCEP and CMP enrolment.
- **Key compromise:** `POST /keys/{id}/compromise` (dual-controlled) rotates,
  flags, revokes and re-issues, and reports re-issued, deferred and failed
  certificates. Cancel a cloud key's scheduled deletion with
  `POST /keys/{id}/cancel-deletion`.
- **Templates:** `enrollment_permissions` and revision history with diffs;
  issued certificates record the template revision.
- **Revocation scale:** opt-in delta CRLs (`KRYPTKEEPER_CRL_DELTA_INTERVAL`)
  and IDP shards (`KRYPTKEEPER_CRL_SHARDS`).
- **HA:** `/readyz` fails and issuance fails closed when the shared database
  is lost; cross-replica CRL/OCSP refresh; serial collisions retry.
- **Key-handling mode** on targets and in the key-custody report; hub-made
  renewal keys are zeroized and removed after a failed install.
- **FIPS:** `Dockerfile.fips` image variant and a `fips140=only` CI job.
- **UI:** CA import/CSR, re-key wizard, revoke, ceremonies, key escrow/BYOK,
  key policy and compromise, pending deletion, template permissions and
  history, and a blast-radius preview before each destructive action.

## Fixed

- OCSP GET rejected requests whose base64 contains `/`, so nginx got no
  staple for many CAs.
- ML-DSA CA certificates had the wrong KeyUsage bit order (OpenSSL error 79).
- Cross-sign bridges lacked an AuthorityKeyIdentifier (OpenSSL error 19).
- Vault transit: Ed25519 public keys, version selection, duplicate create
  and delete.
- CA revoke on Postgres failed on TEXT[] columns.

## Proven live (records in each `tests/live/*` folder)

Day-one hierarchy for all 9 algorithms in 13 s; air-gap offline root in 16 s;
two-human ceremony; Vault 1.17; moto KMS deletion/cancel; CA rollover with a
renewing lego client; CA revoke and key compromise on Postgres with real
ACME/EST/SCEP/CMP clients; Helm on kind at 2 replicas; a 30-minute two-hub
soak (10,001 issued, 0 duplicate serials, 99.919% available); revocation
benchmark (100k-entry CRL in 0.22 s, OCSP p99 under 15 ms at 500 rps).

## Known gaps

- BYOK import is not proven against an AWS-compatible service (moto lacks
  `GetParametersForImport`); the Azure BYOK target is not implemented.
- GCP KMS is tested against an in-repo wire emulator only.
- The CMVP certificate for the FIPS build is recorded at release time
  (`docs/release/CMVP_STATUS.md`).
- Each hub holds about 60 idle Postgres connections; size `max_connections`
  for your replica count. Templates are file-backed and do not replicate
  through Postgres.
- Retired CA keys are not destroyed automatically yet.
