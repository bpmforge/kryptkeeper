# Vendor HSM customer validation checklist

Kryptkeeper talks to HSMs through PKCS#11 (build tag `pkcs11`). SoftHSM2 is
exercised in CI (`tests/live/pkcs11`); a vendor device is validated by the
customer on their own hardware using the steps below. **Kryptkeeper does not
certify vendor HSMs.** A pass here is evidence for your own validation record,
not a compatibility claim by the project.

## 1. Prerequisites

1. Vendor PKCS#11 library installed on the Kryptkeeper host; note its absolute
   path (`KRYPTKEEPER_PKCS11_LIB`).
2. An initialised token with a known label (`KRYPTKEEPER_PKCS11_TOKEN_LABEL`)
   and a user PIN (`KRYPTKEEPER_PKCS11_PIN`). Optionally pin a slot with
   `KRYPTKEEPER_PKCS11_SLOT`; without it the token is located by label.
   There is no PIN-file variant; supply the PIN through your secret store into
   the environment.
3. Build with the tag: `go build -tags pkcs11 ./...`.

**Pass:** `go build -tags pkcs11 ./...` exits 0 and the three required variables
are set in the shell you will use for steps 2-5.

## 2. Live harness against the vendor token

1. Copy `tests/live/pkcs11/run.sh` and replace the SoftHSM2 setup with your
   three variables (skip token initialisation; do not let it wipe a real token).
2. Run it.

**Pass:** 23/23 `PASS:` lines, no `FAIL:`, exit 0.

## 3. Keystore conformance

1. `go test -tags pkcs11 ./internal/keystore -run 'Conformance_PKCS11|PKCS11Store' -count=1 -v`

**Pass:** 0 `FAIL`; note any `SKIP` (for example algorithms the device does not
support) in the evidence.

## 4. CA on the HSM issues a verifiable certificate

1. Create a CA with HSM-backed key storage; confirm the CA record reports
   `key_storage_type=pkcs11`.
2. Issue one leaf certificate.
3. `openssl verify -CAfile ca.pem leaf.pem`.

**Pass:** `leaf.pem: OK`.

## 5. HSM outage fails closed

1. Remove the token or stop the HSM service.
2. Attempt issuance from the HSM-backed CA.

**Pass:** HTTP 503, zero new rows in `GET /api/v1/certificates`, and the alert
`keystore.backend_unavailable` in the logs. Restore the HSM and confirm
issuance recovers.

## 6. Evidence

1. Collect: harness log (step 2), test output (step 3), `openssl verify` output
   (step 4), outage log excerpt (step 5), HSM model and firmware version, PKCS#11
   library name and version, Kryptkeeper version.
2. File it in your vendor-validation record. Redact PINs; no key material should
   appear in any of it, and if it does, treat that as a defect and report it.

**Pass:** all five items attached and steps 1-5 each meet their pass line.
