# DRILL: escrow-recover and BYOK import (W23-20)

- Date (UTC): 2026-10-16T01:52:41Z
- Git SHA: 9b99c208e36595cae5b29d5e85e22734d65d096c
- Machine: Darwin 27.0.0 arm64, go1.27.1, podman 6.1.3
- moto image: docker.io/motoserver/moto:latest (id f9a44bece215, moto 5.2.4.dev)
- Lowkey Vault image: docker.io/nagyesta/lowkey-vault:7.3.112 (id 2d6c1770d0b3)
- Result: go test exit 0

## Leg results (extracted from the run below)

- --- PASS: TestEscrowRecoverRoundTrip (1.36s)
-     --- PASS: TestEscrowRecoverRoundTrip/rsa (0.37s)
-     --- PASS: TestEscrowRecoverRoundTrip/ecdsa (0.31s)
-     --- PASS: TestEscrowRecoverRoundTrip/mldsa (0.29s)
-     --- PASS: TestEscrowRecoverRoundTrip/hybrid (0.39s)
- --- PASS: TestEscrowRecoverWrongPassphrase (0.18s)
- --- PASS: TestEscrowRecoverExistingID (0.19s)
- RESULT: PARTIAL (emulator): ExportEscrowedKeyToKMS returned: byok: import parameters: aws kms GetParametersForImport 15f7f32c-5c9a-4106-bcf7-f05d66207bef: operation error KMS: GetParametersForImport, exceeded maximum number of attempts, 3, https response error StatusCode: 500, RequestID: , deserialization failed, failed to decode response body, invalid character '<' looking for beginning of value
- --- PASS: TestBYOKImportAWS (1.19s)
- RESULT: NOT IMPLEMENTED (refused by design, follow-up W23-20a): byok: Azure Key Vault import is not implemented — its BYOK blob is a signed transfer structure with its own KEK ceremony, not AWS's RSA_AES_KEY_WRAP_SHA_256 layout, so this refuses rather than sending material Azure would reject
- --- PASS: TestBYOKImportAzure (0.00s)

## Full output

```
=== RUN   TestEscrowRecoverRoundTrip
=== RUN   TestEscrowRecoverRoundTrip/rsa
=== RUN   TestEscrowRecoverRoundTrip/ecdsa
=== RUN   TestEscrowRecoverRoundTrip/mldsa
=== RUN   TestEscrowRecoverRoundTrip/hybrid
--- PASS: TestEscrowRecoverRoundTrip (1.36s)
    --- PASS: TestEscrowRecoverRoundTrip/rsa (0.37s)
    --- PASS: TestEscrowRecoverRoundTrip/ecdsa (0.31s)
    --- PASS: TestEscrowRecoverRoundTrip/mldsa (0.29s)
    --- PASS: TestEscrowRecoverRoundTrip/hybrid (0.39s)
=== RUN   TestEscrowRecoverWrongPassphrase
--- PASS: TestEscrowRecoverWrongPassphrase (0.18s)
=== RUN   TestEscrowRecoverExistingID
--- PASS: TestEscrowRecoverExistingID (0.19s)
=== RUN   TestBYOKImportAWS
    escrow_byok_live_test.go:291: created EXTERNAL-origin key 15f7f32c-5c9a-4106-bcf7-f05d66207bef (state Enabled)
    escrow_byok_live_test.go:303: audit sequence reaching moto: byok.params=failure
    escrow_byok_live_test.go:314: RESULT: PARTIAL (emulator): ExportEscrowedKeyToKMS returned: byok: import parameters: aws kms GetParametersForImport 15f7f32c-5c9a-4106-bcf7-f05d66207bef: operation error KMS: GetParametersForImport, exceeded maximum number of attempts, 3, https response error StatusCode: 500, RequestID: , deserialization failed, failed to decode response body, invalid character '<' looking for beginning of value
--- PASS: TestBYOKImportAWS (1.19s)
=== RUN   TestBYOKImportAzure
    escrow_byok_live_test.go:356: RESULT: NOT IMPLEMENTED (refused by design, follow-up W23-20a): byok: Azure Key Vault import is not implemented — its BYOK blob is a signed transfer structure with its own KEK ceremony, not AWS's RSA_AES_KEY_WRAP_SHA_256 layout, so this refuses rather than sending material Azure would reject
--- PASS: TestBYOKImportAzure (0.00s)
PASS
ok  	kryptkeeper/tests/live/escrow-byok	3.134s
```

moto server-side log (why the AWS leg is PARTIAL):
```
   3     raise NotImplementedError(f"The {action} action has not been implemented")
   3 NotImplementedError: The get_parameters_for_import action has not been implemented
```

## Not proven by this drill

- AWS BYOK import is PARTIAL: moto does not implement GetParametersForImport, so the RSA_AES_KEY_WRAP_SHA_256 wrap, ImportKeyMaterial and post-import key equality are NOT exercised against any AWS-compatible service here. The wrap format is covered only by the in-process KMS stand-in in internal/keystore/byok_test.go. Real AWS KMS is needed to close this.
- Azure BYOK: no Azure import target exists (NewKMSImportTarget refuses by design); Lowkey Vault was started and answered /ping only. Follow-up W23-20a. Acceptance #2 is NOT met for Azure.
- moto caveats from tests/live/kms-aws/README.md apply (IAM, quotas, MessageType=DIGEST handling are not emulated). Lowkey Vault runs amd64 under qemu on this arm64 host (slow start, ~75s).
- RTO/RPO of the surrounding DR restore are not measured by this drill; see docs/ops/RESTORE_DRILL.md.

Reproduce: `bash tests/live/escrow-byok/run.sh`
