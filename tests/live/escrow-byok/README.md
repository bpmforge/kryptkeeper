# W23-20 — escrow recover and BYOK import drill

```
bash tests/live/escrow-byok/run.sh                       # moto + Lowkey Vault; writes the drill record
KK_AWS_EMULATOR=aws bash tests/live/escrow-byok/run.sh   # AWS's emulator (aws-emulator package)
```

Real code paths (`keystore.EscrowKey`, `RecoverEscrowedKey`,
`ExportEscrowedKeyToKMS`): escrow and dual-custodian recovery round trips for
RSA, ECDSA, ML-DSA and hybrid keys, wrong-passphrase and existing-id refusals,
and BYOK import of escrow-recovered material into an EXTERNAL-origin AWS KMS key.

The moto run writes `docs/release/DRILL_ESCROW_BYOK_v0.11.md` (override with
`KK_DRILL_OUT`). The AWS emulator run does not rewrite that record; its results
are in `docs/release/LIVE_RESULTS_AWS_EMULATOR_v1.2.md`. It needs no Lowkey
Vault: the Azure leg only asserts the product's in-process refusal. If
`aws-emulator` is not installed it prints a named SKIP and exits 0.

## Proven against AWS's emulator (not real AWS)
- GetParametersForImport, the `RSA_AES_KEY_WRAP_SHA_256` wrap, ImportKeyMaterial
  (key goes from PendingImport to Enabled), and GetPublicKey after import is
  byte-identical to the escrowed key. `KK_BYOK_REQUIRE_FULL=1` (set by run.sh
  for this emulator) makes anything short of that a failure.

## Not proven
- moto does not implement GetParametersForImport, so the moto leg stays PARTIAL.
- Real AWS KMS: IAM and key policies on import, HSM-backed keys, quotas.
- Azure BYOK: no Azure import target exists (refused by design, W23-20a).

| Env | Meaning |
|---|---|
| `KK_LIVE_ESCROW_BYOK=1` | gate (set by run.sh) |
| `KK_AWS_EMULATOR=aws` | AWS's emulator instead of moto |
| `KK_EMULATOR_NAME` | emulator named in the log lines (set by run.sh) |
| `KK_BYOK_REQUIRE_FULL=1` | a PARTIAL or a public-key mismatch fails (set by run.sh for AWS's emulator) |
