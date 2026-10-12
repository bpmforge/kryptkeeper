// Cloud KMS key inventory (GET /inventory/keys). Metadata only, same shape as
// the hub's KeyInventoryResponse; all identifiers are fake.
export const cloudKeyInventory = {
  data: {
    generated_at: "2026-10-09T12:00:00Z",
    total: 5,
    pqc_summary: { vulnerable: 4, quantum_safe: 1 },
    providers: ["aws-kms", "gcp-kms", "azure-kv"],
    keys: [
      {
        provider: "aws-kms",
        location: "us-east-1",
        key_id:
          "arn:aws:kms:us-east-1:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab",
        algorithm: "RSA_2048",
        usage: "SIGN_VERIFY",
        state: "Enabled",
        rotation_enabled: false,
        created_at: "2024-03-14T09:30:00Z",
        pqc_readiness: "vulnerable",
      },
      {
        provider: "aws-kms",
        location: "us-east-1",
        key_id:
          "arn:aws:kms:us-east-1:111122223333:key/9876fedc-98ba-76dc-54fe-0987654321ba",
        algorithm: "SYMMETRIC_DEFAULT",
        usage: "ENCRYPT_DECRYPT",
        state: "PendingDeletion",
        rotation_enabled: true,
        created_at: "2023-11-02T16:05:00Z",
        pqc_readiness: "vulnerable",
      },
      {
        provider: "gcp-kms",
        location: "projects/demo/locations/global/keyRings/prod",
        key_id:
          "projects/demo/locations/global/keyRings/prod/cryptoKeys/signing/cryptoKeyVersions/1",
        algorithm: "EC_SIGN_P256_SHA256",
        usage: "ASYMMETRIC_SIGN",
        state: "ENABLED",
        rotation_enabled: false,
        created_at: "2025-01-20T08:00:00Z",
        pqc_readiness: "vulnerable",
      },
      {
        provider: "gcp-kms",
        location: "projects/demo/locations/global/keyRings/prod",
        key_id:
          "projects/demo/locations/global/keyRings/prod/cryptoKeys/pqc-sig/cryptoKeyVersions/1",
        algorithm: "PQ_SIGN_ML_DSA_65",
        usage: "ASYMMETRIC_SIGN",
        state: "ENABLED",
        rotation_enabled: false,
        created_at: "2026-02-11T10:00:00Z",
        pqc_readiness: "quantum_safe",
      },
      {
        provider: "azure-kv",
        location: "https://demo-vault.vault.azure.net",
        key_id: "https://demo-vault.vault.azure.net/keys/app-wrap/0a1b2c3d",
        algorithm: "RSA",
        usage: "wrapKey",
        state: "Disabled",
        rotation_enabled: false,
        created_at: "2022-06-30T12:00:00Z",
        pqc_readiness: "vulnerable",
      },
    ],
  },
};
