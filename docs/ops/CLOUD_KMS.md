# Cloud KMS key custody (AWS / GCP / Azure)

Applies when `KRYPTKEEPER_KEY_BACKEND=cloudkms-*`. Private keys are created
inside the provider and never leave it; the hub holds only references and
public keys.

## What the hub stamps on every key it creates

| Provider | Marker | Extra |
|---|---|---|
| AWS | tags `kryptkeeper:managed=true`, `kryptkeeper:key-id=<id>` | operator tags |
| GCP | labels `kryptkeeper_managed=true`, `kryptkeeper_key_id=<id>` (lowercased) | operator labels |
| Azure | key tags `kryptkeeper_managed=true`, `kryptkeeper_key_id=<id>` | operator tags |

Operator additions: `KRYPTKEEPER_KMS_TAGS='{"team":"pki","env":"prod"}'` (JSON
object of strings). Names starting `kryptkeeper` are reserved. A malformed value
fails key generation rather than creating untagged keys. GCP lowercases
labels. Key ids for gcp/azure must match `[A-Za-z0-9_-]{1,63}` (Azure
additionally forbids `_`).

Keys created before this change carry no marker. Tag them by hand
(`aws kms tag-resource`) or the tag-conditioned policy below will not let the
hub sign with them.

## Protection level (HSM by default)

| Provider | Default | Opt down | Requirement |
|---|---|---|---|
| AWS | KMS keys are HSM-backed | n/a | none |
| GCP | `protectionLevel: HSM` | `KRYPTKEEPER_GCP_KMS_PROTECTION=software` | location must offer Cloud HSM |
| Azure | `EC-HSM` / `RSA-HSM` | `KRYPTKEEPER_AZURE_KEY_HSM=false` | **Premium** vault or Managed HSM |

Cost: Cloud HSM and Azure Premium/Managed HSM keys are billed higher than
software keys and HSM operations are priced separately; check current
provider pricing before enabling for many keys. A Standard Azure vault
rejects HSM keys at create time with a 400 and the error names the opt-down
variable. Protection only matters at creation; existing keys keep working
and are never migrated.

## Minimal AWS IAM policy

`CreateKey` cannot be resource-scoped, so it is bounded by a request-tag
condition. Everything that uses a key is bounded by the resource tag.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "CreateManagedKeysOnly",
      "Effect": "Allow",
      "Action": ["kms:CreateKey", "kms:TagResource"],
      "Resource": "*",
      "Condition": {
        "StringEquals": { "aws:RequestTag/kryptkeeper:managed": "true" },
        "ForAllValues:StringLike": { "aws:TagKeys": ["kryptkeeper:*", "team", "env"] }
      }
    },
    {
      "Sid": "UseManagedKeysOnly",
      "Effect": "Allow",
      "Action": ["kms:Sign", "kms:GetPublicKey", "kms:DescribeKey", "kms:ScheduleKeyDeletion"],
      "Resource": "*",
      "Condition": {
        "StringEquals": { "aws:ResourceTag/kryptkeeper:managed": "true" }
      }
    },
    {
      "Sid": "KeyInventoryReadOnly",
      "Effect": "Allow",
      "Action": ["kms:ListKeys", "kms:DescribeKey", "kms:GetKeyRotationStatus"],
      "Resource": "*"
    },
    {
      "Sid": "AcmInventory",
      "Effect": "Allow",
      "Action": ["acm:ListCertificates"],
      "Resource": "*"
    }
  ]
}
```

Notes: adjust the `aws:TagKeys` list to your `KRYPTKEEPER_KMS_TAGS` names (or
drop that condition). `kms:TagResource` is required because `CreateKey` with
`Tags` is authorised against both actions. The inventory statement is
read-only and unscoped by design (it lists keys the hub does not own); drop it
if you do not use the key inventory or the ACM scan. Not exercised against a
real account in this repository's test suite; validate with IAM Access
Analyzer / policy simulator before relying on it.

## GCP and Azure

GCP: grant `roles/cloudkms.admin` on the key ring only to the hub identity
(create/destroy) plus `roles/cloudkms.signerVerifier`; add an IAM condition
`resource.labels.kryptkeeper_managed == "true"` where your org supports
conditions on the role. Azure: grant the hub identity key `create`, `sign`,
`get`, `delete` on a dedicated vault (Azure RBAC cannot condition on key tags,
so isolation is per vault).

## Mixed backends on one hub

`KRYPTKEEPER_KEY_BACKEND` stays the default for new CAs. Set
`KRYPTKEEPER_KEY_BACKENDS` to a comma-separated list of extra backends
(`pkcs11,cloudkms,vault,software`) to run several at once; each CA then picks
its backend with `key_storage_type` on `POST /cas` and keeps using it after a
restart (recovered from the CA row). Unset means a single backend, unchanged.
Raw `POST /keys` keys always use the default backend.

## Algorithm support

CA key algorithm support by key backend (`KRYPTKEEPER_KEY_BACKEND`). A backend
that cannot hold an algorithm refuses CA creation with HTTP 422 and a message
naming the backend.

| Algorithm | software | vault | pkcs11 | AWS KMS | GCP KMS | Azure Key Vault |
|---|---|---|---|---|---|---|
| RSA-3072 | yes | yes (`rsa-3072`) | yes | yes (`RSA_3072`) | yes (`RSA_SIGN_PKCS1_3072_SHA256`) | yes (`kty RSA`, `key_size 3072`) |
| Ed25519 | yes | yes | no (refused) | no (refused) | no (refused) | no (refused) |

RSA-3072 provider confirmation (checked 2026-10-15): AWS KMS key spec reference
lists RSA_2048, RSA_3072 and RSA_4096; GCP Cloud KMS algorithms page lists
RSA_SIGN_PKCS1_3072_SHA256; Azure Key Vault key types table lists RSA 2K, 3K, 4K.
PKCS#11 support is verified against SoftHSM2 (`-tags pkcs11`). Policy note: the
default keygen policy requires 4096 bits for CA keys via `/keys`, while
`POST /cas` accepts RSA-3072; set `KRYPTKEEPER_KEYGEN_CA_MIN_RSA_BITS=3072` to
align the policy with the CA matrix.

Ed25519 chains are not validated by Windows/ADCS clients or many TLS stacks; use
them for internal, SSH and workload CAs, not for WSTEP/autoenrollment.

## Cloud key inventory endpoint

`GET /api/v1/inventory/keys` requires `key.manage` or `report.read`, and
returns generic per-provider errors; raw cloud errors are in the hub log only.

## Disaster recovery with KMS-held keys

Key references (not key material) live in the `cloud_kms_keys` table, so the database restore from
`scripts/deploy/backup.sh`/`restore.sh` brings them back. The KMS key itself must still exist in the provider, and the
rebuilt hub's identity needs the same IAM grants as the lost one. The backup bundle lists these keys as
`skipped_non_extractable` (not lost, not exported); a non-zero count there is expected. Back up the KMS keys with the
provider's own mechanisms. The executed-drill procedure (SoftHSM2 reference run, real KMS optional) is
`docs/ops/DR_DRILL_EXTERNAL_KEYS_v0.13.md`, status PENDING until it is run.
