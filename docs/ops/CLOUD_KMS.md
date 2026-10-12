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

## Cloud key inventory endpoint

`GET /api/v1/inventory/keys` requires `key.manage` or `report.read`, and
returns generic per-provider errors; raw cloud errors are in the hub log only.
