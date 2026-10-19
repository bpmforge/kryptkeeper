# kryptkeeper_ca (resource)

Manages a Certificate Authority (root, or intermediate when `parent_ca_id` is set).

## Example

```hcl
resource "kryptkeeper_ca" "root" {
  name          = "corp-root"
  common_name   = "Corp Root CA"
  algorithm     = "ECDSA-P384"
  validity_days = 3650
}

output "ca_id" {
  value = kryptkeeper_ca.root.id
}
```

## Attributes

- `name` (required), `common_name` (required), `algorithm` (RSA-2048, RSA-4096, ECDSA-P256, ECDSA-P384, ML-DSA-44/65/87; default ECDSA-P384), `validity_days` (default 3650), `parent_ca_id`.
- Computed: `id`, `key_size`, `certificate_pem` (public certificate, not sensitive).

## Destroy

The hub deletes only revoked CAs and CA revocation is dual-controlled. `terraform destroy` proposes the revoke; the hub answers 202 and the destroy fails with `pending approval, action id <id>`. A second admin approves that action (`POST /api/v1/pending-actions/<id>/approve`), then run destroy again. The hub keeps a revoked CA's record, so it is removed from state with a warning.

## Import

```
terraform import kryptkeeper_ca.root <ca-id>
```
