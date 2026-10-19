# kryptkeeper_template (resource)

Manages a certificate template: validity, key usage and allowed algorithms.

## Example

```hcl
resource "kryptkeeper_template" "web" {
  name               = "web-server"
  display_name       = "Web server"
  validity_period    = "P90D"
  key_usage          = ["digitalSignature"]
  extended_key_usage = ["serverAuth"]
  allowed_algorithms = ["ECDSA-P256"]
}

output "template_id" {
  value = kryptkeeper_template.web.id
}
```

## Attributes

- `name`, `display_name` (required); `validity_period` (ISO 8601), `key_usage`, `extended_key_usage`, `allowed_algorithms`, `min_key_size`, `auto_enroll`, `active`.
- Computed: `id`.

## Destroy

A template that ever issued a certificate cannot be deleted; it is set inactive and removed from state with a warning.

## Import

```
terraform import kryptkeeper_template.web <template-id>
```
