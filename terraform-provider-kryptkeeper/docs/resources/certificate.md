# kryptkeeper_certificate (resource)

Issues a certificate from a CA and template for a CSR you supply. State never holds a private key.

## Example

```hcl
# The provider never generates keys: bring your own CSR.
resource "kryptkeeper_certificate" "web" {
  ca_id       = data.kryptkeeper_ca.root.id
  template_id = data.kryptkeeper_template.web.id
  csr_pem     = file("${path.module}/server.csr")
}

data "kryptkeeper_ca" "root" {
  name = "corp-root"
}

data "kryptkeeper_template" "web" {
  name = "web-server"
}

output "certificate_pem" {
  value = kryptkeeper_certificate.web.certificate_pem
}
```

## Attributes

- `ca_id`, `template_id`, `csr_pem` (required; a change replaces the certificate).
- Computed: `id` (the SHA-256 fingerprint), `fingerprint`, `certificate_pem`, `chain_pem`, `common_name`, `not_after`.

## Destroy

Destroy revokes the certificate. If the hub answers 202 (pending approval) the destroy fails with the pending action id.

## Import

```
terraform import kryptkeeper_certificate.web <fingerprint>
```

The hub never returns the CSR, so an imported certificate has no `csr_pem` in state. The first plan after import shows `csr_pem` going from null to your config value as an in-place change (not a replacement); apply records it without calling the hub, and later plans are empty.
