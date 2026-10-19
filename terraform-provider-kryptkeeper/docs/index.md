# Kryptkeeper provider

Manage certificate authorities, templates and certificates on a Kryptkeeper hub.

## Example

```hcl
terraform {
  required_providers {
    kryptkeeper = {
      source = "registry.terraform.io/kryptkeeper/kryptkeeper"
    }
  }
}

variable "kryptkeeper_token" {
  type      = string
  sensitive = true
}

provider "kryptkeeper" {
  hub_url = "https://kryptkeeper.example.com"
  token   = var.kryptkeeper_token
}
```

## Arguments

- `hub_url` (required) Hub base URL.
- `token` (required, sensitive) API bearer token. Pass it through a sensitive variable (`TF_VAR_kryptkeeper_token`), never in the configuration.

Resources: `kryptkeeper_ca`, `kryptkeeper_template`, `kryptkeeper_certificate`. Data sources: `kryptkeeper_ca`, `kryptkeeper_template`.
