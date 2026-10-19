# terraform-provider-kryptkeeper

Terraform provider for the Kryptkeeper PKI hub.

## Resources

| Type | Purpose | Import id |
|---|---|---|
| `kryptkeeper_ca` | Root or intermediate CA | CA id |
| `kryptkeeper_template` | Certificate template | template id |
| `kryptkeeper_certificate` | Certificate issued for your CSR | fingerprint |

## Data sources

| Type | Lookup |
|---|---|
| `kryptkeeper_ca` | by exact `name` |
| `kryptkeeper_template` | by exact `name` |

One example per resource and data source is under `docs/` and `examples/`.

## Authentication

```hcl
provider "kryptkeeper" {
  hub_url = "https://kryptkeeper.example.com"
  token   = var.kryptkeeper_token # sensitive; set with TF_VAR_kryptkeeper_token
}
```

## Versioning

The provider is built from this module and versioned with the hub's release tags (`vMAJOR.MINOR.PATCH`, semver). The binary reports the tag through `-ldflags "-X main.version=<tag>"`. Attribute removals or renames are breaking and only ship in a major version. CI (`.github/workflows/terraform-provider.yml`) runs unit tests and a live-hub apply/plan/destroy acceptance run (`tests/live/terraform/run.sh`).

## Development

```
go test ./...                       # unit tests, no hub needed
bash ../tests/live/terraform/run.sh # acceptance run against a hub it starts (needs tofu or terraform)
```
