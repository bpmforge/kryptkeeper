# kryptkeeper_ca (data source)

Looks up an existing CA by exact name. Errors when none or more than one matches.

## Example

```hcl
data "kryptkeeper_ca" "root" {
  name = "corp-root"
}
```

## Attributes

- `name` (required).
- Computed: `id`, `common_name`, `algorithm`, `certificate_pem`.
