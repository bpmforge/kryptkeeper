# kryptkeeper_template (data source)

Looks up an existing template by exact name. Errors when none or more than one matches.

## Example

```hcl
data "kryptkeeper_template" "web" {
  name = "web-server"
}
```

## Attributes

- `name` (required).
- Computed: `id`, `display_name`, `validity_period`, `active`.
