# API v1 Contract — Bearer API Key (`kk_<kid>_<secret>`)

Status: Phase 4 (WS-02 incremental)

## Scope

- Authentication extension for protected bearer-token endpoints.
- Supported alongside existing bearer modes.

## Token Format

- `Authorization: Bearer kk_<kid>_<secret>`

## Validation Model

- API-key auth path must be explicitly enabled: `APP_API_KEY_AUTH_ENABLED=true`
- Resolve `kid` from configured API key records.
- Verify `secret` using HMAC-SHA-256 verifier + server-side pepper.
- Require key to be active and not expired.

## Principal Mapping

- On success, authenticated principal is the key's `principal_id`.
- Example success path covered on `/api/v1/authz-check`.

## Error Behavior

- Invalid/missing bearer token still returns canonical envelope:

```json
{
  "error": "unauthorized",
  "message": "invalid or missing bearer token"
}
```
