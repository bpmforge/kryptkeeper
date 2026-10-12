# API v1 Contract — Error Format Compatibility (Legacy JSON + RFC7807)

Status: Phase 4 (WS-01 incremental)

## Scope

- Applies to shared error helpers used by bootstrap API handlers.

## Default (legacy)

- Response `Content-Type: application/json`
- Body shape:

```json
{
  "error": "unauthorized",
  "message": "invalid or missing bearer token"
}
```

## Compatibility Mode (RFC7807)

- Controlled by environment variable:
  - `APP_ERROR_FORMAT=problem` (or `rfc7807`)
- Response `Content-Type: application/problem+json`
- Body shape:

```json
{
  "type": "about:blank",
  "title": "Unauthorized",
  "status": 401,
  "detail": "invalid or missing bearer token"
}
```

## Rollout Semantics

- Legacy JSON remains default for backward compatibility.
- RFC7807 mode is opt-in in this wave.
