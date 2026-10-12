# API v1 Contract — `PATCH /api/v1/templates/{id}`

Status: Phase 4 (WS-04 incremental)

## Endpoint

- Method: `PATCH`
- Path: `/api/v1/templates/{id}`

## Authentication

- Required: `Authorization: Bearer <token>`
- Auth behavior MUST match existing auth/protected v1 endpoints for active `AUTH_MODE`.

## Mutable Fields

- `display_name`
- `auto_enroll`
- `active`

Immutable-field updates are rejected.

## 200 Response

```json
{
  "data": {
    "id": "tpl-tls-90d",
    "name": "tls-server-90d",
    "display_name": "TLS Server Certificate (90 days) Updated",
    "oid": "1.3.6.1.4.1.99999.1.1",
    "key_usage": ["digitalSignature"],
    "extended_key_usage": ["serverAuth"],
    "allowed_algorithms": ["ECDSA", "RSA"],
    "min_key_size": 2048,
    "validity_period": "P90D",
    "renewal_overlap": "P14D",
    "auto_enroll": false,
    "active": true,
    "revision": 4,
    "schema_version": 1,
    "issued_count": 412,
    "created_at": "2026-01-10T08:00:00Z",
    "updated_at": "2026-04-07T00:00:00Z"
  }
}
```

## 400 Response

```json
{
  "error": "bad_request",
  "message": "invalid request body"
}
```

## 401 Response (unchanged envelope)

```json
{
  "error": "unauthorized",
  "message": "invalid or missing bearer token"
}
```

## 404 Response

```json
{
  "error": "not_found",
  "message": "template not found"
}
```

## 405 Response

- Status: `405 Method Not Allowed`
- Header: `Allow: GET, PUT, PATCH, DELETE` for `/api/v1/templates/{id}` path handling
- Body: `method not allowed` (text/plain)

## 422 Response

```json
{
  "error": "unprocessable_entity",
  "message": "attempt to modify immutable field"
}
```

## 503 Response

When the active template provider cannot serve writes, fail closed:

```json
{
  "error": "service_unavailable",
  "message": "template unavailable"
}
```
