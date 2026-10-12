# API v1 Contract — `GET /api/v1/templates`

Status: Phase 4 (WS-04 incremental)

## Endpoint

- Method: `GET`
- Path: `/api/v1/templates`

## Authentication

- Required: `Authorization: Bearer <token>`
- Auth behavior MUST match existing auth/protected v1 endpoints for active `AUTH_MODE`.

## Query Parameters

- `active` (optional boolean): filters by active status
- `q` (optional string): case-insensitive search over template `name` and `oid`
- `limit` (optional integer): default `25`, max `100`
- `cursor` (optional integer string): offset cursor, default `0`

## 200 Response

```json
{
  "data": [
    {
      "id": "tpl-tls-90d",
      "name": "tls-server-90d",
      "display_name": "TLS Server Certificate (90 days)",
      "oid": "1.3.6.1.4.1.99999.1.1",
      "key_usage": ["digitalSignature"],
      "extended_key_usage": ["serverAuth"],
      "allowed_algorithms": ["ECDSA", "RSA"],
      "min_key_size": 2048,
      "validity_period": "P90D",
      "renewal_overlap": "P14D",
      "auto_enroll": true,
      "active": true,
      "revision": 3,
      "schema_version": 1,
      "issued_count": 412,
      "created_at": "2026-01-10T08:00:00Z",
      "updated_at": "2026-03-01T14:00:00Z"
    }
  ],
  "meta": {
    "total": 1,
    "limit": 25,
    "next_cursor": null,
    "prev_cursor": null
  }
}
```

## 401 Response (unchanged envelope)

```json
{
  "error": "unauthorized",
  "message": "invalid or missing bearer token"
}
```

## 405 Response

- Status: `405 Method Not Allowed`
- Header: `Allow: GET, POST`
- Body: `method not allowed` (text/plain)

## 503 Response

When the active template provider cannot serve data, fail closed:

```json
{
  "error": "service_unavailable",
  "message": "template list unavailable"
}
```
