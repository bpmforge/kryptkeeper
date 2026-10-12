# API v1 Contract — `POST /api/v1/templates`

Status: Phase 4 (WS-04 incremental)

## Endpoint

- Method: `POST`
- Path: `/api/v1/templates`

## Authentication

- Required: `Authorization: Bearer <token>`
- Auth behavior MUST match existing auth/protected v1 endpoints for active `AUTH_MODE`.

## Request Body (required)

```json
{
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
  "active": true
}
```

## 201 Response

- Header: `Location: /api/v1/templates/{id}`
- Header: `ETag: <revision>`

```json
{
  "data": {
    "id": "tpl-tls-server-90d-1712490000000000000",
    "name": "tls-server-90d",
    "display_name": "TLS Server Certificate (90 days)",
    "revision": 1
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

## 405 Response

- Status: `405 Method Not Allowed`
- Header: `Allow: GET, POST`
- Body: `method not allowed` (text/plain)

## 409 Response

```json
{
  "error": "conflict",
  "message": "template name or oid already exists"
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
