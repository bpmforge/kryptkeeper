# API v1 Contract — `PATCH /api/v1/cas/{id}`

Status: Phase 4 (WS-04 incremental)

## Endpoint

- Method: `PATCH`
- Path: `/api/v1/cas/{id}`

## Authentication

- Required: `Authorization: Bearer <token>`
- Auth behavior MUST match existing auth/protected v1 endpoints for active `AUTH_MODE`.

## Mutable Fields

- `display_name`
- `crl_distribution_points`
- `ocsp_service_url`

Immutable-field updates are rejected.

## 200 Response

```json
{
  "data": {
    "id": "ca-root-1",
    "name": "root-1",
    "display_name": "Root 1 Updated",
    "type": "root",
    "parent_ca_id": null,
    "status": "active",
    "key_storage_type": "pkcs11",
    "certificate_fingerprint_sha256": "fp-root-1",
    "crl_distribution_points": ["http://crl.new"],
    "ocsp_service_url": "http://ocsp.new",
    "created_at": "2026-04-01T00:00:00Z",
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
  "message": "ca not found"
}
```

## 405 Response

- Status: `405 Method Not Allowed`
- Header: `Allow: GET` for `/api/v1/cas`, `Allow: GET` or `Allow: POST` depending on specific sub-resource path handling
- Body: `method not allowed` (text/plain)

## 422 Response

```json
{
  "error": "unprocessable_entity",
  "message": "attempt to modify immutable field"
}
```

## 503 Response

When the active CA provider cannot serve writes, fail closed:

```json
{
  "error": "service_unavailable",
  "message": "ca unavailable"
}
```
