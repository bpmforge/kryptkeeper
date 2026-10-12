# API v1 Contract — `GET /api/v1/cas/{id}`

Status: Phase 4 (WS-04 incremental)

## Endpoint

- Method: `GET`
- Path: `/api/v1/cas/{id}`

## Authentication

- Required: `Authorization: Bearer <token>`
- Auth behavior MUST match existing auth/protected v1 endpoints for active `AUTH_MODE`.

## Path Parameters

- `id` (string): CA identifier.

## 200 Response

```json
{
  "data": {
    "id": "ca-root-1",
    "name": "root-1",
    "display_name": "Root 1",
    "type": "root",
    "parent_ca_id": null,
    "status": "active",
    "key_storage_type": "pkcs11",
    "certificate_fingerprint_sha256": "fp-root-1",
    "certificate": {
      "fingerprint_sha256": "fp-root-1",
      "subject_dn": "CN=Root 1",
      "valid_from": "2026-04-01T00:00:00Z",
      "valid_until": "2036-04-01T00:00:00Z",
      "public_key_algorithm": "RSA",
      "key_size_bits": 4096
    },
    "crl_distribution_points": [],
    "ocsp_service_url": null,
    "created_at": "2026-04-01T00:00:00Z",
    "updated_at": "2026-04-01T00:00:00Z"
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

## 404 Response

```json
{
  "error": "not_found",
  "message": "ca not found"
}
```

## 405 Response (canonical baseline)

- Status: `405 Method Not Allowed`
- Header: `Allow: GET`
- Body: `method not allowed` (text/plain)

## 503 Response

When the active CA provider cannot serve data, fail closed:

```json
{
  "error": "service_unavailable",
  "message": "ca unavailable"
}
```
