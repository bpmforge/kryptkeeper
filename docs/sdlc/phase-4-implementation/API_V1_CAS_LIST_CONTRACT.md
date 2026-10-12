# API v1 Contract — `GET /api/v1/cas`

Status: Phase 4 (WS-04 incremental)

## Endpoint

- Method: `GET`
- Path: `/api/v1/cas`

## Authentication

- Required: `Authorization: Bearer <token>`
- Auth behavior MUST match existing auth/protected v1 endpoints for active `AUTH_MODE`.

## Query Parameters

- `type` (optional): `root|issuing|external`
- `status` (optional): `active|suspended|revoked|expired`
- `limit` (optional integer): default `25`, max `100`
- `cursor` (optional integer string): offset cursor, default `0`

## 200 Response

```json
{
  "data": [
    {
      "id": "ca-root-1",
      "name": "root-1",
      "display_name": "Root 1",
      "type": "root",
      "parent_ca_id": null,
      "status": "active",
      "key_storage_type": "pkcs11",
      "certificate_fingerprint_sha256": "fp-root-1",
      "crl_distribution_points": [],
      "ocsp_service_url": null,
      "created_at": "2026-04-01T00:00:00Z",
      "updated_at": "2026-04-01T00:00:00Z"
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

## 405 Response (canonical baseline)

- Status: `405 Method Not Allowed`
- Header: `Allow: GET`
- Body: `method not allowed` (text/plain)

## 503 Response

When the active CA provider cannot serve data, fail closed:

```json
{
  "error": "service_unavailable",
  "message": "ca list unavailable"
}
```
