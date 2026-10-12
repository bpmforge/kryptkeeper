# API v1 Contract — `GET /api/v1/cas/{id}/chain`

Status: Phase 4 (WS-04 incremental)

## Endpoint

- Method: `GET`
- Path: `/api/v1/cas/{id}/chain`

## Authentication

- Required: `Authorization: Bearer <token>`
- Auth behavior MUST match existing auth/protected v1 endpoints for active `AUTH_MODE`.

## Query Parameters

- `format` (optional): `json` (default) or `pem`.

## 200 Response (`format=json`)

```json
{
  "data": {
    "ca_id": "ca-iss-1",
    "chain": [
      {
        "depth": 0,
        "fingerprint_sha256": "fp-iss-1",
        "subject_dn": "CN=Issuing 1",
        "issuer_dn": "CN=Root 1",
        "valid_from": "2026-04-02T00:00:00Z",
        "valid_until": "2031-04-02T00:00:00Z"
      },
      {
        "depth": 1,
        "fingerprint_sha256": "fp-root-1",
        "subject_dn": "CN=Root 1",
        "issuer_dn": "CN=Root 1",
        "valid_from": "2026-04-01T00:00:00Z",
        "valid_until": "2036-04-01T00:00:00Z"
      }
    ]
  }
}
```

## 200 Response (`format=pem`)

- `Content-Type: application/x-pem-file`
- Body contains PEM chain blocks.

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
  "message": "ca chain unavailable"
}
```
