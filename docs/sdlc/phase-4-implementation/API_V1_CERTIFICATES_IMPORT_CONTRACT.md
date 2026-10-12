# API v1 Contract — `POST /api/v1/certificates/import`

Status: Phase 4 (WS-04 incremental)

## Endpoint

- Method: `POST`
- Path: `/api/v1/certificates/import`

## Request Body

```json
{
  "certificate_pem": "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----",
  "team_id": "team-1",
  "notes": "migrated from legacy store"
}
```

Required fields:

- `certificate_pem`

Authorization note:

- Non-bootstrap principals are constrained to their own `team_id` scope. If omitted, server may derive `team_id` from principal.

## 201 Response

Headers:

- `Content-Type: application/json`
- `Location: /api/v1/certificates/{fingerprint_sha256}`

```json
{
  "data": {
    "fingerprint_sha256": "fp-imported",
    "renewal_status": "active",
    "source": "import"
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

## 403 Response

```json
{
  "error": "forbidden",
  "message": "forbidden"
}
```

## 405 Response

- Status: `405 Method Not Allowed`
- Header: `Allow: POST`
- Body: `method not allowed` (text/plain)

## 409 Response

```json
{
  "error": "conflict",
  "message": "certificate with this fingerprint already exists"
}
```

## 503 Response

```json
{
  "error": "service_unavailable",
  "message": "certificate unavailable"
}
```
