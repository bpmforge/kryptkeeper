# API v1 Contract — `GET /api/v1/certificates/{fingerprint}`

Status: Phase 4 (WS-04 incremental)

## Endpoint

- Method: `GET`
- Path: `/api/v1/certificates/{fingerprint}`

## Authentication

- Required: `Authorization: Bearer <token>`

## Response

- `200` returns certificate detail envelope (`data`)
- `ETag` response header is returned
- conditional `If-None-Match` supports `304 Not Modified`

## 401 Response

```json
{
  "error": "unauthorized",
  "message": "invalid or missing bearer token"
}
```

## 403 Response

```json
{
  "error": "forbidden",
  "message": "forbidden"
}
```

## 404 Response

```json
{
  "error": "not_found",
  "message": "certificate not found"
}
```

## 405 Response

- Status: `405 Method Not Allowed`
- Header: `Allow: GET`
- Body: `method not allowed` (text/plain)

## 503 Response

```json
{
  "error": "service_unavailable",
  "message": "certificate unavailable"
}
```
