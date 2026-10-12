# API v1 Contract — `GET /api/v1/certificates`

Status: Phase 4 (WS-04 incremental)

## Endpoint

- Method: `GET`
- Path: `/api/v1/certificates`

## Authentication

- Required: `Authorization: Bearer <token>`

## Query Parameters (implemented baseline)

- `q`
- `ca_id`
- `template_id`
- `team_id`
- `status`
- `grade` (comma-separated)
- `order` (`asc|desc`)
- `limit` (default 25, max 100)
- `cursor` (offset)

## 200 Response

```json
{
  "data": [
    {
      "fingerprint_sha256": "fp-cur",
      "common_name": "api.example.com",
      "renewal_status": "active",
      "grade": "C"
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

## 405 Response

- Status: `405 Method Not Allowed`
- Header: `Allow: GET, POST`
- Body: `method not allowed` (text/plain)

## 503 Response

```json
{
  "error": "service_unavailable",
  "message": "certificate list unavailable"
}
```
