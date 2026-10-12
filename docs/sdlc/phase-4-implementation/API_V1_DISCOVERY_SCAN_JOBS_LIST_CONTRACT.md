# API v1 Contract — `GET /api/v1/discovery/scan-jobs`

Status: Phase 4 (WS-06 incremental)

## Endpoint

- Method: `GET`
- Path: `/api/v1/discovery/scan-jobs`
- Auth: bearer token required

## Query Parameters

- `status` (optional string)
- `q` (optional substring match against target)
- `limit` (optional integer, default `25`, max `100`)
- `cursor` (optional integer offset, default `0`)

## 200 Response

```json
{
  "data": {
    "resource": "discovery-scan-jobs",
    "principal": "bootstrap",
    "scan_jobs": [
      {
        "id": "scan-1700000000000000001",
        "scan_type": "full",
        "target": "10.0.0.0/24",
        "status": "running",
        "queued_at": "2026-04-08T02:00:00Z"
      }
    ]
  },
  "meta": {
    "total": 1,
    "limit": 1,
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
- Header: `Allow: GET`
- Body: `method not allowed` (text/plain)
