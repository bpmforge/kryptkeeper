# API v1 Contract — `GET /api/v1/dashboard/actions/history`

Status: Phase 4 (WS-08 incremental)

## Endpoint

- Method: `GET`
- Path: `/api/v1/dashboard/actions/history`
- Auth: bearer token required

## Query Parameters

- `status` (optional string)
- `category` (optional string)
- `limit` (optional integer, default `25`, max `100`)
- `cursor` (optional integer offset, default `0`)

## 200 Response

```json
{
  "data": {
    "resource": "dashboard-actions-history",
    "principal": "bootstrap",
    "history": [
      {
        "action_id": "act-expired-certs",
        "category": "certificate",
        "status": "open",
        "updated_by": "system",
        "updated_at": "2026-04-08T02:00:00Z",
        "note": "Detected expired certificate inventory"
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
