# API v1 Contract — `GET /api/v1/notifications/deliveries`

Status: Phase 4 (WS-07 incremental)

## Endpoint

- Method: `GET`
- Path: `/api/v1/notifications/deliveries`
- Auth: bearer token required

## Query Parameters

- `status` (optional string)
- `channel` (optional string)
- `limit` (optional integer, default `25`, max `100`)
- `cursor` (optional integer offset, default `0`)

## 200 Response

```json
{
  "data": {
    "resource": "notification-deliveries",
    "principal": "bootstrap",
    "deliveries": [
      {
        "id": "notif-failed-1",
        "channel": "email",
        "target": "ops@example.com",
        "status": "failed",
        "queued_at": "2026-04-07T03:00:00Z"
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
