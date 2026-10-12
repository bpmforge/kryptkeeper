# API v1 Contract — `GET /api/v1/notifications/summary`

Status: Phase 4 (WS-07 baseline)

## Endpoint

- Method: `GET`
- Path: `/api/v1/notifications/summary`
- Auth: bearer token required

## 200 Response

```json
{
  "data": {
    "resource": "notification-summary",
    "principal": "bootstrap",
    "pending_notifications": 0,
    "ownership_escalations": 0,
    "delivery_failures_24h": 0
  }
}
```

Summary counters are environment-controlled integer values (default `0`):

- `APP_NOTIFICATIONS_PENDING`
- `APP_NOTIFICATIONS_ESCALATIONS`
- `APP_NOTIFICATIONS_FAILURES_24H`

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
