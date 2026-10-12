# API v1 Contract — `POST /api/v1/notifications/test-delivery`

Status: Phase 4 (WS-07 incremental)

## Endpoint

- Method: `POST`
- Path: `/api/v1/notifications/test-delivery`
- Auth: bearer token required

## Request Body

```json
{
  "channel": "email",
  "target": "ops@example.com",
  "message": "smoke"
}
```

Required fields:

- `channel` (string)
- `target` (string)
- `message` (string)

## 202 Response

```json
{
  "data": {
    "resource": "notification-test-delivery",
    "principal": "bootstrap",
    "delivery": {
      "id": "notif-1744000000000000000",
      "channel": "email",
      "target": "ops@example.com",
      "status": "queued",
      "queued_at": "2026-04-07T12:00:00Z"
    }
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
- Header: `Allow: POST`
- Body: `method not allowed` (text/plain)
