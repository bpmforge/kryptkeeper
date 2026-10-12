# API v1 Contract — `POST /api/v1/notifications/deliveries/ack`

Status: Phase 4 (WS-07 incremental)

## Endpoint

- Method: `POST`
- Path: `/api/v1/notifications/deliveries/ack`
- Auth: bearer token required

## Request Body

```json
{
  "delivery_id": "notif-failed-1",
  "note": "ack smoke"
}
```

Required fields:

- `delivery_id` (string)
- `note` (string, optional)

## 202 Response

```json
{
  "data": {
    "resource": "notification-delivery-ack",
    "principal": "bootstrap",
    "delivery_id": "notif-failed-1",
    "status": "acknowledged",
    "note": "ack smoke",
    "updated_at": "2026-04-08T00:00:00Z"
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
