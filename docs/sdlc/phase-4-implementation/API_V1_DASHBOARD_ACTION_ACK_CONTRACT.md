# API v1 Contract — `POST /api/v1/dashboard/actions/ack`

Status: Phase 4 (WS-08 incremental)

## Endpoint

- Method: `POST`
- Path: `/api/v1/dashboard/actions/ack`
- Auth: bearer token required

## Request Body

```json
{
  "action_id": "act-expiring-certs",
  "note": "ack from smoke"
}
```

Required fields:

- `action_id` (string)
- `note` (string, optional)

## 202 Response

```json
{
  "data": {
    "resource": "dashboard-action-ack",
    "principal": "bootstrap",
    "action_id": "act-expiring-certs",
    "status": "acknowledged",
    "note": "ack from smoke",
    "acked_at_utc": "2026-04-08T00:00:00Z"
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
