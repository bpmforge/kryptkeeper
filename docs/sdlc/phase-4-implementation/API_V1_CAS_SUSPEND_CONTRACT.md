# API v1 Contract — `POST /api/v1/cas/{id}/suspend`

Status: Phase 4 (WS-04 incremental)

## Endpoint

- Method: `POST`
- Path: `/api/v1/cas/{id}/suspend`

## Authentication

- Required: `Authorization: Bearer <token>`
- Auth behavior MUST match existing auth/protected v1 endpoints for active `AUTH_MODE`.

## 200 Response

```json
{
  "data": {
    "id": "ca-root-1",
    "status": "suspended",
    "updated_at": "2026-04-07T00:00:00Z"
  }
}
```

## 401 Response (unchanged envelope)

```json
{
  "error": "unauthorized",
  "message": "invalid or missing bearer token"
}
```

## 404 Response

```json
{
  "error": "not_found",
  "message": "ca not found"
}
```

## 409 Response

```json
{
  "error": "conflict",
  "message": "ca state conflict"
}
```

## 405 Response

- Status: `405 Method Not Allowed`
- Header: `Allow: POST`
- Body: `method not allowed` (text/plain)

## 503 Response

When the active CA provider cannot serve writes, fail closed:

```json
{
  "error": "service_unavailable",
  "message": "ca unavailable"
}
```
