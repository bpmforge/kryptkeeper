# API v1 Contract — `DELETE /api/v1/cas/{id}`

Status: Phase 4 (WS-04 incremental)

## Endpoint

- Method: `DELETE`
- Path: `/api/v1/cas/{id}`

## Authentication

- Required: `Authorization: Bearer <token>`
- Auth behavior MUST match existing auth/protected v1 endpoints for active `AUTH_MODE`.

## 204 Response

- `204 No Content` when CA is deleted.

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
  "message": "ca has active certificates"
}
```

## 422 Response

```json
{
  "error": "unprocessable_entity",
  "message": "ca must be revoked or expired before deletion"
}
```

## 405 Response

- Status: `405 Method Not Allowed`
- Header: `Allow: GET`
- Body: `method not allowed` (text/plain)

## 503 Response

When the active CA provider cannot serve writes, fail closed:

```json
{
  "error": "service_unavailable",
  "message": "ca unavailable"
}
```
