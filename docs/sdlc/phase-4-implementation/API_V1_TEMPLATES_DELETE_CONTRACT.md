# API v1 Contract — `DELETE /api/v1/templates/{id}`

Status: Phase 4 (WS-04 incremental)

## Endpoint

- Method: `DELETE`
- Path: `/api/v1/templates/{id}`

## Authentication

- Required: `Authorization: Bearer <token>`
- Auth behavior MUST match existing auth/protected v1 endpoints for active `AUTH_MODE`.

## Behavior

- Delete is allowed only when `issued_count == 0`.
- Templates with issued certificates are rejected with `409 conflict`.

## 204 Response

- Status: `204 No Content`
- Body: empty

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
  "message": "template not found"
}
```

## 405 Response

- Status: `405 Method Not Allowed`
- Header: `Allow: GET, PUT, PATCH, DELETE` for `/api/v1/templates/{id}` path handling
- Body: `method not allowed` (text/plain)

## 409 Response

```json
{
  "error": "conflict",
  "message": "template has issued certificates"
}
```

## 503 Response

When the active template provider cannot serve writes, fail closed:

```json
{
  "error": "service_unavailable",
  "message": "template unavailable"
}
```
