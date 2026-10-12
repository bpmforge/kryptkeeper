# API v1 Contract — `PUT /api/v1/templates/{id}`

Status: Phase 4 (WS-04 incremental)

## Endpoint

- Method: `PUT`
- Path: `/api/v1/templates/{id}`

## Authentication

- Required: `Authorization: Bearer <token>`
- Auth behavior MUST match existing auth/protected v1 endpoints for active `AUTH_MODE`.

## Concurrency Guard

- Required header: `If-Match: <revision>`
- Missing/invalid `If-Match` returns `412 precondition_failed`.

## Request Body

- Full template replacement payload (same shape used for create).

## 200 Response

- Header: `ETag: <new-revision>`

```json
{
  "data": {
    "id": "tpl-tls-90d",
    "name": "tls-server-90d",
    "display_name": "TLS Server Certificate (90 days) Replaced",
    "revision": 4
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
  "message": "template name or oid already exists"
}
```

## 412 Response

```json
{
  "error": "precondition_failed",
  "message": "if-match revision mismatch"
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
