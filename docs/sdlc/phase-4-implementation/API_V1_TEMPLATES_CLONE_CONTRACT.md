# API v1 Contract — `POST /api/v1/templates/{id}/clone`

Status: Phase 4 (WS-04 incremental)

## Endpoint

- Method: `POST`
- Path: `/api/v1/templates/{id}/clone`

## Authentication

- Required: `Authorization: Bearer <token>`
- Auth behavior MUST match existing auth/protected v1 endpoints for active `AUTH_MODE`.

## Request Body

```json
{
  "name": "tls-server-47d",
  "display_name": "TLS Server Certificate (47 days)"
}
```

## 201 Response

- Header: `Location: /api/v1/templates/{new-id}`
- Header: `ETag: 1`

```json
{
  "data": {
    "id": "tpl-tls-server-47d-1712490000000000000",
    "name": "tls-server-47d",
    "display_name": "TLS Server Certificate (47 days)",
    "active": false,
    "auto_enroll": false,
    "revision": 1
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
- Header: `Allow: POST` for `/api/v1/templates/{id}/clone` path handling
- Body: `method not allowed` (text/plain)

## 409 Response

```json
{
  "error": "conflict",
  "message": "template name or oid already exists"
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
