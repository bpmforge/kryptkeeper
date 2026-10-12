# API v1 Contract — `/api/v1/api-keys`

Status: Phase 4 (WS-02 incremental)

## Endpoints

- `GET /api/v1/api-keys`
- `POST /api/v1/api-keys`
- `DELETE /api/v1/api-keys/{kid}`

## Auth

- Bearer token required.
- `GET` returns keys visible to principal scope.
- `POST` and `DELETE` require admin role (`pki-admin`).

## GET `/api/v1/api-keys`

### 200 Response

```json
{
  "data": [
    {
      "name": "smoke-created",
      "kid": "kidabc123",
      "key_prefix": "kk_kidabc123_",
      "principal_id": "team-1",
      "role": "service-account",
      "scopes": ["*"],
      "active": true,
      "created_at": "2026-04-07T20:00:00Z"
    }
  ]
}
```

## POST `/api/v1/api-keys`

### Request Body

```json
{
  "name": "ci-automation",
  "principal_id": "team-1",
  "role": "service-account",
  "scopes": ["*"],
  "expires_at": "2026-12-31T00:00:00Z"
}
```

### 201 Response

```json
{
  "data": {
    "kid": "kidabc123",
    "token": "kk_kidabc123_<secret>",
    "key_prefix": "kk_kidabc123_",
    "principal_id": "team-1",
    "role": "service-account",
    "scopes": ["*"],
    "active": true
  }
}
```

## DELETE `/api/v1/api-keys/{kid}`

- `204 No Content` on success

## Common Error Responses

### 400

```json
{
  "error": "bad_request",
  "message": "invalid request body"
}
```

### 401

```json
{
  "error": "unauthorized",
  "message": "invalid or missing bearer token"
}
```

### 403

```json
{
  "error": "forbidden",
  "message": "forbidden"
}
```

### 404

```json
{
  "error": "not_found",
  "message": "api key not found"
}
```
