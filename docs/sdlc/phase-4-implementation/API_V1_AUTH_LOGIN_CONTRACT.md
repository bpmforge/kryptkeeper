# API v1 Contract — `POST /api/v1/auth/login`

Status: Phase 4 (WS-02 incremental)

## Endpoint

- Method: `POST`
- Path: `/api/v1/auth/login`

## Request Body

```json
{
  "email": "admin@example.com",
  "password": "bootstrap-dev-password"
}
```

## 200 Response

```json
{
  "data": {
    "access_token": "<jwt>",
    "token_type": "Bearer",
    "expires_in": 900,
    "refresh_token": "rfr_<opaque>",
    "refresh_expires_in": 2592000,
    "principal": {
      "user_id": "team-1",
      "role": "pki-admin"
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
  "message": "invalid credentials"
}
```

## 403 Response

```json
{
  "error": "forbidden",
  "message": "account inactive"
}
```

## 405 Response

- Status: `405 Method Not Allowed`
- Header: `Allow: POST`
- Body: `method not allowed` (text/plain)

## 429 Response

```json
{
  "error": "too_many_requests",
  "message": "rate limit exceeded"
}
```
