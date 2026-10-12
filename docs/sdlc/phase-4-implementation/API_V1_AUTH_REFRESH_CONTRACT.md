# API v1 Contract — `POST /api/v1/auth/refresh`

Status: Phase 4 (WS-02 incremental)

## Endpoint

- Method: `POST`
- Path: `/api/v1/auth/refresh`

## Request Body

```json
{
  "refresh_token": "rfr_<opaque>"
}
```

## 200 Response

```json
{
  "data": {
    "access_token": "<jwt>",
    "token_type": "Bearer",
    "expires_in": 900,
    "refresh_token": "rfr_<opaque-rotated>",
    "refresh_expires_in": 2592000
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
  "message": "invalid refresh token"
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
