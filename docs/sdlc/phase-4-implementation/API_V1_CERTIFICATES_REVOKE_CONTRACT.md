# API v1 Contract — `POST /api/v1/certificates/{fingerprint}/revoke`

Status: Phase 4 (WS-04 incremental)

## Endpoint

- Method: `POST`
- Path: `/api/v1/certificates/{fingerprint}/revoke`

## Request Body

```json
{
  "reason_code": 1,
  "reason_text": "Key compromise"
}
```

## 200 Response

```json
{
  "data": {
    "fingerprint_sha256": "fp-cur",
    "renewal_status": "revoked",
    "revoked_at": "2026-04-05T10:30:00Z",
    "revocation_reason": 1
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

## 404 Response

```json
{
  "error": "not_found",
  "message": "certificate not found"
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

## 409 Response

```json
{
  "error": "conflict",
  "message": "certificate is already revoked or expired"
}
```

## 503 Response

```json
{
  "error": "service_unavailable",
  "message": "certificate unavailable"
}
```
