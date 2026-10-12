# API v1 Contract — `GET /api/v1/certificates/{fingerprint}/chain`

Status: Phase 4 (WS-04 incremental)

## Endpoint

- Method: `GET`
- Path: `/api/v1/certificates/{fingerprint}/chain`

## 200 Response

```json
{
  "data": {
    "current_fingerprint": "fp-cur",
    "chain": [
      {
        "fingerprint_sha256": "fp-prev",
        "position": "predecessor"
      },
      {
        "fingerprint_sha256": "fp-cur",
        "position": "current"
      },
      {
        "fingerprint_sha256": "fp-next",
        "position": "successor"
      }
    ]
  }
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

## 404 Response

```json
{
  "error": "not_found",
  "message": "certificate not found"
}
```

## 405 Response

- Status: `405 Method Not Allowed`
- Header: `Allow: GET`
- Body: `method not allowed` (text/plain)

## 503 Response

```json
{
  "error": "service_unavailable",
  "message": "certificate chain unavailable"
}
```
