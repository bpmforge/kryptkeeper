# API v1 Contract — `POST /api/v1/certificates/{fingerprint}/renew`

Status: Phase 4 (WS-04 incremental)

## Endpoint

- Method: `POST`
- Path: `/api/v1/certificates/{fingerprint}/renew`

## Request Body

```json
{
  "csr_pem": "-----BEGIN CERTIFICATE REQUEST-----\n...\n-----END CERTIFICATE REQUEST-----"
}
```

## 201 Response

Headers:

- `Content-Type: application/json`
- `Location: /api/v1/certificates/{new_fingerprint}`

```json
{
  "data": {
    "fingerprint_sha256": "fp-next",
    "predecessor_fingerprint": "fp-cur",
    "renewal_status": "active",
    "source": "api"
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
  "message": "certificate already has an active successor"
}
```

## 503 Response

```json
{
  "error": "service_unavailable",
  "message": "certificate unavailable"
}
```
