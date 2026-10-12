# API v1 Contract — `GET /api/v1/certificates/{fingerprint}/download`

Status: Phase 4 (WS-04 incremental)

## Endpoint

- Method: `GET`
- Path: `/api/v1/certificates/{fingerprint}/download`

## Query Parameters

- `format` (optional): `pem` (default) or `der`
- `include_chain` (optional): `true|false` (default `false`)

## 200 Response

Headers:

- `Content-Type: application/x-pem-file` (format `pem`) OR `application/pkix-cert` (format `der`)
- `Content-Disposition: attachment; filename="<generated-filename>"`

Body:

- Binary/text certificate payload (not JSON envelope)

## 400 Response

```json
{
  "error": "bad_request",
  "message": "invalid format parameter"
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
- Header: `Allow: GET`
- Body: `method not allowed` (text/plain)

## 503 Response

```json
{
  "error": "service_unavailable",
  "message": "certificate unavailable"
}
```
