# API v1 Contract — `POST /api/v1/protocols/conformance/recheck`

Status: Phase 4 (WS-05 incremental)

## Endpoint

- Method: `POST`
- Path: `/api/v1/protocols/conformance/recheck`
- Auth: bearer token required

## Request Body

```json
{
  "suite": "acme",
  "reason": "smoke recheck"
}
```

Required fields:

- `suite` (enum: `acme|est|scep|ocsp|crl`)
- `reason` (string, optional)

## 202 Response

```json
{
  "data": {
    "resource": "protocol-conformance-recheck",
    "principal": "bootstrap",
    "suite": "acme",
    "job_id": "conformance-1744070400000000000",
    "status": "queued",
    "reason": "smoke recheck",
    "queued_at": "2026-04-08T00:00:00Z"
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

## 405 Response

- Status: `405 Method Not Allowed`
- Header: `Allow: POST`
- Body: `method not allowed` (text/plain)
