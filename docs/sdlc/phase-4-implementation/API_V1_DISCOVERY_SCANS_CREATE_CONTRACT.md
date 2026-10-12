# API v1 Contract — `POST /api/v1/discovery/scans`

Status: Phase 4 (WS-06 incremental)

## Endpoint

- Method: `POST`
- Path: `/api/v1/discovery/scans`
- Auth: bearer token required

## Request Body

```json
{
  "scan_type": "full",
  "target": "10.0.0.0/24"
}
```

Required fields:

- `scan_type` (string)
- `target` (string)

## 201 Response

```json
{
  "data": {
    "resource": "discovery-scan",
    "principal": "bootstrap",
    "scan_job": {
      "id": "scan-1744000000000000000",
      "status": "queued",
      "scan_type": "full",
      "target": "10.0.0.0/24",
      "queued_at": "2026-04-07T12:00:00Z"
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
