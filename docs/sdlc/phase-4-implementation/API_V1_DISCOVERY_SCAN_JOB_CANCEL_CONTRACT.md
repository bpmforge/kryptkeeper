# API v1 Contract — `POST /api/v1/discovery/scan-jobs/cancel`

Status: Phase 4 (WS-06 incremental)

## Endpoint

- Method: `POST`
- Path: `/api/v1/discovery/scan-jobs/cancel`
- Auth: bearer token required

## Request Body

```json
{
  "scan_job_id": "scan-1700000000000000001",
  "reason": "smoke cancel"
}
```

Required fields:

- `scan_job_id` (string)
- `reason` (string, optional)

## 202 Response

```json
{
  "data": {
    "resource": "discovery-scan-job-cancel",
    "principal": "bootstrap",
    "scan_job_id": "scan-1700000000000000001",
    "status": "canceled",
    "reason": "smoke cancel",
    "updated_at": "2026-04-08T00:00:00Z"
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
