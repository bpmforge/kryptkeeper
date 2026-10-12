# API v1 Contract — `POST /api/v1/discovery/scan-jobs/requeue`

Status: Phase 4 (WS-06 incremental)

## Endpoint

- Method: `POST`
- Path: `/api/v1/discovery/scan-jobs/requeue`
- Auth: bearer token required

## Request Body

```json
{
  "scan_job_id": "scan-1700000000000000001",
  "reason": "smoke requeue"
}
```

Required fields:

- `scan_job_id` (string)
- `reason` (string, optional)

## 202 Response

```json
{
  "data": {
    "resource": "discovery-scan-job-requeue",
    "principal": "bootstrap",
    "previous_scan_job_id": "scan-1700000000000000001",
    "scan_job_id": "scan-1744070400000000000",
    "status": "queued",
    "reason": "smoke requeue",
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
