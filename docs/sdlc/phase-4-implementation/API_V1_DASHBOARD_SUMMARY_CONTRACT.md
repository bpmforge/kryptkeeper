# API v1 Contract — `GET /api/v1/dashboard/summary`

Status: Phase 4 (WS-08 baseline)

## Endpoint

- Method: `GET`
- Path: `/api/v1/dashboard/summary`
- Auth: bearer token required

## 200 Response

```json
{
  "data": {
    "resource": "dashboard-summary",
    "principal": "bootstrap",
    "certificates": {
      "total": 7,
      "expiring_30_days": 2,
      "expired": 1,
      "source": "file-store"
    },
    "discovery": {
      "discovered_endpoints": 0,
      "risky_endpoints": 0,
      "active_scan_jobs": 0
    },
    "notifications": {
      "pending_notifications": 0,
      "escalations": 0
    }
  }
}
```

Notes:

- Certificate metrics are sourced from existing certificate summary provider.
- Discovery/notification cards are sourced from environment-controlled counters.

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

## 503 Response

```json
{
  "error": "service_unavailable",
  "message": "dashboard summary unavailable"
}
```

## 405 Response

- Status: `405 Method Not Allowed`
- Header: `Allow: GET`
- Body: `method not allowed` (text/plain)
