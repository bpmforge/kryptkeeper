# API v1 Contract — `GET /api/v1/dashboard/actions`

Status: Phase 4 (WS-08 incremental)

## Endpoint

- Method: `GET`
- Path: `/api/v1/dashboard/actions`
- Auth: bearer token required

## 200 Response

```json
{
  "data": {
    "resource": "dashboard-actions",
    "principal": "bootstrap",
    "actions": [
      {
        "id": "act-expiring-certs",
        "category": "certificate",
        "severity": "high",
        "title": "Review expiring certificates",
        "count": 7
      },
      {
        "id": "act-expired-certs",
        "category": "certificate",
        "severity": "critical",
        "title": "Replace expired certificates",
        "count": 2
      }
    ]
  }
}
```

Action list is additive and priority-ordered by source checks:

- certificate expiry/expired counts from cert summary provider
- risky endpoint count from `APP_DISCOVERY_RISKY_ENDPOINTS`
- notification delivery failure count from `APP_NOTIFICATIONS_FAILURES_24H`

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
  "message": "dashboard actions unavailable"
}
```

## 405 Response

- Status: `405 Method Not Allowed`
- Header: `Allow: GET`
- Body: `method not allowed` (text/plain)
