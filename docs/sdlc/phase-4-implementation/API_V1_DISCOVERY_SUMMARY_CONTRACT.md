# API v1 Contract — `GET /api/v1/discovery/summary`

Status: Phase 4 (WS-06 baseline)

## Endpoint

- Method: `GET`
- Path: `/api/v1/discovery/summary`
- Auth: bearer token required

## 200 Response

```json
{
  "data": {
    "resource": "discovery-summary",
    "principal": "bootstrap",
    "discovered_endpoints": 0,
    "mapped_certificates": 0,
    "risky_endpoints": 0,
    "active_scan_jobs": 0
  }
}
```

Summary counters are environment-controlled integer values (default `0`):

- `APP_DISCOVERY_DISCOVERED_ENDPOINTS`
- `APP_DISCOVERY_MAPPED_CERTIFICATES`
- `APP_DISCOVERY_RISKY_ENDPOINTS`
- `APP_DISCOVERY_ACTIVE_SCAN_JOBS`

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
- Header: `Allow: GET`
- Body: `method not allowed` (text/plain)
