# API v1 Contract — `GET /api/v1/discovery/endpoints`

Status: Phase 4 (WS-06 incremental)

## Endpoint

- Method: `GET`
- Path: `/api/v1/discovery/endpoints`
- Auth: bearer token required

## Query Parameters

- `protocol` (optional string)
- `risky_only` (optional boolean: `true|1`)
- `limit` (optional integer, default `25`, max `100`)
- `cursor` (optional integer offset, default `0`)

## 200 Response

```json
{
  "data": {
    "resource": "discovery-endpoints",
    "principal": "bootstrap",
    "endpoints": [
      {
        "id": "ep-risky-1",
        "hostname": "legacy-gateway.internal",
        "port": 443,
        "protocol": "tls",
        "risk_score": 92,
        "last_seen_at": "2026-04-07T01:00:00Z"
      }
    ]
  },
  "meta": {
    "total": 1,
    "limit": 1,
    "next_cursor": null,
    "prev_cursor": null
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

## 405 Response

- Status: `405 Method Not Allowed`
- Header: `Allow: GET`
- Body: `method not allowed` (text/plain)
