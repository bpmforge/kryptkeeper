# API v1 Contract — `GET /api/v1/audit`

Status: Phase 4 (WS-03 incremental)

## Endpoint

- Method: `GET`
- Path: `/api/v1/audit`

## Authentication

- Required: `Authorization: Bearer <token>`
- Auth behavior MUST match existing auth/protected v1 endpoints for active `AUTH_MODE`.

## Query Parameters

- `limit` (optional integer): default `25`, max `100`.
- `cursor` (optional integer string): offset cursor for pagination; defaults to `0`.
- `order` (optional): `desc` (default) or `asc`.
- `action` (optional): exact action filter.
- `actor_type` (optional): exact actor type filter.
- `actor_id` (optional): exact actor identifier filter.
- `resource_type` (optional): exact resource type filter.
- `resource_id` (optional): exact resource identifier filter.
- `trace_id` (optional): exact trace identifier filter.
- `after` (optional RFC3339): include rows strictly after this timestamp.
- `before` (optional RFC3339): include rows strictly before this timestamp.

## 200 Response

```json
{
  "data": [
    {
      "id": 1001,
      "timestamp": "2026-04-07T00:00:00Z",
      "action": "certificate.issue",
      "actor_type": "system",
      "actor_id": "system",
      "resource_type": "certificate",
      "resource_id": "fp-1",
      "trace_id": "trace-local-1",
      "outcome": "success"
    }
  ],
  "meta": {
    "total": 1,
    "limit": 25,
    "next_cursor": "25",
    "prev_cursor": null
  },
  "principal": "bootstrap"
}
```

`next_cursor` and `prev_cursor` are opaque string cursors for subsequent requests. Current implementation uses offset-style cursors.

## 401 Response (unchanged envelope)

```json
{
  "error": "unauthorized",
  "message": "invalid or missing bearer token"
}
```

## 405 Response (canonical baseline)

- Status: `405 Method Not Allowed`
- Header: `Allow: GET`
- Body: `method not allowed` (text/plain)

## 503 Response

When the active audit provider cannot serve data, fail closed:

```json
{
  "error": "service_unavailable",
  "message": "audit unavailable"
}
```
