# API v1 Contract — `GET /api/v1/protocols/conformance`

Status: Phase 4 (WS-05 incremental)

## Endpoint

- Method: `GET`
- Path: `/api/v1/protocols/conformance`
- Auth: bearer token required

## 200 Response

```json
{
  "data": {
    "resource": "protocol-conformance",
    "principal": "bootstrap",
    "suites": {
      "acme": {
        "state": "pass",
        "last_run_at": "2026-04-08T00:00:00Z",
        "passing_rate": 100
      },
      "est": {
        "state": "pass",
        "last_run_at": "2026-04-08T00:00:00Z",
        "passing_rate": 100
      },
      "scep": {
        "state": "pass",
        "last_run_at": "2026-04-08T00:00:00Z",
        "passing_rate": 100
      },
      "ocsp": {
        "state": "pass",
        "last_run_at": "2026-04-08T00:00:00Z",
        "passing_rate": 100
      },
      "crl": {
        "state": "pass",
        "last_run_at": "2026-04-08T00:00:00Z",
        "passing_rate": 100
      }
    }
  }
}
```

Conformance fields are environment-controlled with safe defaults:

- State envs (allowed: `pass|warn|fail`, default `pass`)
- Passing-rate envs (0..100 clamp, default `100`)
- Last-run envs (RFC3339, fallback to current UTC timestamp)

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
