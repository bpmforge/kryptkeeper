# API v1 Contract — `GET /api/v1/protocols/readiness`

Status: Phase 4 (WS-05 incremental)

## Endpoint

- Method: `GET`
- Path: `/api/v1/protocols/readiness`
- Auth: bearer token required

## 200 Response

```json
{
  "data": {
    "resource": "protocol-readiness",
    "principal": "bootstrap",
    "protocols": {
      "acme": {
        "enabled": false,
        "healthy": false,
        "last_checked_at": null
      },
      "est": {
        "enabled": false,
        "healthy": false,
        "last_checked_at": null
      },
      "scep": {
        "enabled": false,
        "healthy": false,
        "last_checked_at": null
      },
      "ocsp": {
        "enabled": false,
        "healthy": false,
        "last_checked_at": null
      },
      "crl": {
        "enabled": false,
        "healthy": false,
        "last_checked_at": null
      }
    }
  }
}
```

Readiness values are environment-controlled:

- Enable flags:
  - `APP_PROTOCOL_ACME_ENABLED`
  - `APP_PROTOCOL_EST_ENABLED`
  - `APP_PROTOCOL_SCEP_ENABLED`
  - `APP_PROTOCOL_OCSP_ENABLED`
  - `APP_PROTOCOL_CRL_ENABLED`
- Health flags (default `true` only when protocol is enabled):
  - `APP_PROTOCOL_ACME_HEALTHY`
  - `APP_PROTOCOL_EST_HEALTHY`
  - `APP_PROTOCOL_SCEP_HEALTHY`
  - `APP_PROTOCOL_OCSP_HEALTHY`
  - `APP_PROTOCOL_CRL_HEALTHY`
- Last-check timestamps (RFC3339; invalid/unset → `null`):
  - `APP_PROTOCOL_ACME_LAST_CHECKED_AT`
  - `APP_PROTOCOL_EST_LAST_CHECKED_AT`
  - `APP_PROTOCOL_SCEP_LAST_CHECKED_AT`
  - `APP_PROTOCOL_OCSP_LAST_CHECKED_AT`
  - `APP_PROTOCOL_CRL_LAST_CHECKED_AT`

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
