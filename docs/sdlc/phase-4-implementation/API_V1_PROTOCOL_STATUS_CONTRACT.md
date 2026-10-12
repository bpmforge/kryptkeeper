# API v1 Contract — `GET /api/v1/protocols/status`

Status: Phase 4 (WS-05 baseline)

## Endpoint

- Method: `GET`
- Path: `/api/v1/protocols/status`
- Auth: bearer token required

## 200 Response

```json
{
  "data": {
    "resource": "protocol-status",
    "principal": "bootstrap",
    "protocols": {
      "acme": false,
      "est": false,
      "scep": false,
      "ocsp": false,
      "crl": false
    }
  }
}
```

Protocol flags are environment-controlled booleans:

- `APP_PROTOCOL_ACME_ENABLED`
- `APP_PROTOCOL_EST_ENABLED`
- `APP_PROTOCOL_SCEP_ENABLED`
- `APP_PROTOCOL_OCSP_ENABLED`
- `APP_PROTOCOL_CRL_ENABLED`

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
