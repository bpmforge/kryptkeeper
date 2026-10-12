# API v1 Contract — Request ID Propagation (`X-Request-ID`)

Status: Phase 4 (WS-01 incremental)

## Scope

- Applies to all HTTP responses served by bootstrap runtime routes.
- Header name: `X-Request-ID`

## Behavior

1. If client sends `X-Request-ID` and it is syntactically valid, server echoes the same value in the response header.
2. If header is missing or invalid, server generates a request id and includes it in the response header.
3. Request id is available in request context for downstream handlers/middleware.

## Validation rules (incoming value)

- Max length: 128 characters
- Allowed characters: `A-Z`, `a-z`, `0-9`, `-`, `_`, `.`, `:`
- Any invalid value is ignored and replaced with server-generated id.

## Example

Request:

```http
GET /api/v1/meta HTTP/1.1
Host: localhost:8080
X-Request-ID: req-client-123
```

Response headers include:

```http
X-Request-ID: req-client-123
```

## Error Semantics

- This contract is additive and does not change existing response bodies/status codes.
- Existing endpoint-specific error payloads remain unchanged in this wave.
