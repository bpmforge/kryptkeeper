# Kryptkeeper — REST API Design

**Version:** 1.0
**Date:** 2026-04-05
**Phase:** 3 — Design
**Requirements:** FR-090 through FR-094 (SRS §3.16)

---

## Table of Contents

1. [Conventions](#1-conventions)
   - [1.1 Base URL and Versioning](#11-base-url-and-versioning)
   - [1.2 Request and Response Format](#12-request-and-response-format)
   - [1.3 Authentication](#13-authentication)
   - [1.4 Pagination](#14-pagination)
   - [1.5 Filtering and Sorting](#15-filtering-and-sorting)
   - [1.6 Error Format](#16-error-format)
   - [1.7 Standard Headers](#17-standard-headers)
   - [1.8 Rate Limiting](#18-rate-limiting)
2. [RBAC Matrix](#2-rbac-matrix)
3. [Certificate Authorities](#3-certificate-authorities)
4. [Certificates](#4-certificates)
5. [Certificate Templates](#5-certificate-templates)
6. [Discovery and Scanning](#6-discovery-and-scanning)
7. [Endpoints](#7-endpoints)
8. [Risk and Compliance](#8-risk-and-compliance)
9. [Users and Auth](#9-users-and-auth)
10. [API Keys](#10-api-keys)
11. [Teams](#11-teams)
12. [Notifications](#12-notifications)
13. [Audit Log](#13-audit-log)
14. [System](#14-system)
15. [Error Catalog](#15-error-catalog)

---

## 1. Conventions

### 1.1 Base URL and Versioning

```
https://<host>:8443/api/v1/
```

- All REST endpoints are under `/api/v1/`. Breaking changes increment the path to `/api/v2/`.
- Protocol endpoints (ACME, EST, SCEP, OCSP) are on separate ports and are not covered here.
- The OpenAPI 3.1 machine-readable spec is served at `GET /api/v1/openapi.yaml`.
- Requests and responses use `Content-Type: application/json` unless specified otherwise
  (certificate downloads use format-specific MIME types).

**Backward-compatible changes** (no version increment required):
- Adding new optional response fields
- Adding new optional query parameters
- Adding new endpoints
- Adding new enum values

**Breaking changes** (require `/api/v2/`):
- Removing or renaming fields
- Changing field types
- Removing endpoints
- Changing the error format
- Changing authentication scheme

**Deprecation lifecycle:** Deprecated endpoints receive a `Sunset` response header with the
removal date, a minimum 6-month notice period, and a migration guide in the changelog.

---

### 1.2 Request and Response Format

All request and response bodies are JSON (`Content-Type: application/json`).

**List response envelope:**

```json
{
  "data": [ ... ],
  "meta": {
    "total": 1423,
    "limit": 25,
    "next_cursor": "eyJpZCI6IjAwM...",
    "prev_cursor": null
  }
}
```

**Single resource response envelope:**

```json
{
  "data": { ... }
}
```

**Field conventions:**
- All timestamps: RFC 3339 UTC — `"2026-04-05T14:30:00Z"`
- All IDs: UUID v4 strings — `"550e8400-e29b-41d4-a716-446655440000"`
- Certificate primary key: `fingerprint_sha256` (hex string, 64 chars)
- Boolean fields: `true` / `false` (never `0` / `1`)
- Nullable fields: explicit `null` (never omitted)
- Private key material: **never present in any response** (constraint C-Sec03)

---

### 1.3 Authentication

Every endpoint (except `GET /api/v1/system/health`) requires authentication. Two methods
are accepted:

**Bearer token (JWT):**
```
Authorization: Bearer <jwt>
```
JWTs are issued at login (`POST /api/v1/auth/login`) or via OIDC callback. Token lifetime
is 8 hours; refresh via `POST /api/v1/auth/refresh`.

**API key:**
```
Authorization: Bearer kk_<prefix>_<secret>
```
API keys are created via `POST /api/v1/api-keys`. They carry an explicit scope list and an
optional expiry. The raw secret is returned exactly once on creation; only the `key_hash`
is stored server-side.

**Request ID (required for tracing):**
```
X-Request-ID: <uuid>
```
If not provided by the client, the server generates one and echoes it in the response header.
Include this ID in all support requests.

---

### 1.4 Pagination

All list endpoints use **cursor-based pagination** (stable under concurrent mutations).

**Query parameters:**

| Parameter | Type | Default | Max | Description |
|-----------|------|---------|-----|-------------|
| `limit` | integer | 25 | 100 | Items per page |
| `cursor` | string | — | — | Opaque cursor from previous response |

**Response fields:**

| Field | Description |
|-------|-------------|
| `meta.total` | Total matching records (approximate for very large sets) |
| `meta.limit` | Effective limit applied |
| `meta.next_cursor` | Cursor for the next page; `null` if on the last page |
| `meta.prev_cursor` | Cursor for the previous page; `null` if on the first page |

Cursors are opaque base64-encoded strings. Do not parse or construct them manually.

---

### 1.5 Filtering and Sorting

**Filtering** — query parameters per field:

```
GET /api/v1/certificates?status=active&grade=A,B&ca_id=<uuid>
```

- Multiple values for the same field: comma-separated (`grade=A,B,C`)
- Date range: `valid_until_before=2026-12-31T00:00:00Z` and `valid_until_after=2026-01-01T00:00:00Z`
- Array-contains: `risk_flags=EXPIRED` (matches any certificate with that flag)
- Text search: `q=<term>` (full-text search on `common_name` and `subject_dn`)

**Sorting:**

```
GET /api/v1/certificates?sort=valid_until&order=asc
```

| Parameter | Values | Default |
|-----------|--------|---------|
| `sort` | field name | `created_at` |
| `order` | `asc` \| `desc` | `desc` |

---

### 1.6 Error Format

All errors follow [RFC 7807 Problem Details](https://www.rfc-editor.org/rfc/rfc7807) with
a Kryptkeeper-specific extension (`code` for machine-readable error lookup):

```json
{
  "type": "https://kryptkeeper.io/errors/validation-failed",
  "title": "Validation Failed",
  "status": 422,
  "detail": "The CSR subject does not satisfy the template's subject_requirements.",
  "instance": "/api/v1/certificates",
  "code": "CERT_CSR_SUBJECT_INVALID",
  "errors": [
    {
      "field": "csr",
      "message": "CommonName must match pattern: ^svc-.+"
    }
  ],
  "trace_id": "01HX7Z..."
}
```

`errors` is an optional array for field-level validation failures. The full error catalog
is in [Section 15](#15-error-catalog).

---

### 1.7 Standard Headers

**Request headers (sent by client):**

| Header | Required | Description |
|--------|----------|-------------|
| `Authorization` | Yes (most endpoints) | `Bearer <token>` |
| `Content-Type` | Yes (POST/PUT/PATCH) | `application/json` |
| `X-Request-ID` | Recommended | UUID for distributed tracing |
| `If-None-Match` | Optional | ETag for conditional GET |
| `If-Match` | Optional | ETag for optimistic concurrency on updates |

**Response headers (sent by server):**

| Header | Description |
|--------|-------------|
| `X-Request-ID` | Echoed from request or server-generated |
| `ETag` | Entity tag for cacheable resources |
| `X-RateLimit-Limit` | Request limit for the current window |
| `X-RateLimit-Remaining` | Requests remaining in the current window |
| `X-RateLimit-Reset` | Unix timestamp when the window resets |
| `Retry-After` | Seconds to wait (only on 429 responses) |
| `Sunset` | ISO 8601 date when a deprecated endpoint will be removed |

---

### 1.8 Rate Limiting

Rate limits apply per API key or authenticated user. Limits vary by endpoint tier:

| Tier | Limit | Window | Applies To |
|------|-------|--------|------------|
| Standard | 1,000 req | 1 minute | General read/write endpoints |
| Scan creation | 10 req | 1 minute | `POST /api/v1/scans` |
| Certificate issuance | 100 req | 1 minute | `POST /api/v1/certificates` |
| System health | Unlimited | — | `GET /api/v1/system/health` |

When the limit is exceeded, the server returns `HTTP 429 Too Many Requests` with a
`Retry-After` header.

---

## 2. RBAC Matrix

Four built-in roles. Custom roles are not supported in V1.

| Role | Description |
|------|-------------|
| `pki-admin` | Full access to all resources including CA management |
| `pki-operator` | Issue, renew, revoke certificates; manage templates; run scans |
| `pki-viewer` | Read-only access to all resources |
| `pki-auditor` | Read-only access to all resources plus audit log export |

Roles are assigned per user (`users.role`) or per API key (`api_keys.scopes`).

### Endpoint Permission Matrix

| Endpoint Group | pki-admin | pki-operator | pki-viewer | pki-auditor |
|----------------|-----------|--------------|------------|-------------|
| **Certificate Authorities** | | | | |
| List / Get CAs | R | R | R | R |
| Create / Update / Delete CA | W | — | — | — |
| Suspend / Activate CA | W | — | — | — |
| **Certificates** | | | | |
| List / Get certificates | R | R | R | R |
| Issue certificate | W | W | — | — |
| Renew certificate | W | W | — | — |
| Revoke certificate | W | W | — | — |
| Download certificate | R | R | R | R |
| Import certificate | W | W | — | — |
| **Templates** | | | | |
| List / Get templates | R | R | R | R |
| Create / Update / Delete template | W | — | — | — |
| Clone template | W | — | — | — |
| **Discovery / Scans** | | | | |
| List / Get scans | R | R | R | R |
| Create / Cancel scan | W | W | — | — |
| **Endpoints** | | | | |
| List / Get endpoints | R | R | R | R |
| **Risk & Compliance** | | | | |
| Risk dashboard / reports | R | R | R | R |
| **Users** | | | | |
| List / Get users | R | — | — | R |
| Create / Update / Delete user | W | — | — | — |
| **API Keys** | | | | |
| List own keys / Create / Revoke own keys | W | W | W | W |
| List all keys | W | — | — | — |
| **Teams** | | | | |
| List / Get teams | R | R | R | R |
| Create / Update / Delete team | W | — | — | — |
| Assign certificate ownership | W | W | — | — |
| **Notifications** | | | | |
| List / Get channels and policies | R | R | R | R |
| Create / Update / Delete | W | W | — | — |
| Test channel | W | W | — | — |
| **Audit Log** | | | | |
| List audit entries | W | — | — | R |
| **System** | | | | |
| Health / Version | R | R | R | R |
| Metrics | W | — | — | — |

Legend: `R` = read allowed, `W` = read + write allowed, `—` = denied (returns 403).

---

## 3. Certificate Authorities

Base path: `/api/v1/cas`

The CA hierarchy consists of root CAs (no parent, typically offline) and issuing CAs
(parent required, online signing key). Certificates for CAs live in the `certificates`
table; the CA record itself carries operational config (key storage, status, CRL/OCSP URLs).

---

### GET /api/v1/cas

List all CAs with hierarchy information.

**Authentication:** Required. Roles: any.

**Query parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `type` | string | Filter by type: `root`, `issuing`, `external` |
| `status` | string | Filter by status: `active`, `suspended`, `revoked`, `expired` |
| `limit` | integer | Page size (default 25, max 100) |
| `cursor` | string | Pagination cursor |

**Response: 200 OK**

```json
{
  "data": [
    {
      "id": "550e8400-e29b-41d4-a716-446655440000",
      "name": "kryptkeeper-root-ca-1",
      "display_name": "Kryptkeeper Root CA 1",
      "type": "root",
      "parent_ca_id": null,
      "status": "active",
      "key_storage_type": "pkcs11",
      "certificate_fingerprint_sha256": "a3f1c9d2...",
      "crl_distribution_points": [
        "http://crl.internal/kk/root-ca-1.crl"
      ],
      "ocsp_service_url": null,
      "children": [
        {
          "id": "7a1e3b20-...",
          "name": "kryptkeeper-issuing-ca-1",
          "type": "issuing",
          "status": "active"
        }
      ],
      "created_at": "2026-01-15T09:00:00Z",
      "updated_at": "2026-01-15T09:00:00Z"
    }
  ],
  "meta": {
    "total": 3,
    "limit": 25,
    "next_cursor": null,
    "prev_cursor": null
  }
}
```

**Status codes:**

| Code | Meaning |
|------|---------|
| 200 | Success |
| 401 | Missing or invalid authentication |
| 403 | Insufficient role |

---

### POST /api/v1/cas

Create a new CA (root or issuing).

**Authentication:** Required. Roles: `pki-admin`.

Creating a root CA initiates an offline key ceremony workflow. The CA record is created
with `status: "pending_ceremony"` until the ceremony is acknowledged via
`POST /api/v1/cas/{id}/activate`.

Creating an issuing CA generates the key (per `key_storage_type`) and issues a certificate
signed by the parent CA. The parent CA must be `active`.

**Request body:**

```json
{
  "name": "kryptkeeper-issuing-ca-2",
  "display_name": "Kryptkeeper Issuing CA 2",
  "type": "issuing",
  "parent_ca_id": "550e8400-e29b-41d4-a716-446655440000",
  "key_storage_type": "software",
  "validity_years": 5,
  "subject": {
    "common_name": "Kryptkeeper Issuing CA 2",
    "organization": "Example Corp",
    "country": "US"
  },
  "crl_distribution_points": [
    "http://crl.internal/kk/issuing-ca-2.crl"
  ],
  "ocsp_service_url": "http://ocsp.internal/kk/issuing-ca-2"
}
```

**Request body fields:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `name` | string | Yes | Machine-readable name (slug format) |
| `display_name` | string | Yes | Human-readable name |
| `type` | string | Yes | `root` or `issuing` |
| `parent_ca_id` | UUID | Conditionally | Required when `type` is `issuing` |
| `key_storage_type` | string | Yes | `software`, `pkcs11`, or `cloud_kms` |
| `pkcs11_library_path` | string | Conditionally | Required when `key_storage_type` is `pkcs11` |
| `pkcs11_token_label` | string | Conditionally | Required when `key_storage_type` is `pkcs11` |
| `validity_years` | integer | Yes | CA certificate validity in years (1–20) |
| `subject` | object | Yes | X.509 subject fields |
| `crl_distribution_points` | array | No | CRL distribution point URLs |
| `ocsp_service_url` | string | No | OCSP responder URL |

**Response: 201 Created**

```json
{
  "data": {
    "id": "7a1e3b20-c4f5-4d1e-9a87-123456789abc",
    "name": "kryptkeeper-issuing-ca-2",
    "display_name": "Kryptkeeper Issuing CA 2",
    "type": "issuing",
    "parent_ca_id": "550e8400-e29b-41d4-a716-446655440000",
    "status": "active",
    "key_storage_type": "software",
    "certificate_fingerprint_sha256": "b4e2d8f1...",
    "crl_distribution_points": [
      "http://crl.internal/kk/issuing-ca-2.crl"
    ],
    "ocsp_service_url": "http://ocsp.internal/kk/issuing-ca-2",
    "created_at": "2026-04-05T10:00:00Z",
    "updated_at": "2026-04-05T10:00:00Z"
  }
}
```

**Response headers:**
```
Location: /api/v1/cas/7a1e3b20-c4f5-4d1e-9a87-123456789abc
```

**Status codes:**

| Code | Meaning |
|------|---------|
| 201 | CA created |
| 400 | Invalid request body |
| 401 | Missing or invalid authentication |
| 403 | Insufficient role |
| 409 | A CA with this name already exists |
| 422 | Validation failed (e.g., parent CA not active, invalid key storage config) |

---

### GET /api/v1/cas/{id}

Get a single CA by ID.

**Authentication:** Required. Roles: any.

**Path parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `id` | UUID | CA identifier |

**Response: 200 OK**

Returns the same CA object as the list endpoint, with an additional `certificate` field
containing the abbreviated certificate record.

```json
{
  "data": {
    "id": "550e8400-e29b-41d4-a716-446655440000",
    "name": "kryptkeeper-root-ca-1",
    "display_name": "Kryptkeeper Root CA 1",
    "type": "root",
    "parent_ca_id": null,
    "status": "active",
    "key_storage_type": "pkcs11",
    "certificate_fingerprint_sha256": "a3f1c9d2...",
    "certificate": {
      "fingerprint_sha256": "a3f1c9d2...",
      "subject_dn": "CN=Kryptkeeper Root CA 1, O=Example Corp, C=US",
      "valid_from": "2025-01-01T00:00:00Z",
      "valid_until": "2035-01-01T00:00:00Z",
      "public_key_algorithm": "RSA",
      "key_size_bits": 4096
    },
    "crl_distribution_points": [
      "http://crl.internal/kk/root-ca-1.crl"
    ],
    "ocsp_service_url": null,
    "children": [
      {
        "id": "7a1e3b20-...",
        "name": "kryptkeeper-issuing-ca-1",
        "type": "issuing",
        "status": "active"
      }
    ],
    "created_at": "2026-01-15T09:00:00Z",
    "updated_at": "2026-01-15T09:00:00Z"
  }
}
```

**Status codes:**

| Code | Meaning |
|------|---------|
| 200 | Success |
| 401 | Missing or invalid authentication |
| 403 | Insufficient role |
| 404 | CA not found |

---

### GET /api/v1/cas/{id}/chain

Get the full certificate chain for a CA (the CA's cert plus all ancestor CA certs up to the
root).

**Authentication:** Required. Roles: any.

**Query parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `format` | string | `json` (default), `pem` |

**Response: 200 OK (format=json)**

```json
{
  "data": {
    "ca_id": "7a1e3b20-...",
    "chain": [
      {
        "depth": 0,
        "fingerprint_sha256": "b4e2d8f1...",
        "subject_dn": "CN=Kryptkeeper Issuing CA 2, O=Example Corp, C=US",
        "issuer_dn": "CN=Kryptkeeper Root CA 1, O=Example Corp, C=US",
        "valid_from": "2026-01-15T09:00:00Z",
        "valid_until": "2031-01-15T09:00:00Z"
      },
      {
        "depth": 1,
        "fingerprint_sha256": "a3f1c9d2...",
        "subject_dn": "CN=Kryptkeeper Root CA 1, O=Example Corp, C=US",
        "issuer_dn": "CN=Kryptkeeper Root CA 1, O=Example Corp, C=US",
        "valid_from": "2025-01-01T00:00:00Z",
        "valid_until": "2035-01-01T00:00:00Z"
      }
    ]
  }
}
```

**Response: 200 OK (format=pem)**

Returns `Content-Type: application/x-pem-file` with the PEM-encoded chain.

**Status codes:**

| Code | Meaning |
|------|---------|
| 200 | Success |
| 404 | CA not found |

---

### PATCH /api/v1/cas/{id}

Update mutable CA fields (display name, CRL/OCSP URLs). Type, key storage, and
cryptographic parameters are immutable after creation.

**Authentication:** Required. Roles: `pki-admin`.

**Request body (all fields optional):**

```json
{
  "display_name": "Kryptkeeper Issuing CA 2 (Updated)",
  "crl_distribution_points": [
    "http://crl.internal/kk/issuing-ca-2.crl",
    "http://crl-backup.internal/kk/issuing-ca-2.crl"
  ],
  "ocsp_service_url": "http://ocsp.internal/kk/issuing-ca-2"
}
```

**Response: 200 OK** — returns the updated CA object.

**Status codes:**

| Code | Meaning |
|------|---------|
| 200 | Updated |
| 400 | Invalid fields |
| 404 | CA not found |
| 412 | ETag mismatch (concurrent modification) |
| 422 | Attempt to modify immutable field |

---

### POST /api/v1/cas/{id}/suspend

Suspend a CA. Suspended CAs cannot issue new certificates. Existing certificates remain
valid; revocation operations still proceed.

**Authentication:** Required. Roles: `pki-admin`.

**Request body:**

```json
{
  "reason": "Scheduled maintenance — key rotation in progress"
}
```

**Response: 200 OK**

```json
{
  "data": {
    "id": "7a1e3b20-...",
    "status": "suspended",
    "updated_at": "2026-04-05T11:00:00Z"
  }
}
```

**Status codes:**

| Code | Meaning |
|------|---------|
| 200 | CA suspended |
| 404 | CA not found |
| 409 | CA is already suspended or in a terminal state |

---

### POST /api/v1/cas/{id}/activate

Reactivate a suspended CA (or complete a root CA offline ceremony, transitioning from
`pending_ceremony` to `active`).

**Authentication:** Required. Roles: `pki-admin`.

**Request body:**

```json
{
  "ceremony_complete": true
}
```

`ceremony_complete` is required only when transitioning from `pending_ceremony`. It
acknowledges that the offline key ceremony has been performed and the root CA certificate
has been imported.

**Response: 200 OK** — returns the updated CA object with `status: "active"`.

**Status codes:**

| Code | Meaning |
|------|---------|
| 200 | CA activated |
| 404 | CA not found |
| 409 | CA is not in a suspendable state |
| 422 | `ceremony_complete` required but not provided |

---

### DELETE /api/v1/cas/{id}

Delete a CA record. Only permitted when the CA has `status: "revoked"` or `"expired"` and
has zero active issued certificates.

**Authentication:** Required. Roles: `pki-admin`.

**Response: 204 No Content**

**Status codes:**

| Code | Meaning |
|------|---------|
| 204 | Deleted |
| 404 | CA not found |
| 409 | CA has active certificates and cannot be deleted |
| 422 | CA must be in revoked or expired status before deletion |

---

## 4. Certificates

Base path: `/api/v1/certificates`

The certificate resource is identified by `fingerprint_sha256` (SHA-256 of DER-encoded
certificate) — not a UUID. This is the deduplication key across all discovery sources.

---

### GET /api/v1/certificates

List certificates with filtering, sorting, and pagination.

**Authentication:** Required. Roles: any.

**Query parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `q` | string | Full-text search on `common_name` and `subject_dn` |
| `ca_id` | UUID | Filter by issuing CA |
| `template_id` | UUID | Filter by certificate template |
| `team_id` | UUID | Filter by owning team |
| `status` | string | `active`, `renewed`, `expired`, `revoked` |
| `grade` | string | One or more grades, comma-separated: `A,B,C,D,F` |
| `risk_flags` | string | Filter by risk flag (matches any cert with this flag) |
| `risk_score_min` | integer | Minimum risk score (0–100) |
| `risk_score_max` | integer | Maximum risk score (0–100) |
| `valid_until_before` | RFC 3339 | Certs expiring before this date |
| `valid_until_after` | RFC 3339 | Certs with validity starting after this date |
| `source` | string | `api`, `acme`, `est`, `scep`, `discovery_network`, etc. |
| `pqc_vulnerable` | boolean | Filter by PQC vulnerability |
| `sort` | string | `valid_until`, `risk_score`, `created_at`, `common_name` |
| `order` | string | `asc` or `desc` (default: `desc`) |
| `limit` | integer | Page size (default 25, max 100) |
| `cursor` | string | Pagination cursor |

**Response: 200 OK**

```json
{
  "data": [
    {
      "fingerprint_sha256": "a1b2c3d4e5f6...",
      "serial_number": "02:a1:b2:c3:d4:e5",
      "common_name": "api.example.com",
      "subject_dn": "CN=api.example.com, O=Example Corp, C=US",
      "subject_alt_names": ["api.example.com", "api-staging.example.com"],
      "issuer_cn": "Kryptkeeper Issuing CA 1",
      "issuer_dn": "CN=Kryptkeeper Issuing CA 1, O=Example Corp, C=US",
      "ca_id": "7a1e3b20-...",
      "template_id": "9c3d5e70-...",
      "team_id": "2b4f6a80-...",
      "valid_from": "2026-01-01T00:00:00Z",
      "valid_until": "2026-04-11T00:00:00Z",
      "public_key_algorithm": "ECDSA",
      "key_size_bits": 256,
      "signature_algorithm": "ecdsa-with-SHA256",
      "extended_key_usage": ["TLS Web Server Authentication"],
      "key_usage": ["Digital Signature"],
      "chain_complete": true,
      "chain_trusted": true,
      "pqc_vulnerable": true,
      "risk_score": 35,
      "risk_flags": ["EXPIRING_7_DAYS"],
      "grade": "C",
      "renewal_method": "acme",
      "renewal_status": "active",
      "source": "acme",
      "created_at": "2026-01-01T00:00:00Z",
      "updated_at": "2026-04-03T12:00:00Z"
    }
  ],
  "meta": {
    "total": 1423,
    "limit": 25,
    "next_cursor": "eyJmcCI6ImExYjJjM...",
    "prev_cursor": null
  }
}
```

---

### POST /api/v1/certificates

Issue a new certificate from a CSR and template.

**Authentication:** Required. Roles: `pki-admin`, `pki-operator` (subject to template
`enrollment_permissions`).

The caller must have permission to enroll from the specified template. If the template's
`enrollment_permissions.enroll` does not include the caller's role, `HTTP 403` is returned.

**Request body:**

```json
{
  "ca_id": "7a1e3b20-...",
  "template_id": "9c3d5e70-...",
  "csr_pem": "-----BEGIN CERTIFICATE REQUEST-----\nMIIC...\n-----END CERTIFICATE REQUEST-----\n",
  "team_id": "2b4f6a80-...",
  "metadata": {
    "requested_by": "Jordan Smith",
    "ticket": "OPS-1234"
  }
}
```

**Request body fields:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `ca_id` | UUID | Yes | Issuing CA to sign with |
| `template_id` | UUID | Yes | Template defining policy constraints |
| `csr_pem` | string | Yes | PEM-encoded PKCS#10 CSR |
| `team_id` | UUID | No | Assign ownership to this team |
| `metadata` | object | No | Arbitrary key-value metadata (audit only) |

**Response: 201 Created**

```json
{
  "data": {
    "fingerprint_sha256": "a1b2c3d4e5f6...",
    "serial_number": "02:a1:b2:c3:d4:e5",
    "common_name": "api.example.com",
    "subject_dn": "CN=api.example.com, O=Example Corp, C=US",
    "subject_alt_names": ["api.example.com"],
    "issuer_cn": "Kryptkeeper Issuing CA 1",
    "ca_id": "7a1e3b20-...",
    "template_id": "9c3d5e70-...",
    "team_id": "2b4f6a80-...",
    "valid_from": "2026-04-05T10:00:00Z",
    "valid_until": "2026-07-13T10:00:00Z",
    "public_key_algorithm": "ECDSA",
    "key_size_bits": 256,
    "signature_algorithm": "ecdsa-with-SHA256",
    "extended_key_usage": ["TLS Web Server Authentication"],
    "chain_complete": true,
    "chain_trusted": true,
    "pqc_vulnerable": true,
    "risk_score": 5,
    "risk_flags": [],
    "grade": "A",
    "renewal_method": "api",
    "renewal_status": "active",
    "source": "api",
    "created_at": "2026-04-05T10:00:00Z",
    "updated_at": "2026-04-05T10:00:00Z"
  }
}
```

**Response headers:**
```
Location: /api/v1/certificates/a1b2c3d4e5f6...
```

**Status codes:**

| Code | Meaning |
|------|---------|
| 201 | Certificate issued |
| 400 | Malformed CSR |
| 401 | Missing or invalid authentication |
| 403 | Caller lacks enrollment permission for this template |
| 404 | CA or template not found |
| 409 | Certificate with this fingerprint already exists |
| 422 | CSR fails template policy (key size, algorithm, subject, SAN) |

---

### GET /api/v1/certificates/{fingerprint}

Get a single certificate by its `fingerprint_sha256`.

**Authentication:** Required. Roles: any.

**Path parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `fingerprint` | string | 64-character hex SHA-256 fingerprint |

**Response: 200 OK**

Returns the full certificate object as in the list endpoint, plus:

```json
{
  "data": {
    "fingerprint_sha256": "a1b2c3d4e5f6...",
    "...": "...all standard fields...",
    "predecessor_fingerprint": null,
    "successor_fingerprint": null,
    "revoked_at": null,
    "revocation_reason": null,
    "endpoints": [
      {
        "id": "3c5e7a90-...",
        "hostname": "api.example.com",
        "ip_address": "10.0.1.50",
        "port": 443,
        "protocol": "TLS",
        "first_seen": "2026-01-01T00:00:00Z",
        "last_seen": "2026-04-04T06:00:00Z",
        "currently_active": true
      }
    ]
  }
}
```

**ETags:** This endpoint returns an `ETag` header. Conditional requests with
`If-None-Match` will return `304 Not Modified` when the certificate has not changed.

**Status codes:**

| Code | Meaning |
|------|---------|
| 200 | Success |
| 304 | Not modified (conditional GET) |
| 404 | Certificate not found |

---

### GET /api/v1/certificates/{fingerprint}/chain

Get the renewal chain: all predecessor and successor certificates for this fingerprint.

**Authentication:** Required. Roles: any.

**Response: 200 OK**

```json
{
  "data": {
    "current_fingerprint": "a1b2c3d4e5f6...",
    "chain": [
      {
        "fingerprint_sha256": "0000aabb...",
        "common_name": "api.example.com",
        "valid_from": "2025-07-01T00:00:00Z",
        "valid_until": "2025-10-01T00:00:00Z",
        "renewal_status": "renewed",
        "position": "predecessor"
      },
      {
        "fingerprint_sha256": "a1b2c3d4e5f6...",
        "common_name": "api.example.com",
        "valid_from": "2025-10-01T00:00:00Z",
        "valid_until": "2026-01-01T00:00:00Z",
        "renewal_status": "renewed",
        "position": "current"
      },
      {
        "fingerprint_sha256": "ffee1234...",
        "common_name": "api.example.com",
        "valid_from": "2026-01-01T00:00:00Z",
        "valid_until": "2026-04-11T00:00:00Z",
        "renewal_status": "active",
        "position": "successor"
      }
    ]
  }
}
```

---

### POST /api/v1/certificates/{fingerprint}/renew

Renew a certificate. Creates a new certificate from the same template. The caller provides
a new CSR; the system issues a new certificate and links it as the successor.

**Authentication:** Required. Roles: `pki-admin`, `pki-operator`.

**Request body:**

```json
{
  "csr_pem": "-----BEGIN CERTIFICATE REQUEST-----\nMIIC...\n-----END CERTIFICATE REQUEST-----\n"
}
```

**Response: 201 Created**

Returns the new certificate object. The original certificate's `successor_fingerprint` is
updated to point to the new certificate.

```json
{
  "data": {
    "fingerprint_sha256": "ffee1234...",
    "predecessor_fingerprint": "a1b2c3d4e5f6...",
    "common_name": "api.example.com",
    "valid_from": "2026-04-05T10:00:00Z",
    "valid_until": "2026-07-13T10:00:00Z",
    "...": "...all standard fields..."
  }
}
```

**Response headers:**
```
Location: /api/v1/certificates/ffee1234...
```

**Status codes:**

| Code | Meaning |
|------|---------|
| 201 | Renewed certificate issued |
| 400 | Malformed CSR |
| 404 | Original certificate not found |
| 409 | Certificate already has an active successor |
| 422 | CSR fails template policy |

---

### POST /api/v1/certificates/{fingerprint}/revoke

Revoke a certificate.

**Authentication:** Required. Roles: `pki-admin`, `pki-operator`.

**Request body:**

```json
{
  "reason_code": 1,
  "reason_text": "Key was compromised — see incident INC-8821"
}
```

**Reason codes** follow RFC 5280 §5.3.1:

| Code | Name |
|------|------|
| 0 | unspecified |
| 1 | keyCompromise |
| 2 | cACompromise |
| 3 | affiliationChanged |
| 4 | superseded |
| 5 | cessationOfOperation |
| 6 | certificateHold |
| 9 | privilegeWithdrawn |

**Response: 200 OK**

```json
{
  "data": {
    "fingerprint_sha256": "a1b2c3d4e5f6...",
    "renewal_status": "revoked",
    "revoked_at": "2026-04-05T10:30:00Z",
    "revocation_reason": 1
  }
}
```

**Status codes:**

| Code | Meaning |
|------|---------|
| 200 | Certificate revoked |
| 404 | Certificate not found |
| 409 | Certificate is already revoked or expired |

---

### GET /api/v1/certificates/{fingerprint}/download

Download the certificate in PEM, DER, or PKCS#12 format.

**Authentication:** Required. Roles: any.

**Query parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `format` | string | `pem` (default), `der`, `pkcs12` |
| `include_chain` | boolean | Include full CA chain (default `false`) |

**Response: 200 OK**

Returns raw certificate bytes with the appropriate `Content-Type` and
`Content-Disposition` headers:

| Format | Content-Type | Filename |
|--------|-------------|----------|
| `pem` | `application/x-pem-file` | `<common_name>.pem` |
| `der` | `application/pkix-cert` | `<common_name>.der` |
| `pkcs12` | `application/x-pkcs12` | `<common_name>.p12` |

Note: PKCS#12 download does **not** include the private key (constraint C-Sec03). The
PKCS#12 contains the certificate and chain only.

**Status codes:**

| Code | Meaning |
|------|---------|
| 200 | File download |
| 400 | Invalid format parameter |
| 404 | Certificate not found |

---

### POST /api/v1/certificates/import

Import an externally issued certificate into the inventory.

**Authentication:** Required. Roles: `pki-admin`, `pki-operator`.

**Request body:**

```json
{
  "certificate_pem": "-----BEGIN CERTIFICATE-----\nMIID...\n-----END CERTIFICATE-----\n",
  "team_id": "2b4f6a80-...",
  "notes": "Imported from AWS ACM — pending migration"
}
```

**Request body fields:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `certificate_pem` | string | Yes | PEM-encoded certificate |
| `chain_pem` | string | No | PEM-encoded intermediate chain |
| `team_id` | UUID | No | Assign to this team |
| `notes` | string | No | Free-text import notes (audit only) |

**Response: 201 Created** — returns the certificate object with `source: "import"`.

If the certificate is already in the inventory (same `fingerprint_sha256`), returns
`HTTP 409 Conflict` with the existing resource in the error body.

---

## 5. Certificate Templates

Base path: `/api/v1/templates`

Templates define the policy envelope for certificate issuance: allowed algorithms, key
sizes, EKU, validity period, and who may enroll.

---

### GET /api/v1/templates

List all templates.

**Authentication:** Required. Roles: any.

**Query parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `active` | boolean | Filter by active status |
| `q` | string | Search by name or OID |
| `limit` | integer | Page size |
| `cursor` | string | Pagination cursor |

**Response: 200 OK**

```json
{
  "data": [
    {
      "id": "9c3d5e70-...",
      "name": "tls-server-90d",
      "display_name": "TLS Server Certificate (90 days)",
      "oid": "1.3.6.1.4.1.99999.1.1",
      "key_usage": ["digitalSignature"],
      "extended_key_usage": ["serverAuth"],
      "allowed_algorithms": ["ECDSA", "RSA"],
      "min_key_size": 2048,
      "validity_period": "P90D",
      "renewal_overlap": "P14D",
      "auto_enroll": true,
      "active": true,
      "revision": 3,
      "schema_version": 1,
      "issued_count": 412,
      "created_at": "2026-01-10T08:00:00Z",
      "updated_at": "2026-03-01T14:00:00Z"
    }
  ],
  "meta": {
    "total": 8,
    "limit": 25,
    "next_cursor": null,
    "prev_cursor": null
  }
}
```

---

### POST /api/v1/templates

Create a new certificate template.

**Authentication:** Required. Roles: `pki-admin`.

**Request body:**

```json
{
  "name": "code-signing-1y",
  "display_name": "Code Signing Certificate (1 year)",
  "oid": "1.3.6.1.4.1.99999.1.4",
  "key_usage": ["digitalSignature"],
  "extended_key_usage": ["codeSigning"],
  "allowed_algorithms": ["RSA"],
  "min_key_size": 3072,
  "validity_period": "P1Y",
  "renewal_overlap": "P30D",
  "subject_requirements": {
    "require_organization": true,
    "common_name_pattern": "^[a-zA-Z0-9._-]+$"
  },
  "enrollment_permissions": {
    "enroll": ["pki-admin", "pki-operator"],
    "auto_enroll": ["pki-admin"]
  },
  "issuance_requirements": {
    "require_approval": false
  },
  "auto_enroll": false,
  "active": true
}
```

**Request body fields:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `name` | string | Yes | Machine-readable name (unique) |
| `display_name` | string | Yes | Human-readable name |
| `oid` | string | No | Optional OID for ADCS compatibility |
| `key_usage` | array | Yes | RFC 5280 key usage values |
| `extended_key_usage` | array | Yes | EKU OID names (`serverAuth`, `clientAuth`, etc.) |
| `allowed_algorithms` | array | Yes | `RSA`, `ECDSA`, `Ed25519`, `ML-DSA` |
| `min_key_size` | integer | No | Minimum key size in bits (RSA/ECDSA only) |
| `validity_period` | string | Yes | ISO 8601 duration (e.g., `P90D`, `P1Y`) |
| `renewal_overlap` | string | No | How early renewal is allowed (ISO 8601 duration) |
| `subject_requirements` | object | No | Subject field validation rules |
| `enrollment_permissions` | object | No | Roles permitted to enroll |
| `issuance_requirements` | object | No | Additional issuance constraints |
| `auto_enroll` | boolean | No | Allow automated renewal (default `false`) |
| `active` | boolean | No | Whether template is accepting enrollments (default `true`) |

**Response: 201 Created** — returns the full template object.

**Response headers:**
```
Location: /api/v1/templates/9c3d5e70-...
```

**Status codes:**

| Code | Meaning |
|------|---------|
| 201 | Template created |
| 400 | Invalid request body |
| 409 | Template with this name or OID already exists |
| 422 | Invalid EKU, key usage, or algorithm combination |

---

### GET /api/v1/templates/{id}

Get a single template by ID.

**Authentication:** Required. Roles: any.

**Response: 200 OK** — returns the full template object including all policy fields.

---

### PUT /api/v1/templates/{id}

Replace a template. Increments `revision`. Existing certificates issued from this template
are not affected.

**Authentication:** Required. Roles: `pki-admin`.

**Request body:** Same schema as `POST /api/v1/templates`.

**Headers required:**
```
If-Match: "<etag>"
```

The `If-Match` header is required to prevent lost updates. Fetch the current ETag from
`GET /api/v1/templates/{id}` and include it.

**Response: 200 OK** — returns the updated template with incremented `revision`.

**Status codes:**

| Code | Meaning |
|------|---------|
| 200 | Updated |
| 404 | Template not found |
| 409 | Name or OID conflict |
| 412 | ETag mismatch |
| 422 | Validation failed |

---

### PATCH /api/v1/templates/{id}

Partially update a template. Only provided fields are updated. Increments `revision`.

**Authentication:** Required. Roles: `pki-admin`.

**Request body (example — deactivate a template):**

```json
{
  "active": false
}
```

**Response: 200 OK** — returns the updated template.

---

### DELETE /api/v1/templates/{id}

Delete a template. Only allowed when no certificates have been issued from it, or all
issued certificates are in `revoked` or `expired` status.

**Authentication:** Required. Roles: `pki-admin`.

**Response: 204 No Content**

**Status codes:**

| Code | Meaning |
|------|---------|
| 204 | Deleted |
| 404 | Template not found |
| 409 | Template has active issued certificates |

---

### POST /api/v1/templates/{id}/clone

Clone a template into a new template with a new name. The clone is created with
`active: false` to allow review before use.

**Authentication:** Required. Roles: `pki-admin`.

**Request body:**

```json
{
  "name": "tls-server-47d",
  "display_name": "TLS Server Certificate (47 days)"
}
```

**Response: 201 Created** — returns the new template with `revision: 1`.

---

## 6. Discovery and Scanning

Base path: `/api/v1/scans`

Scan jobs discover certificates across the estate. Types: `network` (masscan + TLS),
`ssh` (agentless Linux), `winrm` (agentless Windows), `cloud` (AWS/Azure/GCP/K8s),
`ct_log` (Certificate Transparency monitoring).

**Security requirement:** All scan jobs require an `authorization_acknowledged` flag
(FR-050). This is a machine-readable acknowledgment that the operator has obtained
permission to scan the target range.

---

### GET /api/v1/scans

List scan jobs.

**Authentication:** Required. Roles: any.

**Query parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `type` | string | Filter by type: `network`, `ssh`, `winrm`, `cloud`, `ct_log` |
| `status` | string | `pending`, `running`, `completed`, `failed`, `cancelled` |
| `created_after` | RFC 3339 | Filter by creation time |
| `limit` | integer | Page size |
| `cursor` | string | Pagination cursor |

**Response: 200 OK**

```json
{
  "data": [
    {
      "id": "1a2b3c4d-...",
      "type": "network",
      "status": "completed",
      "connector": "masscan",
      "scope": {
        "targets": ["10.0.0.0/24", "192.168.1.0/24"],
        "ports": [443, 8443, 8080]
      },
      "results_summary": {
        "hosts_scanned": 512,
        "certificates_found": 47,
        "certificates_new": 12,
        "certificates_updated": 35,
        "errors": 2
      },
      "created_by": "550e8400-...",
      "started_at": "2026-04-05T08:00:00Z",
      "completed_at": "2026-04-05T08:23:41Z",
      "created_at": "2026-04-05T07:59:50Z"
    }
  ],
  "meta": {
    "total": 84,
    "limit": 25,
    "next_cursor": "eyJpZCI6Ij...",
    "prev_cursor": null
  }
}
```

---

### POST /api/v1/scans

Create and enqueue a scan job.

**Authentication:** Required. Roles: `pki-admin`, `pki-operator`.

**Request body:**

```json
{
  "type": "network",
  "authorization_acknowledged": true,
  "scope": {
    "targets": ["10.0.0.0/24"],
    "ports": [443, 8443, 9443]
  },
  "options": {
    "rate_pps": 5000,
    "connect_timeout_ms": 3000
  }
}
```

**Request body fields:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `type` | string | Yes | `network`, `ssh`, `winrm`, `cloud`, `ct_log` |
| `authorization_acknowledged` | boolean | Yes | Must be `true`. Acknowledges operator has permission to scan targets. |
| `scope` | object | Yes | Type-specific scope definition (see below) |
| `options` | object | No | Type-specific tuning options |

**Scope by scan type:**

| Type | Scope fields |
|------|-------------|
| `network` | `targets` (CIDR list), `ports` (integer list) |
| `ssh` | `hosts` (hostname/IP list), `credential_id` (stored credential reference) |
| `winrm` | `hosts` (hostname/IP list), `credential_id` |
| `cloud` | `connector` (`aws_acm`, `azure_keyvault`, `gcp_cm`, `kubernetes`), `regions` (optional) |
| `ct_log` | `domain_patterns` (list of domains/wildcards to monitor) |

**Validation:** If `authorization_acknowledged` is `false` or absent, the request is
rejected with `HTTP 400` and error code `SCAN_AUTH_NOT_ACKNOWLEDGED`. The scan is
**never** initiated (FR-050).

**Response: 202 Accepted**

```json
{
  "data": {
    "id": "1a2b3c4d-...",
    "type": "network",
    "status": "pending",
    "scope": {
      "targets": ["10.0.0.0/24"],
      "ports": [443, 8443, 9443]
    },
    "created_by": "550e8400-...",
    "created_at": "2026-04-05T10:00:00Z",
    "started_at": null,
    "completed_at": null
  }
}
```

**Response headers:**
```
Location: /api/v1/scans/1a2b3c4d-...
```

**Status codes:**

| Code | Meaning |
|------|---------|
| 202 | Scan job accepted and queued |
| 400 | Missing `authorization_acknowledged: true` |
| 400 | Invalid scope for the given type |
| 401 | Missing or invalid authentication |
| 403 | Insufficient role |
| 429 | Scan creation rate limit exceeded |

---

### GET /api/v1/scans/{id}

Get scan job status and results summary.

**Authentication:** Required. Roles: any.

**Response: 200 OK** — returns the full scan job object as in the list endpoint.

---

### GET /api/v1/scans/{id}/results

Get the detailed results for a completed scan job (paginated list of discovered targets).

**Authentication:** Required. Roles: any.

**Query parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `result_type` | string | Filter by result type: `certificate`, `endpoint`, `error` |
| `limit` | integer | Page size (default 25, max 100) |
| `cursor` | string | Pagination cursor |

**Response: 200 OK**

```json
{
  "data": [
    {
      "id": "5d6e7f80-...",
      "scan_job_id": "1a2b3c4d-...",
      "target": "10.0.0.42:443",
      "result_type": "certificate",
      "data": {
        "fingerprint_sha256": "a1b2c3d4...",
        "common_name": "internal.example.com",
        "action": "new"
      },
      "discovered_at": "2026-04-05T08:05:22Z"
    }
  ],
  "meta": {
    "total": 47,
    "limit": 25,
    "next_cursor": "eyJpZCI6Ij...",
    "prev_cursor": null
  }
}
```

---

### POST /api/v1/scans/{id}/cancel

Cancel a running or pending scan job.

**Authentication:** Required. Roles: `pki-admin`, `pki-operator`.

**Request body:** Empty (`{}`)

**Response: 200 OK**

```json
{
  "data": {
    "id": "1a2b3c4d-...",
    "status": "cancelled",
    "updated_at": "2026-04-05T10:05:00Z"
  }
}
```

**Status codes:**

| Code | Meaning |
|------|---------|
| 200 | Cancelled |
| 404 | Scan job not found |
| 409 | Scan is already completed, failed, or cancelled |

---

## 7. Endpoints

Base path: `/api/v1/endpoints`

Endpoints represent network locations (IP:port or hostname:port) where a certificate was
observed. They are populated by scan jobs and the discovery agent.

---

### GET /api/v1/endpoints

List discovered endpoints.

**Authentication:** Required. Roles: any.

**Query parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `hostname` | string | Filter by hostname (exact or `*.example.com` wildcard) |
| `ip_address` | string | Filter by IP address |
| `port` | integer | Filter by port |
| `certificate_fingerprint` | string | Filter by currently-active certificate fingerprint |
| `risk_score_min` | integer | Filter endpoints whose current cert has risk score >= N |
| `grade` | string | Filter endpoints whose current cert has this grade |
| `protocol` | string | `TLS`, `HTTPS`, etc. |
| `sort` | string | `last_scanned`, `hostname`, `risk_score` |
| `order` | string | `asc` or `desc` |
| `limit` | integer | Page size |
| `cursor` | string | Pagination cursor |

**Response: 200 OK**

```json
{
  "data": [
    {
      "id": "3c5e7a90-...",
      "hostname": "api.example.com",
      "ip_address": "10.0.1.50",
      "port": 443,
      "protocol": "TLS",
      "tls_versions": ["TLSv1.2", "TLSv1.3"],
      "cipher_suites": [
        "TLS_AES_256_GCM_SHA384",
        "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"
      ],
      "sni_name": "api.example.com",
      "is_default_cert": true,
      "current_certificate": {
        "fingerprint_sha256": "a1b2c3d4...",
        "common_name": "api.example.com",
        "valid_until": "2026-04-11T00:00:00Z",
        "risk_score": 35,
        "grade": "C"
      },
      "last_scan_job_id": "1a2b3c4d-...",
      "last_scanned": "2026-04-04T06:00:00Z",
      "created_at": "2026-01-01T00:00:00Z",
      "updated_at": "2026-04-04T06:00:00Z"
    }
  ],
  "meta": {
    "total": 892,
    "limit": 25,
    "next_cursor": "eyJpZCI6Ij...",
    "prev_cursor": null
  }
}
```

---

### GET /api/v1/endpoints/{id}

Get a single endpoint with full TLS configuration details and certificate history.

**Authentication:** Required. Roles: any.

**Response: 200 OK**

Returns the full endpoint object, plus:

```json
{
  "data": {
    "id": "3c5e7a90-...",
    "...": "...all standard fields...",
    "certificate_history": [
      {
        "fingerprint_sha256": "0000aabb...",
        "common_name": "api.example.com",
        "first_seen": "2025-07-01T00:00:00Z",
        "last_seen": "2026-01-01T00:00:00Z",
        "currently_active": false
      },
      {
        "fingerprint_sha256": "a1b2c3d4...",
        "common_name": "api.example.com",
        "first_seen": "2026-01-01T00:00:00Z",
        "last_seen": "2026-04-04T06:00:00Z",
        "currently_active": true
      }
    ]
  }
}
```

---

## 8. Risk and Compliance

Base path: `/api/v1/risk`

Read-only reporting endpoints. All are derived views over the `certificates` table;
no data is mutated by these endpoints.

---

### GET /api/v1/risk/summary

Risk dashboard summary — grade distribution and flag counts across the entire inventory.

**Authentication:** Required. Roles: any.

**Response: 200 OK**

```json
{
  "data": {
    "generated_at": "2026-04-05T10:00:00Z",
    "total_certificates": 14230,
    "grade_distribution": {
      "A": 9841,
      "B": 2104,
      "C": 1102,
      "D": 743,
      "F": 440
    },
    "flag_counts": {
      "EXPIRED": 312,
      "EXPIRING_7_DAYS": 28,
      "EXPIRING_30_DAYS": 214,
      "EXPIRING_90_DAYS": 802,
      "WEAK_KEY": 95,
      "SELF_SIGNED": 441,
      "SHA1_SIGNATURE": 67,
      "UNTRUSTED_ROOT": 183,
      "TLS_OLD_PROTOCOL": 52,
      "NULL_EXPORT_CIPHER": 8,
      "CHAIN_INCOMPLETE": 219,
      "WILDCARD": 1042,
      "PQC_VULNERABLE": 11389
    },
    "expiring_soon": {
      "in_7_days": 28,
      "in_30_days": 242,
      "in_90_days": 1044
    }
  }
}
```

**ETags:** This response is cached. Use `If-None-Match` for efficient polling.

---

### GET /api/v1/risk/certificates

List certificates filtered by risk, with default sort by `risk_score` descending.
This is a focused view of `GET /api/v1/certificates` with risk-optimized defaults.

**Authentication:** Required. Roles: any.

**Query parameters:** Same as `GET /api/v1/certificates` plus:

| Parameter | Type | Description |
|-----------|------|-------------|
| `grade` | string | Grade filter, e.g., `D,F` |
| `flags` | string | Comma-separated risk flags |
| `team_id` | UUID | Scope to a team's certificates |

**Response: 200 OK** — same envelope as `GET /api/v1/certificates`.

---

### GET /api/v1/risk/expiring

Certificates expiring within a given number of days.

**Authentication:** Required. Roles: any.

**Query parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `days` | integer | 30 | Certificates expiring within this many days |
| `team_id` | UUID | — | Scope to a team's certificates |
| `limit` | integer | 25 | Page size |
| `cursor` | string | — | Pagination cursor |

**Response: 200 OK**

```json
{
  "data": [
    {
      "fingerprint_sha256": "a1b2c3d4...",
      "common_name": "api.example.com",
      "valid_until": "2026-04-11T00:00:00Z",
      "days_remaining": 6,
      "risk_score": 35,
      "grade": "C",
      "team_id": "2b4f6a80-...",
      "renewal_method": "acme",
      "renewal_status": "active"
    }
  ],
  "meta": {
    "total": 242,
    "limit": 25,
    "next_cursor": "eyJmcCI6Ij...",
    "prev_cursor": null
  }
}
```

---

### GET /api/v1/risk/violations

List certificates with active policy violations (any risk flag set).

**Authentication:** Required. Roles: any.

**Query parameters:** Same filtering as `GET /api/v1/risk/certificates`.

**Response: 200 OK** — same envelope as certificate list, scoped to certs with
`risk_flags != '{}'`.

---

## 9. Users and Auth

Base path: `/api/v1/users`, `/api/v1/auth`

---

### POST /api/v1/auth/login

Authenticate with local credentials and receive a JWT.

**Authentication:** None required.

**Request body:**

```json
{
  "email": "alex@example.com",
  "password": "..."
}
```

**Response: 200 OK**

```json
{
  "data": {
    "token": "eyJhbGci...",
    "expires_at": "2026-04-05T22:00:00Z",
    "user": {
      "id": "550e8400-...",
      "email": "alex@example.com",
      "display_name": "Alex Kim",
      "role": "pki-admin"
    }
  }
}
```

**Status codes:**

| Code | Meaning |
|------|---------|
| 200 | Authenticated |
| 400 | Missing fields |
| 401 | Invalid credentials |
| 403 | Account inactive |
| 429 | Too many failed attempts |

---

### POST /api/v1/auth/refresh

Refresh a JWT before it expires.

**Authentication:** Required (valid JWT in `Authorization` header).

**Request body:** Empty (`{}`)

**Response: 200 OK** — returns a new `token` and `expires_at`.

---

### POST /api/v1/auth/logout

Invalidate the current JWT.

**Authentication:** Required.

**Request body:** Empty (`{}`)

**Response: 204 No Content**

---

### GET /api/v1/users

List users.

**Authentication:** Required. Roles: `pki-admin`, `pki-auditor`.

**Query parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `role` | string | Filter by role |
| `active` | boolean | Filter by active status |
| `q` | string | Search by email or display name |
| `limit` | integer | Page size |
| `cursor` | string | Pagination cursor |

**Response: 200 OK**

```json
{
  "data": [
    {
      "id": "550e8400-...",
      "email": "alex@example.com",
      "display_name": "Alex Kim",
      "role": "pki-admin",
      "active": true,
      "oidc_subject": null,
      "oidc_issuer": null,
      "last_login_at": "2026-04-05T08:00:00Z",
      "created_at": "2026-01-01T00:00:00Z",
      "updated_at": "2026-04-05T08:00:00Z"
    }
  ],
  "meta": {
    "total": 14,
    "limit": 25,
    "next_cursor": null,
    "prev_cursor": null
  }
}
```

---

### POST /api/v1/users

Create a local user account.

**Authentication:** Required. Roles: `pki-admin`.

**Request body:**

```json
{
  "email": "jordan@example.com",
  "display_name": "Jordan Smith",
  "role": "pki-operator",
  "password": "..."
}
```

**Request body fields:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `email` | string | Yes | Unique email address |
| `display_name` | string | Yes | Human-readable name |
| `role` | string | Yes | `pki-admin`, `pki-operator`, `pki-viewer`, `pki-auditor` |
| `password` | string | Conditionally | Required when not using OIDC |

**Response: 201 Created** — returns the user object (no password in response).

**Response headers:**
```
Location: /api/v1/users/7a1e3b20-...
```

---

### GET /api/v1/users/{id}

Get a single user.

**Authentication:** Required. Roles: `pki-admin`, `pki-auditor`. Users may also fetch
their own record.

**Response: 200 OK** — returns the user object.

---

### PATCH /api/v1/users/{id}

Update a user's mutable fields.

**Authentication:** Required. Roles: `pki-admin` (for all fields). Users may update
their own `display_name` and `password`.

**Request body (all fields optional):**

```json
{
  "display_name": "Jordan Smith",
  "role": "pki-viewer",
  "active": false
}
```

**Response: 200 OK** — returns the updated user object.

---

### DELETE /api/v1/users/{id}

Deactivate a user account. Sets `active: false`; does not delete the record (preserves
audit history).

**Authentication:** Required. Roles: `pki-admin`.

**Response: 200 OK**

```json
{
  "data": {
    "id": "7a1e3b20-...",
    "active": false,
    "updated_at": "2026-04-05T10:00:00Z"
  }
}
```

---

## 10. API Keys

Base path: `/api/v1/api-keys`

API keys are used for service-to-service authentication. The raw secret is returned
**only once** at creation time. Only the `key_hash` (bcrypt) is stored.

---

### GET /api/v1/api-keys

List API keys. `pki-admin` sees all keys; other roles see only their own keys.

**Authentication:** Required. Roles: any.

**Query parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `user_id` | UUID | Filter by owner (`pki-admin` only) |
| `limit` | integer | Page size |
| `cursor` | string | Pagination cursor |

**Response: 200 OK**

```json
{
  "data": [
    {
      "id": "4d6f8b10-...",
      "name": "ci-pipeline-prod",
      "key_prefix": "kk_prod_",
      "scopes": ["certificates:read", "certificates:write"],
      "expires_at": "2027-04-05T00:00:00Z",
      "last_used_at": "2026-04-04T23:59:00Z",
      "created_at": "2026-01-01T00:00:00Z",
      "user_id": "550e8400-..."
    }
  ],
  "meta": {
    "total": 3,
    "limit": 25,
    "next_cursor": null,
    "prev_cursor": null
  }
}
```

---

### POST /api/v1/api-keys

Create a new API key.

**Authentication:** Required. Roles: any (keys are created for the authenticated user).

**Request body:**

```json
{
  "name": "ci-pipeline-prod",
  "scopes": ["certificates:read", "certificates:write"],
  "expires_at": "2027-04-05T00:00:00Z"
}
```

**Supported scopes:**

| Scope | Description |
|-------|-------------|
| `certificates:read` | Read certificates and related resources |
| `certificates:write` | Issue, renew, revoke certificates |
| `cas:read` | Read CA records |
| `cas:write` | Create and manage CAs |
| `templates:read` | Read templates |
| `templates:write` | Create and manage templates |
| `scans:read` | Read scan jobs and results |
| `scans:write` | Create and cancel scans |
| `audit:read` | Read audit log |
| `admin` | Full admin access (equivalent to `pki-admin` role) |

**Response: 201 Created**

The `secret` field is returned **only in this response**. Store it immediately.

```json
{
  "data": {
    "id": "4d6f8b10-...",
    "name": "ci-pipeline-prod",
    "key_prefix": "kk_prod_",
    "secret": "kk_prod_a1b2c3d4e5f6...",
    "scopes": ["certificates:read", "certificates:write"],
    "expires_at": "2027-04-05T00:00:00Z",
    "created_at": "2026-04-05T10:00:00Z"
  }
}
```

**Status codes:**

| Code | Meaning |
|------|---------|
| 201 | Key created |
| 400 | Invalid scope or missing name |

---

### DELETE /api/v1/api-keys/{id}

Revoke an API key immediately. Owners may revoke their own keys; `pki-admin` may revoke
any key.

**Authentication:** Required. Roles: owner or `pki-admin`.

**Response: 204 No Content**

**Status codes:**

| Code | Meaning |
|------|---------|
| 204 | Revoked |
| 403 | Attempting to revoke another user's key without `pki-admin` role |
| 404 | Key not found |

---

## 11. Teams

Base path: `/api/v1/teams`

Teams group users for ownership assignment and alert routing. A certificate's `team_id`
determines which team receives expiry and risk alerts.

---

### GET /api/v1/teams

List all teams.

**Authentication:** Required. Roles: any.

**Response: 200 OK**

```json
{
  "data": [
    {
      "id": "2b4f6a80-...",
      "name": "platform-engineering",
      "slug": "platform-engineering",
      "description": "Platform and DevOps team",
      "notification_policy_id": "8e0f2c40-...",
      "member_count": 6,
      "certificate_count": 214,
      "created_at": "2026-01-01T00:00:00Z",
      "updated_at": "2026-01-01T00:00:00Z"
    }
  ],
  "meta": {
    "total": 8,
    "limit": 25,
    "next_cursor": null,
    "prev_cursor": null
  }
}
```

---

### POST /api/v1/teams

Create a team.

**Authentication:** Required. Roles: `pki-admin`.

**Request body:**

```json
{
  "name": "security-team",
  "slug": "security-team",
  "description": "Information Security",
  "notification_policy_id": "8e0f2c40-..."
}
```

**Response: 201 Created** — returns the team object.

---

### GET /api/v1/teams/{id}

Get a team by ID.

**Authentication:** Required. Roles: any.

**Response: 200 OK** — returns the team object including member list.

---

### PATCH /api/v1/teams/{id}

Update a team.

**Authentication:** Required. Roles: `pki-admin`.

**Response: 200 OK** — returns updated team.

---

### DELETE /api/v1/teams/{id}

Delete a team. Only allowed if the team has no certificates assigned to it.

**Authentication:** Required. Roles: `pki-admin`.

**Response: 204 No Content**

**Status codes:**

| Code | Meaning |
|------|---------|
| 204 | Deleted |
| 409 | Team has certificates assigned — reassign first |

---

### GET /api/v1/teams/{id}/members

List members of a team.

**Authentication:** Required. Roles: any.

**Response: 200 OK**

```json
{
  "data": [
    {
      "user_id": "550e8400-...",
      "email": "alex@example.com",
      "display_name": "Alex Kim",
      "role": "pki-admin"
    }
  ],
  "meta": {
    "total": 6,
    "limit": 25,
    "next_cursor": null,
    "prev_cursor": null
  }
}
```

---

### POST /api/v1/teams/{id}/members

Add a user to the team.

**Authentication:** Required. Roles: `pki-admin`.

**Request body:**

```json
{
  "user_id": "550e8400-..."
}
```

**Response: 200 OK** — returns the updated member list.

---

### DELETE /api/v1/teams/{id}/members/{user_id}

Remove a user from the team.

**Authentication:** Required. Roles: `pki-admin`.

**Response: 204 No Content**

---

### GET /api/v1/teams/{id}/certificates

List certificates owned by a team.

**Authentication:** Required. Roles: any.

**Query parameters:** Same filtering as `GET /api/v1/certificates`.

**Response: 200 OK** — same envelope as certificate list, scoped to `team_id`.

---

### POST /api/v1/certificates/{fingerprint}/ownership

Assign or transfer certificate ownership to a team.

**Authentication:** Required. Roles: `pki-admin`, `pki-operator`.

**Request body:**

```json
{
  "team_id": "2b4f6a80-..."
}
```

**Response: 200 OK**

```json
{
  "data": {
    "fingerprint_sha256": "a1b2c3d4...",
    "team_id": "2b4f6a80-...",
    "updated_at": "2026-04-05T10:00:00Z"
  }
}
```

---

## 12. Notifications

Base path: `/api/v1/notifications`

Notification channels define where alerts are sent (email, Slack, webhook, PagerDuty).
Notification policies define when alerts fire (expiry thresholds, risk grade changes) and
which channels receive them.

---

### GET /api/v1/notifications/channels

List notification channels.

**Authentication:** Required. Roles: any.

**Response: 200 OK**

```json
{
  "data": [
    {
      "id": "6e8f0a20-...",
      "name": "slack-pki-alerts",
      "channel_type": "slack",
      "active": true,
      "config": {
        "webhook_url": "https://hooks.slack.com/services/...",
        "channel": "#pki-alerts"
      },
      "policy_id": "8e0f2c40-...",
      "created_at": "2026-01-01T00:00:00Z",
      "updated_at": "2026-01-01T00:00:00Z"
    }
  ],
  "meta": {
    "total": 4,
    "limit": 25,
    "next_cursor": null,
    "prev_cursor": null
  }
}
```

---

### POST /api/v1/notifications/channels

Create a notification channel.

**Authentication:** Required. Roles: `pki-admin`, `pki-operator`.

**Request body:**

```json
{
  "name": "email-pki-team",
  "channel_type": "email",
  "policy_id": "8e0f2c40-...",
  "config": {
    "to": ["pki-team@example.com"],
    "from": "kryptkeeper@example.com"
  }
}
```

**Channel types and required config fields:**

| `channel_type` | Required config fields |
|----------------|----------------------|
| `email` | `to` (array), `from` (string) |
| `slack` | `webhook_url` (string) |
| `webhook` | `url` (string), `method` (`POST`/`PUT`) |
| `pagerduty` | `integration_key` (string) |

**Response: 201 Created** — returns the channel object.

**Note:** `config` is stored server-side and returned on read. Sensitive fields (e.g.,
`integration_key`) are redacted in list/get responses — showing only the first 4 characters
plus `****`.

---

### GET /api/v1/notifications/channels/{id}

Get a single notification channel.

**Authentication:** Required. Roles: any.

**Response: 200 OK** — returns the channel object with redacted sensitive config fields.

---

### PATCH /api/v1/notifications/channels/{id}

Update a notification channel.

**Authentication:** Required. Roles: `pki-admin`, `pki-operator`.

**Response: 200 OK** — returns updated channel.

---

### DELETE /api/v1/notifications/channels/{id}

Delete a notification channel.

**Authentication:** Required. Roles: `pki-admin`, `pki-operator`.

**Response: 204 No Content**

---

### POST /api/v1/notifications/channels/{id}/test

Send a test notification through this channel to verify configuration.

**Authentication:** Required. Roles: `pki-admin`, `pki-operator`.

**Request body:** Empty (`{}`)

**Response: 200 OK**

```json
{
  "data": {
    "channel_id": "6e8f0a20-...",
    "success": true,
    "message": "Test notification delivered to #pki-alerts",
    "sent_at": "2026-04-05T10:00:00Z"
  }
}
```

**Status codes:**

| Code | Meaning |
|------|---------|
| 200 | Test sent (check `success` field for delivery outcome) |
| 404 | Channel not found |

---

### GET /api/v1/notifications/policies

List notification policies.

**Authentication:** Required. Roles: any.

**Response: 200 OK**

```json
{
  "data": [
    {
      "id": "8e0f2c40-...",
      "name": "platform-cert-policy",
      "active": true,
      "thresholds": {
        "expiry_days": [90, 30, 7, 1],
        "on_grade_change": true,
        "on_revocation": true,
        "on_new_certificate": false,
        "on_risk_flag": ["EXPIRED", "WEAK_KEY"]
      },
      "channels": [
        {
          "id": "6e8f0a20-...",
          "name": "slack-pki-alerts",
          "channel_type": "slack"
        }
      ],
      "created_at": "2026-01-01T00:00:00Z",
      "updated_at": "2026-01-01T00:00:00Z"
    }
  ],
  "meta": {
    "total": 3,
    "limit": 25,
    "next_cursor": null,
    "prev_cursor": null
  }
}
```

---

### POST /api/v1/notifications/policies

Create a notification policy.

**Authentication:** Required. Roles: `pki-admin`, `pki-operator`.

**Request body:**

```json
{
  "name": "security-cert-policy",
  "thresholds": {
    "expiry_days": [30, 7],
    "on_grade_change": true,
    "on_revocation": true,
    "on_new_certificate": false,
    "on_risk_flag": ["EXPIRED", "WEAK_KEY", "SHA1_SIGNATURE"]
  }
}
```

**Response: 201 Created** — returns the policy object.

---

### PATCH /api/v1/notifications/policies/{id}

Update a notification policy.

**Authentication:** Required. Roles: `pki-admin`, `pki-operator`.

**Response: 200 OK** — returns updated policy.

---

### DELETE /api/v1/notifications/policies/{id}

Delete a notification policy. Only allowed if no teams reference this policy.

**Authentication:** Required. Roles: `pki-admin`, `pki-operator`.

**Response: 204 No Content**

**Status codes:**

| Code | Meaning |
|------|---------|
| 204 | Deleted |
| 409 | Policy is in use by one or more teams |

---

## 13. Audit Log

Base path: `/api/v1/audit`

The audit log is **append-only** (constraint C-Sec02). No update or delete endpoints exist.
Every state-changing API operation writes an entry atomically within the same database
transaction as the operation itself (FR-094).

---

### GET /api/v1/audit

List audit log entries.

**Authentication:** Required. Roles: `pki-admin`, `pki-auditor`.

**Query parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `actor_id` | string | Filter by actor UUID or `system` |
| `actor_type` | string | `user`, `api_key`, `system` |
| `action` | string | Filter by action (e.g., `certificate.issue`, `ca.create`) |
| `resource_type` | string | `certificate`, `ca`, `template`, `scan_job`, `user`, etc. |
| `resource_id` | string | Filter by affected resource ID |
| `after` | RFC 3339 | Entries after this timestamp |
| `before` | RFC 3339 | Entries before this timestamp |
| `trace_id` | string | Filter by request trace ID |
| `sort` | string | `timestamp` only |
| `order` | string | `asc` or `desc` (default: `desc`) |
| `limit` | integer | Page size (default 25, max 100) |
| `cursor` | string | Pagination cursor |

**Response: 200 OK**

```json
{
  "data": [
    {
      "id": 100423,
      "timestamp": "2026-04-05T10:05:33Z",
      "action": "certificate.revoke",
      "actor_type": "user",
      "actor_id": "550e8400-...",
      "resource_type": "certificate",
      "resource_id": "a1b2c3d4...",
      "client_ip": "10.0.0.1",
      "trace_id": "01HX7Z...",
      "details": {
        "reason_code": 1,
        "reason_text": "Key was compromised — see INC-8821",
        "revoked_at": "2026-04-05T10:05:33Z"
      },
      "diff": {
        "before": { "renewal_status": "active" },
        "after": { "renewal_status": "revoked" }
      }
    }
  ],
  "meta": {
    "total": 48291,
    "limit": 25,
    "next_cursor": "eyJpZCI6MTAwNDI...",
    "prev_cursor": null
  }
}
```

**Audit action names:**

| Action | Triggered by |
|--------|-------------|
| `ca.create` | POST /api/v1/cas |
| `ca.update` | PATCH /api/v1/cas/{id} |
| `ca.suspend` | POST /api/v1/cas/{id}/suspend |
| `ca.activate` | POST /api/v1/cas/{id}/activate |
| `ca.delete` | DELETE /api/v1/cas/{id} |
| `certificate.issue` | POST /api/v1/certificates |
| `certificate.renew` | POST /api/v1/certificates/{fp}/renew |
| `certificate.revoke` | POST /api/v1/certificates/{fp}/revoke |
| `certificate.import` | POST /api/v1/certificates/import |
| `certificate.ownership_assign` | POST /api/v1/certificates/{fp}/ownership |
| `template.create` | POST /api/v1/templates |
| `template.update` | PUT/PATCH /api/v1/templates/{id} |
| `template.delete` | DELETE /api/v1/templates/{id} |
| `scan_job.create` | POST /api/v1/scans |
| `scan_job.cancel` | POST /api/v1/scans/{id}/cancel |
| `user.create` | POST /api/v1/users |
| `user.update` | PATCH /api/v1/users/{id} |
| `user.deactivate` | DELETE /api/v1/users/{id} |
| `api_key.create` | POST /api/v1/api-keys |
| `api_key.revoke` | DELETE /api/v1/api-keys/{id} |
| `auth.login` | POST /api/v1/auth/login |
| `auth.logout` | POST /api/v1/auth/logout |
| `auth.login_failed` | POST /api/v1/auth/login (failure) |
| `rbac.denied` | Any endpoint (403) |

---

## 14. System

Base path: `/api/v1/system`

---

### GET /api/v1/system/health

Health check endpoint. No authentication required. Used by load balancers and readiness
probes.

**Authentication:** None.

**Response: 200 OK** (healthy) or **503 Service Unavailable** (degraded)

```json
{
  "data": {
    "status": "healthy",
    "version": "1.0.0",
    "checks": {
      "database": "ok",
      "cache": "ok",
      "ca_engine": "ok"
    },
    "uptime_seconds": 86400,
    "timestamp": "2026-04-05T10:00:00Z"
  }
}
```

**Degraded response (503):**

```json
{
  "data": {
    "status": "degraded",
    "checks": {
      "database": "ok",
      "cache": "error: connection refused",
      "ca_engine": "ok"
    }
  }
}
```

---

### GET /api/v1/system/version

Version and build information.

**Authentication:** Required. Roles: any.

**Response: 200 OK**

```json
{
  "data": {
    "version": "1.0.0",
    "git_commit": "abc123def456",
    "build_date": "2026-04-05T00:00:00Z",
    "go_version": "go1.23.0",
    "api_version": "v1"
  }
}
```

---

### GET /metrics

Prometheus metrics endpoint. Exposed on the same port as the API.

**Authentication:** Required. Roles: `pki-admin`.

**Response: 200 OK**

Returns Prometheus text format (`Content-Type: text/plain; version=0.0.4`).

**Key metrics exposed:**

| Metric | Type | Description |
|--------|------|-------------|
| `kk_certificates_total` | Gauge | Total certificates by status |
| `kk_certificates_expiring` | Gauge | Certificates expiring in N days |
| `kk_certificate_risk_grade` | Gauge | Certificate count by grade |
| `kk_ca_status` | Gauge | CA count by status |
| `kk_scan_job_duration_seconds` | Histogram | Scan job duration |
| `kk_api_request_duration_seconds` | Histogram | API request latency by endpoint |
| `kk_api_requests_total` | Counter | API requests by method, path, status |
| `kk_ocsp_response_duration_seconds` | Histogram | OCSP response latency |
| `kk_audit_log_entries_total` | Counter | Audit log writes |

---

## 15. Error Catalog

Every error response uses the format defined in [Section 1.6](#16-error-format). The `code`
field is the machine-readable identifier. HTTP clients should branch on `code`, not on
`title` (which may change).

### Authentication and Authorization

| Code | Status | Description |
|------|--------|-------------|
| `AUTH_TOKEN_MISSING` | 401 | No `Authorization` header present |
| `AUTH_TOKEN_INVALID` | 401 | JWT is malformed, expired, or signature invalid |
| `AUTH_TOKEN_EXPIRED` | 401 | JWT has expired — call `/auth/refresh` |
| `AUTH_API_KEY_INVALID` | 401 | API key not found or revoked |
| `AUTH_API_KEY_EXPIRED` | 401 | API key has passed its `expires_at` |
| `AUTH_CREDENTIALS_INVALID` | 401 | Wrong email or password |
| `AUTH_ACCOUNT_INACTIVE` | 403 | User account is deactivated |
| `RBAC_PERMISSION_DENIED` | 403 | Authenticated principal lacks required role |
| `RBAC_TEMPLATE_ENROLL_DENIED` | 403 | Role not in template's `enrollment_permissions` |

### Resource Errors

| Code | Status | Description |
|------|--------|-------------|
| `RESOURCE_NOT_FOUND` | 404 | The requested resource does not exist |
| `RESOURCE_CONFLICT` | 409 | Unique constraint violation (name, fingerprint, etc.) |
| `RESOURCE_PRECONDITION_FAILED` | 412 | `If-Match` ETag mismatch — resource was modified |

### CA Errors

| Code | Status | Description |
|------|--------|-------------|
| `CA_PARENT_NOT_ACTIVE` | 422 | Issuing CA's parent CA is not in `active` status |
| `CA_PARENT_NOT_FOUND` | 422 | `parent_ca_id` references a non-existent CA |
| `CA_ALREADY_SUSPENDED` | 409 | CA is already suspended |
| `CA_IN_TERMINAL_STATE` | 409 | CA is revoked or expired; state cannot change |
| `CA_HAS_ACTIVE_CERTS` | 409 | CA cannot be deleted while it has active certificates |
| `CA_CEREMONY_REQUIRED` | 422 | Root CA cannot be activated without `ceremony_complete: true` |
| `CA_IMMUTABLE_FIELD` | 422 | Attempt to modify type, key storage type, or algorithm |

### Certificate Errors

| Code | Status | Description |
|------|--------|-------------|
| `CERT_CSR_MALFORMED` | 400 | CSR cannot be parsed or is not valid PKCS#10 |
| `CERT_CSR_SUBJECT_INVALID` | 422 | Subject DN does not satisfy template `subject_requirements` |
| `CERT_CSR_SAN_INVALID` | 422 | SAN violates template SAN policy |
| `CERT_CSR_KEY_TOO_SMALL` | 422 | Public key size is below template `min_key_size` |
| `CERT_CSR_ALGORITHM_DENIED` | 422 | Algorithm not in template `allowed_algorithms` |
| `CERT_ALREADY_REVOKED` | 409 | Certificate has already been revoked |
| `CERT_ALREADY_EXPIRED` | 409 | Certificate has expired; revocation has no effect |
| `CERT_HAS_SUCCESSOR` | 409 | Certificate already has an active renewal |
| `CERT_IMPORT_DUPLICATE` | 409 | Certificate already in inventory (includes `existing_fingerprint`) |
| `CERT_REVOCATION_REASON_INVALID` | 422 | Reason code is not in the allowed RFC 5280 set |

### Template Errors

| Code | Status | Description |
|------|--------|-------------|
| `TEMPLATE_HAS_ACTIVE_CERTS` | 409 | Template cannot be deleted while active certs exist |
| `TEMPLATE_NAME_CONFLICT` | 409 | Template with this name already exists |
| `TEMPLATE_OID_CONFLICT` | 409 | Template with this OID already exists |
| `TEMPLATE_INVALID_EKU` | 422 | Unknown or invalid EKU value |
| `TEMPLATE_INVALID_ALGORITHM` | 422 | Unrecognized algorithm in `allowed_algorithms` |

### Scan Errors

| Code | Status | Description |
|------|--------|-------------|
| `SCAN_AUTH_NOT_ACKNOWLEDGED` | 400 | `authorization_acknowledged` must be `true` |
| `SCAN_INVALID_SCOPE` | 400 | Scope is missing required fields for the scan type |
| `SCAN_INVALID_TARGET` | 400 | CIDR, hostname, or IP address is not valid |
| `SCAN_NOT_CANCELLABLE` | 409 | Scan is already completed, failed, or cancelled |

### Notification Errors

| Code | Status | Description |
|------|--------|-------------|
| `NOTIFY_CHANNEL_TYPE_INVALID` | 422 | Unknown `channel_type` |
| `NOTIFY_CHANNEL_CONFIG_MISSING` | 422 | Required config field missing for channel type |
| `NOTIFY_POLICY_IN_USE` | 409 | Policy is referenced by one or more teams |
| `NOTIFY_TEST_DELIVERY_FAILED` | 200 | Test notification sent but delivery failed (see `message`) |

### System Errors

| Code | Status | Description |
|------|--------|-------------|
| `RATE_LIMIT_EXCEEDED` | 429 | Request rate limit exceeded (see `Retry-After` header) |
| `REQUEST_BODY_INVALID` | 400 | Request body is not valid JSON |
| `REQUEST_FIELD_MISSING` | 400 | Required field is absent |
| `REQUEST_FIELD_TYPE_INVALID` | 400 | Field value has wrong type |
| `INTERNAL_ERROR` | 500 | Unexpected server error (include `trace_id` in support requests) |
| `SERVICE_UNAVAILABLE` | 503 | Platform is starting up or a dependency is unhealthy |

---

*Document status: Draft — pending review.*
*Next: OpenAPI 3.1 spec auto-generated from this design.*
