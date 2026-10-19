# EST authentication (W20-14, D-112)

Status (2026-10-07): implemented. Proven live on the lab hub and with the real
`globalsign/est` client (`tests/live/protocols`).

EST enrollment is **off unless a credential type is configured**. `cacerts`
is always served anonymously (it issues nothing, RFC 7030 §4.1.1). Every other
route, `csrattrs` included, answers 401 without credentials (W26-06). EST is served only on the hub's own TLS listener. Do
not put it behind a TLS-terminating proxy: the hub refuses EST credentials
on any request that did not arrive over TLS (RFC 7030 §3.2.3), and a proxy
would also drop client certificates.

## Credential types (both may be on)

| Operation | Credential | Identity it yields |
|---|---|---|
| `simpleenroll` | HTTP Basic over TLS (users file) | `CN` = the CSR's CN, DNS SANs = the CSR's. Every name must be under one of that user's suffixes. Nothing else from the CSR survives. |
| `simpleenroll` | TLS client certificate chaining to a configured anchor | the presented certificate's subject and DNS SANs; the CSR only proves the key |
| `simplereenroll` | TLS client certificate **this hub issued** | that certificate's subject and DNS SANs (same checks as WSTEP renewal: validity, client-auth EKU, unrevoked, fail closed) |

When a client presents a certificate that does not chain to an anchor, it is
ignored and Basic is asked for instead. Clients may offer unrelated
certificates on their own. For re-enrollment there is no fallback: a
certificate that fails the checks gets 403.

## Configuration

| Variable | Meaning |
|---|---|
| `KRYPTKEEPER_EST_USERS_FILE` | JSON array of `{username, bcrypt_hash, allowed_dns_suffixes}`. Keep it at mode 0600; the hub warns otherwise. |
| `KRYPTKEEPER_EST_CLIENT_CA_FILE` | PEM bundle of trust anchors for first enrollment by client certificate (for example a device manufacturer CA). |
| `KRYPTKEEPER_TLS_REQUEST_CLIENT_CERT=true` | Required for the client-certificate method and for re-enrollment (D-111). |

The hub logs, once at startup, which methods are live and why any is not.

### Users file

```json
[
  {
    "username": "factory-line-3",
    "bcrypt_hash": "$2y$10$…",
    "allowed_dns_suffixes": [".devices.example.com"]
  }
]
```

- **Generating a hash:** `htpasswd -nbBC 10 factory-line-3 '<password>'` and
  take the part after the colon. Use `-C 10` or higher; `htpasswd -B`
  defaults to cost 5.
- **Suffixes:** each must start with `.` and matches whole labels only.
  `.devices.example.com` admits `a.devices.example.com`, but not
  `devices.example.com` or `evildevices.example.com`. An empty list is
  refused at startup.
- **What a request may ask for:** wildcards and IP, URI and email SANs are
  refused. The subject is reduced to the CN.
- **Unknown users:** they cost the same bcrypt work as known ones, so
  response times do not reveal which usernames exist.

## API-managed users (W26-07)

pki-admins can create, rotate, disable and delete Basic users without file
edits: `POST/GET /api/v1/est/users`, `GET/PATCH/DELETE /api/v1/est/users/{username}`,
`POST /api/v1/est/users/{username}/rotate`. The server generates the password
and shows it once; only a bcrypt hash is stored. **A user defined in
`KRYPTKEEPER_EST_USERS_FILE` wins on a name clash**: creating a stored user with
a file user's name is refused (409) and a stored user later shadowed by the
file is flagged `shadowed_by_file`. Audit actions: `est.user.create|rotate|update|delete`.

## Audit

Every outcome except the bare first 401 challenge is written to the hub
audit log:

- `est.enroll` success: actor is the username or the certificate subject,
  and the detail carries the method, serial and subject.
- `est.enroll.failure` (outcome `denied`): invalid credentials, a disabled
  user, or a name outside the user's suffixes. More than 10 failed Basic
  attempts per minute for one username raise one `alert.est.basic.failures`
  audit entry (and an `ALERT` log line) per minute.
- `est.reenroll` success and denied, with the reason (for example
  "certificate is revoked").

## Live evidence (lab-hub, 2026-10-07)

**Basic:**

| Request | Result |
|---|---|
| No credentials | 401 `Basic realm="est"` |
| Wrong password | 401, audited |
| `CN=Administrator` | 403, audited ("not under an allowed suffix") |
| `O=Domain Admins, CN=dev1.est.corp.example.test` with two SANs | 200, issued `CN=dev1.est.corp.example.test` (O dropped) with both SANs, plus CRL/OCSP pointers |

**Re-enroll** (client-certificate requests on):

| Request | Result |
|---|---|
| No certificate | 403 at the time; 401 since W26-06 |
| The Basic-issued certificate, with a CSR asking for `CN=Administrator` | 200, same subject and SANs, new serial |
| After revoking it | 403 "certificate is revoked", audited |

The lab hub was then returned to EST disabled.

## Label routes (W26-06)

`/.well-known/est/<label>/{cacerts,simpleenroll,simplereenroll,csrattrs}` serves
a named endpoint bound to one template. Manage labels with `/api/v1/est/labels`
(pki-admin). The bare routes are the default label and keep using
`KRYPTKEEPER_EST_TEMPLATE`. Enrollment on a label is gated by the label's
template: list the role `protocol:est` in that template's
`enrollment_permissions.enroll`. An unknown, reserved or malformed label is a
404 with the same body. Issued certificates are recorded in the inventory with
the template id. Needs the hub database.
