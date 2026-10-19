# SSH CA operator guide

Kryptkeeper signs OpenSSH user and host certificates from a hub-held SSH CA key
(`APP_CERTIFICATE_PROVIDER=ca`). Issuance is audited and runs only against a
certificate template that carries an `ssh_policy`.

## Trust the CA

`GET /api/v1/ssh/ca` returns `authority_line` (the CA public key) and
`authority_fingerprint`.

- Servers (trust user certs): write `authority_line` to a file and set
  `TrustedUserCAKeys /etc/ssh/kk_user_ca.pub` in `sshd_config`.
- Clients (trust host certs): add `@cert-authority <host-pattern> <authority_line>`
  to `known_hosts`.

## Template `ssh_policy`

Create a template (`POST /api/v1/templates`) with an `ssh_policy` object:

| Field | Meaning |
|---|---|
| `cert_types` | `user`, `host` or both. |
| `allowed_principals` | Exact login names the template may sign (required for `user`). |
| `host_patterns` | Lowercase DNS names, or one leading `*.` label (required for `host`). |
| `max_ttl_hours` | Ceiling for this template. |

`POST /api/v1/ssh/certificates` requires `template_id`, `public_key`,
`cert_type`, `key_id`, `principals` and `ttl_hours`. A principal or host outside
the policy, or a request without `template_id`, is refused 400.

## TTL ceilings

The hub ceilings are 24 hours for user certificates and 30 days for host
certificates. A request above the ceiling, or above the template's
`max_ttl_hours`, is refused with HTTP 400. It is refused, not clamped. See
`/ssh/certificates` in `docs/openapi.yaml`.

## Approval

A template with `require_approval: true` parks SSH issuance: the POST answers
202 `{"status":"pending_approval","approval_id":...}` and signs nothing. A
different principal with an approver role (`approval_roles`, default pki-admin)
approves with `POST /api/v1/approvals/{id}/approve` and receives 201 with the SSH
certificate record. The requester, the bootstrap token and keys minted with it
cannot approve. Policy is re-checked at approval time.

## Audit

Each issuance writes `ssh_certificate.issue`. The resource is
`template_id:serial:key_id` for an issued certificate; a request held for
approval records outcome `pending_approval` with the approval id in the detail.
Approval itself is `approval.approve`.

## Revocation

v1.0 SSH certificate revocation is TTL-only: there is no KRL. To end access, wait for the certificate to expire or rotate the SSH CA key.

Keep user certificates short (hours). Rotating the CA key invalidates every
certificate it signed, so servers must be given the new `TrustedUserCAKeys` line
first.
