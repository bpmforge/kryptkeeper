# Migrate from Vault PKI mounts to Kryptkeeper

This playbook moves HashiCorp Vault PKI secrets-engine mounts and roles to Kryptkeeper
templates and issuance, with a per-application-group cutover. It uses the `vault` template
importer (`internal/migration/vault`, API `/api/v1/migration/*`) and the certificate
inventory APIs. Style and phasing follow [Replace ADCS](replace-adcs.md) and
[Migrate from Venafi](migrate-from-venafi.md).

> **Honesty note.** Role field names come from the Vault PKI API documentation
> (https://developer.hashicorp.com/vault/api-docs/secret/pki) and are **not verified against a
> real export** (comment above the field constants in `internal/migration/vault/vault.go`).
> Unknown role fields are reported unmapped, not dropped, so a wrong name lowers the visible
> mapping percentage. Read the dry run before you apply. The importer has no UI; use the API.

**The importer is file-input only.** You upload the role JSON as `content`. It does not call
Vault and no Vault token is ever sent to the hub (it does not implement the optional
`LiveReader` interface in `internal/migration/framework.go`). **Private keys do not migrate:**
Vault clients generate their own keys, so "migrating" a certificate means re-issuing it.

## Overview

1. Inventory mounts, roles and still-valid certificates.
2. Map each mount to an issuing CA and each role to a template.
3. Dry run, then apply the templates (second approver).
4. Cut over one application group at a time by changing the client's issuer.
5. Keep the Vault mount read-only for two renewal cycles, then decommission.

## Prerequisites

- A running Kryptkeeper hub ([Getting Started](getting-started.md)) with an issuing CA ready,
  and a token with `ca.manage` for the migration routes. `$HUB` is the hub URL, `$T` the bearer
  token.
- A second approver: `POST /api/v1/migration/apply` returns `202` and is queued in
  `/api/v1/pending-actions`.
- A Vault token with `read` and `list` on `pki*/roles/*` and `pki*/certs` (and `pki*/cert/*`
  to read each certificate), used only on your workstation to produce the export files.
- The list of mounts and their issuers, and the Vault clients per application group: Vault
  Agent templates, the cert-manager Vault issuer, Terraform and any custom callers.
- The Kryptkeeper CA chain ready to distribute to every client trust store before cutover.

## Inventory

Roles, one JSON file per role, combined into `{"roles":{"<name>":{...}}}` (each value may be
the field map or Vault's `{"data":{...}}` read response):

```bash
vault list -format=json pki/roles
vault read -format=json pki/roles/<name>     # repeat per role, merge under "roles"
```

Certificates: `vault list pki/certs`, then `vault read -format=json pki/cert/<serial>` (the
`certificate` field is PEM) per serial [per the Vault PKI docs linked above; verify on your
Vault version]. Keep only certificates that are still valid (check not-after), concatenate
them into one PEM file and import:

```bash
jq -Rs '{format:"pem", bundle:.}' certs.pem |
  curl -s -X POST $HUB/api/v1/certificates/bulk-import \
    -H "Authorization: Bearer $T" -H "Content-Type: application/json" -d @-
```

Limits: 8 MiB and 1000 certificates per call; duplicates by SHA-256 fingerprint are skipped.
For owners, use format `csv` (header `cert_b64[,owner_email,owner_team,service_name]`), or set
them later with `PATCH /api/v1/certificates/{fingerprint}/ownership`. Imported certificates
land as `origin=imported`, `management_state=unmanaged`. Expired certificates are not worth
importing; short-lived ones (see below) usually expire before the import matters.

## Mount and role to template mapping

- A **mount** maps to one issuing CA choice in Kryptkeeper. The importer does not migrate
  CAs or issuer keys: after import you choose which Kryptkeeper CA issues for each template.
  Decide per mount whether it becomes its own CA or shares one.
- A **role** maps to one **template**, named after the role. Roles are separate per mount;
  if two mounts hold a role of the same name, rename one in the export before importing.

### Step A: dry run

```bash
jq -Rs '{source:"vault", content:.}' vault-roles.json |
  curl -s -X POST $HUB/api/v1/migration/dryrun \
    -H "Authorization: Bearer $T" -H "Content-Type: application/json" -d @-
```

Writes nothing. Confirm the importer is registered with `GET /api/v1/migration/sources`.
Max 48 KiB per request: split by mount if larger.

### Step B: apply (approval gated)

```bash
jq -Rs '{source:"vault", content:.}' vault-roles.json |
  curl -s -X POST $HUB/api/v1/migration/apply \
    -H "Authorization: Bearer $T" -H "Content-Type: application/json" -d @-
```

The response is `202`; a second person approves it in `/api/v1/pending-actions`. Templates
are created under a batch id (`GET /api/v1/migration/batches`; report
`GET /api/v1/migration/{batch}/report`). Re-running an applied export creates nothing.

## Field mapping

From `Map` in `internal/migration/vault/vault.go`. Status is the importer's own report.

| Vault role field | Kryptkeeper target | Status |
|---|---|---|
| `ttl` | `validity_period` | mapped |
| `max_ttl` | `validity_period` (a template has one validity; `ttl` wins, `max_ttl` is used only when there is no `ttl`) | partial |
| neither set | `validity_period` defaulted to `P32D`, Vault's 768h system default | partial |
| `key_type` | `allowed_algorithms` (`rsa`, `ec`, `any`; `ed25519` and others make the role unsupported and it is skipped) | mapped |
| `key_bits` | `min_key_size` (unset defaults to 2048, or 256 for `ec`) | mapped |
| `signature_bits`, `use_pss` | none, the CA chooses the signature hash | unmapped |
| `server_flag`, `client_flag`, `code_signing_flag`, `email_protection_flag` | `extended_key_usage` | mapped |
| `ext_key_usage`, `ext_key_usage_oids` | `extended_key_usage` (custom OIDs unmapped) | mapped |
| `key_usage` | `key_usage` (CA usages unmapped; unset gets Vault's default set) | mapped |
| `allowed_domains` with `allow_subdomains`, `allow_bare_domains` | `name_policy` DNS suffixes (a leading `.` for subdomains) and exact names; a domain with neither flag has no effect and is reported partial | mapped / partial |
| `allow_any_name` | no name policy is set; `allowed_domains` and `allowed_uri_sans` are then ignored (partial) | mapped |
| `allow_ip_sans` | `name_policy` IP SANs | mapped |
| `allowed_uri_sans` | `name_policy` URI prefixes (only `prefix*` patterns; others unmapped) | mapped / partial |
| `require_cn` | the CN is always checked against the SAN rules | partial |

Every other role field is reported unmapped ("no equivalent"). A role with no usable
extended key usage or key usage is reported unsupported and not created.

## Short-lived certificates

A Vault role that issues minutes or hours maps to a single template `validity_period`, and
`ValidityFromDuration` in `internal/migration/framework.go` **rounds up to whole days with a
minimum of `P1D`**. Issuance policy `max_validity_days` is also whole days (`docs/openapi.yaml`,
policies schema; enforced in `internal/ca/policy_engine.go`).

**Minimum supported validity: 1 day.** Validity below 1 day is not supported by template or
policy (day granularity). Keep Vault for sub-day certificates, or use ACME with 1-day
certificates. Do not promise an hours-long lifetime.

Also note that the hub puts CRL and OCSP pointers only on leaves valid for more than 7 days
(`internal/ca/engine.go`), so a 1 to 7 day certificate carries none; clients cannot revoke
it, they let it expire.

Handling rules:

- Clients must **auto-renew** through ACME or EST (the certificate lifetime drives the
  cadence). Renew at about two thirds of the lifetime. A one-time import is not a plan.
- Do not import inventory of short-lived certificates; it is stale before the batch finishes.
- Verify that renewal succeeds twice before you consider a group cut over.

## Cutover per application group

1. Dry run and apply the templates (above).
2. **Pilot group.** Put the Kryptkeeper CA chain in the group's trust stores first. Then change
   the issuer in the client: the cert-manager `Issuer` to an ACME issuer pointed at the hub's
   directory (`$HUB/acme/directory`), the Vault Agent template to an ACME or EST client, or
   the Terraform provider to one that requests from the hub. Verify the new serial at the
   endpoint is issued by the Kryptkeeper CA.
3. **Long-lived certificates.** Import the remaining valid certificates and take them under
   management:

   ```bash
   curl -s -X POST $HUB/api/v1/estate/takeover/bulk \
     -H "Authorization: Bearer $T" -H "Content-Type: application/json" -d '{
     "items":[{"fingerprint":"<sha256>","owner_team":"platform","service_name":"billing-api",
               "renewal_path":{"mode":"internal"}}]}'
   ```

   Maximum **500 items per call** (`docs/openapi.yaml`). A bad row never stops later rows.
   The route is **audit-only** (`estate.takeover` per item, `estate.takeover.bulk`); it is
   not approval gated.
4. **Hold Vault.** Leave the Vault mount in place, read-only if you can restrict its policy,
   until two renewal cycles have completed on Kryptkeeper.

Revocation: certificates already issued by Vault keep the CRL and OCSP URLs of the Vault
mount (when the mount's URLs are configured). Keep those endpoints reachable until those
certificates have expired.

## Decommission

After two renewal cycles per group, no live certificate chains to the Vault mount, and its
CRL/OCSP URLs are no longer referenced: disable the mount's roles, then remove it. Each step
is a human decision outside this tooling.

## Rollback

- Issuance: repoint the client issuer back at Vault. The mount is still in place and still
  issues, so this is the whole rollback for a group.
- Templates: `POST /api/v1/migration/{batch}/rollback` disables the templates the batch
  created and never deletes them. Templates with a pending certificate approval stay active
  and are reported as kept. Rolling back twice is a no-op.
- Taken-over certificates: `POST /api/v1/estate/revert {"fingerprint":"..."}` returns a
  managed certificate to `management_state=unmanaged` (one call per fingerprint; recorded
  renewal metadata stays as stale data; imported certificates are never deleted).

## Verification query

```bash
# imported count equals the number of Vault certificates you imported
curl -s -H "Authorization: Bearer $T" "$HUB/api/v1/certificates?origin=imported&limit=1" | jq '.meta.total'
# no imported certificate without an owner team (expect 0)
curl -s -H "Authorization: Bearer $T" "$HUB/api/v1/certificates?origin=imported&owner=unassigned&limit=1" | jq '.meta.total'
# per application group: certificates matching the service name
curl -s -H "Authorization: Bearer $T" "$HUB/api/v1/certificates?management_state=managed&q=billing-api&limit=1" | jq '.meta.total'
```

The first number must equal your import count; the second must be 0; compare the third with
the group size. `GET /certificates` accepts `limit`, `cursor`, `q`, `ca_id`, `status`, `origin`,
`management_state`, `owner` and `trust_class`; there is no `owner_team` filter, so `q` is used
and can over-match. For a fingerprint-by-fingerprint check, run `scripts/migration-verify.sh --manifest FILE`
(see `tests/live/migration/README.md`); it exits non-zero unless every manifest fingerprint is mapped.
