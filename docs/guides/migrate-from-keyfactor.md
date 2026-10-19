# Migrate from Keyfactor Command / EJBCA to Kryptkeeper

This playbook moves an estate run on Keyfactor Command or EJBCA to Kryptkeeper: inventory,
template mapping, a parallel run, takeover one application group at a time, cutover and
rollback. It includes the trap that bites most migrations: revocation URLs baked into the
certificates the old CA already issued. Style and phasing follow [Replace ADCS](replace-adcs.md)
and [Migrate from Venafi](migrate-from-venafi.md).

## Tooling coverage

| Source | Template import | Certificate inventory |
|---|---|---|
| Keyfactor Command | **Importer exists**: `internal/migration/keyfactor`, source name `keyfactor`. Input is the response of `GET /KeyfactorAPI/Templates` (a JSON array or `{"templates":[...]}`) | PEM export plus `POST /api/v1/certificates/bulk-import` |
| EJBCA | **No importer.** `GET /api/v1/migration/sources` lists `adcs`, `certcentral`, `keyfactor`, `vault`, `venafi` and nothing for EJBCA. Recreate templates by hand (see [EJBCA manual path](#ejbca-manual-path)) | PEM export plus `POST /api/v1/certificates/bulk-import` |

> **Honesty note.** The Keyfactor field names the importer reads come from the Command API
> documentation (https://software.keyfactor.com, Command API reference; exact page not
> pinned here, unverified) and are **not verified against a live export** (comment above the
> field constants in `internal/migration/keyfactor/keyfactor.go`). Unknown fields are reported
> unmapped, so a wrong name lowers the visible mapping percentage instead of dropping data:
> read the unmapped count in the dry run before you apply. The EJBCA commands and options in
> this playbook are from the EJBCA documentation (https://docs.keyfactor.com/ejbca) and are
> **unverified** against your EJBCA version: check each against `ejbca.sh <command> --help`.
> The importer has no UI; use the API.

**Private keys do not migrate.** This playbook does not move end-entity private keys, and Kryptkeeper rejects any bundle containing one (`400`, nothing
imports). Certificates are inventoried for tracking and **re-issued** at their next renewal.

## Overview

1. Inventory the certificates and templates (or certificate profiles).
2. Import or recreate templates.
3. Import certificates and assign owners.
4. Parallel run: the old CA stays authoritative.
5. Take over per application group, then cut over enrollment.
6. Keep the old CA's revocation endpoints reachable, then decommission.

Imported certificates land as `origin=imported`, `management_state=unmanaged`.

## Prerequisites

- A running Kryptkeeper hub ([Getting Started](getting-started.md)) with a CA ready, and a
  token with `ca.manage` for the migration and template routes. `$HUB` is the hub URL,
  `$T` the bearer token.
- Keyfactor: a read-only Command API user able to call `GET /KeyfactorAPI/Templates` and
  export certificates. EJBCA: an administrator role allowed to export certificates and read
  certificate profiles.
- A second approver: `POST /api/v1/migration/apply` returns `202` and is queued in
  `/api/v1/pending-actions`; a different person must approve it.
- Egress allow-list entries if you pull the inventory live from a CA (see the inventory-source
  notes in [Day-one estate](day-one-estate.md)); the importer itself reads a file you upload.
- A list of application groups, each with an owner team and service name, and the enrollment
  client used per group (ACME, EST, SCEP or WSTEP).
- Private keys cannot be exported: plan re-issuance, not key transfer.

### Step A (Keyfactor): dry run, then apply

```bash
# templates.json is the saved response of GET /KeyfactorAPI/Templates (max 48 KiB per request)
jq -Rs '{source:"keyfactor", content:.}' templates.json |
  curl -s -X POST $HUB/api/v1/migration/dryrun \
    -H "Authorization: Bearer $T" -H "Content-Type: application/json" -d @-
```

The dry run writes nothing. Read the per-field status and the unmapped count. Then:

```bash
jq -Rs '{source:"keyfactor", content:.}' templates.json |
  curl -s -X POST $HUB/api/v1/migration/apply \
    -H "Authorization: Bearer $T" -H "Content-Type: application/json" -d @-
```

The response is `202`; a second person approves it in `/api/v1/pending-actions`. Templates are
created under a batch id (`GET /api/v1/migration/batches`, report
`GET /api/v1/migration/{batch}/report`). Re-running an applied export creates nothing.

### EJBCA manual path

Export certificates from the Admin UI (search, then download as PEM), or with the EJBCA CLI
(`ejbca.sh ca getcertificate` for CA certificates, `ejbca.sh ra getendentitycert` for
end-entity certificates; names and options unverified, check `--help`). Concatenate the
public certificates into one PEM file. Recreate each template by hand from the EJBCA
certificate profile with `POST /api/v1/templates` (body schema `TemplateRecord` in
`docs/openapi.yaml`; `validity_period` is an ISO 8601 duration such as `P90D`):

| EJBCA certificate profile field | Kryptkeeper template field | Note (manual) |
|---|---|---|
| Profile name | `name` | choose a stable name |
| Available key algorithms | `allowed_algorithms` | RSA, ECDSA |
| Available bit lengths | `min_key_size` | one minimum, take the smallest you still allow |
| Key usage | `key_usage` | |
| Extended key usage | `extended_key_usage` | custom OIDs have no equivalent |
| Validity | `validity_period` | one duration per template |

### Step B: certificates and owners

```bash
# CSV header: cert_b64[,owner_email,owner_team,service_name]; or format "pem" for a bundle
jq -Rs '{format:"pem", bundle:.}' certs.pem |
  curl -s -X POST $HUB/api/v1/certificates/bulk-import \
    -H "Authorization: Bearer $T" -H "Content-Type: application/json" -d @-
```

Limits: 8 MiB and 1000 certificates per call. Duplicates (by SHA-256 fingerprint) are skipped.
Set owners afterwards with `PATCH /api/v1/certificates/{fingerprint}/ownership` or
`POST /api/v1/ownership/cmdb-import`.

## Field mapping

Keyfactor, from `Map` in `internal/migration/keyfactor/keyfactor.go`. Status is the importer's
own report.

| Keyfactor field | Kryptkeeper target | Status |
|---|---|---|
| `Id` | `source_key` | mapped |
| `TemplateName` | `name` | mapped |
| `CommonName` | `display_name` | mapped |
| `Oid` | `oid` | mapped |
| `KeySize` | `min_key_size` (absent defaults to 2048) | mapped |
| `KeyType` | `allowed_algorithms` (RSA, ECC to ECDSA; other types make the template unsupported and it is skipped) | mapped |
| `Curve` | none, chosen by the CA | partial |
| `KeyUsage` | `key_usage` (CA usages keyCertSign, cRLSign are unmapped) | mapped |
| `ExtendedKeyUsages` | `extended_key_usage` (custom OIDs unmapped) | mapped |
| `AllowedEnrollmentTypes` | not modelled per template | partial |
| `AllowedRequesters`, `UseAllowedRequesters` | requester ACLs are not modelled | unmapped |
| `ForestRoot`, `ConfigurationTenant`, `EnrollmentFields`, `RFCEnforcement`, `KeyRetention`, `KeyRetentionDays`, `TemplateRegexes` | no equivalent | unmapped |
| (validity) | taken from the CA template in Keyfactor, so defaulted to `P365D` | partial |

Any other field is reported unmapped. A template with no mappable key usage or extended key
usage is reported unsupported and not created.

## Parallel run

Both CAs issue. The old CA stays authoritative. Move a pilot group's **new** enrollments to
Kryptkeeper (ACME, EST, SCEP or WSTEP as fits the client) while everything else keeps
enrolling against Keyfactor or EJBCA. Imported certificates stay `unmanaged` and are only
inventoried, tracked and alerted on.

Clients need both trust anchors during this period: the Kryptkeeper CA chain must be in the
trust stores of every relying party before any Kryptkeeper certificate is served, and the old
roots must stay until the last old certificate is gone. Name constraints and chain-shape
differences (different intermediates, cross-signing) can break validation on strict clients;
test the pilot group's clients against a Kryptkeeper certificate first.

## Takeover by application group

Per group, take its imported certificates under management:

```bash
curl -s -X POST $HUB/api/v1/estate/takeover/bulk \
  -H "Authorization: Bearer $T" -H "Content-Type: application/json" -d '{
  "items":[{"fingerprint":"<sha256>","owner_team":"payments","service_name":"checkout",
            "renewal_path":{"mode":"internal"}}]}'
```

- `renewal_path` is `{"mode":"internal"}` or `{"mode":"connector","connector_id":"..."}`.
- Maximum **500 items per call** (`docs/openapi.yaml`; split larger groups).
- An invalid `renewal_path` or unknown connector fails the whole call with `400` and changes
  nothing. Otherwise you get per-row results: a bad row (unknown fingerprint, already
  managed, other tenant) never stops later rows.
- Audit rows: `estate.takeover` per successful item and `estate.takeover.bulk` for the call.
  The route is **audit-only; it is not approval gated**. Do not rely on a gate here.
- UI: the "Take over" action on `/certificates/{fingerprint}?takeover=1`; a single
  certificate uses `POST /api/v1/estate/takeover`.

Taking over records ownership and the renewal path; it does not move the private key. The
certificate is re-issued by Kryptkeeper at its next renewal.

## Revocation URLs in old certificates

Every certificate the old CA already issued carries that CA's CRL distribution point and
AIA/OCSP URLs, and keeps them until it expires or is re-issued. Taking a group over does not
change them. If you switch off the Keyfactor or EJBCA CRL and OCSP endpoints too early,
clients that check revocation (or require it) will fail or soft-fail on certificates that are
still valid.

**Rule:** keep the old CRL and OCSP endpoints reachable until the last old certificate has
expired or been re-issued. List the URLs for a certificate:

```bash
openssl x509 -in cert.pem -noout -ext crlDistributionPoints,authorityInfoAccess
```

Collect the distinct hostnames across the whole imported set before decommissioning and
confirm each still resolves and answers.

New Kryptkeeper certificates carry Kryptkeeper's own URLs (`/crl/...` and `/ocsp` are mounted
on the revocation listener; see [OCSP stapling](../ops/OCSP_STAPLING.md)). The hub adds them
only to leaves valid for more than 7 days; shorter-lived leaves carry none by design
(`internal/ca/engine.go`).

## Cutover and decommission

Per application group: take it over, repoint the enrollment client (ACME, EST, SCEP or WSTEP)
at the hub, and let the next renewal re-issue from Kryptkeeper. Verify new serials at the
endpoints. Decommission Keyfactor or EJBCA only after two renewal cycles have completed on
Kryptkeeper **and** the revocation endpoints above are no longer referenced by any live
certificate. Both are human decisions outside this tooling.

## Rollback

- Templates: `POST /api/v1/migration/{batch}/rollback` disables the templates the batch
  created and never deletes them. Templates with a pending certificate approval stay active
  and are reported as kept. Rolling back twice is a no-op. Templates you created by hand
  (EJBCA path) are not part of a batch; disable them through `PATCH`/`DELETE` on
  `/api/v1/templates/{id}` as your policy allows.
- Taken-over certificates: `POST /api/v1/estate/revert {"fingerprint":"..."}` returns a
  managed certificate to `management_state=unmanaged` (one call per fingerprint; recorded
  renewal metadata stays as stale data; imported certificates are never deleted).
- Enrollment: repoint the group's clients back at Keyfactor or EJBCA, which still holds
  trust and still serves revocation for everything it issued.
- Keep the old CA enrolling until cutover is signed off, so rollback is "stop using
  Kryptkeeper for that group".

## Verification query

```bash
# imported count equals the exported certificate count
curl -s -H "Authorization: Bearer $T" "$HUB/api/v1/certificates?origin=imported&limit=1" | jq '.meta.total'
# no imported certificate without an owner team (expect 0)
curl -s -H "Authorization: Bearer $T" "$HUB/api/v1/certificates?origin=imported&owner=unassigned&limit=1" | jq '.meta.total'
# per group: managed certificates matching the team or service name
curl -s -H "Authorization: Bearer $T" "$HUB/api/v1/certificates?management_state=managed&q=checkout&limit=1" | jq '.meta.total'
```

The first number must equal the number of certificates you exported; the second must be 0;
the third is compared with the group size. `GET /certificates` has no `owner_team` filter, so
`q` (a free-text search) is used, and may match more than the group: confirm by fingerprint
when it matters. For a fingerprint-by-fingerprint check, run `scripts/migration-verify.sh --manifest FILE`
(see `tests/live/migration/README.md`); it exits non-zero unless every manifest fingerprint is mapped.
