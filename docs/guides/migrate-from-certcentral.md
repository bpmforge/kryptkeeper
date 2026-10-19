# Migrate from DigiCert CertCentral to Kryptkeeper

This playbook moves a DigiCert CertCentral estate into Kryptkeeper. Inventory uses the
**direct-CA sync adapter** (`type: digicert` inventory source, the W11-05 pattern): the hub
reads your orders from CertCentral on a schedule, so no certificate file export is needed.
Templates come from the `certcentral` importer (`internal/migration/certcentral`). Style
and phasing follow [Replace ADCS](replace-adcs.md).

> **Honesty note.** The sync adapter's endpoint shapes come from DigiCert's developer
> documentation (https://dev.digicert.com; the code in `internal/bootstrap/inventory_source.go`
> records the fetch date 2026-08-18). The template importer's product field names
> (`name_id`, `allowed_validity_years`, `signature_hash_types`, ...) are from the
> CertCentral API documentation and are **not verified against a live account export**
> (comment in `certcentral.go`). Treat them as assumptions to verify; unknown fields are
> reported unmapped, not dropped. There is no UI for the importer; use the API.

CertCentral remains the issuing CA for certificates it already issued. Kryptkeeper does not
take over private keys; certificates are tracked now and re-issued at renewal.

## Overview

1. Store a CertCentral API key as a credential.
2. Create and run the `digicert` inventory source (sync twice to prove idempotence).
3. Optionally import product profiles as templates.
4. Take application groups under management, per group.

## Prerequisites

- A running Kryptkeeper hub ([Getting Started](getting-started.md)); `$HUB` is the hub URL,
  `$T` an admin bearer token (the credential routes require the admin role).
- A CertCentral API key with read access to orders. The adapter sends it in the
  `X-DC-DEVKEY` header and reads `/services/v2/order/certificate` [per DigiCert docs, verify
  for your account type and region base URL].
- For templates: a CertCentral product list JSON export (max 48 KiB) and `ca.manage`, plus a
  second approver for `/migration/apply` (queued in `/api/v1/pending-actions`).
- Application groups and owner teams to take over.

### Step A: store the API key

```bash
curl -s -X POST $HUB/api/v1/credentials \
  -H "Authorization: Bearer $T" -H "Content-Type: application/json" \
  -d '{"name":"certcentral-key","credential_type":"api_token","payload":{"api_key":"<paste>"}}'
```

The payload is write-only; the response is metadata including the credential id.

### Step B: create the inventory source and sync

```bash
curl -s -X POST $HUB/api/v1/inventory-sources \
  -H "Authorization: Bearer $T" -H "Content-Type: application/json" \
  -d '{"name":"certcentral","type":"digicert","credential_ref":"<credential id>","schedule_minutes":60}'
curl -s -X POST $HUB/api/v1/inventory-sources/<source id>/sync -H "Authorization: Bearer $T"
```

`config_json` is optional (`base_url`, defaulting to https://www.digicert.com). Secrets in
`config_json` are refused. Synced certificates enter as `origin=synced`,
`management_state=external` (upstream CA manages them). Sync a second time: it must add 0
(idempotent by fingerprint). Revoked orders propagate to `renewal_status=revoked`.

### Step C: templates (optional)

```bash
jq -Rs '{source:"certcentral", content:.}' products.json |
  curl -s -X POST $HUB/api/v1/migration/dryrun \
    -H "Authorization: Bearer $T" -H "Content-Type: application/json" -d @-
```

Then the same body to `/api/v1/migration/apply` (202, second approver). The report is at
`GET /api/v1/migration/{batch}/report`; batches at `GET /api/v1/migration/batches`.

## Field mapping

From `Map` in `internal/migration/certcentral/certcentral.go`.

| CertCentral field | Kryptkeeper target | Status |
|---|---|---|
| `name_id` | `name` (prefixed `certcentral-`) | mapped |
| `name` | `display_name` | mapped |
| `type` | `extended_key_usage` and enrolee type; only `ssl_certificate`, `client_certificate`, `code_signing_certificate` are supported, others are skipped | mapped |
| `allowed_validity_years` | `validity_period`, the longest allowed year count | partial |
| `signature_hash_types` | none, chosen by the CA | unmapped |
| organizations | reported only; the organization is chosen per order by the CertCentral connector (`OrganizationID`) | partial / unmapped (inactive) |
| allowed algorithms, min key size | defaulted to RSA and ECDSA, 2048 | partial |

Synced certificate fields: the adapter stores the PEM from the order and the upstream
status (`issued` is active, `revoked` is revoked). Other attributes are not carried.

## Cutover

Per application group, take certificates under management and choose who renews them:

```bash
curl -s -X POST $HUB/api/v1/estate/takeover/bulk \
  -H "Authorization: Bearer $T" -H "Content-Type: application/json" \
  -d '{"items":[{"fingerprint":"<sha256>","owner_team":"payments","renewal_path":{"mode":"connector","connector_id":"<digicert connector>"}}]}'
```

`mode:"connector"` keeps CertCentral as the renewal source (create the connector via
`POST /api/v1/connectors`, type `digicert`); `mode:"internal"` moves renewals to the
Kryptkeeper CA. Up to 500 items per call. These routes are **audit-only**
(`estate.takeover` rows), not approval gated. Then repoint ACME or EST clients as needed.

## Rollback

- Templates: `POST /api/v1/migration/{batch}/rollback` disables (never deletes) the
  templates the batch created.
- Certificates: `POST /api/v1/estate/revert {"fingerprint":"..."}` returns a certificate to
  `management_state=unmanaged`; renewal metadata remains as stale data. To stop syncing,
  `DELETE /api/v1/inventory-sources/{id}`. CertCentral itself is untouched throughout, so
  it stays authoritative until you cancel orders there (human act, out of scope).

## Verification query

```bash
# synced count equals the CertCentral valid-order count
curl -s -H "Authorization: Bearer $T" "$HUB/api/v1/certificates?origin=synced&limit=1" | jq '.meta.total'
# synced certificates should never be unmanaged (expect 0)
curl -s -H "Authorization: Bearer $T" "$HUB/api/v1/certificates?origin=synced&management_state=unmanaged&limit=1" | jq '.meta.total'
```

The first number must equal your count of valid orders in CertCentral. Run the sync a
second time and confirm it reports 0 added.
