# Migrate from Venafi TPP to Kryptkeeper

This playbook takes a Venafi Trust Protection Platform (TPP) estate from inventory,
through a parallel run, to cutover. It uses only tooling in this repo: the template
importer (`internal/migration/venafi`, API `/api/v1/migration/*`) and the certificate
inventory APIs. Style and phasing follow [Replace ADCS](replace-adcs.md).

> **Honesty note.** The importer's TPP attribute names come from Venafi's public
> documentation (https://docs.venafi.com) and are **not verified against a real TPP
> export** (see the comment above the attribute constants in
> `internal/migration/venafi/venafi.go`). Treat every attribute name below as an
> assumption to verify against your own export. Any attribute the importer does not
> recognise is reported as unmapped, so a wrong name lowers the visible mapping
> percentage rather than silently dropping data. The importer has no UI; use the API.

**Private keys do not migrate.** TPP does not export private keys and Kryptkeeper rejects
any bundle that contains one. Certificates are inventoried for tracking; they are
**re-issued** by Kryptkeeper (or your upstream CA) at their next renewal, not moved.

## Overview

1. Inventory: export the TPP policy-folder tree and the certificate set.
2. Import templates (dry run, then apply with a second approver).
3. Import certificates and assign owners.
4. Parallel run: Venafi stays authoritative; Kryptkeeper reports.
5. Cutover per application group, then decommission after two renewal cycles.

Certificates imported this way land as `origin=imported`, `management_state=unmanaged`.

## Prerequisites

- A running Kryptkeeper hub ([Getting Started](getting-started.md)) and a token with
  `ca.manage` for the migration routes. `$HUB` is the hub URL, `$T` the bearer token.
- A second approver: `POST /api/v1/migration/apply` is queued in `/api/v1/pending-actions`
  and a different person must approve it.
- A TPP policy-folder export as JSON, shaped
  `{"folders":[{"path":"\\VED\\Policy\\Web","attributes":{"Key Algorithm":["RSA"]}}]}`
  (max 48 KiB per request; split by subtree if larger). How you produce this from TPP
  (for example from its configuration API) is not defined by Kryptkeeper: [assumption to verify].
- A PEM export of the certificates (public certificates only), and a list of
  folder -> owner team.
- Confirm the importer is registered: `curl -H "Authorization: Bearer $T" $HUB/api/v1/migration/sources`.

### Step A: dry run (writes nothing)

```bash
jq -Rs '{source:"venafi", content:.}' tpp-folders.json |
  curl -s -X POST $HUB/api/v1/migration/dryrun \
    -H "Authorization: Bearer $T" -H "Content-Type: application/json" -d @-
```

Read the per-field mapping status and the unmapped count before you apply.

### Step B: apply (approval gated)

```bash
jq -Rs '{source:"venafi", content:.}' tpp-folders.json |
  curl -s -X POST $HUB/api/v1/migration/apply \
    -H "Authorization: Bearer $T" -H "Content-Type: application/json" -d @-
```

The response is `202`; a second person approves it in `/api/v1/pending-actions`. The
templates are then created under a batch id (`GET /api/v1/migration/batches`, report:
`GET /api/v1/migration/{batch}/report`). Re-running an applied export creates nothing.

### Step C: certificates and owners

```bash
# CSV header: cert_b64[,owner_email,owner_team,service_name]
jq -Rs '{format:"csv", bundle:.}' certs.csv |
  curl -s -X POST $HUB/api/v1/certificates/bulk-import \
    -H "Authorization: Bearer $T" -H "Content-Type: application/json" -d @-
```

Duplicates (by SHA-256 fingerprint) are skipped. For certificates already imported, set an
owner with `PATCH /api/v1/certificates/{fingerprint}/ownership`, or map hosts, IPs and
CIDRs to teams in bulk with `POST /api/v1/ownership/cmdb-import`.

## Field mapping

From `Map` in `internal/migration/venafi/venafi.go`. Status is the importer's own report.

| TPP attribute | Kryptkeeper target | Status |
|---|---|---|
| Key Algorithm | `allowed_algorithms` (RSA, ECC to ECDSA; other values make the folder unsupported) | mapped |
| Key Bit Strength | `min_key_size` | mapped |
| Elliptic Curve | none, chosen by the CA | partial |
| Domain Suffix Whitelist | `name_policy.allowed_dns_suffixes` | mapped |
| Prohibit Wildcard | not enforced by the template; enforced by the issuing CA profile | partial |
| Contact | `owner_hint`, carried on the batch item only; apply owners via CSV or cmdb-import | partial |
| Approver | `require_approval`; approver names are not carried (approval defaults to pki-admin) | partial |
| Disable Automatic Renewal | `auto_enroll` | mapped |
| Renewal Window | `renewal_overlap` | mapped |
| Validity Period | `validity_period` (default `P365D` when unset) | mapped |
| Management Type | per-certificate state, not a template field | partial |
| Certificate Authority | not migrated; pick a CA after import | unmapped |

Folder -> template, owner:

| Venafi | Kryptkeeper |
|---|---|
| Folder path (`\VED\Policy\Web\Prod`) | Template name `Web-Prod`; display name is the last path segment. Inheritance is flattened; a folder that sets no attribute of its own produces no template |
| Contact | `owner_team` via `owner_hint`, then set with CSV `owner_team` or `ownership/cmdb-import` |

Key usage and extended key usage are synthesised (digitalSignature, keyEncipherment;
clientAuth, serverAuth) and reported partial: review them before use.

## Parallel run

Keep Venafi enrolling. Kryptkeeper only inventories and alerts. Optionally take a pilot
group under management with `POST /api/v1/estate/takeover` or `/estate/takeover/bulk`
(max 500 items) using `renewal_path {"mode":"internal"}` or
`{"mode":"connector","connector_id":"..."}`. These routes are **audit-only**
(`estate.takeover` rows); they are not approval gated. Do not rely on a gate here.

## Cutover

Per application group: take it under management, repoint the enrolment client (ACME, EST
or SCEP) at Kryptkeeper, let the next renewal re-issue from Kryptkeeper. Decommission
Venafi only after two renewal cycles have completed on Kryptkeeper (a human decision,
outside this tooling).

## Rollback

- Templates: `POST /api/v1/migration/{batch}/rollback` disables the templates the batch
  created and never deletes them. Templates with a pending certificate approval stay
  active and are reported as kept. Rolling back twice is a no-op.
- Certificates: `POST /api/v1/estate/revert {"fingerprint":"..."}` returns a managed
  certificate to `management_state=unmanaged`. Recorded renewal metadata remains as stale
  data. Imported certificates are not deleted.
- Leave the incumbent Venafi enrolment in place until cutover is signed off, so Venafi
  stays authoritative and rollback is just "stop using Kryptkeeper for that group".

## Verification query

```bash
# imported count equals the TPP export count
curl -s -H "Authorization: Bearer $T" "$HUB/api/v1/certificates?origin=imported&limit=1" | jq '.meta.total'
# no imported certificate without an owner team (expect 0)
curl -s -H "Authorization: Bearer $T" "$HUB/api/v1/certificates?origin=imported&owner=unassigned&limit=1" | jq '.meta.total'
```

The first number must equal the number of certificates in the TPP export; the second
must be 0. For a fingerprint-by-fingerprint check, run `scripts/migration-verify.sh --manifest FILE`
(see `tests/live/migration/README.md`); it exits non-zero unless every manifest fingerprint is mapped.
