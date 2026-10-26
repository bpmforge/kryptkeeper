# Cloud certificates in the inventory

A cloud scan (AWS ACM, Azure Key Vault, GCP Certificate Manager; scan types
`cloud_acm`, `cloud_azure_kv`, `cloud_gcp_cm`, scopes in `discovery.cloud_scopes`)
now writes what it finds into the certificate inventory, so the certificates
are listed, graded, reported and eligible for takeover like any other row.

## How a row is made

- **Estate:** origin `discovered`, management `unmanaged`, source
  `discovery_cloud`, like every other discovery source. A row that is already
  managed (a certificate this hub issued and later exported to the cloud) is
  never changed; the cloud resource is still recorded against it.
- **Fingerprint:** the SHA-256 of the real certificate whenever the provider
  returns the body. ACM needs `acm:GetCertificate`, Key Vault needs
  `certificates/get`, Certificate Manager returns it in the list. The same
  certificate found twice (two regions, or already discovered on a server) is one
  row with several resources.
- **No body (a denied permission, a pending certificate):** only AWS ACM
  certificates with a known RSA or EC key and an expiry become a row, keyed by a
  synthetic fingerprint (`sha256` of a versioned label, provider, scope and
  resource id) and marked `synthetic` on the resource link. Key Vault and
  Certificate Manager list no key type, so without the body they are counted as
  `skipped`, never stored with a guessed key. When the body later arrives, the
  real row replaces the synthetic one (the old row is marked renewed and points
  at the new one).

## Where it came from

`certificate_cloud_resources` (migration 000383) holds one row per
provider, scope, resource id and tenant: account (AWS account id, vault host,
GCP project), region, status, in-use, first and last seen, and whether the
resource is still there. A resource a scan no longer sees is marked removed
(`currently_active` off, `removed_at` set) only for scopes that answered; a
failed scope retires nothing. The certificate row itself stays, like a
discovered certificate whose endpoint went quiet.

## Tenancy

Links carry the tenant of the scan job that found them, and a scan only
refreshes or retires its own tenant's links. Certificate visibility is the
same as for every other CA-less discovered row (it follows the issuing CA's
tenant, so a cloud certificate is visible to the default tenant and to
super-admins).

## Reading the result

The scan job summary has an `import` block: `imported`, `known` (already in the
inventory, deduplicated), `skipped`, `metadata_only`, `removed_at_source` and
any `failed`. A rerun reports `imported: 0`.

# Per-agent inventory

`GET /api/v1/agents/{id}/inventory?limit=&offset=` returns the certificates an
agent last pushed and the files its host pass flagged, with counts of every
statted file by posture. Public facts only. Authorized like
`GET /api/v1/agents/{id}/tasks`: agents have no tenant (D-203), so with
multi-tenancy on only a platform super-admin may read it.
