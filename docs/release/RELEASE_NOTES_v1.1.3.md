# Kryptkeeper 1.1.3

A fix release. Editing a CA's display name, CRL distribution points or OCSP URL through the API
now takes effect. Upgrade if you set custom revocation URLs on a CA. Nothing in the database
schema changes.

## Fixed

- **CA edits were not saved, and CRL/OCSP overrides were ignored.** On a hub with the built-in
  CA engine (the default), `PATCH /api/v1/cas/{id}` returned success but only renamed the CA in
  memory, so the new name was lost on restart. It accepted `crl_distribution_points` and
  `ocsp_service_url` and stored neither, so certificates kept pointing at the hub's own CRL and
  OCSP endpoints. All three fields are now saved and read back, and new certificates use the
  CA's configured URLs.
  - URLs are validated: CRL distribution points must be absolute `http`, `https` or `ldap` URLs
    (at most 8), and the OCSP URL an absolute `http` or `https` URL, or empty to clear it.
  - An external CA refuses CRL and OCSP changes with 422, because its revocation data comes
    from its upstream CA.
  - The `ca.update` audit event now records each changed field as old -> new.
  - Certificates issued before an edit keep the URLs they were issued with.

## Other changes

- Removed unused code found by an anti-slop audit (no behaviour change).

## Upgrade notes

- No migrations, no new settings. The database columns already existed.
- If you set CRL or OCSP URLs on a CA under 1.1.2 or earlier, set them again after upgrading:
  they were never stored.

## Verifying this release

The steps are the same as for 1.1.2 ([packaging/SIGNING.md](../../packaging/SIGNING.md)):

```bash
cosign verify \
  --certificate-identity "https://github.com/bpmforge/kryptkeeper/.github/workflows/release.yml@refs/tags/v1.1.3" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  ghcr.io/bpmforge/charts/kryptkeeper:1.1.3
```
