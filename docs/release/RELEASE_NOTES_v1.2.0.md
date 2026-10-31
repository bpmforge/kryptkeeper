# Kryptkeeper 1.2.0

A feature release for CAs with name constraints. ACME clients can only ask for
a CN, so under a CA whose name constraints permit only, say, `DC=foo,DC=bar`
they used to get certificates that relying parties reject. A template can now
fix the subject components that come after the CN, and the CA refuses, before
signing, any certificate that its issuing CA's name constraints would make
invalid. Nothing in the database schema changes.

Read the upgrade notes if you bind a template to ACME: it now governs ACME
issuance fully.

## Added

- **Fixed subject components on templates.** `subject_policy.fixed_rdns`
  (DC, O, OU, L, ST, C) are appended after the CN of every certificate issued
  under the template, whatever the request asked for. A win-acme request for
  `CN=webserver.foo.bar` is issued as `CN=webserver.foo.bar,DC=foo,DC=bar`.
  Set it on the Templates page ("Fixed subject components") or in the API.
  It applies on API issuance, renewal, Windows autoenrollment and ACME. Setup:
  [docs/ops/ACME_NAME_CONSTRAINTS.md](../ops/ACME_NAME_CONSTRAINTS.md).
- **Name-constraint check before signing.** Every issuance is checked against
  the DNS, IP, email, URI and directoryName constraints of the issuing CA and
  of its ancestors held by the hub. A certificate that would be invalid is
  refused with a `name_constraints` policy error naming the subtree, instead
  of being signed and failing at the relying party.

## Changed

- **ACME uses its template's whole policy.** A template named by
  `KRYPTKEEPER_ACME_TEMPLATE` or by an ACME provisioner used to decide only
  who may enroll. Its allowed algorithms, minimum key size, EKUs, name policy
  and fixed subject components now apply as well. A template validity shorter
  than 90 days shortens ACME certificates, a request that breaks the template
  gets an ACME `badCSR` error naming the rule, and an unreadable template
  stops ACME issuing (fail closed).

## Fixed

- An external CA whose issuing certificate carries directoryName name
  constraints failed every issuance with "does not chain to this external
  CA's trusted certificates", because the Go library cannot evaluate those
  constraints. They are now checked by the hub instead.
- Saving a template in the UI cleared its device-attestation grant.

## Other changes

- The public release workflow runs its tests as seven parallel jobs.
- A connector test that failed under heavy load has a realistic wait budget.

## Upgrade notes

- No migrations, no new settings.
- **Check every template bound to ACME** (`KRYPTKEEPER_ACME_TEMPLATE`, or a
  provisioner's `template_id`). After upgrading, ACME refuses orders that the
  template does not allow:
  - its extended key usages must include `serverAuth` (or `clientAuth` for
    device attestation), or be empty;
  - its name policy, if set, must cover the names your ACME clients request;
  - its allowed algorithms and minimum key size must cover the keys your
    clients generate.
- A CA that issued certificates outside its own name constraints will now
  refuse those requests. Those certificates were already invalid to any
  relying party that checks constraints.

## Verifying this release

The steps are the same as for 1.1.3 ([packaging/SIGNING.md](../../packaging/SIGNING.md)):

```bash
cosign verify \
  --certificate-identity "https://github.com/bpmforge/kryptkeeper/.github/workflows/release.yml@refs/tags/v1.2.0" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  ghcr.io/bpmforge/charts/kryptkeeper:1.2.0
```
