# Certificate templates by issuing protocol (W20-09)

| Path | Template concept | What governs the issued certificate |
|---|---|---|
| REST API (`POST /api/v1/certificates`) | Yes: `template_id` | The template's policy: algorithms, minimum key size, maximum validity, EKUs (`bootstrap.TemplatePolicy`). |
| WSTEP (Windows autoenrollment) | Yes: the CSR's certificate-template extension (Windows), or a template OID or name in `TokenType` | That template's policy, enforced by the CA engine. Its validity period is the issued validity; one year if it sets none. Advertised identically by XCEP. The template's enrollee type (machine or user, W20-17) must match the caller. |
| ACME | No | Fixed profile: 90 days, server-auth, names validated by challenge. |
| EST | No | Fixed profile: one year, client-auth, identity bound by EST authentication (D-112). |
| SCEP | No | Fixed profile: one year, client-auth. Names come from a one-time challenge minted through the API, never the CSR (W20-16, `docs/ops/SCEP.md`). |
| CMP | Approval only | Fixed profile: one year, client-auth, shared-secret MAC. `KRYPTKEEPER_CMP_TEMPLATE` names a template whose `require_approval` makes ir/cr/kur answer `waiting` until approved (clients poll with `pollReq`). |

The protocols without templates are not unconstrained. Every issuance on
every path also passes the data-driven issuance policy engine
(`issuance_policies`, W5-05), which applies per CA, and receives the CA's
CRL/OCSP pointers (W20-12).

## Where a template is resolved

One list of offered templates (active, with an OID) feeds three things in
`cmd/kryptkeeper/main.go`:

- what XCEP tells Windows;
- the WSTEP resolver for the CSR extension;
- the WSTEP `TokenType` lookup.

So a template a client is offered is always the template it is held to.

A WSTEP certificate's inventory row carries the ID of the template it was
held to (W20-15), as an API-issued row does. The other protocols' rows have
no template ID, because no template governed them.
