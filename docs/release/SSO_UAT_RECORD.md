# SSO UAT record (Okta and Entra ID)

This is the manual acceptance record for single sign-on against **real
identity-provider tenants**. The automated Keycloak run
([`tests/live/sso/README.md`](../../tests/live/sso/README.md)) proves the hub's
OIDC, SAML and SCIM code paths against a stand-in IdP; it says nothing about
how Okta or Entra ID behave, which is what this record is for.

Every row ships unfilled. Only a human with a real tenant can fill one; nobody
has run these flows yet, and no row may be completed from a reading of the
code, a screenshot, or the Keycloak run. Recipes: [Okta](../guides/sso-okta.md),
[Entra ID](../guides/sso-entra.md).

Legend: a tester replaces the Result cell with PASS or FAIL after running the
flow, and fills Date (UTC, `YYYY-MM-DD`) and Tester; put tenant details,
hub version and anything surprising in Notes.

## How to run each flow

| Flow | What the tester does | A row passes when |
|------|----------------------|-------------------|
| OIDC login | Provision a user in a mapped group, open the hub, sign in with the IdP over OIDC | The session is created and `GET /api/v1/protected/whoami` shows the role mapped to that group |
| SAML login | Same, over SAML (SP-initiated from the hub's SAML login URL) | Same role as above; a second post of the same SAMLResponse is refused |
| Unmapped 403 | Sign in as a provisioned user in no mapped group (default `APP_AUTH_UNMAPPED_ROLE`) | The hub answers 403 and sets no session cookie |
| SCIM create | Assign a user and a group to the IdP's provisioning app | The user appears in `GET /scim/v2/Users`, with the role from `APP_SCIM_GROUP_ROLE_MAP_JSON` |
| SCIM deactivate (15 min) | Unassign or deactivate the user in the IdP, note the time, retry the old session | The old session and a fresh sign-in are both refused within 15 minutes of the deactivation |

## Environment

| Item | Value |
|------|-------|
| Hub version / commit | _to be filled by tester_ |
| Hub URL | _to be filled by tester_ |
| Okta org / plan | _to be filled by tester_ |
| Entra tenant / license | _to be filled by tester_ |

## Results

| Date | IdP | Flow | Tester | Result | Notes |
|------|-----|------|--------|--------|-------|
|  | Okta | OIDC login |  | PENDING (human run required) |  |
|  | Okta | SAML login |  | PENDING (human run required) |  |
|  | Okta | Unmapped 403 |  | PENDING (human run required) |  |
|  | Okta | SCIM create |  | PENDING (human run required) |  |
|  | Okta | SCIM deactivate <= 15 min |  | PENDING (human run required) |  |
|  | Entra ID | OIDC login |  | PENDING (human run required) |  |
|  | Entra ID | SAML login |  | PENDING (human run required) |  |
|  | Entra ID | Unmapped 403 |  | PENDING (human run required) |  |
|  | Entra ID | SCIM create |  | PENDING (human run required) |  |
|  | Entra ID | SCIM deactivate <= 15 min |  | PENDING (human run required) |  |
