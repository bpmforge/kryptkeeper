# Single sign-on with Microsoft Entra ID (OIDC, SAML, SCIM)

This recipe connects Entra ID to Kryptkeeper for browser sign-in (OIDC or SAML)
and for user and group provisioning (SCIM). It lists the exact settings on both
sides. Nothing here has been run against a real Entra tenant yet; the hub side
is exercised against Keycloak (`tests/live/sso`), and the Entra side is tracked
in [`docs/release/SSO_UAT_RECORD.md`](../release/SSO_UAT_RECORD.md). Where a
value depends on your tenant, it says **verify in your tenant**.

## How roles are decided

Read this first; it differs from what most SSO products do.

- **Accounts are never created at login.** OIDC and SAML sign-in both refuse a
  person the hub does not already know (401). SCIM (or an operator) creates the
  account first.
- **The role is decided at sign-in, in this order:**
  1. If `APP_AUTH_ROLE_CLAIM` is set and a value of that claim (OIDC) or
     attribute (SAML) matches an entry in `APP_AUTH_ROLE_MAP_JSON`, the first
     matching entry (list order is precedence) sets the role and is saved on
     the account.
  2. Otherwise the role already on the account is used. SCIM sets it from
     group membership through `APP_SCIM_GROUP_ROLE_MAP_JSON`.
  3. Otherwise sign-in is refused with **403**
     ("no Kryptkeeper role is mapped to your IdP groups"). Set
     `APP_AUTH_UNMAPPED_ROLE=read-only` only if you want such people to get the
     read-only `viewer` role instead.
- **Entra emits group object IDs (GUIDs) in tokens, not group names.** The
  token-side map therefore needs GUIDs as `claim_value`, while the SCIM-side
  map uses the group's display name (what Entra sends as the SCIM group
  `displayName`). The two maps are separate settings; you can use either or
  both. Using only the SCIM map avoids GUIDs in configuration.
- A person removed from every group keeps the last role the hub saved; end
  access by deactivating the user (SCIM `active=False`), not by emptying groups.
- Preview a mapping without signing in: `GET /api/v1/auth/role-map/preview?groups=a,b`
  (needs role-management permission).

Routes the IdP needs (replace `<hub>` with the hub's public host name):

| Purpose | URL |
|---------|-----|
| OIDC start | `GET https://<hub>/api/v1/auth/oidc/login` |
| OIDC redirect URI | `https://<hub>/api/v1/auth/oidc/callback` |
| SAML start (SP-initiated) | `GET https://<hub>/api/v1/auth/saml/login` |
| SAML ACS | `POST https://<hub>/api/v1/auth/saml/acs` |
| SCIM base | `https://<hub>/scim/v2` (`/Users`, `/Groups`) |

## Prerequisites

- The hub is reachable over HTTPS at `<hub>`, and its clock is within a minute
  of real time.
- `APP_AUTH_LOGIN_SIGNING_SECRET` is set to a long random value.
- An Entra tenant where you can register applications and add enterprise
  applications (Entra ID P1 or higher is needed for group-based assignment and
  for automatic provisioning to a non-gallery SCIM app; **verify in your tenant**).
- Entra groups for your roles, for example `kk-admins`, `kk-operators`,
  `kk-auditors`.

## 1. OIDC

### Entra side

Create an **App registration** (single tenant, platform **Web**).

| Setting | Value |
|---------|-------|
| Redirect URI (Web) | `https://<hub>/api/v1/auth/oidc/callback` |
| Certificates & secrets | create a client secret and copy its value |
| Token configuration > Add groups claim | Security groups (or Groups assigned to the application); emits group **object IDs** |
| Token configuration > Optional claims (ID token) | `email` |
| API permissions | Microsoft Graph delegated `openid`, `profile`, `email` |

The issuer for a v2.0 endpoint is `https://login.microsoftonline.com/<tenant-id>/v2.0`
(**verify in your tenant**; the issuer in the ID token must equal
`APP_OIDC_ISSUER` exactly). The ID token's audience is the application (client) ID.

### Hub side

| Variable | Value |
|----------|-------|
| `APP_OIDC_LOGIN_ENABLED` | `true` |
| `APP_OIDC_ISSUER` | `https://login.microsoftonline.com/<tenant-id>/v2.0` |
| `APP_OIDC_AUDIENCE` | the application (client) ID |
| `APP_OIDC_CLIENT_ID` | the application (client) ID |
| `APP_OIDC_CLIENT_SECRET` | the client secret value |
| `APP_OIDC_DISCOVERY_URL` | `https://login.microsoftonline.com/<tenant-id>/v2.0/.well-known/openid-configuration` |
| `APP_OIDC_REDIRECT_URL` | `https://<hub>/api/v1/auth/oidc/callback` |
| `APP_OIDC_LOGIN_SCOPES` | `openid profile email` |
| `APP_OIDC_POST_LOGIN_REDIRECT_URL` | `/` |
| `APP_AUTH_ROLE_CLAIM` | `groups` (optional; omit to rely on the SCIM map) |
| `APP_AUTH_ROLE_MAP_JSON` | `[{"claim_value":"<kk-admins object id>","role":"pki-admin"},{"claim_value":"<kk-operators object id>","role":"pki-operator"}]` |

Claims the hub reads from the ID token: `email` (matched to the account's
email), `email_verified`, `nonce`, and the claim named by `APP_AUTH_ROLE_CLAIM`.

**Known gap, verify in your tenant first.** The hub only matches an account by
email when the token says `email_verified` is true (otherwise it would let an
IdP user claim someone else's address). Entra does not normally send an
`email_verified` claim. If yours does not, OIDC sign-in answers 401 and this
build offers no way to link an Entra identity to an account by hand. SAML
sign-in does not have this requirement; use SAML for Entra until this is
resolved (see the UAT record).

**Group overage.** A token lists at most 200 groups (150 in SAML). Beyond that
Entra sends a link instead of the list, and the hub sees no group, so only the
role already saved on the account (from SCIM) applies. Assign the application
to a small set of role groups, or use "Groups assigned to the application".

## 2. SAML

### Entra side

Add an **Enterprise application** (create your own, non-gallery) and choose
**Single sign-on > SAML**.

| Setting | Value |
|---------|-------|
| Identifier (Entity ID) | the value you will put in `APP_SAML_AUDIENCE`, for example `https://<hub>/saml/sp` |
| Reply URL (Assertion Consumer Service URL) | `https://<hub>/api/v1/auth/saml/acs` |
| Sign-on URL | `https://<hub>/api/v1/auth/saml/login` |
| Unique User Identifier (Name ID) format | Email address, source `user.mail` |
| Attribute: name `Email` | source attribute `user.mail` |
| Groups claim | Security groups / Groups assigned to the application (emits object IDs); set the claim's name to `groups` |
| SAML Signing Certificate > Signing Option | **Sign SAML response and assertion** (the hub requires the response envelope to be signed) |
| Signing algorithm | SHA-256 |
| Verification certificates / signed requests | not required (the hub sends unsigned AuthnRequests) |

From **Set up** copy the **Login URL**, the **Microsoft Entra Identifier**
(issuer) and download the signing certificate (Base64), then convert it to PEM
text for the variable below.

### Hub side

| Variable | Value |
|----------|-------|
| `APP_SAML_LOGIN_ENABLED` | `true` |
| `APP_SAML_IDP_SSO_URL` | the Login URL |
| `APP_SAML_IDP_ISSUER` | the Microsoft Entra Identifier |
| `APP_SAML_IDP_CERTIFICATE` | the signing certificate, PEM |
| `APP_SAML_SP_ISSUER` | the Identifier (Entity ID) above |
| `APP_SAML_ACS_URL` | `https://<hub>/api/v1/auth/saml/acs` |
| `APP_SAML_AUDIENCE` | the Identifier (Entity ID) above |
| `APP_AUTH_ROLE_CLAIM` | the group attribute name you set (`groups`) if you use the token-side map |
| `APP_AUTH_ROLE_MAP_JSON` | group object IDs to roles, as in the OIDC table |

The hub takes the email from an attribute named `Email` or `email`, else from
the NameID. Starting from the My Apps tile sends an IdP-initiated response,
which the hub refuses unless `APP_SAML_ALLOW_IDP_INITIATED=true`; start from the
hub instead. A SAMLResponse is accepted once.

## 3. SCIM and the group to role map

### Hub side

| Variable | Value |
|----------|-------|
| `APP_SCIM_TOKEN` | a long random bearer token (the Secret Token in Entra) |
| `APP_SCIM_GROUP_ROLE_MAP_JSON` | a JSON object of Entra group **display name** to role, for example `{"kk-admins":"pki-admin","kk-operators":"pki-operator","kk-auditors":"auditor"}` |
| `APP_SCIM_DEFAULT_ROLE` | leave unset (a user in no mapped group has no role and cannot sign in); setting it grants that role to every SCIM-created user |

### Entra side

In the enterprise application open **Provisioning**.

| Setting | Value |
|---------|-------|
| Provisioning Mode | Automatic |
| Tenant URL | `https://<hub>/scim/v2` |
| Secret Token | the `APP_SCIM_TOKEN` value |
| Mappings: `userPrincipalName` to `userName` | keep; `mail` to `emails[type eq "work"].value` |
| Mappings: `Switch([IsSoftDeleted], , "False", "True", "True", "False")` to `active` | keep (Entra sends `active` as the string `"True"`/`"False"`) |
| Mappings: groups | enable "Provision Microsoft Entra ID Groups" so `displayName` and `members` reach the hub |

Use **Test Connection**, then assign users and the role groups to the
application and start provisioning. Entra's provisioning cycle runs about every
40 minutes after the initial one; use **Provision on demand** for a single
user when testing.

The hub's PATCH handling for Entra's shapes (capitalised ops such as `Replace`,
`active` as the string `"False"`, `members[value eq "<id>"]` removal,
`emails[type eq "work"].value` replace as a no-op) is covered by the table
tests in `internal/bootstrap/scim_conformance_test.go`. Other details: list
filters are one clause of `eq`, `sw`, `co` (Entra's existence check
`userName eq "..."` works); PUT is not supported; SCIM users are created in the
default tenant.

## 4. Verify

1. Put three test users in `kk-admins`, `kk-operators` and `kk-auditors`, assign
   them to the application, and provision. Confirm each exists with
   `GET /scim/v2/Users?filter=userName eq "..."` and the SCIM bearer token.
2. Sign each one in (SAML, and OIDC if your tokens carry `email_verified`).
   `GET /api/v1/protected/whoami` with the session shows `role`: `pki-admin`,
   `pki-operator`, `auditor`.
3. Provision a user in an unmapped group and sign in: expect **403**, no
   session cookie.
4. Disable or unassign a signed-in user in Entra. Within 15 minutes (after
   Entra's next provisioning run, or on demand) their old session returns 401
   and a fresh sign-in is refused. Time it from the moment Entra sends the
   deactivation, which is visible in the provisioning logs.

Record outcomes in [`SSO_UAT_RECORD.md`](../release/SSO_UAT_RECORD.md).

## Troubleshooting

| Symptom | Likely cause |
|---------|--------------|
| SAML 401 | Clock skew over a minute, `APP_SAML_AUDIENCE` not equal to the Identifier (Entity ID), Signing Option not "Sign SAML response and assertion", or an old signing certificate after rollover |
| SAML 401 from the My Apps tile | IdP-initiated response; start from the hub or set `APP_SAML_ALLOW_IDP_INITIATED=true` |
| OIDC 401 after Entra sign-in | No verified email in the ID token (see the known gap above), account not provisioned, or the issuer string differs from `APP_OIDC_ISSUER` |
| 403 "no Kryptkeeper role is mapped" | The token carries GUIDs but the map has names (or the reverse), the user is over the group limit, or no group matched and the account has no role |
| SCIM 401 | Wrong Secret Token |
| Users appear but never get a role | The role groups were not pushed, or `APP_SCIM_GROUP_ROLE_MAP_JSON` names do not match Entra's group display names exactly |
| Deactivation is slow | Entra's provisioning interval; use Provision on demand to confirm the hub side is immediate |
