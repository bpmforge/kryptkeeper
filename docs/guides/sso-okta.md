# Single sign-on with Okta (OIDC, SAML, SCIM)

This recipe connects Okta to Kryptkeeper for browser sign-in (OIDC or SAML)
and for user and group provisioning (SCIM). It lists the exact settings on both
sides. Nothing here has been run against a real Okta org yet; the hub side is
exercised against Keycloak (`tests/live/sso`), and the Okta side is tracked in
[`docs/release/SSO_UAT_RECORD.md`](../release/SSO_UAT_RECORD.md). Where a value
depends on your org, it says **verify in your tenant**.

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
- A person removed from every group keeps the last role the hub saved; end
  access by deactivating the user (SCIM `active=false`), not by emptying groups.
- Preview a mapping without signing in: `GET /api/v1/auth/role-map/preview?groups=a,b`
  (needs role-management permission) returns the role, the unmapped policy and
  whether that person could sign in.

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
  of real time (SAML assertions are short-lived).
- `APP_AUTH_LOGIN_SIGNING_SECRET` is set to a long random value (the browser
  session is signed with it).
- An Okta org where you can create app integrations and a SCIM provisioning app.
- Okta groups for your roles, for example `kk-admins`, `kk-operators`,
  `kk-auditors`.

## 1. OIDC

### Okta side

Create an app integration: **OIDC - OpenID Connect**, application type **Web
Application**.

| Setting | Value |
|---------|-------|
| Grant type | Authorization Code |
| Sign-in redirect URIs | `https://<hub>/api/v1/auth/oidc/callback` |
| Assignments | The groups that may sign in |
| Scopes | `openid`, `profile`, `email` |
| Groups claim name | `groups` |
| Groups claim filter | Matches regex `.*` (narrow it to your `kk-` groups in production) |
| Groups claim included in | ID Token (Always) |

Copy the **Client ID** and **Client secret**. The issuer is your authorization
server's issuer URL, for example `https://<okta-domain>/oauth2/default`
(**verify in your tenant**: the groups claim must be configured on the same
authorization server the issuer names).

### Hub side

| Variable | Value |
|----------|-------|
| `APP_OIDC_LOGIN_ENABLED` | `true` |
| `APP_OIDC_ISSUER` | `https://<okta-domain>/oauth2/default` |
| `APP_OIDC_AUDIENCE` | the Client ID |
| `APP_OIDC_CLIENT_ID` | the Client ID |
| `APP_OIDC_CLIENT_SECRET` | the Client secret |
| `APP_OIDC_DISCOVERY_URL` | `https://<okta-domain>/oauth2/default/.well-known/openid-configuration` |
| `APP_OIDC_REDIRECT_URL` | `https://<hub>/api/v1/auth/oidc/callback` |
| `APP_OIDC_LOGIN_SCOPES` | `openid profile email` |
| `APP_OIDC_POST_LOGIN_REDIRECT_URL` | `/` (where the browser lands after sign-in) |
| `APP_AUTH_ROLE_CLAIM` | `groups` |
| `APP_AUTH_ROLE_MAP_JSON` | `[{"claim_value":"kk-admins","role":"pki-admin"},{"claim_value":"kk-operators","role":"pki-operator"},{"claim_value":"kk-auditors","role":"auditor"}]` |

Claims the hub reads from the ID token: `email` (matched to the account's
email) with `email_verified` true, `nonce`, and the claim named by
`APP_AUTH_ROLE_CLAIM`. An ID token without a verified email cannot be matched
to an account.

## 2. SAML

### Okta side

Create an app integration: **SAML 2.0**.

| Setting | Value |
|---------|-------|
| Single sign-on URL | `https://<hub>/api/v1/auth/saml/acs` (also use it as Recipient and Destination) |
| Audience URI (SP Entity ID) | the value you will put in `APP_SAML_AUDIENCE`, for example `https://<hub>/saml/sp` |
| Name ID format | EmailAddress |
| Application username | Email |
| Response | **Signed** (the hub requires the response envelope to be signed) |
| Assertion signature | Signed |
| Signature algorithm | RSA-SHA256 |
| Attribute statement: name `Email` | value `user.email` |
| Group attribute statement: name `groups` | filter Matches regex `.*` (narrow in production) |
| Single Logout / signed requests | off (the hub sends unsigned AuthnRequests) |

From **Sign On > SAML Signing Certificates > View SAML setup instructions**
copy the **Identity Provider Single Sign-On URL**, the **Identity Provider
Issuer**, and the **X.509 certificate** (PEM).

### Hub side

| Variable | Value |
|----------|-------|
| `APP_SAML_LOGIN_ENABLED` | `true` |
| `APP_SAML_IDP_SSO_URL` | Identity Provider Single Sign-On URL |
| `APP_SAML_IDP_ISSUER` | Identity Provider Issuer |
| `APP_SAML_IDP_CERTIFICATE` | the X.509 certificate, PEM |
| `APP_SAML_SP_ISSUER` | your SP entity ID, for example `https://<hub>/saml/sp` |
| `APP_SAML_ACS_URL` | `https://<hub>/api/v1/auth/saml/acs` |
| `APP_SAML_AUDIENCE` | the Audience URI above |
| `APP_AUTH_ROLE_CLAIM` | `groups` (the SAML attribute name carrying group values) |
| `APP_AUTH_ROLE_MAP_JSON` | as in the OIDC table |

The hub takes the email from an attribute named `Email` or `email`, else from
the NameID (hence NameID format EmailAddress).

Notes:

- **Start sign-in from the hub** (`/api/v1/auth/saml/login`). A tile click in
  the Okta dashboard sends an unsolicited, IdP-initiated response, which the
  hub refuses unless you set `APP_SAML_ALLOW_IDP_INITIATED=true`. Leave it off
  unless you need dashboard launch; it removes the request-binding check.
- A SAMLResponse is accepted once; re-posting it is refused.

## 3. SCIM and the group to role map

### Hub side

| Variable | Value |
|----------|-------|
| `APP_SCIM_TOKEN` | a long random bearer token (also entered in Okta) |
| `APP_SCIM_GROUP_ROLE_MAP_JSON` | a JSON object of Okta group name to role, for example `{"kk-admins":"pki-admin","kk-operators":"pki-operator","kk-auditors":"auditor"}` |
| `APP_SCIM_DEFAULT_ROLE` | leave unset (a user in no mapped group has no role and cannot sign in); setting it grants that role to every SCIM-created user |

SCIM requests authenticate with `Authorization: Bearer <APP_SCIM_TOKEN>`;
ordinary user sessions are rejected there.

### Okta side

Add the provisioning app (**SCIM 2.0 Test App (Header Auth)**, or a SCIM
connector in your own app integration), then configure provisioning:

| Setting | Value |
|---------|-------|
| SCIM connector base URL | `https://<hub>/scim/v2` |
| Unique identifier field for users | `userName` |
| Supported provisioning actions | Push New Users, Push Profile Updates, Push Groups |
| Authentication mode | HTTP Header |
| Authorization (Bearer token) | the `APP_SCIM_TOKEN` value |
| To App | enable Create Users, Update User Attributes, Deactivate Users |

Map `userName` to the user's email address (the hub reads `userName` when it
contains `@`, else `emails[0].value`). Push the role groups with Push Groups.

What the hub supports (covered by `internal/bootstrap/scim_conformance_test.go`):
PATCH `replace`/`add`/`remove` with or without a path, `active` as a boolean or
a string, `members` add, remove (array or `members[value eq "<id>"]`) and
replace; list filters `eq`, `sw`, `co` on one clause (for example
`userName eq "a@b.c"`); `startIndex`/`count` paging. PUT is not supported; if
your Okta app only sends PUT for profile updates, those updates fail
(**verify in your tenant**), but create, group push and deactivate use POST,
PATCH and DELETE. SCIM users are created in the default tenant.

## 4. Verify

1. Put three test users in `kk-admins`, `kk-operators` and `kk-auditors`, assign
   them to the apps, and let provisioning run. Confirm each exists:
   `curl -H "Authorization: Bearer $APP_SCIM_TOKEN" 'https://<hub>/scim/v2/Users?filter=userName%20eq%20%22user@example.com%22'`.
2. Sign each one in (OIDC, then SAML). `GET /api/v1/protected/whoami` with the
   session shows `role`: `pki-admin`, `pki-operator`, `auditor`.
3. Provision a fourth user in a group that is not mapped and sign in: expect
   **403**, no session cookie.
4. Deactivate (unassign) a signed-in user in Okta. Within 15 minutes, their old
   session returns 401 and a fresh sign-in is refused. Access is checked on
   every request, so it normally ends as soon as Okta sends the deactivation.

Record outcomes in [`SSO_UAT_RECORD.md`](../release/SSO_UAT_RECORD.md).

## Troubleshooting

| Symptom | Likely cause |
|---------|--------------|
| SAML 401, nothing else | Clock skew over a minute, `APP_SAML_AUDIENCE` not equal to Okta's Audience URI, Response not set to Signed, or the wrong IdP certificate |
| SAML 401 only from the Okta dashboard tile | IdP-initiated response; start from the hub or set `APP_SAML_ALLOW_IDP_INITIATED=true` |
| OIDC 401 after Okta sign-in | Account not provisioned, ID token has no verified `email`, or the issuer/audience do not match the token |
| 403 "no Kryptkeeper role is mapped" | No group matched `APP_AUTH_ROLE_MAP_JSON` and the account has no role; check the groups claim name and the group filter, or preview with `/api/v1/auth/role-map/preview` |
| SCIM 401 | Wrong or missing `APP_SCIM_TOKEN` |
| SCIM 400 `invalid filter` | Only single-clause `eq`, `sw`, `co` filters are accepted (no `and`/`or`) |
| User created, cannot sign in | The account has no role: its groups were pushed before `APP_SCIM_GROUP_ROLE_MAP_JSON` was set; push the group again |
