# CSRF Posture

## Enforced posture: Bearer-or-cookie auth, SameSite=Strict, same-origin check on cookie writes

Kryptkeeper does **not** use synchroniser-token or double-submit CSRF tokens. The API accepts
two credential transports, and they are defended differently:

### 1. `Authorization: Bearer` (API keys, JWTs, bootstrap token)

CLI, MCP, agents and integrations authenticate with an explicit header. A browser never adds an
`Authorization` header on its own, so a cross-site page cannot ride it. No CSRF exposure.

### 2. The `kk_token` session cookie (browser UI)

`POST /api/v1/auth/login` (and the OIDC/SAML callbacks) set `kk_token` as an `HttpOnly`,
`SameSite=Strict` cookie, `Secure` whenever the request arrived over TLS. The UI sends it with
`credentials: "include"` to its own origin (`ui/src/lib/api.ts`), and **every** route accepts it
in place of a bearer header (`authenticatePrincipal`, `auth.go`). Cookies are therefore real
ambient authority, and earlier revisions of this document that said auth was Bearer-only were
wrong.

Controls, in order:

1. **`SameSite=Strict`** keeps browsers from attaching the cookie to cross-site requests. It does
   not stop a *same-site* foreign origin (a sibling subdomain with XSS or a takeover, or an
   http downgrade of the same registrable domain).
2. **Origin / Fetch-Metadata check on unsafe methods (F9).** A POST, PUT, PATCH or DELETE that
   authenticates by cookie alone (no `Authorization` header) must be same-origin
   (`crossSiteCookieRequest`, `auth.go`):
   - `Sec-Fetch-Site` is authoritative when present: `same-origin` and `none` pass; `same-site`
     and `cross-site` fail. It is browser-set and cannot be forged by page script.
   - Without it, an `Origin` header must match the request `Host` (or the `X-Forwarded-Host`
     of a fronting proxy); `null` and malformed origins fail.
   - A request carrying neither header is not a browser fetch (curl, scripts, server-to-server)
     and is allowed: CSRF needs a browser to attach the cookie, and rejecting it would break
     cookie-bearing CLI use without protecting anyone.
   - Safe methods (GET, HEAD, OPTIONS, TRACE) are not checked; no handler mutates on them.

   `authenticatePrincipal` enforces this for every handler, so a refused request is an
   authentication failure (401) and the handler records it as a denied audit event, the same
   as any other failed authentication.
3. **No permissive CORS.** The API sends no `Access-Control-Allow-Origin`, so browsers do not
   expose cross-origin responses to foreign pages. This limits reads; the checks above are what
   stop writes.

### Protocol endpoints (ACME, SCEP, EST, OCSP, CRL, CMP, XCEP)

Client-certificate or challenge-based authentication, not browser sessions. Not exposed to
browser CSRF.

### Residual risk

| Scenario | Risk | Mitigation |
|---|---|---|
| Token leak via XSS | High if it occurs | CSP headers on the UI; short-lived access JWT; cookie is `HttpOnly` |
| Same-site XSS or subdomain takeover | Low | Fetch-Metadata / Origin check above; host the UI on its own origin |
| Browser too old to send `Sec-Fetch-Site` and `Origin` on a write | Low | Falls back to allow; all current browsers send at least `Origin` on cross-origin writes |
| HTTP (non-TLS) deployment | High | Deployment guide requires TLS; the `Secure` attribute follows the request scheme |

### Testing

`internal/bootstrap/auth_cookie_csrf_test.go` covers the matrix: same-origin, none, cross-site,
same-site, origin mismatch, `null`, forwarded host, bearer auth, no-header non-browser writes,
and the end-to-end refusal of a valid session cookie on a cross-site write.

## Decision record

- **2026-04-17:** Bearer + same-origin recorded as the CSRF posture, on the assumption that the
  cookie was not an auth transport.
- **2026-10-17 (security review F9), supersedes the above:** the cookie *is* an auth transport on
  all routes. Posture is `SameSite=Strict` plus a mandatory same-origin check on cookie-authenticated
  unsafe methods. No CSRF token is introduced.
- **Owner:** Security team
