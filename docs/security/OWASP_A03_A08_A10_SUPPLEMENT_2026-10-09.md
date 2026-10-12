# OWASP A03/A04/A08/A10 supplement (2026-10-09)

A second, independent pass (a helper started by the first, interrupted OWASP
run) reported read-only, by code tracing. It agrees with the focused pass in
`OWASP_A03_A08_A10_FINDINGS_2026-10-09.md` on the ACME CRITICAL (its A04-1 =
A04-001), the ACME http-01 SSRF (A10-1 = A10-001; the focused pass proved a
redirect to a metadata path and rates it HIGH), the connector health-probe
SSRF (A10-2 = A10-002), the discovery scanner (A10-3), WinRM `cmdQuote`
(A03-1) and the minor ACME/nonce gaps (A04-4). Only its additional findings
are below.

**SUP-A04-2 (MEDIUM, REAL): CMP issues whatever names the CSR asks for, under one shared secret.**
`internal/cmp/server.go:130-135`; `internal/cmp/protection.go` (verifyPBMProtection). PBM protection is checked correctly (constant-time), but the whole endpoint shares one secret (`KRYPTKEEPER_CMP_SECRET`); the IssuanceRequest carries no names, Subject or CallerNamesOnly, so certTemplate SANs and Subject pass through; senderKID is never compared with the reference; no transactionID/nonce replay tracking.
Preconditions: network access to /cmp; the shared secret (any enrolled CMP client has it). Yields: a 1-year clientAuth certificate for arbitrary SANs and Subject.
Fix: a secret per client bound to its allowed names; set CallerNamesOnly and Subject; replay tracking.

**SUP-A04-3 (MEDIUM, REAL): templates cannot restrict names, and the API path takes SANs from the CSR.**
`internal/bootstrap/certificate_ca_provider.go:326-384`; `internal/ca/template_policy.go:25-31`. TemplatePolicy has algorithms, minimum key size, maximum validity and EKUs only; there is no allowed-domain field, and a policy applies only when a TemplateID is supplied. The API path, ACME and CMP take SANs from the CSR; only EST (suffix allowlist), SCEP (challenge-bound names) and WSTEP (Kerberos identity) constrain names. (isCA never comes from the CSR and CSR extensions are not copied: good.)
Preconditions: certificate.issue. Yields: a certificate for any name, even for a caller meant to be scoped to a template.
Fix: SAN/CN pattern or domain allowlists on templates, enforced in ValidateAgainstTemplate on every path; require a template on API issuance.

**SUP-A08-1 (MEDIUM, REAL): a plugin's network grant is self-declared, and `hosts_from_credential` skips the second approver.**
`internal/bootstrap/delivery_plugins.go:156,296-308,455`; `sdk/delivery-go/abi/manifest.go:218`; `internal/plugins/delivery/host.go:226-229`. Install and load pass the manifest's own Capabilities as the grant; the operator only enables or not. `Tier()` rates network access High only when `len(Hosts) > 0`, so a manifest declaring only `hosts_from_credential` is Standard and is enabled directly by one admin; `allowedHost` then admits whatever host the target credential's URL names. Unsigned uploads are accepted as community.
Preconditions: one pki-admin; delivery plugins on. Yields: unsigned plugin code making https calls to any host named in a credential, with responses returned to the plugin.
Fix: rate any network capability (hosts_from_credential included) High, or show the effective host on approval; store the operator-approved grant separately from the manifest.

**SUP-A10-4 (LOW, REAL): OIDC discovery/JWKS fetch follows redirects to http.**
`internal/bootstrap/auth_oidc.go:31,97`. `requireHTTPSURL` checks only the initial URLs; the client follows https→http redirects. Admin-set issuer; not reflected. Fix: CheckRedirect requiring https.

**SUP-A03-2 (LOW, REAL): log injection from ACME identifiers.**
`internal/acme/server.go:1204,1212,1224` log the account-supplied identifier with `%s`; newlines forge log lines. Fix: `%q`.

Not covered by this pass (as reported): internal/sshkeys principals/critical options (now covered by A01S-4 in the A01 supplement), audit field escaping, citrix/f5 request construction, wazero memory/time limits, plugin update/rollback, SIEM/cloud inventory/k8s base URLs, commercial CA adapters.
