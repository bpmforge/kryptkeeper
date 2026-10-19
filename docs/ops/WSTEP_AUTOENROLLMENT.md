# WSTEP / XCEP autoenrollment

Status (2026-10-07): **W20-08 done; W18-08 proven on the lab domain.**
Authenticated WSTEP/XCEP merged in PR #27. GPO-driven autoenrollment and
autoenrollment renewal by a domain-joined Windows 11 machine work against the
hub (runbook below, evidence in `docs/STATUS.md` 2026-10-07). `/wstep` and `/xcep` are served only when
`KRYPTKEEPER_WSTEP_KEYTAB_FILE` and `KRYPTKEEPER_WSTEP_SPN` are set and the
keytab holds that SPN. The lab-only `KRYPTKEEPER_WSTEP_ALLOW_UNAUTHENTICATED`
override from PR #25 is deleted. W18-08 (real GPO autoenrollment) and W19-10
(UAT) are unblocked.

## Why authentication first

Before PR #25, `/wstep` signed any CSR from any caller and returned a 1-year
client-auth certificate with the requested subject from the default CA. On the
lab hub, one anonymous request returned `CN=Administrator`. Authentication is
therefore not hardening on top of a working feature. Without it the endpoint
must not exist. The model is D-109: **Kerberos (SPNEGO) for enrollment,
client certificate for renewal.** Username/password was not chosen.

## Design (W20-08)

### Who may call what

| Endpoint | Credential | Identity it yields |
|---|---|---|
| `/xcep` (policy) | Kerberos (HTTP `Negotiate`) | principal, used only for audit |
| `/wstep` enroll | Kerberos (HTTP `Negotiate`) | principal → certificate subject |
| `/wstep` renew | TLS client certificate issued by this hub | the presented certificate's subject + SANs |

There is no anonymous path and no username/password path. The
`KRYPTKEEPER_WSTEP_ALLOW_UNAUTHENTICATED` override is **deleted**: with a real
mode there is no honest use for it.

### Configuration (fail closed)

| Variable | Meaning |
|---|---|
| `KRYPTKEEPER_WSTEP_KEYTAB_FILE` | keytab for the hub's service principal |
| `KRYPTKEEPER_WSTEP_SPN` | e.g. `HTTP/lab-hub.corp.example.test`. Must match the keytab entry and the name clients use |

Both endpoints are served only when both variables are set, the keytab
loads, **and** it holds an entry for the SPN (any realm). Anything else logs one line saying why and leaves them unregistered,
as SCEP/CMP do. `GET /api/v1/integrations/microsoft` reports the same state.

The keytab is a secret on the order of a private key: 0600, never logged, and
never in the repo or the board. The hub logs a warning at startup when the
file is readable by group or other.

### Kerberos path

`spnego.SPNEGOKRB5Authenticate` (gokrb5 v8.4.4, already in the module graph via
go-ldap) wraps the handlers with these settings:
- `KeytabPrincipal(spn)`;
- `Logger(std log)`;
- `DecodePAC(false)`: group membership is not used for any decision, and PAC
  validation is a known source of lab-only failures;
- default 5-minute clock skew.

The identity comes from `goidentity.FromHTTPRequestContext`.

Windows only uses Kerberos when it addresses the hub **by DNS name**. Against
an IP it falls back to NTLM, which gokrb5 rejects with a 401. The hub's TLS
certificate must carry that name (`KRYPTKEEPER_TLS_SANS`), and the SPN must be
registered on a dedicated service account (`setspn`, `ktpass`).

### Subject binding (the part that closes the hole)

The CSR proves possession of a key and nothing else. Its subject and SANs are
**ignored**. `ca.IssuanceRequest` gains two fields:
- `Subject *pkix.Name`: when set, used instead of the CSR subject on every CSR
  path (classical, PQC, hybrid);
- `CallerNamesOnly bool`: when set, SAN lists come only from the request's
  `DNSNames`/`IPAddresses`/`URIs`, never from the CSR. Today an empty request
  list falls back to the CSR's, which would let a requester choose their own
  SANs.

The mapping from a Kerberos principal:
- **Machine** (`NAME$@REALM`): `CN=<name>.<realm>`, lower-cased, with the same
  value as the only DNS SAN.
- **User** (`name@REALM`): `CN=<name>` and no SANs. The UPN otherName SAN
  (1.3.6.1.4.1.311.20.2.3) needs `ExtraExtensions` and belongs to W18-08's
  client-compatibility work. It is deferred, not dropped.

The EKU stays client-auth only. Since W20-09 the template a request names
governs issuance. Windows names it with the CSR's template extension; other
clients may put a template OID or name in `TokenType`. That template's
policy is enforced: allowed algorithms, minimum key size and allowed EKUs.
A violation is a client SOAP fault naming the rule. Its validity period is
the issued validity. With no template named, validity is one year.

### Renewal path

With `KRYPTKEEPER_TLS_REQUEST_CLIENT_CERT=true` (opt-in since W20-13; off by
default, see D-111), the hub's listener uses `tls.RequestClientCert`: it asks
for a certificate and verifies nothing during the handshake. Off, no client
presents one and every request takes the Kerberos path below. A `Verify*` mode would fail the handshake on every other
endpoint whenever a client offered an unrelated certificate. `/wstep` then
decides:

1. **No peer certificate:** Kerberos path.
2. **A peer certificate that does not chain to a hub CA:** not a credential
   here. Ignore it and take the Kerberos path. Windows may present unrelated
   certificates on its own.
3. **Chains to a hub CA:** it must be within its validity, carry client-auth
   EKU, and be unrevoked in the hub's `RevocationStore`. Otherwise the request
   is refused with 403 and audited. If it passes, the new certificate gets the
   presented certificate's subject and SANs, and the CSR again supplies only
   the public key.

**What Windows actually does (W18-08 finding).** A domain machine does not use
this TLS path. CES `clientAuthentication` 8 means WS-Security message-level
X.509 signing, which the hub does not implement, so XCEP advertises only the
Kerberos URI. Windows renews over that Kerberos URI with a PKCS#7 request
signed by the old key (MS-WSTEP 4.1.5.1), and the identity again comes from
Kerberos. The TLS client-certificate path stays for non-Windows clients.

### Key size and the issuance policy

XCEP does not advertise the template's `min_key_size` as is. For each template
it advertises the smallest RSA size that is at least the template's minimum
**and** that the effective issuance policy accepts (the same `PolicyEngine`
evaluation WSTEP applies at enrollment, so the two cannot disagree). With the
default `Baseline` policy (`min_rsa_bits` 3072 since W22-14) a template whose
`min_key_size` is 2048 is therefore advertised as 3072, and **Windows now
generates 3072-bit keys**; a 4096 template stays 4096. No template data
changes: deployments upgraded from v0.9 or earlier with 2048-bit templates are
covered automatically, and clients that enrolled earlier keep their
certificates until renewal. Loosening the policy lowers what is advertised on
the next fetch (XCEP reads the policy per request).

If no RSA size satisfies both the template and the policy (for example an
ECDSA-only allow-list), the template is not offered and the hub logs
`xcep: template X not offered to P: no RSA key size is accepted: <rule>`.
XCEP policies are schema 2, which cannot advertise an ECDSA key, so Windows
machine autoenrollment needs an RSA size in the policy's allow-list. If the
policy cannot be read, `GetPolicies` faults rather than advertise a key
WSTEP might refuse.

A refused enrollment returns a SOAP fault (HTTP 500) whose reason names the
policy and rule, e.g. `issuance policy "Baseline": rule min_rsa_bits: ...`.
Windows logs it in the `CertificateServicesClient` event log where it
surfaces it; it never contains key material.

### Audit

`wstep.WithAuditFunc` and `xcep.WithAuditFunc` take a narrow callback. `main`
adapts it to `AuditProvider.AppendEntry`; there is no new global. The events:

- Success: `wstep.enroll`, `wstep.renew`, and `xcep.policy` (at most one row
  per principal per 15 minutes, listing the templates offered with their
  advertised minimum key size, so a policy poll every GPO refresh does not
  bury the enrollment trail).
- Denied: `wstep.enroll`, `wstep.renew`, `xcep.policy`. The actor is the
  principal or certificate subject when known. A WSTEP refusal by template
  checks or the issuance policy has the template as its resource and the
  violated rule in the detail (`rule=min_rsa_bits policy="Baseline": ...`);
  the engine's own `policy.violation` row is written as well.

The bare first-leg 401 challenge, sent with no `Authorization` header, is the
normal start of every Negotiate exchange and is **not** audited. A presented
credential that fails is. Issuance is still recorded in inventory
(`source=wstep`, PR #25).

### Tests (RED first)

- An anonymous POST to `/wstep` gets 401 with `WWW-Authenticate: Negotiate`,
  no issuance, and no audit row (it is a challenge).
- A Kerberos identity, injected through a test seam, is bound into the subject.
  A CSR asking for `CN=Administrator` and a foreign SAN still gets the
  principal's subject and no foreign SAN.
- Renewal with a valid hub-issued certificate gets the same subject.
  - An expired or revoked certificate gets 403 plus an audit row.
  - A foreign certificate falls through to Kerberos and gets 401.
- `internal/ca`: `Subject` overrides on all three CSR paths, and
  `CallerNamesOnly` drops CSR SANs.
- Config: a missing or unreadable keytab, or a missing SPN, leaves the
  endpoints unregistered.

### Live check (UAT lab, `corp.example.test`)

1. On `lab-dc01`:
   - DNS A record `lab-hub.corp.example.test` → the hub.
   - A service account, `setspn -S HTTP/lab-hub.corp.example.test`, and
     `ktpass ... /crypto AES256-SHA1`.
   - Move the keytab to the hub over sealed channels only, then delete it from
     the DC.
2. The hub's TLS SANs include `lab-hub.corp.example.test`. `lab-win11` trusts the hub CA
   (`LocalMachine\Root`).
3. From `lab-win11`, run `Invoke-WebRequest https://lab-hub.corp.example.test:8443/wstep
   -UseDefaultCredentials` with an RST. Expect an issued certificate whose
   subject is the Kerberos user, with audit and inventory rows.
4. Negative checks: the anonymous probe gets 401, and the same request against
   the hub's IP fails (NTLM).

A real GPO-driven autoenrollment (machine principal, XCEP policy consumption)
is **W18-08**, not this ticket. It will surface XCEP-response gaps that this
ticket should not absorb.

## GPO autoenrollment runbook (W18-08)

Proven on the UAT lab (`corp.example.test`, Windows Server 2025 DC, Windows 11
26100 machine) on 2026-10-07.

### Hub

1. WSTEP/XCEP enabled as above (keytab, SPN, TLS SANs with the DNS name).
2. A template the hub offers through XCEP: `active=true`, `auto_enroll=true`,
   and an OID. Microsoft template OIDs live under `1.3.6.1.4.1.311.21.8`; any
   OID that parses works, and one that does not parse is left out of the
   policy. Created in the lab with
   `POST /api/v1/templates` (`name=KKMachine`,
   `oid=1.3.6.1.4.1.311.21.8.4150237.1.1`, `extended_key_usage=[clientAuth]`).
   Every template is for machines or for users (`enrollee_type`, W20-17;
   machine by default). XCEP offers a machine only machine templates and a
   user only user templates, and WSTEP refuses the other kind with a client
   fault and a denied audit row. For users, create a second template, e.g.
   `name=KKUser`, `oid=1.3.6.1.4.1.311.21.8.4150237.3.1`,
   `enrollee_type=user`.
3. Optional:
   - `KRYPTKEEPER_WSTEP_URL`: the CES URL XCEP advertises. The default is
     `/wstep` on the host the client used for XCEP, which is the name it
     holds a Kerberos ticket for.
   - `KRYPTKEEPER_XCEP_RENEWAL_PERIOD`: a Go duration for when clients start
     renewing. The default is six weeks. Windows reads it in whole weeks
     (8759h58m showed as "52 Weeks"), so it cannot force a renewal within
     minutes.
   - `KRYPTKEEPER_XCEP_POLICY_ID`.

### Revocation pointers (W20-10)

WSTEP certificates carry a CRL distribution point and an OCSP URL. Since
W20-12 the pointers are set by the CA engine for every issuing path (ACME,
EST, SCEP, CMP, WSTEP and the API), from one resolver in `cmd/kryptkeeper`.
The issuing CA's configured `crl_distribution_points` and `ocsp_service_url`
are used when set.
Otherwise the hub's own `/crl/<ca-id>.crl` and `/ocsp` are used, under
`KRYPTKEEPER_REVOCATION_BASE_URL`, or under `KRYPTKEEPER_BASE_URL` when that
is unset.

Point them at plain HTTP, the standard transport for CDP/AIA. Over HTTPS,
Windows' WinHTTP revocation fetch fails with
`ERROR_WINHTTP_CLIENT_AUTH_CERT_NEEDED` (revocation offline or unknown)
whenever the main listener requests client certificates. Since W20-13 that
request is off unless `KRYPTKEEPER_TLS_REQUEST_CLIENT_CERT=true`. Set:

- `KRYPTKEEPER_REVOCATION_HTTP_ADDR=:8081` starts a plain-HTTP listener that
  serves only `/crl/` and `/ocsp` (GET and POST). No API, UI or enrollment
  endpoint is reachable on it. CRLs and OCSP responses are signed, so they need
  no transport security.
- `KRYPTKEEPER_REVOCATION_BASE_URL=http://lab-hub.corp.example.test:8081` is the
  address relying parties use to reach it.

Verified on lab-win11: `certutil -verify -urlfetch` gives "Base CRL Verified",
"OCSP Verified" and "Leaf certificate revocation check passed".

### Enroll lists and the D-291 upgrade

A template's enroll list (`enrollment_permissions.enroll`) is enforced over
XCEP and WSTEP exactly as EST, SCEP and ACME enforce it: an empty list is open;
a non-empty list lets a Windows client enroll (and XCEP offer the template)
only if it holds `protocol:wstep` (every Windows client) or
`protocol:wstep:<host fqdn, lower case>` (one machine, e.g. a domain
controller). `pki-admin`, `pki-operator` and other API roles never match a
Windows caller. A refused request gets a SOAP fault, "... is not permitted to
enroll certificate template ...", and a denied audit row.

Before D-291 a list with no `protocol:wstep*` entry was ignored for Windows, so
a template restricted to `["pki-admin"]` was still enrollable by every domain
machine (finding S-01). **Upgrade:** on first start of a build with D-291 the
hub appends `protocol:wstep` to the enroll list of each *autoenrolled* template
that has a role-only list not naming `pki-admin`, so autoenrollment keeps
working; the template revision is not bumped. Every other role-only list (not
autoenrolled, or naming `pki-admin`) is left as is and is refused on WSTEP from
then on; the startup log names them. It runs once (marker file
`bootstrap-templates.json.d291-enroll-upgrade`), so a list narrowed afterwards
is never re-widened. To let Windows enroll a template the upgrade left alone,
add `protocol:wstep` to its enroll list.

### Template mapping (what TokenType carries)

Nothing. Windows sends the generic X509v3 TokenType. The template travels as
the CertificateTemplate extension (`1.3.6.1.4.1.311.21.7`: template OID,
major, minor) inside the CSR. CertEnroll adds it only because the XCEP policy
lists it under the policy's `extensions`. The hub:

- checks the requested template is one it offers;
- stamps the extension on the certificate with the hub's revision, not the
  client's;
- refuses a template it does not offer.

Autoenrollment matches installed certificates to templates by this
extension. Without it, every pulse enrolled another certificate.

How the policy describes a template:

- **Validity:** the template's validity period, which is also what WSTEP
  issues (W20-09). One year when the template sets none. Measured live: a
  720h template issued a 30-day certificate.
- **Subject:** "built by the CA" (DNS name as CN and SAN for machines, CN for
  users). This matches what WSTEP does from the Kerberos principal.
- **Machine or user:** a machine principal (`NAME$`) is offered only
  machine templates, with machine flags, and a user only user templates
  (W20-17). Before W20-17 every template was offered to both, so a user
  autoenrolled the machine template.

### Domain controller (GPO)

One GPO linked at the domain root, with registry policy values. These are
what the "Certificate Services Client - Certificate Enrollment Policy" and
"Auto-Enrollment" settings write:

```powershell
$name = 'KK Certificate Autoenrollment'
New-GPO -Name $name
$ps = 'HKLM\Software\Policies\Microsoft\Cryptography\PolicyServers\44438a214d8e7dfbbe4da7d8a5934dee5285bd8e'
Set-GPRegistryValue -Name $name -Key $ps -ValueName URL          -Type String -Value 'https://lab-hub.corp.example.test:8443/xcep'
Set-GPRegistryValue -Name $name -Key $ps -ValueName PolicyID     -Type String -Value 'kryptkeeper-default-policy'
Set-GPRegistryValue -Name $name -Key $ps -ValueName FriendlyName -Type String -Value 'Kryptkeeper'
Set-GPRegistryValue -Name $name -Key $ps -ValueName Flags        -Type DWord  -Value 50
Set-GPRegistryValue -Name $name -Key $ps -ValueName AuthFlags    -Type DWord  -Value 2   # Kerberos
Set-GPRegistryValue -Name $name -Key $ps -ValueName Cost         -Type DWord  -Value 1
Set-GPRegistryValue -Name $name -Key 'HKLM\Software\Policies\Microsoft\Cryptography\AutoEnrollment' -ValueName AEPolicy -Type DWord -Value 7  # enroll + renew + update
New-GPLink -Name $name -Target 'DC=kkuat,DC=lab'
# A GPO at the domain root also reaches the Domain Controllers OU. Filter it
# to member machines so DCs do not autoenroll from the hub:
Set-GPPermission -Name $name -TargetName 'Domain Computers' -TargetType Group -PermissionLevel GpoApply
Set-GPPermission -Name $name -TargetName 'Authenticated Users' -TargetType Group -PermissionLevel GpoRead -Replace
```

In production, link it to the OU holding the workstations or servers that
should enroll, rather than to the root.

For user autoenrollment, a second GPO sets the same values under `HKCU`
(`HKCU\Software\Policies\Microsoft\Cryptography\PolicyServers\<same key>`
and `HKCU\...\AutoEnrollment\AEPolicy=7`). User Group Policy applies only
at an interactive logon: a scheduled task's batch logon gets no user policy
("The user does not have RSoP data"). The lab GPO,
`KK User Autoenrollment (UAT)`, applies to `corp-user1` only.

The subkey name and the values were copied from what
`Add-CertificateEnrollmentPolicyServer -context Machine -AutoEnrollmentEnabled`
writes under `HKLM\SOFTWARE\Microsoft\Cryptography\PolicyServers`.

### Client

- `gpupdate /force /target:computer`, then `certutil -pulse`. Enrollment took
  under 20 seconds.
- Windows caches the policy for `nextUpdateHours` (8). After changing the
  policy, run `certutil -f -PolicyServer * -PolicyCache delete` before
  pulsing. A stale cache hid the template-extension fix during bring-up.
- **Renewal:** raising the hub template's revision (any PATCH bumps it) makes
  every holder renew on the next pulse. This is the "Reenroll all
  certificate holders" behaviour: the old certificate is archived and the
  new one carries the new major version. Time-based renewal follows the
  renewal period, in whole weeks.
- **Diagnostics:**
  - On the client, the Application log (`CertificateServicesClient-*`).
  - `certutil -v -PolicyServer <url> -Kerberos -Template` shows what the
    client parsed.
  - On the hub, every SOAP fault reason is logged as `wstep: SOAP fault ...`.
    Clients only ever report `WS_E_ENDPOINT_FAULT_RECEIVED`.

### Gaps found against a real client, all fixed in W18-08

| Symptom on Windows | Cause | Fix |
|---|---|---|
| `WS_E_INVALID_FORMAT` adding the policy server | XCEP response was a stub (string policyOIDReference, no cAs/oIDs) | Rebuilt from MS-XCEP 3.1.4.1.2.2 |
| `WS_E_ENDPOINT_FAULT_RECEIVED` on enroll | CSR arrives as PKCS#7 around CMC PKIData, base64 with line breaks | Strict CMC unwrap (exactly one PKCS#10) |
| Old RSTR shape | Missing RelatesTo, DispositionMessage, PKCS#7 chain, RequestID | Response per MS-WSTEP 4.1.1.2 |
| `CERT_E_EXPIRED` installing a fresh certificate | NotBefore equal to the issue instant, a moment in the client's future | WSTEP backdates 5 min (the Kerberos skew bound), clamped to the CA |
| A new certificate on every pulse | No template extension | XCEP lists it, WSTEP stamps it |

Verified live since: user-context autoenrollment (W19-10), and on 2026-10-08
the per-kind template offer (W20-17). See STATUS.

Not verified live:
- a time-based renewal (it needs about a day at the weeks granularity).
- Windows 10, Server 2019 and Server 2022 (W26-13 matrix kit exists in `tests/live/wstep/matrix/`;
  results are `PENDING-RUN`, see `docs/release/LIVE_RESULTS_FG2_WSTEP_MATRIX_v0.14.md`).

Filed:
- W20-10 (done, see Revocation pointers above).
- W20-11 (done): a renewal over Kerberos is audited as `wstep.renew` with
  `predecessor=<old serial>`. That label applies when the request carries a
  signature by a certificate this hub issued to the same identity. Windows
  sends that as a version-1 SignerInfo next to a version-3 one, which both
  pkcs7 libraries fail to parse, so `internal/wstep/renewal_signer.go`
  verifies it (RFC 5652 5.4). The label is for the audit log only;
  authorization is Kerberos.
- W20-12 (done): every issuing path now gets the pointers from the engine.

## Lab and failures

- [WSTEP_LAB_RUNBOOK.md](WSTEP_LAB_RUNBOOK.md): domain, service account, keytab, templates and GPO from scratch.
- [WSTEP_FAILURES.md](WSTEP_FAILURES.md): client symptom to audit action and fix. The
  `wstep.kerberos.failure` alert is planned, not emitted in v0.14.

## Implementation state (2026-10-07)

Done. The live check above passed with the machine principal `LAB-WIN11$`:
Kerberos by name issued `CN=lab-win11.corp.example.test` for a CSR that asked for
`CN=Administrator`, and both the anonymous and the by-IP (NTLM) requests got
401. A practical note for the lab: when you check ktpass output, never print
its key line, because ktpass echoes the derived key in hex.
