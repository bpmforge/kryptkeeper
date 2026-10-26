# SCEP enrollment (W20-16, D-121)

Status (2026-10-08): implemented. Proven with the real micromdm/scep client
(`tests/live/protocols`).

SCEP enrollment is **off unless `KRYPTKEEPER_SCEP_ENABLED=true`**. It needs
the hub database and an RSA CA, because SCEP's PKCS#7 envelope needs an RSA
recipient key. The startup log says whether SCEP is live, and if not, why.

## How a device enrolls

1. **Mint a challenge.** A pki-admin or pki-operator calls
   `POST /api/v1/scep/challenges` with the device's names:

   ```json
   {"common_name": "printer-7.example.com",
    "dns_names": ["printer-7.example.com"],
    "ttl": "30m"}
   ```

   The response carries `challenge`: 64 hex characters, shown this once.
   The hub stores only its SHA-256.
2. **Configure the device.** Give it the hub's SCEP URL (`/scep`) and the
   challenge.
3. **The device enrolls.** The hub consumes the challenge and issues a
   one-year, client-auth certificate for exactly the challenge's names. The
   CSR proves the key and nothing else: a CSR that asks for
   `CN=Administrator` still gets `CN=printer-7.example.com`.

## Rules

| Rule | Detail |
|---|---|
| One-time | The challenge is claimed in one atomic database update before issuance. Of two concurrent requests, exactly one wins. If issuance fails afterwards, the challenge is spent. |
| Expiry | The default is 1 hour and the maximum is 24 hours. |
| Names | The common name and up to 20 DNS names. All must be host names: no wildcards, IPs or spaces. |
| CA | The challenge is tied to the SCEP CA it was minted for (`KRYPTKEEPER_SCEP_CA_ID`, or the default CA if that is RSA). |
| Withdraw | `DELETE /api/v1/scep/challenges/{id}` removes an unused challenge. A used one stays as a record. |
| List | `GET /api/v1/scep/challenges` lists challenges without their secrets. |

## Renewal (W26-30)

`GetCACaps` advertises `Renewal`. A device renews by sending a `PKCSReq` (19)
or `RenewalReq` (17) whose PKCS#7 signer is its **current** certificate rather
than a throwaway self-signed one. No challenge is needed; a challengePassword
in the CSR is ignored and not consumed. A request signed by a self-signed
certificate is an initial enrollment (challenge path, unchanged), and a
`RenewalReq` signed by a self-signed certificate is refused.

All of these must hold, else the reply is a FAILURE CertRep (`badRequest`, or
`badMessageCheck` when the signature does not verify) and nothing falls back to
the challenge path:

1. the PKCS#7 signature verifies with the signer certificate;
2. the signer certificate was issued by this SCEP CA and carries client-auth EKU;
3. it is inside its validity period;
4. it is not revoked (an unknown revocation status refuses: no revocation
   store means every renewal is refused);
5. the template enrollment gate (`enrollment_permissions`) allows it, as for
   enrollment.

The CSR may carry the same key or a new one. The new certificate takes its
common name and DNS names from the **old certificate**, never from the CSR; the
CSR only proves possession of the key. The reply is encrypted to the signer
certificate.

## Microsoft Intune (W20-23, D-327)

Intune-managed devices enroll through a **SCEP label**, `/scep/<label>`, set to
the `intune` challenge mode. The hub does not mint these challenges: Intune
creates one per device, encrypted, and the hub asks Intune to validate each
request before it issues. This is Microsoft's third-party CA integration
([overview](https://learn.microsoft.com/en-us/intune/fundamentals/certificates/third-party-ca-scep),
[developer contract](https://learn.microsoft.com/en-us/intune/fundamentals/certificates/ref-scep-api)).

### Set it up

1. **Register an app in Entra ID** (Azure portal, Microsoft Entra ID, App
   registrations, New registration; "Accounts in any organizational
   directory"). Copy the **Application (client) ID** and the **Tenant ID**.
2. **Give it two application permissions**, then **Grant admin consent**:
   - Intune API: `scep_challenge_provider` (SCEP challenge validation)
   - Microsoft Graph: `Application.Read.All` (the hub uses it to find the
     Intune validation service)
3. **Add a credential to the app**: a client secret, or upload a certificate.
4. **Store it in the hub** as an `api_token` credential (Credentials page or
   `POST /api/v1/credentials`), with the payload
   `{"client_secret": "..."}` or
   `{"certificate_pem": "...", "private_key_pem": "..."}` (an RSA key; the hub
   signs a PS256 client assertion with it). Note the credential id.
5. **Create the label** (pki-admin):

   ```json
   POST /api/v1/scep/labels
   {"label": "intune", "mode": "intune", "template_id": "<template>",
    "intune_tenant_id": "<tenant GUID or domain>",
    "intune_client_id": "<application id>",
    "credential_ref": "<credential id>",
    "issuing_authority": "Kryptkeeper Issuing CA"}
   ```

   The template's `enrollment_permissions.enroll` must list the role
   `protocol:scep`, as for the other protocols. The Entra secret is never
   accepted by this API, kept in the label or shown again.
6. **In Intune**, upload the CA certificate as a Trusted certificate profile,
   then create a SCEP certificate profile whose **SCEP Server URL** is
   `https://<hub>/scep/intune`. The URL must be https for Android. Set the
   subject and SAN to what you want: **the certificate carries the subject,
   SANs, key usage and EKU of the CSR that Intune just validated against the
   profile**. DNS, IP address and URI SANs are supported. A profile that asks
   for a UPN or email SAN, or an EKU other than server authentication, client
   authentication or email protection, is refused with the reason in the
   audit log rather than issued without it.

### What the hub does on each request

1. The template gate, then `validateRequest` with the CSR and SCEP transaction
   id. Only Intune's `Success` lets issuance continue. A refusal (for example
   `SubjectNameMismatch`, `ChallengeExpired`) or any failure to reach Intune,
   Entra or Graph **refuses enrollment**: nothing is issued.
2. Issues the certificate and records it in the inventory (source `scep`).
3. Sends Intune the success notification (thumbprint, serial, expiry, issuing
   authority). If that fails the certificate is **withheld and revoked** and
   the device gets a failure, because Microsoft's contract says a certificate
   must not be issued when the notification fails.
4. If issuance itself fails after a good validation, sends Intune the failure
   notification. It is not sent for validation failures (the contract reserves
   it for errors after validation).

A label does not advertise the `Renewal` capability: Intune sends every
renewal as a new request with a new challenge, and it goes through the same
validation.

### Audit

`scep.enroll` rows carry `label=<name>`. Success adds the serial, subject and
DNS names. A denial adds `intune refused: <Code>`, `intune validation
unavailable: <stage>`, the template gate, an unsupported SAN or EKU, or
`withheld: success notification failed`. No CSR bytes, token, challenge or
Entra secret is logged or audited. `scep.label.create` and `scep.label.delete`
record label changes.

### Not covered yet

- Revoking certificates when Intune asks (wipe, retire) through Intune's
  revocation download API. Revoke from the certificate list for now.
- Proof against a real tenant. The tests use a TLS stand-in for Entra, Graph
  and the Intune service built from Microsoft's published client. On the first
  real run, check that Intune accepts the notification fields (thumbprint
  case, serial format, expiry format) and the token scope
  `https://api.manage.microsoft.com//.default`, which is copied byte for byte
  from Microsoft's library.

## Removed in W20-16

- **`KRYPTKEEPER_SCEP_CHALLENGE`**, one static challenge shared by every
  device. If it is still set, SCEP stays off and the startup log says so.
- **`/scep/mscep_admin`**, which returned that challenge to anyone, without
  authentication. Intune never used it; see
  [`docs/guides/intune-byoca.md`](../guides/intune-byoca.md). Intune
  support is W20-23.

## Audit

| Action | Recorded |
|---|---|
| `scep.challenge.create` | Who minted it, the bound names and the expiry. |
| `scep.challenge.delete` | The withdrawal. |
| `scep.enroll` success | The bound CN as actor; the challenge id, serial, subject and DNS names. |
| `scep.enroll` denied | The reason: unknown, already used, expired, minted for another CA, or no challenge in the CSR. |
| `scep.renew` success | The signer CN as actor; `old_serial`, `new_serial` and subject. |
| `scep.renew` denied | The reason: not issued by this CA, outside validity, revoked, revocation status unavailable, enrollment gate, bad signature, or self-signed RenewalReq. |

The challenge itself never appears in logs, audit rows or API listings.

## Live evidence (2026-10-08)

`tests/live/protocols/run.sh` on the Mac, with the real micromdm/scep
client over TLS against an RSA CA: **39 PASS, 0 FAIL**. The SCEP steps:

| Step | Result |
|---|---|
| Mint two challenges via the API | 64-character secrets; the list shows neither |
| Enroll with a fresh challenge | Issued `CN=uat-scep-leaf.scep.uat.example` with that DNS name; chains to the RSA CA; in inventory as `source=scep` |
| The same challenge again | Refused (already used) |
| A challenge the hub never minted | Refused |
| A fresh challenge with a CSR naming `Administrator` | Issued `CN=uat-scep-bound.scep.uat.example`, the challenge's name |
| Audit | Two successes and two denials |

The CMP shared secret (`KRYPTKEEPER_CMP_SECRET`) has the same reusable shape
as the old SCEP challenge. It is noted in D-121 and is not changed here.
