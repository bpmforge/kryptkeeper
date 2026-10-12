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
