# Risk scoring: how a certificate's score and grade are computed

Every certificate Kryptkeeper tracks gets a risk score from 0 to 100 and a
letter grade from A (best) to F (worst). The score is deterministic: the same
certificate evaluated at the same instant always yields the same number, and
every point can be traced to a named flag.

## Formula

1. Evaluate the certificate against the rule ladder at a single instant
   ("now"). Each rule that fires raises a flag.
2. The score is the sum of the points of the flags raised, capped at 100.
3. If the certificate's chain is not trusted, the flag `UNTRUSTED_CHAIN` is
   added and 25 points are added to the score, then the score is capped at 100
   again. This penalty is applied after the table below because chain trust
   comes from verifying against the CA pool, not from the certificate alone.

Source of truth: `riskFlagWeights` in
`internal/bootstrap/certificate_ca_provider.go`. A test
(`TestRiskScoringDocMatchesCode`) fails if the table below and the code differ.

## Weights

The `EXPIRING_*` flags are mutually exclusive: the first match wins, so a
certificate carries at most one of them.

| Flag | Points | Raised when |
|---|---|---|
| `EXPIRED` | 40 | NotAfter is before now |
| `EXPIRING_7_DAYS` | 20 | Expires within 7 days |
| `EXPIRING_30_DAYS` | 20 | Expires within 30 days (but not 7) |
| `EXPIRING_47_DAYS` | 5 | Expires within 47 days (but not 30) |
| `EXPIRING_90_DAYS` | 5 | Expires within 90 days (but not 47) |
| `PQC_VULNERABLE` | 10 | Classical (RSA/ECDSA) public key that a quantum computer could break |
| `WEAK_SIGNATURE` | 30 | Signed with SHA-1, MD5 or MD2 over any key type (SHA1WithRSA, ECDSAWithSHA1, DSAWithSHA1, MD5WithRSA, MD2WithRSA) |
| `WEAK_RSA_KEY` | 35 | RSA key shorter than 2048 bits |
| `NIST_SUNSET_RSA2048` | 20 | RSA-2048 key evaluated after 2031-01-01 (NIST SP 800-131A Rev.3 sunset) |
| `WEAK_EC_KEY` | 20 | ECDSA curve smaller than 256 bits |
| `NIST_SUNSET_ECC224` | 20 | ECC key of 224 bits or less evaluated after 2031-01-01 |
| `OUTLIVES_NIST_SUNSET` | 10 | RSA-2048 or 224-bit-or-smaller ECC key whose NotAfter is after 2031-01-01 |
| `VALIDITY_EXCEEDS_397_DAYS` | 10 | Validity period longer than 397 days |
| `VALIDITY_EXCEEDS_200_DAYS` | 15 | Validity longer than 200 days, evaluated on or after 2027-03-15 (CA/B Forum SC-081v3) |
| `SELF_SIGNED` | 15 | Issuer equals subject and the certificate is not a CA |
| `WILDCARD_SAN` | 5 | Any DNS SAN starts with `*.` |
| `SAN_SPRAWL` | 5 | More than 25 DNS SANs (blast radius) |
| `NO_OCSP_URL` | 10 | Non-CA certificate valid longer than 7 days with no OCSP responder |
| `NO_CRL_DP` | 5 | Non-CA certificate with no CRL distribution point |

Two flags carry no points of their own:

- `PQC_MIGRATION_NEEDED` is a refinement of `PQC_VULNERABLE` (long-lived
  classical certificates that need active migration planning).
- `UNTRUSTED_CHAIN` is not in the weights table; it triggers the flat +25
  chain penalty described in the formula.

## Grades

| Grade | Score range |
|---|---|
| A | 0-10 |
| B | 11-30 |
| C | 31-50 |
| D | 51-70 |
| F | 71-100 |

## Worked examples

- Expired certificate with a SHA-1 signature: `EXPIRED` 40 +
  `WEAK_SIGNATURE` 30 = 70, grade D. (User story US-030 calls this a "weak
  key" example; the 30-point flag is the SHA-1/MD5 signature, not
  `WEAK_RSA_KEY`, which is 35.)
- Healthy certificate, modern signature, valid for months, no flags: 0,
  grade A.
- Expired, SHA-1 signature, 1024-bit RSA key: 40 + 30 + 35 + 10
  (`PQC_VULNERABLE`) = 115, clamped to 100, grade F.
- The score 70 above on an untrusted chain: 70 + 25 = 95, grade F; a score
  of 90 on an untrusted chain is capped at 100.

## Install posture and privilege findings

These findings describe where and how a certificate is installed and what the
scan could see. They are raised on a host file, an endpoint or a target, not on
the certificate, so they carry **no points** in the formula above; the high
severity ones join the "Risky only" filter and the dashboard.

| Finding | Severity | Meaning | Remediation |
|---|---|---|---|
| `PRIVILEGED_INSTALL_PATH` | Medium; High when the target has `auto_renew` and no privileged credential | The certificate, key or keystore is owned by root (or another account) and the service runs as a different non-root user, so a renewal needs root on that file. Typically an admin imported it with `sudo`. | Give the target's credential a privileged mode (helper preferred), or fix ownership so the service account can write the file (`chown`/`chmod`). Renewal proceeds through a privileged credential when one exists and flags that credential as privileged. |
| `SERVICE_RUNS_AS_ROOT` | High | The listening process is an application server (java, node, python, dotnet or custom) running as uid 0. Master processes of nginx, Apache, HAProxy and Postfix running as root are normal and not flagged; they are judged by their worker uid. | Run the service under its own account. If it must stay as it is, use **Accept risk** on the file with a justification; the exception is listed in the access review. |
| `KEY_WORLD_READABLE` | High | A private key file's mode lets group or other read it. Raised from the file's mode only; the key is never read. | `chmod 0600` (or `0640` with a narrow group). |
| `HOME_DIR_KEYSTORE` | Medium | A keystore or certificate sits under `/root` or `/home/*` and a service configuration references it. | Move it to a service-owned directory such as `/etc/<service>/`. |
| `INSUFFICIENT_PRIVILEGE` | Medium (a target finding) | The scan ran without the privilege to stat or read some configured certificate paths. It names the uid the scan ran as, the privilege mode, the unreadable paths and the fix for that mode. | Apply the shown fix: the sudoers line, the helper, or `chown`/`chmod`. See [agentless on a hardened Linux host](agentless-hardened-linux.md). |
| `MSSQL_TLS_DISABLED` | High | SQL Server answered the TDS pre-login with encryption off, so the connection is not protected. | Enable force encryption and install a certificate in SQL Server Configuration Manager. |
| `MYSQL_TLS_DISABLED` | High | The MySQL greeting did not advertise SSL support. | Configure `ssl-cert`/`ssl-key` and `require_secure_transport`. |
| `HELPER_TAMPERED` | High | The installed privilege helper's sha256 differs from the hash pinned in the credential. The hub refuses to run it; privileged scans and renewals on that host stop. | Find out who changed `/usr/local/sbin/kryptkeeper-helper`; reinstall it from the target's privilege bundle, or update the pinned hash if you changed it on purpose. |

