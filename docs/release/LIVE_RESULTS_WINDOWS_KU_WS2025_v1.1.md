# Live results: Windows accepts the new key usages; Server 2025 member (P14)

Date: 2026-10-26. Hub build: `origin/main` 99fe06db (includes `0d66fd7a`, the leaf key-usage change), cross-built for linux/amd64 and run as a **throwaway second
process** on the lab-hub VM (192.0.2.106, port 8444, CRL/OCSP on 8082) from a copy of the lab hub's data. The lab hub on 8443 (`v1.0.0-main-78494f48`) was not touched,
upgraded or restarted. No secrets are recorded here.
Lab: `corp.example.test`. DC lab-dc01 (Server 2025), lab-ca01 (Enterprise CA), lab-win11 (Windows 11 25H2, build 26200), lab-ws22 (Server 2022, 20348), **lab-ws25 (new, Server 2025 Standard, 26100)**.
Check script: `tests/live/wstep/matrix/ku-check.ps1` (pulse, then key usage, EKU, key algorithm, `certutil -verify -urlfetch`).

## Verdict

- **A. PASS.** Windows 11, Server 2022 and Server 2025 accept the new key usages. RSA machine leaves keep `keyEncipherment` by design (`leafKeyUsage` keeps it on RSA TLS and client leaves).
  ECDSA, time-stamping and OCSP-signer leaves issued by the new build validate and serve TLS. **ECDSA through GPO autoenrollment is not possible today** (XCEP is RSA-only), so the ECDSA leg used CSRs.
- **B. PASS.** lab-ws25 built unattended, joined `corp.example.test`, autoenrolled from the hub in 7 s, chain valid.
- One open observation, not a verified defect: the renewals were audited as `wstep.enroll`, not `wstep.renew` (section 4).

## 1. Setup

- Throwaway hub: copy of `/var/lib/kryptkeeper` (same root CA, so clients already trust it), the same keytab and SPN `HTTP/lab-hub.corp.example.test`, own port and own revocation port.
  Clients reach it by the Kerberos name, so only the GPO policy-server URL changed (port 8443 to 8444).
- Templates on the copy only: the existing `KKMachine` (RSA 3072 enforced by the policy; revision bumped by PATCH on the copy), plus `KKMachineEC` (ECDSA only, auto-enroll), `KKWebEC` (serverAuth), `KKTimeStamp`, `KKOcspSigner`, all ECDSA P-256.
- lab-ws25: VMID **126**, node hypervisor, IP **192.0.2.156**, MAC BC:24:11:8F:ED:74, 2 vCPU, 4 GB, 50 GB on externalSSD, OVMF, e1000, `onboot=1`, guest agent enabled (the agent never reported; use `nc` on 5985).
  Built like lab-ws22: `build-unattend-iso.sh` role `ws25` (copy of `ws22-tail.ps1`), image `Windows Server 2025 Standard (Desktop Experience)`, Microsoft's public KMS client key, install ISO `local:iso/en-us_windows_server_2025_updated_june_2025_x64_dvd_e743555f.iso`
  (already on hypervisor), virtio-win and the unattend ISO on `ide3` and `ide0`. The Enter key is sent over the hypervisor API at power-on for the "press any key" prompt. Domain join happened at first logon.
  The hub root was imported into `LocalMachine\Root` by hand (the GPO does not distribute it). The IIS role was installed on it for the TLS check and left installed.

## 2. RSA machine template, GPO autoenrollment

All three: policy cache deleted, `gpupdate /force /target:computer`, `certutil -pulse`; no manual enrollment. Kerberos (SPNEGO) succeeded for each machine account; audit `xcep.policy success offered=[KKMachine(min_key=3072)]` then `wstep.enroll success`.

| Host / OS | How | Seconds | Store | Key | KU | EKU | Template ext | `certutil -verify -urlfetch` |
|---|---|---|---|---|---|---|---|---|
| lab-win11 / 26200 | revision bump (4 to 5); old cert archived | 9 | `LocalMachine\My`, private key present | RSA-3072 | Digital Signature, Key Encipherment | clientAuth | major 5 | success; CRL and OCSP verified, leaf revocation check passed |
| lab-ws22 / 20348 | revision bump (4 to 5, then 6, 7); old cert archived | 9 | same | RSA-3072 | same | same | major 5, 6, 7 | success, same |
| lab-ws25 / 26100 | fresh enrollment (no prior cert) | 7 | same | RSA-3072 | same | same | major 7 | success, same |

Thumbprints (throwaway-issued, removed in the revert): win11 5A1D3C68..., ws22 47547AAA... and 4AEF1E43..., ws25 43BA8494....

## 3. ECDSA (and the other changed profiles), CSR route

Done on lab-ws22 and lab-ws25. CSR from `certreq -new` (ECDSA_P256, Microsoft Software Key Storage Provider, machine key), `POST /api/v1/certificates` on the throwaway hub, `certreq -accept -machine`.

| Profile | Hub response | On the client (both OSes) |
|---|---|---|
| ECDSA TLS server (`KKWebEC`) | KU `[digitalSignature]`, EKU serverAuth | accepted into `LocalMachine\My` with the key; KU critical `Digital Signature (80)`, **no Key Encipherment**; `certutil -verify -urlfetch` success, CRL and OCSP verified |
| Time stamping (`KKTimeStamp`) | KU digitalSignature | EKU `Time Stamping` **critical=True**; verify success |
| OCSP signer (`KKOcspSigner`) | KU digitalSignature | EKU OCSP Signing plus `1.3.6.1.5.5.7.48.1.5` (`05 00`, ocsp-nocheck); verify success |

IIS: an `https *:443` binding with the ECDSA TLS cert on each host. Local Schannel `Invoke-WebRequest https://<host>.corp.example.test/` returned 200 on both. From the Mac, `openssl s_client` against both:
`Verification: OK`, TLS 1.3 `TLS_AES_256_GCM_SHA384`, peer signature `ecdsa_secp256r1_sha256`; forced TLS 1.2 on lab-ws25 negotiated `ECDHE-ECDSA-AES256-GCM-SHA384`. So Schannel on Server 2022 and 2025 serves an ECDSA leaf with no keyEncipherment.

**ECDSA via GPO is not offered.** With `KKMachineEC` active and auto-enroll on, a pulse on lab-ws22 still got only `KKMachine`. Hub log: `xcep: template KKMachineEC not offered to LAB-WS22$@CORP.EXAMPLE.TEST: no RSA key size is accepted: the template permits no RSA key size`.
This is the documented behaviour in `internal/xcep/server.go` (schema-2 policy has no key algorithm), not a regression. It stays a roadmap item.

## 4. Observation: renewals audited as `wstep.enroll`, no `predecessor=`

Windows did renew (the old certificate was archived and the new one carries the new major version), but the hub wrote `wstep.enroll`, not `wstep.renew predecessor=`. On 2026-10-18 the same flow produced `wstep.renew` rows with `predecessor=`.
A temporary diagnostic build (not committed) logged the request: `signer=false embeddedCerts=0`. The request carried **no old-certificate signature at all**, so `oldKeySigner` and `renewalPredecessor` have nothing to match.
Ranked causes:

1. Windows did not sign with the old key: it treated the template-revision upgrade as a new request. It happened on all three bumps and on both hosts, from certificates this build issued and from one the 10-18 hub issued. Not verified why.
2. The policy-server URL changed (port). Weakened: the cert that failed on the third bump had been enrolled via the same 8444 URL.
3. A hub regression in the CMC unwrap. Weakened: unit tests in `internal/wstep` pass, and `embeddedCerts=0` means the certificates were absent before any hub matching code runs.

No fix: the label is audit-only (Kerberos authorizes), and nothing shows the hub mishandled a signed request. To settle it, capture the WSTEP body on a revision bump against the unchanged lab hub (8443).

## 5. Not proven

- ECDSA or ML-DSA through GPO autoenrollment (XCEP is RSA-only); Schannel serving ML-DSA.
- The Kerberos clock-skew refusal on Server 2025 (lab-ws25 now exists to run it); time-based renewal (needs weeks); `wstep.renew` labelling this run (section 4).
- Windows 10 and Server 2019: no ISO, the owner-only.
- Cross-host Schannel from lab-win11 to lab-ws22: WinRM returned `Access is denied` for any script that opened a network connection on lab-win11 (a plain query on it worked). Schannel on ws22 and ws25 was covered by local requests and the Mac probe.
- The lab hub (8443) itself: it still runs the older build. The new code was run beside it, on a copy of its data, so behaviour with the live database is not shown.
- The main hub was never given these certificates. The three clients ended on certificates from the lab hub (major 4), see Revert.

## 6. Lab changes and revert

| Change | Reverted |
|---|---|
| GPO `KK Certificate Autoenrollment` policy-server URL `https://lab-hub.corp.example.test:8443/xcep` set to `:8444` | Yes: read back as `:8443`, all other values unchanged |
| Throwaway hub process, `~/ku` on lab-hub (copy of the CA key, keytab, data) | Yes: process stopped, `~/ku` deleted; only 8443 and 8081 listen; `kryptkeeper-hub.service` active, `v1.0.0-main-78494f48`, never restarted |
| Throwaway-issued certificates on win11, ws22, ws25 (RSA and ECDSA, keys deleted) | Yes: removed; each host then pulsed against the lab hub and holds a fresh lab-hub certificate (win11 2F4B5DBA, ws22 F230C891, ws25 E04A2B89, major 4) |
| ws22 and ws25: `https *:443` binding, SSL cert registration, firewall rule `KK KU IIS 443`, `C:\kk-ku`, `C:\root.cer` | Yes: bindings back to `http *:80` |
| Template edits (revision bumps, four test templates) | Never applied to the lab hub; they lived in the copy |
| lab-ws25 `LocalMachine\Root` holds the hub root; IIS role installed | Left on purpose (needed for future runs) |
| New: VM 126 lab-ws25; `lab-ws25-unattend.iso` in `local:iso` on hypervisor; local `~/.config/kryptkeeper-lab/lab-ws25-unattend.iso` and `src/ws25-tail.ps1` | Left on purpose |

Residue: the throwaway hub shared the lab CA key, so its leaves are genuine `KK UAT Lab Root CA` certificates that the lab hub does not know and cannot revoke. They were deleted from every client and none left the lab. They expire 2026-11-25 (ECDSA test) and 2027-10-26 (RSA).
