# Microsoft Intune and Kryptkeeper SCEP

**Status (2026-10-25): supported** through SCEP labels (W20-23, D-327).
Proven against a test double of Entra, Graph and the Intune service; a run
against a real tenant is on the roadmap.

## How it works

Intune's third-party SCEP support does not fetch a challenge from the CA. For
each device Intune builds a challenge, encrypts and signs it together with
what the certificate request must look like, and sends it to the device with
the SCEP profile. The device sends its request and that challenge to the SCEP
server, which asks Intune to validate it. Kryptkeeper does this on a SCEP
label in `intune` mode, using an app registered in Microsoft Entra ID.

Setup (Entra app and permissions, the credential, the label, the Intune SCEP
profile) is in the Intune section of [`docs/ops/SCEP.md`](../ops/SCEP.md).

## What you get

- **Validation:** every enrollment is checked by Intune before anything is
  issued. If Intune or Entra cannot be reached, nothing is issued.
- **Names:** the certificate carries the subject, SANs, key usage and EKU
  of the request Intune validated against the device's profile.
- **Reporting:** Intune is told about each issued certificate, and about an
  issuance failure after validation.
- **Secrets:** the Entra app's secret or certificate lives in the encrypted
  credential store; the label holds only its id. It never reaches logs or the
  audit trail.

## Limits today

- UPN and email SANs are refused (the hub issues DNS, IP and URI SANs).
- Intune-requested revocation (wipe, retire) is not yet downloaded and
  applied.
- For domain-joined Windows machines and users, Windows autoenrollment
  ([`docs/ops/WSTEP_AUTOENROLLMENT.md`](../ops/WSTEP_AUTOENROLLMENT.md)) is
  still the simpler path.
