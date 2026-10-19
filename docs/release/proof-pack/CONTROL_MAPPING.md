# Kryptkeeper control mapping

## Purpose and scope

How Kryptkeeper features and evidence support the controls a customer is assessed against under
SOC 2, ISO/IEC 27001:2022 Annex A, PCI DSS 4.0.1 and NIST SP 800-53 Rev. 5. This is a mapping of
product capability to customer controls. It is not an attestation of Kryptkeeper, and it does not
state that any framework is satisfied. Each row names evidence that exists in this repository; where
the customer owns the control, the row says so and points at the document that describes their step.

Release tag: `<tag>` (replaced by the proof-pack index at publish).

## Getting the evidence pack

The compliance evidence report is an authenticated API call (a Bearer token):

    GET /api/v1/reports/compliance-evidence?framework=soc2|pci|nist|dora|nis2|all&format=json|pdf

The UI page is `/reports/compliance-evidence`. Control ids the report emits today: `SOC2-CC6.7`,
`PCI-DSS-4.2.1.1`, `NIST-800-57-3.6`, `NIST-800-131A`, `INTERNAL-CA-HEALTH` (code:
`internal/bootstrap/handlers_reports.go`), plus `DORA-Art6|9|10` and `NIS2-Art21-2h|2i`
(`internal/bootstrap/compliance_dora_nis2.go`).

Status values: `Evidence pack` (the report emits a control id), `Artifact` (an API, UI page or
repository document is the evidence), `Customer responsibility` (the customer performs the control;
the target is the document describing their step).

Targets used below: audit log `GET /api/v1/audit` (UI `/audit`), tamper-evidence proofs
`/api/v1/audit/transparency/*`, inventory `GET /api/v1/certificates` (UI `/certificates`), approvals
`/api/v1/approvals` and `/api/v1/pending-actions` (UI `/inbox`, `/approvals`), roles and
separation-of-duties `/api/v1/roles`, `/api/v1/roles/sod-constraints` (UI `/roles`), notification
rules `/api/v1/notifications/rules` (UI `/alerts`), crypto posture `/api/v1/reports/crypto-posture`
(UI `/crypto-posture`).

## SOC 2 (Trust Services Criteria)

| Control | What the control asks | Kryptkeeper capability | Artifact / evidence target | Status |
|---|---|---|---|---|
| CC6.1 | Logical access is restricted to authorized users | Role-based access with custom roles and separation-of-duties constraints; SCIM provisioning; SSO | `GET /api/v1/roles`, `/api/v1/roles/sod-constraints` (UI `/roles`); `docs/guides/sso-okta.md` | Artifact |
| CC6.2 | Access is provisioned, reviewed and removed | Access-review reports and campaigns; SCIM Users and Groups | `GET /api/v1/admin/access-review/report`, `/api/v1/admin/access-review/campaigns` (UI `/access-review`) | Artifact |
| CC6.6 | Boundaries protect against external threats | Egress guard for user-supplied URLs; trusted-proxy and rate limits, each tied to a named test | `docs/security/SECURITY_CLAIMS.md` | Artifact |
| CC6.7 | Data in transit and certificate lifecycle are controlled | Lifecycle control over expiring and unknown-expiry certificates | `/api/v1/reports/compliance-evidence?framework=soc2`, control `SOC2-CC6.7` | Evidence pack |
| CC7.2 | System activity is monitored for anomalies | Audit log of API mutations; CT-log findings; discovery scans | `GET /api/v1/audit`; `GET /api/v1/ct/findings` (UI `/ct-findings`); `GET /api/v1/discovery/summary` | Artifact |
| CC7.3 | Security events are evaluated and escalated | Notification rules route alerts; incident procedure documented | `GET /api/v1/notifications/rules` (UI `/alerts`); `docs/ops/INCIDENT_RESPONSE.md` | Artifact |
| CC8.1 | Changes are authorized and controlled | Approval workflow with proposer cannot approve own request; key export and backup need a second human (dual control, D-122) | `GET /api/v1/approvals`, `/api/v1/pending-actions` (UI `/inbox`); `docs/DECISIONS.md` D-122 | Artifact |
| A1.2 | Availability, recovery and backup | HA soak and Helm HA runs recorded; DR runbook and restore drill | `docs/release/HA_SOAK_v0.11.md`; `docs/release/UAT_HELM_HA_v0.13.md`; `docs/ops/DR_RUNBOOK.md` | Artifact |
| C1.1 | Confidential information is protected | Root key custody in HSM or cloud KMS; FIPS statement and boundary | `docs/release/proof-pack/FIPS_STATEMENT.md`; `docs/ops/CLOUD_KMS.md` | Artifact |
| CC9.2 | Vendor and business-partner risk is managed | Hub dependencies are scanned with govulncheck in CI; a CycloneDX SBOM from the 2026-10-09 audit is checked in; release SBOMs are built by `release.yml` | `docs/security/DEPENDENCY_FINDINGS_2026-10-09.md`; `docs/security/sbom_2026-10-09.cdx.json`; `.github/workflows/release.yml` | Artifact |

## ISO/IEC 27001:2022 Annex A

There is no `iso27001` framework key in the evidence pack; every ISO row points to an artifact.

| Control | What the control asks | Kryptkeeper capability | Artifact / evidence target | Status |
|---|---|---|---|---|
| A.5.15 | Access control rules are defined and implemented | Roles, custom roles and separation-of-duties constraints | `GET /api/v1/roles`, `/api/v1/roles/sod-constraints` (UI `/roles`) | Artifact |
| A.5.23 | Information security for use of cloud services | Cloud KMS custody and cloud key inventory; the customer assesses their own cloud suppliers | `docs/ops/CLOUD_KMS.md`; `docs/ops/EGRESS.md` | Customer responsibility |
| A.8.2 | Privileged access rights are restricted | Separation of duties; dual control on key export and backup; bootstrap token never approves | `GET /api/v1/roles/sod-constraints`; `docs/DECISIONS.md` D-122 | Artifact |
| A.8.5 | Secure authentication | OIDC and SAML single sign-on, SCIM, break-glass activations with review | `docs/guides/sso-okta.md`; `docs/guides/sso-entra.md`; `GET /api/v1/auth/breakglass/status` | Artifact |
| A.8.15 | Logging | Audit log with export and archive; RFC 6962 style inclusion and consistency proofs over the log | `GET /api/v1/audit`, `/api/v1/audit/export`, `/api/v1/audit/transparency/checkpoint` | Artifact |
| A.8.20 | Networks are secured | Egress guard; trusted-proxy handling; per-IP rate limits | `docs/security/SECURITY_CLAIMS.md`; `docs/ops/EGRESS.md` | Artifact |
| A.8.21 | Security of network services | Hub TLS configured with a TLS 1.2 minimum (`cmd/kryptkeeper/tls.go`); the customer sets network policy | `docs/deployment.md` | Customer responsibility |
| A.8.24 | Use of cryptography | Algorithm policy, FIPS posture, crypto-posture report, key rotation and destruction procedures | `docs/release/proof-pack/FIPS_STATEMENT.md`; `/api/v1/reports/compliance-evidence?framework=nist`, control `NIST-800-131A` | Evidence pack |
| A.8.32 | Change management | Approvals and pending-action queue for sensitive changes; policy versions | `GET /api/v1/approvals`, `GET /api/v1/policies/{id}/versions` | Artifact |

## PCI DSS 4.0.1

| Control | What the control asks | Kryptkeeper capability | Artifact / evidence target | Status |
|---|---|---|---|---|
| 3.6 | Cryptographic keys protecting data are secured | Root keys in HSM or KMS; software keystore refused for the CA role in FIPS custody mode | `docs/ops/CLOUD_KMS.md`; `docs/ops/VENDOR_HSM_CHECKLIST.md` | Artifact |
| 3.7 | Key-management processes are defined and followed | Documented rotation and destruction procedures; dual control on key export | `docs/ops/KEY_ROTATION.md`; `docs/ops/KEY_DESTRUCTION.md` | Artifact |
| 4.2.1 | Strong cryptography protects data in transit | Strong-cryptography check over inventoried certificates | `/api/v1/reports/compliance-evidence?framework=pci`, control `PCI-DSS-4.2.1.1` | Evidence pack |
| 4.2.1.1 | An inventory of trusted keys and certificates is maintained | Certificate inventory with origin, owner and expiry | `GET /api/v1/certificates` (UI `/certificates`); control `PCI-DSS-4.2.1.1` | Evidence pack |
| 6.3.3 | Components are protected from known vulnerabilities by patching | Dependency scans in CI (govulncheck) and recorded findings; applying patches to the deployment is the customer's | `docs/security/DEPENDENCY_FINDINGS_2026-10-09.md`; `docs/deployment.md` | Customer responsibility |
| 8.3 | User authentication is strong | SSO with the customer's identity provider; API key last-used tracking | `docs/guides/sso-okta.md`; `docs/guides/sso-entra.md` | Customer responsibility |
| 10.2 | Audit logs capture required events | Audit log of API actions with actor, resource and outcome | `GET /api/v1/audit`, `/api/v1/audit/export` (UI `/audit`) | Artifact |
| 10.3 | Audit logs are protected from modification | Checkpoint, inclusion and consistency proofs make edits detectable against a recorded head | `GET /api/v1/audit/transparency/consistency` | Artifact |

## NIST SP 800-53 Rev. 5

There is no `nist-800-53` framework selector in the evidence pack (`framework=nist` emits the
`NIST-800-57-3.6` and `NIST-800-131A` controls only); other rows point to artifacts.

| Control | What the control asks | Kryptkeeper capability | Artifact / evidence target | Status |
|---|---|---|---|---|
| AC-2 | Account management | SCIM Users and Groups; user invite and role assignment; access review | `GET /api/v1/users`; `GET /api/v1/admin/access-review/campaigns` (UI `/users`, `/access-review`) | Artifact |
| AC-6 | Least privilege | Role-based access with custom roles; separation-of-duties constraints | `GET /api/v1/roles`, `/api/v1/roles/sod-constraints` (UI `/roles`) | Artifact |
| AU-2 | Event logging | Audit events emitted on mutating routes; a test checks every mutating path is audited | `GET /api/v1/audit`; `internal/bootstrap/audit_route_matrix_test.go` | Artifact |
| AU-12 | Audit record generation | Audit log with actor, resource, outcome and trace id; export and archive | `GET /api/v1/audit/export`, `/api/v1/audit/archive` | Artifact |
| CM-3 | Configuration change control | Approval workflow, pending actions, policy versions | `GET /api/v1/approvals`, `/api/v1/pending-actions`, `/api/v1/policies/{id}/versions` | Artifact |
| CM-8 | System component inventory | Certificate inventory and discovery of endpoints; key inventory | `GET /api/v1/certificates`, `/api/v1/discovery/endpoints`, `/api/v1/keys` | Artifact |
| IA-5 | Authenticator management | SSO; API keys with last-used tracking; break-glass credentials with review | `GET /api/v1/api-keys`; `docs/guides/sso-okta.md` | Artifact |
| SC-12 | Cryptographic key establishment and management | CA key custody, rotation and destruction procedures | `/api/v1/reports/compliance-evidence?framework=nist`, control `NIST-800-57-3.6`; `docs/ops/KEY_ROTATION.md` | Evidence pack |
| SC-13 | Cryptographic protection | Algorithm checks against NIST SP 800-131A; Go FIPS 140-3 module posture | `/api/v1/reports/compliance-evidence?framework=nist`, control `NIST-800-131A`; `docs/release/proof-pack/FIPS_STATEMENT.md` | Evidence pack |
| SC-17 | Public key infrastructure certificates | Internal CAs with issuance, revocation and CA health reporting | `GET /api/v1/cas`; `GET /api/v1/reports/ca-health`; control `INTERNAL-CA-HEALTH` | Evidence pack |
| SI-4 | System monitoring | Discovery scans, CT findings and notification rules | `GET /api/v1/discovery/summary`, `GET /api/v1/ct/findings`, `GET /api/v1/notifications/rules` | Artifact |

## Gaps

- The evidence pack has no `iso27001` framework key: ISO rows are mapped to artifacts only.
- The evidence pack has no `nist-800-53` framework selector: NIST 800-53 rows are mapped to
  artifacts only, except where a `NIST-800-57` / `NIST-800-131A` / `INTERNAL-CA-HEALTH` control id
  is cited.
- The CMVP certificate number and status are not recorded
  ([`../CMVP_STATUS.md`](../CMVP_STATUS.md)); rows that rely on FIPS posture inherit that limit.
- The SBOM checked in under `docs/security/` is dated 2026-10-09; per-release SBOMs come from
  `release.yml` and are listed by the W33-28 proof-pack index, not here.
