# Kryptkeeper competitive matrix (W33-28)

Accessed dates are the verification dates. Competitor products change; re-verify each release.

Release: v0.21 (pending tag) - matrix compiled 2026-10-17.

## Method

- Rows are the 14 fixed capabilities from the W33-28 spec; columns are Kryptkeeper plus the nine competitor codes (VEN, KEY, DIG, AVX, SEC, SMS, HCV, CMG, ADCS). No row or column was cut.
- Every cell is `value [n]`; `n` indexes the numbered sources at the bottom. Vocabulary for Kryptkeeper cells: `Yes`, `Partial`, `No`, `Not documented`.
- **Competitor columns were sourced on 2026-10-17** by fetching each vendor's own product or documentation pages (one source per cell, listed under Sources). Cell vocabulary is `Yes`, `Partial`, `No`, `Not documented`. No cell is `No`, because no vendor page explicitly says it lacks a capability.
- **Reading rules.** `Yes` means the cited page states the capability (all of the listed protocols or discovery sources for the multi-part rows); `Partial` means some of a multi-part row, or a related but narrower statement (see Competitor cell notes); `Not documented` means the cited page, as returned by the fetch tool, does not state it. It is absence of evidence, not a claim that the product lacks the capability, and the fetch tool summarises pages, so a capability buried in a sub-page may be missed. Re-check against full documentation before quoting externally.
- For the Ownership/ROI row, competitor cells assess ownership features only; no vendor page fetched states ROI tooling. For ITSM/ChatOps, `Partial` means ITSM or ServiceNow integration is stated but ChatOps is not.
- Pages that could not be fetched on 2026-10-17 and were therefore not used: sectigo.com/platform/certificate-manager (HTTP 404), docs.digicert.com/zf/trust-lifecycle-manager/ (HTTP 403), digicert.com/pricing (HTTP 404). cyberark.com/products/certificate-manager/ redirects to the Palo Alto Networks site (source 19), whose page names Venafi TLS Protect as the predecessor of its product but states none of the capabilities, so VEN cells cite the CyberArk/Venafi documentation (sources 15 to 18) instead.
- Kryptkeeper cells cite repo evidence only (dated live-result records, or the validation inventory when the evidence is unit tests). A capability with only unit or emulator evidence is `Partial`, never `Yes`. Kryptkeeper claims here are no stronger than `docs/release/FEATURE_VALIDATION_v0.9.md` and the v0.15 to v0.21 live records support.
- Internal research (`docs/research/RESEARCH_FINDINGS.md` section 8 and `docs/research/CLM_LEADERSHIP_2026.md`) carries competitor opinions with few or no vendor URLs. It was used only to confirm the competitor set, and no row was reused from it.

## Matrix

| Capability | Kryptkeeper | VEN | KEY | DIG | AVX | SEC | SMS | HCV | CMG | ADCS |
|---|---|---|---|---|---|---|---|---|---|---|
| ACME server | Yes [1] | Yes [16] | Yes [22] | Yes [26] | Yes [32] | Yes [33] | Yes [36] | Yes [39] | Not documented [46] | Not documented [49] |
| EST/SCEP/CMP protocols | Yes [2] | Partial [17] | Yes [22] | Yes [27] | Partial [32] | Partial [33] | Partial [38] | Yes [39] | Not documented [46] | Not documented [49] |
| Internal CA with HSM/KMS custody | Partial [3] | Partial [17] | Yes [21] | Not documented [26] | Partial [28] | Not documented [33] | Yes [36] | Partial [42] | Not documented [46] | Not documented [49] |
| Agentless install over SSH/WinRM | Partial [4] | Not documented [17] | Partial [20] | Not documented [26] | Not documented [28] | Not documented [33] | Not documented [36] | Not documented [39] | Not documented [46] | Not documented [49] |
| Agent-based install | Yes [5] | Yes [17] | Yes [20] | Not documented [26] | Not documented [28] | Yes [35] | Not documented [38] | Not documented [39] | Not documented [46] | Not documented [49] |
| Discovery (network + CT + cloud) | Partial [6] | Partial [17] | Partial [20] | Yes [26] | Partial [28] | Partial [33] | Not documented [36] | Not documented [39] | Not documented [46] | Not documented [49] |
| Ownership/ROI | Partial [7] | Partial [15] | Partial [20] | Partial [26] | Not documented [28] | Not documented [33] | Not documented [36] | Not documented [39] | Not documented [46] | Not documented [49] |
| Approvals with dual control | Partial [8] | Partial [15] | Partial [20] | Not documented [27] | Not documented [28] | Not documented [33] | Not documented [36] | Partial [40] | Partial [47] | Not documented [49] |
| PQC (ML-DSA) issuance | Partial [9] | Not documented [15] | Yes [22] | Partial [26] | Partial [29] | Partial [33] | Not documented [36] | Not documented [39] | Not documented [46] | Yes [49] |
| FIPS 140-3 posture | Partial [10] | Not documented [15] | Not documented [22] | Not documented [26] | Not documented [29] | Not documented [33] | Not documented [37] | Partial [41] | Not documented [48] | Not documented [49] |
| SSO/RBAC/tenancy | Partial [11] | Partial [15] | Partial [20] | Partial [26] | Partial [31] | Partial [33] | Partial [36] | Partial [40] | Partial [47] | Partial [49] |
| ITSM/ChatOps | Partial [12] | Not documented [15] | Partial [20] | Partial [26] | Partial [30] | Not documented [33] | Not documented [36] | Not documented [39] | Not documented [46] | Not documented [49] |
| Open-source license / self-host | Yes [13] | Partial [15] | Yes [24] | Not documented [26] | Not documented [28] | Not documented [33] | Yes [38] | Partial [45] | Yes [48] | Partial [49] |
| Public pricing disclosed | Not documented [14] | Not documented [15] | Not documented [20] | Not documented [26] | Not documented [28] | Not documented [33] | Not documented [37] | Not documented [43] | Not documented [46] | Not documented [49] |

## Caveats on Kryptkeeper cells

- Protocols (row 2): SCEP and EST are proven against software clients; no real network-device SCEP client (F5, Citrix, Palo Alto) is recorded (`docs/release/FEATURE_VALIDATION_v0.9.md`).
- HSM/KMS (row 3): only PKCS#11 on SoftHSM2 is a live result. No vendor HSM or CloudHSM run is recorded.
- Agentless install (row 4): SSH install passed live on four servers; WinRM/IIS is lab-only, so the row is `Partial`.
- FIPS (row 10): the claim is exactly 'uses the Go FIPS 140-3 module (CMVP status: certificate #5247, Active)', the upstream Go module's certificate. The product is not described as validated.
- SSO/RBAC/tenancy (row 11): OIDC and SAML pass against Keycloak; Okta and Entra ID acceptance (`docs/release/SSO_UAT_RECORD.md`) is unfilled, so no real-IdP result is claimed; multi-tenancy is experimental.
- ITSM/ChatOps (row 12): no ServiceNow or Jira evidence was found, so only the chat/SIEM side is claimed.
- Pricing (row 14): this reflects the repository, which discloses no pricing; it is not a statement about the market.
- Penetration test: not yet done (`docs/release/proof-pack/PENTEST_SCOPE.md` is a draft scope). Accessibility: ACR/VPAT exists but manual screen-reader testing is PENDING-RUN (`docs/release/ACR_VPAT_v0.21.md`). Neither is claimed as a strength here.

## Competitor cell notes

- ACME (row 1): KEY cell rests on EJBCA (ACME marked Enterprise-only in source 22); Command's page does not mention ACME. cert-manager is documented as an ACME client of other CAs; its page does not state an ACME server. DIG and AVX/SEC: pages state ACME-based automation; AVX evidence is a 2020.3.0 guide.
- Protocols (row 2): VEN names EST and SCEP (no CMP); AVX names ACME, EST, SCEP; SEC names SCEP and EST (no CMP); SMS: SCEP provisioner in the repo README, while the docs list no dynamic SCEP for Intune or Jamf and do not mention EST. ADCS lists the Network Device Enrollment Service without naming SCEP on the cited page.
- HSM (row 3): VEN lists a virtual HSM backend (code signing); HCV lists PKCS#11 HSM support as an Enterprise feature for auto-unseal; AVX lists HSMs as an integration target. None of these pages states CA-key custody exactly as the row defines it.
- Approvals (row 8): `Partial` means approval workflows or roles are stated, with no explicit dual control. HCV is a sidebar mention of control groups only.
- FIPS (row 10): HCV states Enterprise FIPS 140-3 builds (BoringCrypto, Enterprise Plus license); the page does not claim a CMVP certificate. KEY's EJBCA page cites Common Criteria, not FIPS 140.
- Open source / self-host (row 13): HCV is Business Source License 1.1 (source-available, self-hostable), so `Partial`. VEN and ADCS are self-hosted but not open source. KEY rests on EJBCA Community (LGPL).
- Pricing (row 14): `Not documented` means no prices appear on the cited page (DIG, SEC and others route to a quote or demo).

## Sources

### Kryptkeeper (repo evidence)

1. test: docs/release/LIVE_RESULTS_FG2_ACME_v0.14.md (certbot 5.8.0, lego 5.5.2; 53 passed, 0 failed) - run date 2026-10-16
2. test: docs/release/LIVE_RESULTS_FG2_PROTOCOLS_v0.14.md (EST, SCEP, CMP; 105 PASS lines, 0 failures) - run date 2026-10-16
3. test: docs/release/FEATURE_VALIDATION_v0.9.md section 3.11 keystore backends (PKCS#11 on SoftHSM2 live 23/23; AWS KMS and Azure Key Vault against emulators; no vendor HSM) - snapshot 2026-10-09, updated 2026-10-11. tests/live/kms-gcp exists but no run record is in docs/release
4. test: docs/release/LIVE_RESULTS_SSH_INSTALL_v0.15.md (43 checks, nginx/apache/haproxy/tomcat) - run date 2026-10-16; WinRM/IIS install is lab-only per docs/release/FEATURE_VALIDATION_v0.9.md (UAT 2026-09-10)
5. test: docs/release/FEATURE_VALIDATION_v0.9.md section 3.5 (tests/live/agent/run.sh 18 passed, 0 failed) - run date 2026-10-11; docs/release/LIVE_RESULTS_WINDOWS_AGENT_v0.9.4.md - run date 2026-10-15
6. test: docs/release/DISCOVERY_RATES_v0.12.md (network TLS corpus, ALL PASS) - run date 2026-10-15; CT monitoring and cloud inventory are UNIT-ONLY in docs/release/FEATURE_VALIDATION_v0.9.md section 3.4 - snapshot 2026-10-11
7. test: docs/release/RELEASE_NOTES_v0.10.0.md (ownership source, unowned filter, CMDB import) and docs/release/FEATURE_VALIDATION_v0.9.md (bulk and ownership UNIT-ONLY; no ROI evidence found) - record date 2026-10-11
8. test: docs/release/FEATURE_VALIDATION_v0.9.md section 3.10 (approval queue INTEGRATION; self-approve 403 in the live plugins harness; key dual control UNIT-ONLY) - snapshot 2026-10-11
9. test: docs/release/FEATURE_VALIDATION_v0.9.md section 3.1 PQC row (ML-DSA, hybrid: UNIT-ONLY, software keys only, no interop test) - snapshot 2026-10-11
10. record: docs/release/CMVP_STATUS.md and docs/release/proof-pack/FIPS_STATEMENT.md (build pin GOFIPS140=v1.0.0; Go Cryptographic Module CMVP #5247 Active, checked 2026-10-17)
11. test: docs/release/LIVE_RESULTS_KEYCLOAK_v0.21.md (OIDC and SAML via Keycloak, 39 passed, 0 failed) - run date 2026-10-17; custom RBAC UNIT-ONLY and multi-tenancy experimental per docs/release/FEATURE_VALIDATION_v0.9.md sections 3.9 and 3.13
12. test: docs/release/FEATURE_VALIDATION_v0.9.md section 3.7 (Slack and SIEM webhook payloads to a stand-in receiver; PagerDuty/Teams UNIT-ONLY); no ITSM (ServiceNow/Jira) evidence found in docs/release - snapshot 2026-10-11
13. record: LICENSE (Apache License 2.0) and docs/release/UAT_COMPOSE_QUICKSTART_v0.13.md (compose self-host quickstart; clean-machine verdict TBD) - checked 2026-10-17
14. record: README.md searched for pricing on 2026-10-17; no pricing section found

### Competitors (vendor pages fetched 2026-10-17)

15. CyberArk Certificate Manager - Self-Hosted Introduction (VEN) - https://docs.venafi.com/Docs/current/TopNav/Content/Products/c-tls-protect-landing.php - accessed 2026-10-17
16. ACME integration with Certificate Manager - Self-Hosted (VEN) - https://docs.venafi.com/Docs/current/TopNav/Content/ACME/cco-ACME-about.php - accessed 2026-10-17
17. Trust Protection Foundation components (VEN) - https://docs.venafi.com/Docs/currentSDK/TopNav/Content/Install/r-install-select-components.php - accessed 2026-10-17
18. Configuring network device enrollment (VEN) - https://docs.venafi.com/Docs/current/TopNav/Content/Devices/t-devices-NDE-server-support-configuring.php - accessed 2026-10-17 (fetched; confirms SCEP network device enrollment, not cited in a cell)
19. Palo Alto Networks Certificate Manager (redirect target of the CyberArk product URL; states none of the matrix capabilities) - https://www.paloaltonetworks.com/network-security/next-gen-trust-security/certificate-manager - accessed 2026-10-17
20. Keyfactor Command product page (KEY) - https://www.keyfactor.com/products/command/ - accessed 2026-10-17
21. Keyfactor EJBCA Enterprise product page (KEY) - https://www.keyfactor.com/products/ejbca-enterprise/ - accessed 2026-10-17
22. EJBCA Interoperability and Certifications (KEY) - https://docs.keyfactor.com/ejbca/latest/interoperability-and-certifications - accessed 2026-10-17
23. EJBCA documentation home (KEY) - https://docs.keyfactor.com/ejbca/latest/ - accessed 2026-10-17 (fetched; lists no capability, not cited in a cell)
24. EJBCA Community repository README (KEY) - https://github.com/Keyfactor/ejbca-ce - accessed 2026-10-17
25. EJBCA introduction page (KEY) - https://docs.keyfactor.com/ejbca/latest/ejbca-introduction - accessed 2026-10-17 (fetched; no approvals, tenancy, RBAC, HSM or FIPS statement, not cited in a cell)
26. DigiCert Trust Lifecycle Manager product page (DIG) - https://www.digicert.com/trust-lifecycle-manager - accessed 2026-10-17
27. DigiCert Trust Lifecycle Manager: enroll and manage certificates (DIG) - https://docs.digicert.com/zf/trust-lifecycle-manager/enroll-and-manage-certificates.html - accessed 2026-10-17
28. AppViewX AVX ONE product page (AVX) - https://www.appviewx.com/products/avx-one/ - accessed 2026-10-17
29. AppViewX home page (AVX) - https://www.appviewx.com/ - accessed 2026-10-17
30. AppViewX on ServiceNow guides, docs 2026.2.0 (AVX) - https://docs.appviewx.com/2026.2.0/oxy_ex/appviewx_on_servicenow_guides.html - accessed 2026-10-17
31. AppViewX SSO, docs 2026.2.0 (AVX) - https://docs.appviewx.com/2026.2.0/oxy_ex/sso.html - accessed 2026-10-17
32. AppViewX CERT admin guide 2020.3.0, auto enrollment protocols (AVX; old release, re-check against current docs) - https://helpcenter.appviewx.com/frontend/web/Published%20Guides/2020.3.0/CERT/Admin%20Guide/webhelp-responsive/auto_enrollment_protocols_0.html - accessed 2026-10-17
33. Sectigo Certificate Manager product page (SEC) - https://www.sectigo.com/enterprise-solutions/certificate-manager - accessed 2026-10-17
34. Sectigo Certificate Manager SCEP integration page (SEC) - https://www.sectigo.com/enterprise-solutions/certificate-manager/integrations-scep - accessed 2026-10-17 (fetched; SCEP only, not cited in a cell)
35. Sectigo blog: SSL certificate automation options (SEC; post dated 2019-05-02, so dated evidence) - https://www.sectigo.com/blog/when-it-comes-to-ssl-certificate-automation-sectigo-provides-plenty-of-options - accessed 2026-10-17
36. step-ca documentation (SMS) - https://smallstep.com/docs/step-ca/ - accessed 2026-10-17
37. Smallstep pricing page (SMS) - https://smallstep.com/pricing/ - accessed 2026-10-17
38. smallstep/certificates repository README (SMS) - https://github.com/smallstep/certificates - accessed 2026-10-17
39. Vault PKI secrets engine documentation (HCV) - https://developer.hashicorp.com/vault/docs/secrets/pki - accessed 2026-10-17
40. Vault Enterprise documentation (HCV) - https://developer.hashicorp.com/vault/docs/enterprise - accessed 2026-10-17
41. Vault built-in FIPS 140-3 support (HCV) - https://developer.hashicorp.com/vault/docs/enterprise/fips/fips1403 - accessed 2026-10-17
42. Vault Enterprise HSM support (HCV) - https://developer.hashicorp.com/vault/docs/enterprise/hsm - accessed 2026-10-17
43. HashiCorp pricing page (HCV) - https://www.hashicorp.com/en/pricing - accessed 2026-10-17
44. hashicorp/vault repository README (HCV) - https://github.com/hashicorp/vault - accessed 2026-10-17 (fetched; links to LICENSE, not cited in a cell)
45. hashicorp/vault LICENSE file (HCV) - https://raw.githubusercontent.com/hashicorp/vault/main/LICENSE - accessed 2026-10-17
46. cert-manager documentation home (CMG) - https://cert-manager.io/docs/ - accessed 2026-10-17
47. cert-manager CertificateRequest usage (CMG) - https://cert-manager.io/docs/usage/certificaterequest/ - accessed 2026-10-17
48. cert-manager repository README (CMG) - https://github.com/cert-manager/cert-manager - accessed 2026-10-17
49. What is Active Directory Certificate Services in Windows Server (ADCS) - https://learn.microsoft.com/en-us/windows-server/identity/ad-cs/active-directory-certificate-services-overview - accessed 2026-10-17
