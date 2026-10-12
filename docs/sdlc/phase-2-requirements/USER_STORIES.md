# Kryptkeeper — User Stories

**Version:** 1.0
**Date:** 2026-04-05
**Phase:** 2 — Requirements

Story points use Fibonacci scale: 1, 2, 3, 5, 8, 13.
Priorities: Must / Should / Could (map to Must-have / Should-have / Could-have).

---

## Persona Reference

| Code | Persona | Role |
|------|---------|------|
| **Alex** | PKI Administrator | Senior Security Engineer / PKI Lead |
| **Jordan** | Platform Engineer | Senior Platform / DevOps Engineer |
| **Sam** | CISO / Security Leader | VP of Security / CISO |
| **Riley** | Network/Infrastructure Engineer | Network Engineer / Systems Administrator |
| **Casey** | Open-Source Contributor | Go developer interested in PKI |

---

## Epic 1: CA Operations

*Build and manage a complete Certificate Authority hierarchy from root CA through issuing CAs.*

---

### US-001: Create Root CA

**As an** Alex (PKI Admin), **I want to** create a self-signed root CA with my choice of key algorithm and key storage backend, **so that** I have a trusted anchor for our entire PKI without requiring a Windows Server or third-party CA service.

**Priority:** Must | **Version:** V1 | **Points:** 8
**Maps to:** FR-001, FR-003, FR-004

**Acceptance Criteria:**
- Given a valid root CA config (name, validity, algorithm RSA-4096/ECDSA P-384/Ed25519, key storage), when I submit the create request via the API, then a self-signed root CA certificate is generated, stored, and returned with its `fingerprint_sha256`.
- Given I choose software key storage, when the root CA is created, then the key file on disk is PKCS#8 encrypted with Argon2id (minimum 64MB memory, 4 iterations) and cannot be read without the correct passphrase.
- Given I choose PKCS#11 key storage, when the root CA is created, then the key is generated on the HSM/token and never leaves it.
- Given the dashboard CA hierarchy view, when the root CA is created, then it appears as a root node with `status=active`.
- Given an unsupported key algorithm (e.g., DSA), when the create request is submitted, then the API returns HTTP 400 with a clear error identifying the unsupported algorithm.

---

### US-002: Air-Gapped Root CA Key Ceremony

**As an** Alex (PKI Admin), **I want to** generate the root CA key on an air-gapped machine and import only the signed root certificate into the platform, **so that** the root CA private key is never exposed on an internet-connected system and meets our security policy for root CAs.

**Priority:** Must | **Version:** V1 | **Points:** 5
**Maps to:** FR-001, FR-006

**Acceptance Criteria:**
- Given an externally-generated root CA certificate (PEM-encoded), when I submit it to the import API, then the certificate is stored as a trust anchor with `type=root, key_storage_type=external`.
- Given the imported root CA has no private key in the platform, when I attempt to issue a certificate directly from it (without an intermediate), then the system returns HTTP 422 with an error stating the root CA has no signing key available.
- Given the imported root CA, when I create an issuing CA subordinate to it, then the system generates an issuing CA CSR for me to sign offline, and I can import the signed issuing CA certificate to complete the hierarchy.
- Given the complete documentation for the air-gapped workflow, when an operator follows the quickstart, then the entire ceremony (root CA import + issuing CA creation + first certificate issuance) can be completed in under 30 minutes.

---

### US-003: Create Issuing CA Subordinate to Root

**As an** Alex (PKI Admin), **I want to** create an issuing (intermediate) CA subordinate to my root CA, **so that** I can keep the root CA offline and limit the blast radius of a potential key compromise to the issuing CA.

**Priority:** Must | **Version:** V1 | **Points:** 5
**Maps to:** FR-002, FR-003

**Acceptance Criteria:**
- Given an active root CA with a software key, when I create an issuing CA specifying the root as parent, then the issuing CA certificate is signed by the root CA (verified by `openssl verify -CAfile root.pem issuing.pem`), stored with `status=active`, and appears nested under the root in the CA hierarchy view.
- Given the issuing CA, when I view it in the dashboard, then I can see: the CA certificate details, the number of certificates issued, and the expiry date of the CA certificate itself.
- Given an issuing CA approaching expiry (< 90 days remaining), when the dashboard loads, then an expiry warning is shown on the CA hierarchy view for that issuing CA.
- Given I create a second issuing CA under the same root, when the hierarchy view loads, then both issuing CAs appear as children of the root node with their individual metadata.

---

### US-004: Revoke CA Certificate

**As an** Alex (PKI Admin), **I want to** revoke an issuing CA certificate and have all certificates issued by that CA immediately reflected as revoked, **so that** I can respond to a key compromise without waiting for CRL TTLs to expire.

**Priority:** Must | **Version:** V1 | **Points:** 5
**Maps to:** FR-012, FR-040, FR-042

**Acceptance Criteria:**
- Given an active issuing CA, when I revoke it via the API with reason `cACompromise`, then the issuing CA's `status` is set to `revoked`, the parent CA generates an updated CRL within 60 seconds including the issuing CA's serial, and OCSP queries for any certificate issued by that CA return `revoked`.
- Given a revoked issuing CA, when any enrollment protocol (ACME, EST, SCEP) attempts to issue through it, then the request is rejected with an appropriate error.
- Given the dashboard CA hierarchy view, when an issuing CA is revoked, then it is visually distinguished from active CAs and no issuance actions are available.

---

### US-005: Manage Key Storage Backend per CA

**As an** Alex (PKI Admin), **I want to** configure each CA's key storage backend independently (software, PKCS#11 HSM, or cloud KMS), **so that** I can use hardware key protection for production issuing CAs while using software keys for dev/test CAs without managing separate deployments.

**Priority:** Should | **Version:** V1 | **Points:** 8
**Maps to:** FR-003, FR-004

**Acceptance Criteria:**
- Given a CA configured with `key_storage_type=pkcs11`, when a certificate is issued from that CA, then the signing operation uses the PKCS#11 `C_Sign` function and the private key bytes are never accessible in Go heap memory.
- Given a CA configured with `key_storage_type=software` Layer 2 (envelope encryption), when the platform starts, then the master key is fetched from the configured Vault path and the CA key is decrypted in memory only for the duration of the signing operation.
- Given SoftHSM2 configured as the PKCS#11 provider in CI, when all PKCS#11 integration tests run, then they pass without a physical HSM.
- Given a CA key storage configuration change (which is not supported post-creation), when the API is called to change `key_storage_type` on an existing CA, then HTTP 422 is returned with an error explaining that key storage type is immutable after CA creation.

---

## Epic 2: Certificate Lifecycle

*Issue, renew, and revoke certificates with template-based policy enforcement.*

---

### US-010: Issue Certificate from CSR

**As a** Jordan (Platform Engineer), **I want to** submit a PKCS#10 CSR and receive a signed certificate in return using a named template, **so that** I can issue certificates for internal services programmatically without filing a ticket with the PKI team.

**Priority:** Must | **Version:** V1 | **Points:** 5
**Maps to:** FR-005, FR-010, FR-021

**Acceptance Criteria:**
- Given a valid CSR with an RSA-2048 key and the `internal-tls` template, when `POST /api/v1/certificates` is called with my API key, then I receive HTTP 200 with the signed certificate in PEM format, the full issuing chain in PEM format, and the certificate `fingerprint_sha256`.
- Given a CSR with an RSA-1024 key (below the template minimum of 2048), when the issuance request is submitted, then HTTP 400 is returned with `error_code: WEAK_KEY` and a message specifying the minimum required key size.
- Given a CSR requesting an EKU not permitted by the template, when submitted, then HTTP 400 is returned with `error_code: POLICY_VIOLATION` identifying the specific constraint.
- Given the same CSR submitted twice before the first certificate expires, when the second request is made, then the same existing certificate is returned (idempotent issuance by public key + template).

---

### US-011: Define and Enforce Certificate Templates

**As an** Alex (PKI Admin), **I want to** create certificate templates that define key usage, EKU, minimum key size, validity period, and enrollment permissions, **so that** all certificates issued from each template conform to our security policy without requiring manual review of every CSR.

**Priority:** Must | **Version:** V1 | **Points:** 8
**Maps to:** FR-020, FR-021, FR-022

**Acceptance Criteria:**
- Given a template creation request with `extended_key_usage: [serverAuth]`, `min_key_size: 2048`, `allowed_algorithms: [RSA, ECDSA]`, `validity_period: 90`, when submitted, then the template is stored with a unique OID and a `revision=1`.
- Given a template with `enrollment_permissions: {enroll: ["pki-admin", "service-account"]}`, when a caller with role `developer` attempts to issue from this template, then HTTP 403 is returned.
- Given a template with `validity_period: 90`, when a certificate is issued from it, then `valid_until - valid_from` equals exactly 90 days regardless of what validity period the CSR requested.
- Given a template update changing `validity_period` from 90 to 47 days, when saved, then `revision` increments to 2 and certificates issued afterwards have a 47-day validity; previously issued certificates are unaffected.

---

### US-012: Renew Certificate with Chain Tracking

**As an** Alex (PKI Admin), **I want to** renew a certificate by submitting a new CSR and have the renewal chain tracked (predecessor/successor links), **so that** I can trace the full history of any certificate and understand its renewal lineage.

**Priority:** Must | **Version:** V1 | **Points:** 5
**Maps to:** FR-011, FR-014

**Acceptance Criteria:**
- Given an active certificate `C1` within 30 days of expiry, when a renewal CSR is submitted, then a new certificate `C2` is issued and `C2.predecessor_fingerprint = C1.fingerprint_sha256`.
- Given `C1` after `C2` is issued, when `C1` is queried, then `C1.successor_fingerprint = C2.fingerprint_sha256` and `C1.renewal_status = renewed`.
- Given a certificate renewed 3 times (C1 → C2 → C3 → C4), when `GET /api/v1/certificates/{C4.fingerprint}/chain` is called, then the response contains all 4 certificates in chronological order (C1 first).
- Given a certificate renewal via ACME auto-renewal, when the ACME flow completes, then the predecessor/successor chain is populated automatically without any manual API call.

---

### US-013: Revoke Certificate

**As an** Alex (PKI Admin), **I want to** revoke a certificate by fingerprint with a specific RFC 5280 reason code, **so that** I can immediately invalidate a compromised or superseded certificate and have the revocation reflected in both OCSP and CRL within 60 seconds.

**Priority:** Must | **Version:** V1 | **Points:** 5
**Maps to:** FR-012, FR-040, FR-042

**Acceptance Criteria:**
- Given an active certificate, when `DELETE /api/v1/certificates/{fingerprint}` is called with reason `keyCompromise`, then HTTP 200 is returned, the certificate status becomes `revoked`, and an audit log entry records the actor, timestamp, and reason.
- Given the revocation, when an OCSP query is made for the certificate's serial number within 60 seconds, then the OCSP response returns `revoked` with the correct `revokedInfo`.
- Given the next scheduled CRL generation (or the immediate CRL regeneration triggered by revocation), when `openssl crl -text -noout -in crl.pem` is run, then the serial appears in the revoked list with reason `keyCompromise`.
- Given a `certificateHold` revocation followed by a `removeFromCRL` operation, when the subsequent CRL is generated, then the certificate serial is absent from the revoked list and OCSP returns `good`.

---

### US-014: Configure Multi-Tier Expiry Alerts

**As an** Alex (PKI Admin), **I want to** configure expiry alert thresholds (90, 60, 30, 14, 7 days, and at expiry) routed to each certificate's owner team, **so that** the right people are notified at the right time without flooding everyone with every expiry in the organization.

**Priority:** Must | **Version:** V1 | **Points:** 5
**Maps to:** FR-013, FR-081

**Acceptance Criteria:**
- Given a certificate with `owner_team=platform-eng` and a Slack channel configured for that team, when the certificate's `valid_until` crosses the 30-day threshold, then a Slack message is sent containing the CN, exact expiry date, days remaining, risk score, and a direct link to the certificate in the dashboard.
- Given the same certificate, when the 30-day threshold fires, then no subsequent alert fires for the 30-day threshold for this certificate in this expiry cycle (each threshold fires exactly once per cycle).
- Given a certificate with no `owner_team`, when a threshold is breached, then the alert is sent to the configured global inbox.
- Given thresholds configured at the global level, when a template-specific override is set for a template's certificates, then the template-specific thresholds take precedence for certificates issued from that template.

---

### US-015: Export Compliance Report

**As a** Sam (CISO), **I want to** export a filtered certificate inventory report (e.g., "all certificates expiring in 90 days") as CSV, **so that** I can present it to auditors as evidence of cryptographic hygiene without building a custom query.

**Priority:** Should | **Version:** V1 | **Points:** 3
**Maps to:** FR-071, FR-085

**Acceptance Criteria:**
- Given a filter applied to the certificate inventory (e.g., `expiry_days_max=90`), when I click "Export CSV" in the dashboard or call `GET /api/v1/certificates?format=csv`, then I receive a CSV file with columns: common_name, subject_dn, issuer_cn, valid_from, valid_until, days_remaining, risk_score, grade, owner_team, owner_email, fingerprint_sha256, source.
- Given a filter producing 50,000 results, when the export is requested, then the CSV download completes within 30 seconds.
- Given the exported CSV, when each row is verified, then the data matches the inventory state at the time of export (not a stale snapshot).

---

## Epic 3: Discovery and Inventory

*Find every certificate in the organization, regardless of how it was issued or where it lives.*

---

### US-020: Run Network TLS Scan

**As an** Alex (PKI Admin), **I want to** scan a network IP range and automatically discover all TLS endpoints and extract their certificates, **so that** I can see certificates I didn't know existed — especially ones deployed by other teams without going through the PKI process.

**Priority:** Must | **Version:** V1 | **Points:** 13
**Maps to:** FR-050, FR-051

**Acceptance Criteria:**
- Given an authorized /24 CIDR, when a network scan job is created with `scan_authorization_acknowledged=true`, then Phase 1 (masscan port detection) identifies all open TLS ports within 5 minutes.
- Given the Phase 1 results, when Phase 2 runs, then all reachable TLS endpoints have their certificates extracted (full chain, cipher suite, TLS version) and stored in the inventory within 30 minutes for up to 10,000 endpoints.
- Given a scan job created without `scan_authorization_acknowledged=true`, when submitted, then HTTP 400 is returned and no scanning is initiated.
- Given a host serving different certificates for `app.example.internal` vs. `api.example.internal` (SNI-based virtual hosting), when both hostnames are in the DNS dataset, then both certificates are discovered as distinct `certificates` rows linked to the same IP via separate `endpoints` rows with different `sni_name` values.
- Given 1,000 already-known certificates from a previous scan, when the scan re-runs, then the `certificates` table is not duplicated (dedup by `fingerprint_sha256`) and the `endpoints.last_scanned` timestamps are updated.

---

### US-021: Schedule Recurring Scans

**As an** Alex (PKI Admin), **I want to** schedule recurring network and host discovery scans, **so that** the certificate inventory stays current automatically as new services are deployed or certificates are rotated.

**Priority:** Should | **Version:** V1 | **Points:** 5
**Maps to:** FR-050, FR-088

**Acceptance Criteria:**
- Given a scan target configured with a weekly schedule (e.g., every Sunday at 02:00 UTC), when the scheduled time arrives, then the scan job is automatically created and executed without manual intervention.
- Given a schedule for a cloud API discovery job (daily), when the schedule fires, then the cloud discovery job runs and the inventory is updated.
- Given the discovery management dashboard, when I view scheduled scan targets, then each target shows its schedule, last run time, last run status, and next scheduled run time.
- Given a scan job currently running when its next scheduled instance would fire, then the new job is skipped (not queued in parallel) and a warning is logged.

---

### US-022: Discover Certificates via SSH on Linux Hosts

**As an** Alex (PKI Admin), **I want to** run agentless discovery on Linux hosts via SSH, **so that** I can find certificates stored as PEM files or referenced in nginx/Apache configs without installing an agent on every host.

**Priority:** Must | **Version:** V1 | **Points:** 8
**Maps to:** FR-055

**Acceptance Criteria:**
- Given a Linux host with SSH key-based auth configured, when a host discovery job runs against it, then all `.pem`, `.crt`, `.cer`, `.key` (certificate-only), and `.pfx` files outside excluded paths are found, parsed, and added to the inventory within 10 minutes.
- Given a host running nginx with `ssl_certificate /etc/nginx/ssl/app.pem`, when discovery runs, then the certificate is found via nginx config parsing (not just filesystem search) and tagged with `source_reference=nginx_config`.
- Given a path excluded in the scan configuration (e.g., `/var/lib/docker`), when discovery runs, then no certificates under that path are reported (even if PEM files exist there).
- Given a discovery attempt on an unreachable host (SSH timeout), when the job completes, then the host is marked as `scan_error` with the error message, and the rest of the batch continues unaffected.

---

### US-023: Discover Certificates via WinRM on Windows Hosts

**As an** Alex (PKI Admin), **I want to** discover certificates from Windows hosts via WinRM (enumerating Windows certificate stores and IIS bindings), **so that** I have a complete picture of TLS certificates on our Windows-based services alongside Linux.

**Priority:** Must | **Version:** V1 | **Points:** 8
**Maps to:** FR-056

**Acceptance Criteria:**
- Given a Windows host with WinRM enabled and valid credentials, when a WinRM discovery job runs, then all certificates in `Cert:\LocalMachine\My` and `Cert:\LocalMachine\Root` are discovered and added to the inventory.
- Given an IIS site with a TLS binding on port 443, when WinRM discovery runs, then the certificate is discovered and an `endpoints` row is created with `hostname` from the IIS binding and `port=443`.
- Given Windows credentials stored encrypted in the platform, when a WinRM discovery job runs, then the credentials are used without appearing in any log output or error message.

---

### US-024: Deploy Agent for Real-Time Discovery

**As a** Jordan (Platform Engineer), **I want to** deploy the Kryptkeeper agent binary on our servers for real-time certificate change detection, **so that** when my deployment pipeline rotates a certificate, the inventory is updated within 60 seconds without waiting for the next scheduled scan.

**Priority:** Must | **Version:** V1 | **Points:** 8
**Maps to:** FR-060, FR-061, FR-062

**Acceptance Criteria:**
- Given the `pki-agent` binary (under 15MB compressed), when copied to a Linux host and started with a valid config file, then the agent starts without any additional runtime dependencies, discovers local certificates, and reports them to the platform within 15 minutes.
- Given the agent monitoring `/etc/ssl/certs`, when a new `.pem` file is written to that directory, then the agent detects the change via inotify and reports the new certificate to the platform within 60 seconds (without waiting for the next poll cycle).
- Given an agent that has already reported 1,000 certificates, when no certificates have changed since the last poll, then the next poll transmits only a heartbeat (delta report with zero new or changed certificates).
- Given an agent configured with a 15-minute poll interval, when the agent's inotify watcher fails, then the agent falls back to polling and logs a warning — it does not crash.

---

### US-025: Integrate Cloud Certificate Inventory

**As a** Jordan (Platform Engineer), **I want to** pull certificates from AWS ACM, Azure Key Vault, and GCP Certificate Manager into the unified inventory, **so that** I can see cloud-managed certificates alongside internally-issued ones in a single view.

**Priority:** Should | **Version:** V1 | **Points:** 8
**Maps to:** FR-057

**Acceptance Criteria:**
- Given AWS credentials with `acm:ListCertificates` and `acm:DescribeCertificate` IAM permissions, when a cloud discovery job runs for the configured AWS region, then all ACM certificates are added to the inventory with `source=cloud_aws_acm` and correct `valid_until` dates.
- Given the inventory, when filtered by `source=cloud_aws_acm`, then only ACM-sourced certificates are returned.
- Given an ACM certificate that also appears as a discovered certificate from a network scan (same `fingerprint_sha256`), when both discoveries are processed, then exactly one `certificates` row exists (deduplication by `fingerprint_sha256`), with both sources recorded in `source_references`.
- Given no cloud credentials configured, when the platform starts, then it starts successfully without any outbound network calls to cloud APIs (cloud discovery is strictly on-demand).

---

### US-026: Monitor Certificate Transparency Logs

**As an** Alex (PKI Admin), **I want to** monitor CT logs for certificates issued for our domains, **so that** I can detect shadow IT certificates or misissuance without running a scan.

**Priority:** Should | **Version:** V1 | **Points:** 5
**Maps to:** FR-052

**Acceptance Criteria:**
- Given a configured domain pattern `*.example.com`, when CT log monitoring polls crt.sh and finds a new certificate matching the pattern, then the certificate is added to the inventory within 4 hours of its CT log inclusion.
- Given a certificate already in the inventory (by `fingerprint_sha256`), when CT monitoring encounters it, then no duplicate is created.
- Given a new CT-discovered certificate issued by an unexpected CA (not in our configured issuing CAs), when it is added to the inventory, then it receives the `UNTRUSTED_ROOT` or unexpected-issuer risk flag and triggers an alert to the configured security inbox.

---

### US-027: Discover Kubernetes Certificates

**As a** Jordan (Platform Engineer), **I want to** discover TLS certificates from Kubernetes Secrets and cert-manager CRDs, **so that** I have visibility into cluster-internal certificates without running network scans against pod IPs.

**Priority:** Should | **Version:** V1 | **Points:** 5
**Maps to:** FR-058

**Acceptance Criteria:**
- Given a kubeconfig with `get/list` permissions on `secrets` and `certificates.cert-manager.io` in the target namespaces, when a Kubernetes discovery job runs, then all TLS Secrets and cert-manager Certificate resources are added to the inventory with `source=kubernetes`.
- Given a cert-manager `Certificate` resource in namespace `prod`, when discovered, then the inventory entry's `source_reference` field contains `kubernetes/<cluster-name>/prod/<secret-name>`.
- Given an Ingress resource with a TLS host `api.internal`, when discovered, then an `endpoints` row is created linking the certificate to the hostname.

---

### US-028: View Unified Certificate Inventory

**As a** Sam (CISO), **I want to** view all certificates across the organization in a single, filterable inventory — regardless of whether they were issued by our CA, discovered via scan, or pulled from cloud APIs — **so that** I can answer "how many certificates do we have?" without combining multiple tools.

**Priority:** Must | **Version:** V1 | **Points:** 5
**Maps to:** FR-070, FR-071, FR-085

**Acceptance Criteria:**
- Given certificates from CA issuance, network scan, SSH discovery, and AWS ACM, when the inventory page is loaded, then all certificates appear in a single list and can be filtered by `source`.
- Given the same certificate discovered via network scan and via SSH (same `fingerprint_sha256`), when the inventory is displayed, then exactly one row appears for that certificate.
- Given an inventory of 100,000 certificates, when the unfiltered inventory page loads, then the first page of results renders within 2 seconds.
- Given a text search for `mail.`, when executed, then all certificates with `common_name` or `subject_alt_names` containing `mail.` are returned.

---

## Epic 4: Risk and Compliance

*Score, grade, and alert on cryptographic risk across the certificate estate.*

---

### US-030: View Risk Scores and Grades

**As a** Sam (CISO), **I want to** see a risk score (0–100) and letter grade (A–F) for every certificate based on cryptographic and operational risk factors, **so that** I can quickly identify the highest-risk certificates without being a PKI expert.

**Priority:** Must | **Version:** V1 | **Points:** 5
**Maps to:** FR-075, FR-076

**Acceptance Criteria:**
- Given a certificate with flags `EXPIRED` (+40) and `WEAK_KEY` (+30), when the certificate's detail view is opened, then the risk score is 70 and the grade is D.
- Given a certificate with no risk flags, when viewed, then risk score is 0 and grade is A.
- Given a certificate where multiple flags accumulate to over 100, when displayed, then the score is shown as 100 (clamped) and grade is F.
- Given the risk dashboard, when loaded, then the grade distribution (count of A/B/C/D/F certificates) is displayed as a bar chart and matches the computed grades in the inventory.

---

### US-031: Identify Certificates with Weak Cryptography

**As an** Alex (PKI Admin), **I want to** filter the inventory for certificates with weak cryptographic properties (RSA < 2048 bits, SHA-1 signatures, self-signed, expired), **so that** I can prioritize which certificates to replace first.

**Priority:** Must | **Version:** V1 | **Points:** 3
**Maps to:** FR-075, FR-071

**Acceptance Criteria:**
- Given the inventory, when filtered by `risk_flags contains WEAK_KEY`, then all returned certificates have `key_size_bits < 2048` for RSA keys.
- Given the inventory, when filtered by `risk_flags contains SHA1_SIGNATURE`, then all returned certificates have `signature_algorithm = sha1WithRSAEncryption` or equivalent.
- Given a newly issued certificate from our CA with an RSA-2048 key, when added to the inventory, then it does not have `WEAK_KEY` or `SHA1_SIGNATURE` flags.

---

### US-032: Identify PQC-Vulnerable Certificates

**As a** Sam (CISO), **I want to** see which certificates are vulnerable to post-quantum attacks (RSA or ECDSA public keys), **so that** I can begin planning the migration to ML-DSA ahead of the 2030 NSA CNSA 2.0 deadline.

**Priority:** Should | **Version:** V1 | **Points:** 3
**Maps to:** FR-075, FR-076, FR-087

**Acceptance Criteria:**
- Given any certificate with an RSA or ECDSA public key, when the risk score is calculated, then the `PQC_VULNERABLE` flag is set and adds +5 to the risk score.
- Given the risk dashboard, when loaded, then a "PQC Vulnerable" count shows the total number of certificates with the `PQC_VULNERABLE` flag.
- Given a certificate with an Ed25519 key, when risk flags are evaluated, then `PQC_VULNERABLE` is NOT set (Ed25519 is Curve25519, not PQC-vulnerable in the same way; however, any RSA/ECDSA cert receives the flag regardless of validity period).

---

### US-033: Assign Ownership to Certificates

**As an** Alex (PKI Admin), **I want to** assign team ownership to certificates and surface unowned certificates in a dedicated inbox, **so that** every certificate in the inventory has a responsible owner who will receive expiry alerts.

**Priority:** Must | **Version:** V1 | **Points:** 5
**Maps to:** FR-080

**Acceptance Criteria:**
- Given an unowned certificate, when I call `PATCH /api/v1/certificates/{fingerprint}/owner` with `{owner_team: "platform-eng", owner_email: "platform@example.com"}`, then `ownership_source=manual` is set and the certificate is removed from the unowned inbox.
- Given a CMDB CSV import mapping IP `10.1.2.3` to team `payments-team`, when certificates on that IP are processed, then they are auto-assigned to `payments-team` with `ownership_source=cmdb`.
- Given the risk dashboard, when loaded, then a "Unowned Certificates" count is shown and clicking it shows all certificates with no `owner_team`.
- Given a certificate where CMDB-based ownership is set, when I manually override it via the API, then `ownership_source` changes to `manual` and the CMDB value is overridden.

---

### US-034: Detect Certificate Changes on Endpoints

**As an** Alex (PKI Admin), **I want to** receive an alert when a certificate on a known endpoint is unexpectedly replaced, disappears, or is downgraded, **so that** I can investigate potential unauthorized changes or certificate theft.

**Priority:** Should | **Version:** V1 | **Points:** 5
**Maps to:** FR-082

**Acceptance Criteria:**
- Given a network scan detecting a different certificate on `loadbalancer.example.internal:443` compared to the previous scan (different `fingerprint_sha256`, same hostname), when the scan result is processed, then an alert event `CERTIFICATE_REPLACED` is generated with the old and new fingerprints and sent to the configured owner or global inbox.
- Given a scan detecting that `api.example.internal:8443` no longer serves a TLS certificate (port still open, no TLS), when processed, then a `CERTIFICATE_DISAPPEARED` event is generated.
- Given a scan detecting that `legacy.example.internal:443` previously served RSA-4096 and now serves RSA-2048, when processed, then a `KEY_DOWNGRADE` event is generated.

---

### US-035: Audit Log for Compliance Evidence

**As a** Sam (CISO), **I want to** access a tamper-evident audit log of all certificate-related operations (issuance, revocation, template changes), **so that** I can provide it as evidence for SOC 2 Type II audits.

**Priority:** Must | **Version:** V1 | **Points:** 5
**Maps to:** FR-094

**Acceptance Criteria:**
- Given any state-changing operation (CA create, cert issue, cert revoke, template update), when the operation completes, then an audit log entry exists with: `action`, `actor` (user ID or API key ID — never the API key value), `resource_type`, `resource_id`, `timestamp` (UTC), and `details` JSONB with before/after state.
- Given an attempt to UPDATE or DELETE an `audit_log` row directly in the database, then the database rejects the operation (row-level security or equivalent).
- Given the audit log API endpoint, when queried with a date range filter, then all audit entries within the range are returned in chronological order with complete `details`.
- Given an audit log export request, when processed, then the response includes all entries since the platform started (not just recent entries).

---

## Epic 5: Dashboard and API

*Provide a first-class management interface and a fully documented REST API.*

---

### US-040: Use ACME to Automate Certificate Issuance

**As a** Jordan (Platform Engineer), **I want to** use certbot, acme.sh, or any RFC 8555-compliant ACME client against the platform without modification, **so that** I can automate TLS certificate issuance for internal services using the same workflow as Let's Encrypt.

**Priority:** Must | **Version:** V1 | **Points:** 8
**Maps to:** FR-030, FR-031, FR-032, FR-034

**Acceptance Criteria:**
- Given the ACME server at `https://kryptkeeper.internal/acme/internal-tls/directory`, when `certbot --server https://kryptkeeper.internal/acme/internal-tls/directory certonly -d api.internal --standalone` is run, then certbot completes successfully and produces a valid certificate without any platform-specific modifications.
- Given a DNS-01 challenge configured with a custom DNS resolver for `.internal` zones, when an ACME order for `*.internal` is processed, then the challenge validation queries the configured resolver, not a public DNS server.
- Given an ACME provisioner `internal-tls` configured to allow only `*.internal` domains, when certbot requests a certificate for `external.example.com` from that provisioner, then the order fails with a `rejectedIdentifier` error.
- Given an ACME auto-renewal, when certbot renews a certificate (re-submits an order for the same domain), then the new certificate's `predecessor_fingerprint` is linked to the previous certificate.

---

### US-041: SCEP Enrollment for Network Devices

**As a** Riley (Network Engineer), **I want to** enroll certificates on F5 BIG-IP, Palo Alto, and Citrix ADC using SCEP, **so that** I can automate certificate management on network devices without writing custom code or manual intervention.

**Priority:** Must | **Version:** V1 | **Points:** 5
**Maps to:** FR-045

**Acceptance Criteria:**
- Given an F5 BIG-IP configured with the platform's SCEP URL and challenge password, when the F5 submits a SCEP `PKCSReq`, then the platform issues a certificate meeting the provisioner's template and the F5 installs it.
- Given a SCEP challenge password mismatch, when a `PKCSReq` is submitted, then the SCEP response is a `FAILURE` `PKIOperation` with `failInfo=badRequest`.
- Given the SCEP `GetCACaps` operation, when called, then the response includes `SHA-256` and `AES` indicating algorithm support.
- Given the issued certificate, when viewed in the Kryptkeeper dashboard, then it shows `source=scep` with the provisioner name.

---

### US-042: EST Enrollment for Enterprise Devices

**As an** Alex (PKI Admin), **I want to** support RFC 7030 EST enrollment for enterprise devices and services, **so that** modern devices that support EST (instead of SCEP) can enroll certificates from our CA without a custom integration.

**Priority:** Must | **Version:** V1 | **Points:** 5
**Maps to:** FR-044

**Acceptance Criteria:**
- Given a valid HTTP Basic credential and a PKCS#10 CSR, when `POST /est/<provisioner>/simpleenroll` is called with `Content-Type: application/pkcs10`, then HTTP 200 is returned with the signed certificate in `application/pkcs7-mime; smime-type=certs-only`.
- Given an EST client renewing an existing certificate (using its current certificate for TLS client auth), when `POST /est/<provisioner>/simplereenroll` is called, then the renewal is processed without requiring Basic credentials.
- Given an invalid EST credential, when called, then HTTP 401 is returned with a `WWW-Authenticate` header.

---

### US-043: Integrate via REST API

**As a** Jordan (Platform Engineer), **I want to** interact with every platform capability through a documented REST API with a published OpenAPI 3.1 spec, **so that** I can write my own integrations (Terraform provider, CI/CD scripts, Slack bot) without reverse-engineering the dashboard.

**Priority:** Must | **Version:** V1 | **Points:** 8
**Maps to:** FR-090, FR-091

**Acceptance Criteria:**
- Given `GET /api/v1/openapi.yaml`, when downloaded and validated with `openapi-cli validate`, then zero errors are reported.
- Given a valid API key in `Authorization: Bearer kk_<token>`, when any API endpoint is called, then the request is authenticated and the audit log contains the API key ID (not the key value).
- Given any list endpoint (e.g., `GET /api/v1/certificates`), when called with `?limit=100&cursor=<next_cursor>`, then the response contains at most 100 items and a `next_cursor` for the next page.
- Given any error response, then the body is a valid RFC 7807 Problem Details object with `type`, `title`, and `status` fields.
- Given a private key operation (e.g., CA creation), then no API response body contains private key material under any circumstances.

---

### US-044: Configure Notification Routing

**As an** Alex (PKI Admin), **I want to** configure notification routing rules that send expiry alerts and change events to the correct team's Slack channel or email address based on certificate ownership, **so that** the right person is paged — not everyone.

**Priority:** Must | **Version:** V1 | **Points:** 5
**Maps to:** FR-081, FR-082

**Acceptance Criteria:**
- Given a notification rule mapping `owner_team=platform-eng` to Slack channel `#platform-alerts`, when a 30-day expiry alert fires for a certificate owned by `platform-eng`, then the Slack message is sent to `#platform-alerts` and not to any other channel.
- Given a notification rule for PagerDuty, when a certificate expires (reaches the `EXPIRED` threshold), then the PagerDuty Events API v2 is called with the certificate CN and expiry information.
- Given a notification rule for email via SMTP, when an alert fires, then the email contains the certificate CN, expiry date, risk score, grade, and a direct link to the certificate in the dashboard.
- Given a certificate with no owner and no global inbox configured, when an alert fires, then the alert is queued in the platform's internal notification queue (visible in the dashboard) and no external notification is sent.

---

### US-045: Manage RBAC Roles and API Keys

**As an** Alex (PKI Admin), **I want to** create role-based access control policies and issue API keys scoped to specific roles, **so that** service accounts and automation tools have the minimum necessary permissions and cannot perform destructive operations.

**Priority:** Must | **Version:** V1 | **Points:** 5
**Maps to:** FR-091, FR-092

**Acceptance Criteria:**
- Given a new API key created with role `service-account`, when used to call `POST /api/v1/cas` (create CA), then HTTP 403 is returned.
- Given the same API key, when used to call `POST /api/v1/certificates` (issue certificate), then the request succeeds if the template is permitted for `service-account`.
- Given an API key that has been revoked, when used in any API call, then HTTP 401 is returned.
- Given API key creation, when the response is returned, then the response includes the full key value exactly once (so the operator can copy it). Subsequent queries for that key ID return only the key ID, prefix, and creation date — never the key value.

---

### US-046: Set Up OIDC SSO for Dashboard

**As an** Alex (PKI Admin), **I want to** configure OIDC (e.g., Okta, Keycloak) for dashboard authentication with role mapping from OIDC groups, **so that** my team can log in with their SSO credentials and I don't manage separate passwords for the PKI platform.

**Priority:** Should | **Version:** V1 | **Points:** 5
**Maps to:** FR-093, FR-092

**Acceptance Criteria:**
- Given an OIDC provider configured with discovery URL, client ID/secret, and a groups-to-roles mapping (e.g., `pki-admins` → `pki-admin`), when a user in the `pki-admins` group logs in via the dashboard, then they are authenticated with `pki-admin` role and can perform all admin operations.
- Given a user in a group not mapped to any role, when they complete OIDC authentication, then they are denied access with HTTP 403.
- Given no OIDC configuration, when the platform starts, then it operates normally using local username/password authentication (OIDC is optional).

---

### US-047: Access a Developer-Friendly OCSP Responder

**As a** Jordan (Platform Engineer), **I want to** use the platform's OCSP responder — free, in the Apache 2.0 OSS tier — to validate certificate revocation status, **so that** I don't have to pay for the Smallstep enterprise tier just to get OCSP support.

**Priority:** Must | **Version:** V1 | **Points:** 5
**Maps to:** FR-040, FR-041

**Acceptance Criteria:**
- Given the platform running without a commercial license, when `openssl ocsp -issuer ca.pem -cert issued.pem -url http://ocsp.kryptkeeper.internal/ocsp` is run, then the OCSP response is returned successfully with status `good`.
- Given a revoked certificate, when OCSP is queried for its serial, then the response is `revoked` within 60 seconds of revocation.
- Given a cached pre-signed OCSP response, when an HTTP GET request is made with the appropriate base64-encoded request URL, then the response includes `Cache-Control: max-age=14400` (configurable).
- The OCSP responder is available in the Apache 2.0 distribution without any commercial license key requirement. This is explicitly verified by the "Does Not Require License" acceptance test.

---

### US-048: Deploy with Docker Compose in Under 15 Minutes

**As a** Casey (Open-Source Contributor), **I want to** run `docker compose up` and have a working PKI platform in under 15 minutes by following the quickstart, **so that** I can explore the codebase, test my changes, and verify the platform works locally without a complex setup.

**Priority:** Must | **Version:** V1 | **Points:** 3
**Maps to:** NFR-027, NFR-028

**Acceptance Criteria:**
- Given a machine with Docker Compose installed and no prior Kryptkeeper setup, when the operator follows the quickstart and runs `docker compose up`, then all services are healthy and the dashboard is accessible at `https://localhost:8443` within 15 minutes.
- Given the platform started with `docker compose up`, when the operator creates a root CA, creates an issuing CA, and issues a certificate — all via the dashboard — then the certificate can be validated with `openssl verify`.
- Given the platform started with no internet connection (network isolated), when `docker compose up` is run, then all services start successfully without any external network requests.

---

## Epic 6: ADCS Integration (V2)

*Replace Microsoft ADCS as the backend for Windows auto-enrollment via native MS-XCEP and MS-WSTEP implementation.*

---

### US-050: Replace ADCS for Windows Auto-Enrollment

**As an** Alex (PKI Admin), **I want to** configure Windows clients to enroll certificates from Kryptkeeper's XCEP/WSTEP endpoints instead of ADCS, via Group Policy, **so that** I can retire the Windows CA server and eliminate the Windows Server license cost and Domain Admin blast radius.

**Priority:** Must | **Version:** V2 | **Points:** 13
**Maps to:** FR-100, FR-101

**Acceptance Criteria:**
- Given a Windows 10/11 client with GPO configured to use the Kryptkeeper XCEP endpoint URL, when the Windows Certificate Enrollment client queries `GetPolicies`, then the response is a valid MS-XCEP `GetPoliciesResponse` listing available templates.
- Given the Windows client using WSTEP to enroll, when a `RequestSecurityToken` is submitted with a valid CSR for a configured template, then the client receives a signed certificate issued by the Kryptkeeper CA.
- Given the issued certificate, when the client installs it, then it appears in `Cert:\LocalMachine\My` without any manual intervention.
- The XCEP and WSTEP servers run on Linux with no Windows CA server, no COM/DCOM, and no Windows Registry dependencies.

---

### US-051: Sync Templates to Active Directory

**As an** Alex (PKI Admin), **I want to** synchronize Kryptkeeper certificate templates to Active Directory's Configuration partition, **so that** Windows auto-enrollment via GPO works correctly (Windows requires templates to exist in AD for auto-enrollment).

**Priority:** Must | **Version:** V2 | **Points:** 8
**Maps to:** FR-102

**Acceptance Criteria:**
- Given a Kryptkeeper template with `schema_version=4`, when AD sync runs, then the corresponding `CN=<template-name>,CN=Certificate Templates,...` LDAP object contains correct `msPKI-Cert-Template-OID`, `pkiKeyUsage`, `pkiextendedkeyusage`, and `pKIExpirationPeriod` (correctly encoded as little-endian negative FILETIME).
- Given an AD domain with schema version 2 (older), when sync runs for a schema-version-4 template, then version-4-only attributes are skipped with a warning, and the sync succeeds for all schema-v2-compatible attributes.
- Given a template revision change in Kryptkeeper (e.g., validity_period updated), when AD sync runs, then the corresponding LDAP object is updated to reflect the change.

---

### US-052: Support Windows Server 2019 and 2022 ADCS Replacement

**As an** Alex (PKI Admin), **I want to** verify that Kryptkeeper's XCEP/WSTEP implementation works correctly against Windows 10, 11, Server 2019, and Server 2022 in a real Active Directory environment, **so that** I can migrate production Windows enrollments to Kryptkeeper with confidence.

**Priority:** Must | **Version:** V2 | **Points:** 8
**Maps to:** FR-100, FR-101, FR-102

**Acceptance Criteria:**
- Given a test environment with Windows 10, 11, and Server 2022 clients, when XCEP/WSTEP enrollment is tested against all three, then all clients successfully enroll and receive valid certificates.
- Given Windows `CertificateServicesClient` event log tracing enabled, when enrollment is attempted, then the event log shows `GetPolicies` and `RequestSecurityToken` operations completing successfully.
- Given enrollment tested via Wireshark packet capture, when the capture is analyzed, then the XCEP and WSTEP wire format matches the documented MS-XCEP and MS-WSTEP protocol specifications.

---

## Epic 7: Crypto Management (V3)

*Extend visibility beyond TLS certificates to SSH keys, code signing, and PQC migration planning.*

---

### US-060: Inventory SSH Keys

**As an** Alex (PKI Admin), **I want to** discover and inventory SSH public keys from `authorized_keys` files across my Linux fleet, **so that** I can identify stale keys (not rotated in over a year) and enforce a key rotation policy.

**Priority:** Must | **Version:** V3 | **Points:** 8
**Maps to:** FR-110

**Acceptance Criteria:**
- Given a Linux host with `authorized_keys` files, when SSH key discovery runs, then all public keys are inventoried with algorithm, key size, fingerprint, host, and last-modified date of the `authorized_keys` file.
- Given a key that has not been rotated in over 365 days (configurable threshold), when the inventory is viewed, then it is flagged as `stale` and appears in the stale key report.
- Given the SSH key inventory view in the dashboard, when filtered by algorithm `ssh-rsa`, then all RSA SSH keys are returned and the count is shown.

---

### US-061: PQC Migration Planning Dashboard

**As a** Sam (CISO), **I want to** see a PQC migration planning dashboard showing which certificates are vulnerable to post-quantum attacks and a roadmap for migrating to ML-DSA, **so that** I can demonstrate to the board and regulators that we have a concrete plan ahead of the 2030 CNSA 2.0 deadline.

**Priority:** Must | **Version:** V3 | **Points:** 13
**Maps to:** FR-111

**Acceptance Criteria:**
- Given the inventory, when the PQC migration dashboard loads, then it shows: total PQC-vulnerable certificate count, breakdown by algorithm (RSA-2048, RSA-4096, ECDSA P-256, etc.), breakdown by validity period (expires before 2030 vs. after), and a migration readiness percentage.
- Given a certificate issued with ML-DSA (FIPS 204) by the Kryptkeeper CA, when viewed in the inventory, then `PQC_VULNERABLE=false` and the certificate appears in the "PQC-Ready" section of the migration dashboard.
- Given the 2030 NSA CNSA 2.0 milestone, when a migration timeline is generated, then it shows how many certificates per quarter need to be migrated to meet the deadline.

---

## Story Point Summary

### Epic 1: CA Operations
| Story | Points |
|-------|--------|
| US-001: Create Root CA | 8 |
| US-002: Air-Gapped Root CA Key Ceremony | 5 |
| US-003: Create Issuing CA | 5 |
| US-004: Revoke CA Certificate | 5 |
| US-005: Manage Key Storage Backend | 8 |
| **Epic Total** | **31** |

### Epic 2: Certificate Lifecycle
| Story | Points |
|-------|--------|
| US-010: Issue Certificate from CSR | 5 |
| US-011: Define and Enforce Templates | 8 |
| US-012: Renew Certificate with Chain Tracking | 5 |
| US-013: Revoke Certificate | 5 |
| US-014: Configure Multi-Tier Expiry Alerts | 5 |
| US-015: Export Compliance Report | 3 |
| **Epic Total** | **31** |

### Epic 3: Discovery and Inventory
| Story | Points |
|-------|--------|
| US-020: Run Network TLS Scan | 13 |
| US-021: Schedule Recurring Scans | 5 |
| US-022: Discover via SSH (Linux) | 8 |
| US-023: Discover via WinRM (Windows) | 8 |
| US-024: Deploy Agent for Real-Time Discovery | 8 |
| US-025: Integrate Cloud Certificate Inventory | 8 |
| US-026: Monitor CT Logs | 5 |
| US-027: Discover Kubernetes Certificates | 5 |
| US-028: View Unified Inventory | 5 |
| **Epic Total** | **65** |

### Epic 4: Risk and Compliance
| Story | Points |
|-------|--------|
| US-030: View Risk Scores and Grades | 5 |
| US-031: Identify Weak Cryptography Certificates | 3 |
| US-032: Identify PQC-Vulnerable Certificates | 3 |
| US-033: Assign Ownership | 5 |
| US-034: Detect Certificate Changes | 5 |
| US-035: Audit Log for Compliance | 5 |
| **Epic Total** | **26** |

### Epic 5: Dashboard and API
| Story | Points |
|-------|--------|
| US-040: ACME Automated Issuance | 8 |
| US-041: SCEP for Network Devices | 5 |
| US-042: EST for Enterprise Devices | 5 |
| US-043: REST API + OpenAPI Spec | 8 |
| US-044: Configure Notification Routing | 5 |
| US-045: RBAC and API Keys | 5 |
| US-046: OIDC SSO for Dashboard | 5 |
| US-047: OSS OCSP Responder | 5 |
| US-048: Docker Compose Quickstart | 3 |
| **Epic Total** | **49** |

### Epic 6: ADCS Integration (V2)
| Story | Points |
|-------|--------|
| US-050: Replace ADCS for Windows Auto-Enrollment | 13 |
| US-051: Sync Templates to Active Directory | 8 |
| US-052: Windows Server 2019/2022 Compatibility | 8 |
| **Epic Total** | **29** |

### Epic 7: Crypto Management (V3)
| Story | Points |
|-------|--------|
| US-060: Inventory SSH Keys | 8 |
| US-061: PQC Migration Planning Dashboard | 13 |
| **Epic Total** | **21** |

---

## Grand Total

| Version | Epics | Stories | Story Points |
|---------|-------|---------|-------------|
| V1 | 1–5 | 38 | 202 |
| V2 | 6 | 3 | 29 |
| V3 | 7 | 2 | 21 |
| **Total** | **7** | **43** | **252** |
