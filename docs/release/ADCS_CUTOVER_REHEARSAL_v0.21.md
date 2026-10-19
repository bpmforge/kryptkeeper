# ADCS cutover rehearsal record (W33-19) - v0.21

Date: 2026-10-18 (03:35Z to 03:42Z). Hub commit: 55724328 (`kryptkeeper v0.21.0-adcsfix
(commit 55724328)`, branch `fix/adcs-migration-rehearsal`, with fixes for run 1's B1-B5 and D1).
Operator: automated agent run (Claude), authorized by the owner on 2026-10-17 23:58Z.
Lab DC OS: Windows Server 2025 Standard. Playbook: `docs/guides/replace-adcs.md`, section
"Cutover playbook", followed as written. Lab prerequisites: `tests/live/ad-ldap/windows/README.md`.

## Verdict: PASS (run 2)

All six steps passed with no operator workaround. The template import used the live LDAP
read. The cutover used the migrated `Workstation` template, which carries its ADCS OID.
The workstation was offered neither the DC template, the Kerberos template nor the RAS
template. The takeover survived a re-sync. Revert returned the certificate to `external`.
Two minor observations (N1, N2) are listed below; neither blocks the playbook.

Alert events `import_completed` and `import_unmatched_rows` are NOT built (UC-I01); the
rehearsal did not exercise them.

## Header

| Field | Value |
|---|---|
| K (certificates inventoried) | 11: 10 user certs in `OU=KKW33Rehearsal` + 1 ADCS machine cert of LAB-WIN11 |
| Application group cut over | LAB-WIN11 (domain-joined Windows 11 Enterprise 26200), machine context |
| Hub version / commit | v0.21.0-adcsfix, 55724328; fresh instance `kkw33-hub` on the lab-hub VM, port 9443, root `KKW33 Rehearsal Hub CA 2` |
| Lab DC / CA names | LAB-DC01.corp.example.test; Enterprise Root CA `LAB-CA01.corp.example.test\CORP Lab Enterprise CA` |

## Steps (run 2)

| Step | Result | Evidence |
|---|---|---|
| 1 Inventory (playbook 1): `adcs_live` sync, K certs; `migration-verify.sh` | PASS | Credential `cred-83b58d1af39b9000097572de6c8cf6cc` (`windows_password`, `{"password":...}`). Source `invsrc-2e989ebcf46ff46385d1935cb230e0fe` (`ldaps://LAB-DC01.corp.example.test:636`, base `DC=kkuat,DC=lab`). Sync `{"synced":11,"skipped":0,"revoked_marked":0}`, 11 x `synced/external`. Manifest built on the DC (11 SHA-256 values, the same set as run 1). `migration-verify.sh --origin synced`: `total=11 mapped=11 unmatched=0 percent=100.0`, exit 0. |
| 2 Template mapping (playbook 2-3): live dry run, apply, approval, batch | PASS | **Live read now works:** `POST /migration/dryrun` with `credential_ref` + `options.ldap_url/bind_dn/base_dn` -> 200, `create=5 update=0 skip=28 conflict=0`. Mapped: DomainControllerAuthentication, KerberosAuthentication, OCSPResponseSigning, RASAndIASServer, Workstation. Skipped: 24 v1 built-ins and 4 with no mappable EKU. Field level: 87 mapped / 19 partial / 527 unmapped. All five entries note `key size raised from 2048 to 3072 to meet policy "Baseline"`. DC/Kerberos/RAS entries also note `not offered to general autoenrollment (...): enrollment restricted to pki-admin, protocol:wstep:restricted`. Apply (same live body) by alice -> 202, approval `act-8ad5119bf49922fb1cc94077`. Self-approval 403, bootstrap 403, bob 200 -> batch `mb_58c7fbb6bb39a692`, `created=5`. Resulting templates: all `min_key_size=3072`. DC/Kerberos/RAS have `auto_enroll=false`, `enroll=["pki-admin","protocol:wstep:restricted"]`. Workstation has `auto_enroll=true` and keeps OID `...11026834.190.1.30`. Re-applying the unchanged source -> `nothing_to_apply`. |
| 3 Parallel run (playbook 4): dual-issue at a test endpoint | PASS | One RSA-3072 key generated on lab-runner (it never left the host). Kryptkeeper issued with the migrated `RASAndIASServer` template via the API as pki-admin: serial `B557095325C7A7E87C10BC6962805C5F`, SHA-256 `2ce7c279...7b6d95db`. ADCS issued the same CSR (`WebServer`, request 15): serial `610000000F0A64107B164CCAF500000000000F`. Served on lab-runner:9444 / :9445; `openssl s_client -verify_return_error` gave `Verify return code: 0 (ok)` for both chains. |
| 4 Cutover of one group + takeover (playbook 5) | PASS | GPO `KKW33-Cutover-XCEP` was linked only to `OU=KKW33-Cutover` (LAB-WIN11 only), with policy server `https://lab-hub.corp.example.test:9443/xcep` over Kerberos. `gpresult` lists it, and the client's URL became :9443. **Offered templates:** `certutil -v -PolicyServer ... -Kerberos -Template`, run as SYSTEM (LAB-WIN11$), parsed exactly two: `OCSPResponseSigning` and `Workstation`, both `TemplatePropMinimumKeySize = c00 (3072)`; no DomainControllerAuthentication, KerberosAuthentication or RASAndIASServer. **Enrollment:** one pulse, hub log `/xcep 200` x3 and `/wstep 200` x1, no SOAP faults, no client errors. LAB-WIN11 got `CN=lab-win11.corp.example.test` from `KKW33 Rehearsal Hub CA 2`, RSA-3072, thumbprint `9A9F06EB31F5E2F00435BE943465688BA8BE88D5`, serial `79403EE5ADDE7A532C99BF5FEB895F78`. Its template extension names `Workstation Authentication(1.3.6.1.4.1.311.21.8.12189506.10184651.7684799.15371974.11026834.190.1.30)`, the migrated template. Audit `wstep.enroll success LAB-WIN11$@CORP.EXAMPLE.TEST method=kerberos`; inventory `source=wstep`, `template_id=tpl-workstation-...`, `internal/managed`. **Takeover** of the ADCS cert (fp `eb2e6f96...50d14253`, serial `610000000D4681042970521C9D00000000000D`): `external/manual` -> 200 `managed/api`, `owner_team=kkw33-win11-group`. **Re-sync after takeover:** `{"synced":0,"skipped":11}`, and the cert stays `managed`. |
| 5 Rollback (playbook 6.1-6.3) | PASS | GPO: `Remove-GPLink`, `Remove-GPO`; LAB-WIN11 moved back to `CN=Computers`; OU deleted (GPO false, OU false, 0 GPOs named KKW33*). After `gpupdate` the client applies only the pre-existing GPOs, its URL is back to `https://lab-hub.corp.example.test:8443/xcep`, and the next pulse made 0 requests to kkw33-hub. The hub-issued cert was revoked (`revocation_reason=4`) and removed from `LocalMachine\My`. **Revert:** `POST /estate/revert` -> 200, `management_state=external`; audit `estate.takeover.revert {"from":"managed","to":"external"}`. `POST /migration/mb_58c7fbb6bb39a692/rollback` -> `disabled=5 kept=0`; second call `already_rolled_back=true`; batch `rolled_back`, all 5 templates inactive. No hand-made templates existed, so none needed manual deactivation. |
| 6 Verification query (playbook 6.4) | PASS | `migration-verify.sh --origin synced`: `total=11 mapped=11 unmatched=0 percent=100.0`, exit 0; inventory 11 x `synced/external/active`. Negative: manifest plus one random fingerprint -> `total=12 mapped=11 unmatched=1 percent=91.7`, `UNMATCHED ... (not in inventory)`, exit 1. |

## Observations (run 2, non-blocking)

| Id | Observation |
|---|---|
| N1 | XCEP offers the migrated `OCSPResponseSigning` template (machine, `auto_enroll=false`, no enroll list) to a workstation. Windows did not autoenroll it, but a user could request it by hand. Consider restricting OCSP-signing EKU templates like the DC/Kerberos/RAS ones. |
| N2 | `/estate/revert` restored `management_state` (`external`) but left `renewal_method=api` and `owner_team` from the takeover (pre-takeover `renewal_method` was `manual`). The playbook says "returns to its pre-takeover state"; that holds for the management state only. |

## Lab setup (run 2)

- Hub: a fresh second instance on the lab-hub VM (`systemd-run --unit kkw33-hub`, data
  `/var/lib/kkw33b`, port 9443, revocation :9081). It reused the existing keytab and SPN
  `HTTP/lab-hub.corp.example.test` read-only. Two API-key principals (alice proposes, bob approves);
  secrets were generated fresh for this run. The lab hub on :8443 was not touched.
- The `kkw33-ldapread` bind password was reset to a new generated value, used only from a
  0600 file, and that file was deleted at the end.
- LDAPS trust via `SSL_CERT_FILE` (system bundle plus the lab root). A temporary
  `/etc/hosts` entry for LAB-DC01 was added on lab-hub.
- Baseline: the ADCS `Machine` certificate from run 1 on LAB-WIN11 was republished to the
  computer's `userCertificate` (K = 10 + 1). The new hub root was added to LAB-WIN11
  `LocalMachine\Root`.
- GPO scope: `KKW33-Cutover-XCEP` was linked only to `OU=KKW33-Cutover` (LAB-WIN11 only). It
  overrides the root-linked `KK Certificate Autoenrollment` by OU precedence, and was
  unlinked and deleted in step 5.

## Cleanup (2026-10-18 ~03:43Z)

Removed:
- the GPO and the OU (LAB-WIN11 is back in `CN=Computers`);
- on LAB-WIN11: the hub-issued and ADCS test certificates, both rehearsal hub roots, and `C:\kkw33`;
- LAB-WIN11's `userCertificate` value (the domain is back to K = 10);
- the endpoint key, certificates and listeners on lab-runner;
- on lab-hub: the `kkw33-hub` unit (stopped), its env file (shredded), the `/etc/hosts`
  entry, and `/opt/kkw33`, `/opt/kkw33b`, `/var/lib/kkw33`, `/var/lib/kkw33b` (runs 1 and 2).

Revoked on LAB-CA01 (reason 4, superseded): ADCS test certificates `...0D` (LAB-WIN11
Machine), `...0E` and `...0F` (kkw33-endpoint, runs 1 and 2).

Kept: the `kkw33-ldapread` account with an unrecorded password. Reset it before the next
run.

## Run 1 (2026-10-18, before fixes)

Hub c9e0e766, 01:18Z to 01:30Z. Verdict **PARTIAL**: steps 1, 3, 5 and 6 passed. Step 2's
live LDAP read failed with LDAP 52e, returned as a 503 (B1); the mapping was done from a
JSON export (batch `mb_14912c63fbbb6f7b`). Step 4 with the migrated `Workstation`
template failed: RSA-2048 was refused by the `Baseline` policy (B2). `min_key_size` was
immutable and a same-OID replacement got 409, so the cutover used a hand-made RSA-3072
template on a new OID. An inventory re-sync reverted the takeover to `external` (B3).
`/estate/revert` set `unmanaged` (B4). The migrated DC, Kerberos and RAS templates were
offered to the workstation (B5). The playbook had no cutover steps (D1). All were fixed
on `fix/adcs-migration-rehearsal` and re-tested in run 2 above.

## Follow-ups after run 2

- **OCSP and CA-infrastructure templates offered to workstations** (B5 gap): the B5
  filter covered DC, Kerberos and RAS only. Fixed in `962d1a04`: OCSP signing, certificate
  request agent, key archival and key recovery agent EKUs, and the CA built-in names
  (CAExchange, CrossCA, SubCA, EnrollmentAgent, KeyRecoveryAgent, ...), import with
  auto_enroll=false and the restricted enroll list. Templates with no mappable EKU are
  not imported at all.
- **Estate revert left the renewal path** (B4 gap): fixed in `0b60b056`. Revert restores
  the renewal method (manual, or api for internal origin) and clears the connector
  takeover set; the audit row carries both transitions. Takeover stores no snapshot, so
  the prior method is derived from origin, not read back.
