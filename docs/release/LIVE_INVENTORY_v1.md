# Live harness inventory v1

Date 2026-10-18. Base commit c9e0e766 (main, kk-v1-final worktree). Purpose: v1 final lab pass.
Nothing was run to build this table. `podman-host.sh` is a sourced helper, not a harness (no row). Plan keywords: run / run-lab-windows / skip-not-free / defer-other-thread; text in parentheses narrows the plan to specific legs.
`git diff --stat origin/main...feat/v1-discovery-posture -- tests/live` shows W34 only ADDS agentless-sudo/ and fingerprint-corpus/; it changes no existing harness, so discovery, discovery-protocols and ssh-discovery run now and are rerun after W34 for safety.

| Harness | Feature covered | Last recorded result + date + doc | Runner needed | Plan |
|---|---|---|---|---|
| tests/live/ad-ldap/windows | adcs_live inventory vs real Windows AD DC (ADCS rehearsal) | PENDING-RUN (LIVE_RESULTS_ADCS_v0.12.md, ADCS_CUTOVER_REHEARSAL_v0.21.md) | windows-lab: KK_ADCS_LDAP_URL, KK_ADCS_BIND_DN, KK_ADCS_BIND_PASSWORD (+ others per run.sh, exit 2 if missing) | defer-other-thread (v0.21 adoption and UX) |
| tests/live/migration | Bulk-import 200 certs + migration-verify script (adoption) | Referenced by ADCS_CUTOVER_REHEARSAL_v0.21.md (PENDING-RUN); no own result | linux-podman or host hub; KK_MIG_HUB_PORT, KK_KEEP | defer-other-thread (v0.21 adoption and UX) |
| tests/live/acme | ACME server vs certbot/lego (issue/renew/revoke, EAB, OCSP/CRL) | PASS 28/28 2026-10-11 (LIVE_RESULTS_v0.9.md); fg2-run PASS 53/53 2026-10-16 (LIVE_RESULTS_FG2_ACME_v0.14.md) | linux-podman | run |
| tests/live/acme-dns-providers | dns-01 via Route53/Azure/GCP/RFC2136/CNAME/wildcard | rfc2136, wildcard, long-wait PASS 2026-10-16 vs local BIND+Pebble; route53/azure/gcp/cname PENDING-RUN (LIVE_RESULTS_ACME_DNS_PROVIDERS_v0.15.md) | mixed: podman local legs; external-account for route53/azure/gcp/cname (KK_R53_*, KK_AZ_*, KK_GCP_*, KK_CNAME_* cred files) | run (rfc2136, wildcard, long-wait local); skip-not-free for real route53/azure/gcp/cname |
| tests/live/acme-upstream | Upstream ACME renew at LE staging, dns-01 in Cloudflare, SSH install to nginx | FAIL (blocked at dns-01 propagation) 2026-10-15 (LIVE_RESULTS_ACME_UPSTREAM_v0.9.3.md) | external-account: needs ~/.config/kryptkeeper-lab/cloudflare-token (KK_CF_TOKEN_FILE), zone kryptkeeper.io (KK_ACME_ZONE), LE staging default (KK_ACME_DIRECTORY); plus podman nginx/sshd fixture | run (retry; no extra env if token file valid) |
| tests/live/ad-ldap | adcs_live inventory pull vs Samba AD DC container | Blocked 2026-09-10 (Samba provisioning); UNVALIDATED (FEATURE_VALIDATION_v0.9.md) | linux-podman (Samba AD; may still fail to provision) | run |
| tests/live/agent | kryptkeeper-agent vs hub in podman (enroll, ACME renew, install) | PASS 18/18 2026-10-11 (LIVE_RESULTS_v0.9.md) | linux-podman | run |
| tests/live/airgap | Air-gap bundle install on egress-denied kind, zero packets | PASS 0 FAIL, v0.13 (UAT_AIRGAP_v0.13.md; date 2026-10-15/16) | kind (podman provider); KIND_OK | run |
| tests/live/autopilot | Unattended renew+install: agentless SSH, agent, negative, push modes, policy tick, IIS | PASS 29 checks (LIVE_RESULTS_v0.9.md); push-modes 15/15, policy-tick 14/14 2026-10-16, IIS NOT RUN (LIVE_RESULTS_PUSH_MODES_v0.15.md) | mixed: linux-podman; IIS leg windows-lab (KK_IIS_HOST, KK_IIS_USER, KK_IIS_PASSWORD_FILE) | run (podman legs); run-lab-windows (IIS leg) |
| tests/live/ca-hierarchy | Day-one CA hierarchy for every CA algorithm, timed | PASS all algs 2026-10-16 (tests/live/ca-hierarchy/last-run.json) | linux-podman (compose) or attach mode KK_BASE_URL/KK_TOKEN | run |
| tests/live/ca-offline-root | Air-gap offline root quickstart (UC-A02) | PASS ok=true 2026-10-16, 16 s (tests/live/ca-offline-root/last-run.json) | go-test-only (host hub process + openssl) | run |
| tests/live/ca-revoke | Revoke issuing CA: dual control, OCSP/CRL, ACME/EST/SCEP/CMP refused | ALL STEPS PASSED 2026-10-16 postgres + sqlite (tests/live/ca-revoke/RESULTS.md) | linux-podman | run |
| tests/live/ca-rollover | CA cross-sign rollover during lego renew loop | never run (no result doc) | linux-podman | run |
| tests/live/ceremony | 2-of-3 key ceremony and D-122 dual control | ALL STEPS PASSED 2026-10-15 (tests/live/ceremony/RUN_RECORD.md) | linux-podman (Postgres container, host hub) | run |
| tests/live/certmanager | cert-manager external issuer on kind | PASS ALL STEPS 2026-10-16 (LIVE_RESULTS_FG2_CERTMANAGER_v0.14.md) | kind | run |
| tests/live/cloud-inventory | ACM/Azure/GCP cert inventory scan vs moto emulator + bad-cred cases | never run (no result doc) | linux-podman (moto emulator); real Azure/GCP optional (KK_LIVE_AZURE_KV_URL, KK_LIVE_GCP_PROJECT) | run (moto emulator) |
| tests/live/codesign | Code-signing lifecycle on SoftHSM2 + osslsigncode | PASS 2026-10-16, attestation path PENDING hardware (LIVE_RESULTS_FG2_CODESIGN_v0.14.md) | linux-podman (builds Dockerfile) | run |
| tests/live/codesign-oidc | CI OIDC code-signing + RFC 3161 timestamp, cosign | never run (no result doc) | linux-podman | run |
| tests/live/compose | docker-compose stack over TLS, healthcheck/nginx trust | PASS 5/5 2026-09-11 (docs/UAT_PLAN.md); v0.13 quickstart DRAFT, clean-machine run TBD (UAT_COMPOSE_QUICKSTART_v0.13.md) | linux-podman (podman compose) | run |
| tests/live/ct | Certificate Transparency monitoring vs crt.sh (live) | never run (README: paste result block into docs) | external-account: internet to crt.sh; KK_LIVE_CT=1, KK_LIVE_CT_DOMAIN=<domain with a non-hub cert, e.g. via certbot> | run (needs domain + externally issued cert first) |
| tests/live/delivery-cloud | Delivery plugins to Vault, AKV, GCP SM, AWS SM/ALB/CloudFront, Azure AppGW/FrontDoor, Cloudflare | vault leg PASS 2026-10-16; all other legs PENDING-RUN (LIVE_RESULTS_DELIVERY_CLOUD_v0.15.md) | mixed: vault local podman; others external-account (KK_AWS_*, KK_AZ_*, KK_AKV_*, KK_GCP_*, KK_CF_CRED_FILE/KK_CF_HOST/KK_CF_ZONE_ID) | run (vault leg); skip-not-free for real AWS/Azure/GCP; cloudflare leg runnable only with a CF zone/LB (token file exists, KK_CF_* unset) |
| tests/live/discovery | TLS discovery recall/FP over 43 seeded endpoints | PASS recall 43/43 2026-10-15 (DISCOVERY_RATES_v0.12.md) | linux-podman | run (existing unchanged by W34; rerun after W34 anyway) |
| tests/live/discovery-protocols | Protocol scan: SMTP/IMAP/PG/LDAP/RDP/SSH | PASS 8/8 2026-10-15 (DISCOVERY_RATES_v0.12.md) | linux-podman | run (existing unchanged by W34; rerun after W34 anyway) |
| tests/live/egress | Zero default egress, tripwire sink + strace | Referenced in RELEASE_NOTES_v0.18.0.md; no dated result doc found | linux-podman (strace in container); --short 10 min | run (--short) |
| tests/live/escrow-byok | Escrow recover + BYOK import to AWS KMS (moto), Azure refusal | PASS go test exit 0 2026-10-16 (DRILL_ESCROW_BYOK_v0.11.md) | linux-podman (moto, Lowkey Vault emulators) | run |
| tests/live/evidence-mail | Scheduled evidence-pack email vs Mailpit, 3 retries | Automated part run; auditor review PENDING-RUN (EVIDENCE_PACK_DRYRUN_v0.16.md) | linux-podman (Mailpit) | run |
| tests/live/ha | 2-replica HA chaos + soak on one Postgres | soak PASS 99.919% (HA_SOAK_v0.11.md; date in tests/live/ha/soak-result.json); chaos record not found | linux-podman | run (chaos; --soak --short) |
| tests/live/helm-ha | Helm 2 replicas+Postgres, lease failover, PDB drain, ServiceMonitor | Partial: 1b NOT MET (30 s lease does not exist), rest PASS 2026-10 (UAT_HELM_HA_v0.13.md) | kind | run |
| tests/live/helm-kind | Helm install on kind, replicaCount 2, issue leaf | never run (no result doc; HA covered by helm-ha) | kind | run |
| tests/live/images | Published release images: digest pull, cosign, non-root, amd64/arm64 | PASS cosign 4/4 for v0.9.4, 2026-10-15/16 (UAT_RELEASE_IMAGES_v0.13.md) | mixed: podman + public GHCR + cosign, no account; arg = release tag | run (pass the current v1 tag) |
| tests/live/inventory-sources | Vendor inventory sync: DigiCert sandbox, Sectigo/Entrust/AWS PCA/GCP CAS fixtures | never run (no result doc) | mixed: python fixture servers + host/podman; DigiCert leg external-account (KK_DIGICERT_API_KEY, KK_DIGICERT_BASE_URL) | run (fixture legs); DigiCert leg SKIPs without key |
| tests/live/issuance-approval | Issuance policy refusal + approval gate (X.509 and SSH certs) | PASS 18 steps 2026-10-16 (LIVE_RESULTS_FG2_ISSUANCE_v0.14.md) | linux-podman | run |
| tests/live/istio-mtls | SPIFFE Workload API SVIDs on kind (Path S); Istio path not attempted | Path S PASS 2026-10-16 (LIVE_RESULTS_FG2_MESH_v0.14.md) | kind | run |
| tests/live/itsm | ServiceNow/Jira connectors, approval bridge, CMDB sync | PASS 63 / 0 FAIL / 1 SKIP 2026-10-16 vs STAND-IN stub; real ServiceNow/Jira PENDING-RUN (tests/live/itsm/RESULTS.md) | mixed: python stub (local); KK_ITSM_MODE=real external-account (KK_JIRA_URL/EMAIL/TOKEN/PROJECT, KK_SNOW_*) | run (stub mode); skip-not-free for real mode |
| tests/live/k8s | k8s Secret push + cert-manager discovery on kind; autopilot, dr-failover, rolling-upgrade scripts | run.sh PASS 31/31 2026-09-11 (UAT_PLAN.md); autopilot.sh PASS 16/16 2026-10-16 (LIVE_RESULTS_PUSH_MODES_v0.15.md) | kind | run |
| tests/live/key-compromise | Key-compromise drill: rotate-before-revoke, OCSP/CRL in 60 s | ALL STEPS PASSED 2026-10-16 (tests/live/key-compromise/RESULTS.md) | linux-podman (Postgres, sshd/nginx) | run |
| tests/live/key-inventory | Unified key inventory vs moto AWS KMS (+Lowkey Azure) | never run (no result doc) | linux-podman (moto; KK_KEYINV_AZURE=1 for Lowkey Vault); GCP skipped by design | run (emulator) |
| tests/live/keychain | macOS keychain installer (gated Go test) | macOS validation PASS 2026-10-15 via tart VM (LIVE_RESULTS_MACOS_v0.9.3.md, v0.9.4.md); harness itself unvalidated per FEATURE_VALIDATION_v0.9.md | macos-host: disposable Mac, KK_LIVE_KEYCHAIN=1 | run (disposable Mac/tart VM) |
| tests/live/keycloak | Nightly wrapper over sso (Keycloak OIDC/SAML/SCIM) | PASS 39/39 (LIVE_RESULTS_KEYCLOAK_v0.21.md, v0.21) | linux-podman | run |
| tests/live/kms-aws | AWS KMS keystore code path vs moto | PASS vs moto (FEATURE_VALIDATION_v0.9.md; DRILL_ESCROW_BYOK_v0.11.md 2026-10-16); IAM/real HSM unproven | linux-podman (moto emulator, free) | run (moto emulator); skip-not-free for real AWS KMS account |
| tests/live/kms-azure | Azure Key Vault keystore vs Lowkey Vault + stub Entra | INTEGRATION pass vs Lowkey Vault (FEATURE_VALIDATION_v0.9.md); RBAC/HSM unproven | linux-podman (Lowkey Vault emulator, free) | run (Lowkey Vault emulator); skip-not-free for real Azure KV |
| tests/live/kms-gcp | GCP Cloud KMS keystore vs in-repo wire emulator | never run (no result doc) | go-test-only (in-repo emulator, no container); KK_GCPKMS_PORT | run (in-repo emulator); skip-not-free for real GCP KMS |
| tests/live/mcp | kryptkeeper-mcp propose/approve E2E over stdio and HTTP | never run (no result doc) | go-test-only (host processes) | run |
| tests/live/mesh | Linkerd/Istio mesh discovery on kind | PASS 18/18 2026-09-11 (docs/UAT_PLAN.md) | kind | run |
| tests/live/notifications | SMTP/webhook/PagerDuty/Slack/CEF delivery to real receivers | PASS 18/18 2026-09-11 (UAT_PLAN.md); W32-09 stand-in PagerDuty, no real account (FEATURE_VALIDATION_v0.9.md) | mixed: podman Mailpit/echo; real Slack/PagerDuty external-account (KK_LIVE_REAL=1, KK_LIVE_SLACK_WEBHOOK_URL, KK_LIVE_PD_ROUTING_KEY) | run (local receivers) |
| tests/live/packages | deb/rpm install/upgrade/remove on Debian 12 and Rocky 9 | PASS 8/8 2026-10-15 (UAT_PACKAGES_v0.13.md) | linux-podman (PKG_SOURCE=local; repo mode needs PKG_REPO_URL, PKG_REPO_KEY_URL, PKG_OLD/NEW_VERSION) | run |
| tests/live/pkcs11 | PKCS#11 keystore on SoftHSM2 | PASS 23/23 2026-09-11 (UAT_PLAN.md, FEATURE_VALIDATION_v0.9.md) | mixed: host softhsm2-util + libsofthsm2 (brew) + pkcs11-tool, cgo; no podman | run |
| tests/live/plugins | Delivery plugin framework vs mock appliance (device.Containerfile) | PASS 27 checks 2026-10-11 (FEATURE_VALIDATION_v0.9.md); real F5/Citrix PENDING-RUN (LIVE_RESULTS_PLUGINS_F5_CITRIX_v0.20.md) | linux-podman (mock device; ADMIN2* second-admin vars) | run (mock device); skip-not-free for real F5/Citrix (none in this directory) |
| tests/live/pqc | ML-DSA and hybrid leaf interop with OpenSSL >= 3.5 | ALL STEPS PASSED 2026-10-17 (tests/live/pqc/RESULTS.md; LIVE_RESULTS_PQC_v0.19.md) | linux-podman (host OpenSSL >= 3.5) | run |
| tests/live/pqc-wave | PQC migration wave vs nginx on OpenSSL 3.5 | ALL RUN STEPS PASSED 2026-10-17; ep-fail rollback PENDING/BLOCKED (tests/live/pqc-wave/RESULTS.md) | linux-podman | run |
| tests/live/promote-rollback | by-digest deploy: promote and rollback on kind | PASS 0 FAIL v0.13 (UAT_PROMOTE_ROLLBACK_v0.13.md) | kind (KIND_OK, local registry) | run |
| tests/live/protocols | EST/SCEP/CMP + OCSP/CRL vs real clients | PASS 105 lines 2026-10-16 (LIVE_RESULTS_FG2_PROTOCOLS_v0.14.md) | linux-podman | run |
| tests/live/revocation-bench | CRL/OCSP load benchmark (inproc; replica mode) | Ran 2026-10-16 (REVOCATION_BENCH_v0.11.md; tests/live/revocation-bench/results/*.json) | go-test-only (inproc; replica mode needs KK_A_URL, KK_B_URL, KK_B_REVOCATION_URL, KK_TOKEN) | run (inproc) |
| tests/live/rollout | Cluster-atomic staged rollout, 3 nginx+sshd nodes | PASS 3/3 cases 2026-10-16 (tests/live/rollout/last-run.json) | linux-podman | run |
| tests/live/siem | SIEM forwarding to Elasticsearch + syslog-ng (json/cef) | Mentioned in RELEASE_NOTES_v0.10.0.md; no dated result doc found | linux-podman (KK_SIEM_HOST_IP) | run |
| tests/live/slo | SLO breach drill vs Prometheus + Grafana | never run (no result doc) | linux-podman | run |
| tests/live/spiffe | SPIFFE Workload API + NHI vs go-spiffe client | Mentioned in RELEASE_NOTES_v0.17.0.md; no dated result doc found | go-test-only (host hub on Unix socket) | run |
| tests/live/sse | 600 s SSE stream through shipped nginx | never run (no result doc) | linux-podman (podman compose) | run |
| tests/live/ssh-discovery | Agentless SSH cert discovery on real sshd | never run (no result doc) | linux-podman | run (existing unchanged by W34; rerun after W34 anyway) |
| tests/live/ssh-install | Agentless SSH install nginx/apache/HAProxy/Tomcat + rollback | ALL PASS 43 checks 2026-10-16 (LIVE_RESULTS_SSH_INSTALL_v0.15.md) | linux-podman | run |
| tests/live/sshca | SSH CA vs real OpenSSH sshd/client | ALL STEPS PASSED 2026-10-11 (LIVE_RESULTS_v0.9.md) | linux-podman | run |
| tests/live/sso | Keycloak OIDC/SAML/SCIM live harness | PASS 39/39 (SSO_UAT_RECORD.md template; LIVE_RESULTS_KEYCLOAK_v0.21.md) | linux-podman (KK_SSO_* ports/images) | run |
| tests/live/storm | 2,000-cert renewal storm vs rate-limited stub CA | PARTIAL 2026-10-16 (strict zero-violation fails, W27-39); later result files unrecorded in docs (LIVE_RESULTS_v0.15.md) | linux-podman (full or smoke) | run (smoke first, then full) |
| tests/live/terraform | Terraform provider acceptance tests vs live hub | ALL STEPS PASSED 2026-10-17 (tests/live/terraform/RESULTS.md) | go-test-only (host hub + tofu/terraform; KK_ACC_TF_BIN) | run |
| tests/live/tls | Hub TLS listener + EST via globalsign/est; listener-rotation | ALL STEPS PASSED 2026-10-11 (LIVE_RESULTS_v0.9.md); rotation PASS 2026-10-15/16 (UAT_LISTENER_ROTATION_v0.13.md) | linux-podman | run |
| tests/live/upstream-renew | SCEP (micromdm) and EST (libest) upstream renewal | SCEP, EST PASS 2026-10-16; WSTEP, DigiCert NOT RUN (LIVE_RESULTS_UPSTREAM_RENEW_v0.15.md) | linux-podman | run |
| tests/live/vault | VaultStore transit vs Vault dev server | never run (no result doc; vault delivery leg ran in delivery-cloud) | linux-podman | run |
| tests/smoke/run.sh | Hub smoke: binary, API, OIDC JWKS stub | 331/331 2026-10-11 (LIVE_RESULTS_v0.9.md) | go-test-only (hub binary, curl); KRYPTKEEPER_SMOKE_MODE | run |
| tests/live/wstep | MS-WSTEP/XCEP vs Windows Kerberos/AD; matrix kit | Windows 11 autoenroll 2026-10-08 (FEATURE_VALIDATION_v0.9.md); matrix PENDING-RUN (LIVE_RESULTS_FG2_WSTEP_MATRIX_v0.14.md) | windows-lab (Windows VM + AD DC) | run-lab-windows |
| tests/live/scep-appliance | SCEP enroll from real F5 BIG-IP VE or Palo Alto VM-Series | PENDING-RUN (LIVE_RESULTS_FG2_SCEP_APPLIANCE_v0.14.md) | external-account: vendor appliance; KK_SCEP_HUB_ADDR | skip-not-free (F5/PAN appliance) |

Counts: 70 rows. Plan: defer-other-thread 2, run 66, run-lab-windows 1, skip-not-free 1. Runner (first token): external-account 3, go-test-only 7, kind 8, linux-podman 41, macos-host 1, mixed 8, windows-lab 2.

## Known limitations

- **No install mode for SQL Server, Exchange or RDP certificates (v1).** The hub discovers these certificates on Windows hosts but cannot push renewals into them; renew them by hand or with the issuing tool. Install modes are filed for 1.1 as W35-02 (SQL Server), W35-03 (Exchange) and W35-04 (RDP) — the owner, 2026-10-18: defer to 1.1.

- **Upgrade note (D-291): template enroll lists now apply to Windows.** Any non-empty enroll list is enforced over
  XCEP/WSTEP; Windows clients need `protocol:wstep` or `protocol:wstep:<fqdn>` in it. On first start the hub adds
  `protocol:wstep` to autoenrolled templates whose list had only API roles (not `pki-admin`), so existing GPO
  autoenrollment keeps working; any other role-only list stops being offered/issued to Windows (the startup log names
  them). See `docs/ops/WSTEP_AUTOENROLLMENT.md`.
- **Retry-After does not survive a restart.** The connector backoff and upstream Retry-After gate are in process
  memory; a hub restarted during a CA 429 window may send a few orders (storm leg B: 3 orders, up to 2.8 s early)
  before the CA's Retry-After ends, and the CA answers 429 again. Not shared between replicas either. See
  `docs/ops/ACME_UPSTREAM.md` and `tests/live/storm/README.md`; backlog W35-01.
- **`approver` is a certificate-requests role.** It lists and decides certificate requests on templates naming it in
  `approval_roles`; key and CA pending actions stay pki-admin/pki-operator. See `docs/API_DESIGN.md`.
