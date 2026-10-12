# CLOUD_FINDINGS 2026-10-09 (kryptkeeper, --deep audit, cloud phase)

## Coverage statement (read first)

- **Platforms detected:** AWS (aws-sdk-go-v2: `service/kms` v1.50.4, `service/acm` v1.38.2, `config` v1.32.15), GCP (raw REST to Cloud KMS, Certificate Manager), Azure (raw REST to Key Vault). No AWS Config service client is linked; the HANDOFF's "config" is the SDK `config` loader package.
- **Code surface read in full:** `internal/keystore/cloudkms.go`, `cloudkms_aws.go`, `cloudkms_gcp.go`, `cloudkms_azure.go`, `destroy_cloud.go`; `internal/cloudinventory/aws_acm.go`, `azure_keyvault.go`, `gcp_certmanager.go` (token, URL and pagination paths); `internal/keyinventory/aws.go`, `azure.go`, `gcp.go`; `internal/bootstrap/handlers_key_inventory.go`, `cloud_discovery.go`, `handlers_keys.go:70-135`; `cmd/kryptkeeper/main.go` `buildCloudKMSStore`; `deploy/terraform/modules/compute/main.tf` (hub IAM role only).
- **Automated scanners:** not re-run here. Opengrep and bpm-rulepacks ran in the SAST phase (`SEMGREP_FINDINGS_2026-10-09.md`). No cloud rule there fired on these files, and none of these findings duplicate SEMGREP-001..014. Checkov on the Terraform belongs to the IaC specialist.
- **Not exercised live:** real-cloud UAT has not been run (docs/UAT_PLAN.md uses KMS fakes). Everything here is judged from the code. Provider-side behaviour (for example, how Azure normalises `..` in a key path) is marked where it matters.
- **Hardcoded credential check:** ran. No static AWS keys (`AKIA`, `NewStaticCredentialsProvider`), no GCP service-account JSON, and no Azure secrets in source. Cloud credentials come only from the environment or the platform metadata/default chain (see CLOUD-004).

## Summary

| Status | Count |
|---|---|
| REAL | 9 (CRITICAL 0, HIGH 0, MEDIUM 3, LOW 6) |
| UNVERIFIED | 0 |
| FP / verified-good | see "Verified controls" |

## Verified controls (checked, no finding)

- **No private key export.** `CloudKMSStore.ExportEncryptedKey` and `ImportEncryptedKey` refuse (`internal/keystore/cloudkms.go:388-395`). Keys are created as `SIGN_VERIFY` / `ASYMMETRIC_SIGN` / `sign,verify` only.
- **ML-DSA/hybrid on cloudkms is refused before any cloud call.** `keystore.CheckHSMPQCSupport` runs at `internal/bootstrap/handlers_keys.go:105`.
- **AWS signing algorithm mapping is correct.** ECDSA SHA-256/384/512 and RSA PKCS#1 v1.5 and PSS are mapped from `opts` (`cloudkms_aws.go:50-84`), and `MessageType: DIGEST` is set (`:39`). Go's PSS salt length (equals hash) matches what KMS produces.
- **Azure ECDSA raw (r||s) is converted to ASN.1 DER** with a length check (`cloudkms_azure.go:86-94`).
- **AWS credentials come from the default chain** (`config.LoadDefaultConfig`), so IRSA, instance profiles and SSO all work. No endpoint override (`BaseEndpoint`) is configurable, so AWS has no SSRF via endpoint.
- **The GCP KMS base URL is hardcoded** to `https://cloudkms.googleapis.com/v1`, and the key URI is appended as a path under `/v1/`, so it cannot change the host.
- **`AZURE_AUTHORITY_HOST` is validated** to https or loopback http (`cloudkms_azure.go:190-209`).
- **Cloud API error bodies are truncated** to 200/512 bytes before they are wrapped. Generic HTTP error envelopes are used on key generation (`handlers_keys.go:127`).

---

## REAL findings

### CLOUD-001: Cloud key inventory endpoint has no authorization check and returns raw cloud errors (ARNs, account IDs)
- id: CLOUD-001 | severity: MEDIUM | category: cloud | tool: manual | status: REAL
- file: internal/bootstrap/handlers_key_inventory.go:87
- evidence:
  - `:87` calls `auth.AuthenticatePrincipal(r, time.Now())`, and `:94` goes straight to `keyinventory.Collect(...)`. There is no `requirePermission` or role check in between. Other handlers, for example `handlers_targets.go:230`, emit an explicit `"denied"` permission check.
  - `:101` sets `Errors: inv.Errors`, and `internal/keyinventory/inventory.go:51` builds each entry as `s.Provider()+": "+err.Error()`. An AWS `AccessDeniedException` text contains the caller ARN, for example `arn:aws:sts::<account-id>:assumed-role/<role>/<instance-id>`. Azure and GCP errors carry tenant, project and key-ring paths.
  - Each request fans out live to every provider: AWS `ListKeys` plus per-key `DescribeKey` and `GetKeyRotationStatus` (`internal/keyinventory/aws.go:50-69`), and Azure per-key `GET kid` (`internal/keyinventory/azure.go:71`). Results are not cached.
- preconditions:
  - "authenticated as any principal (any role or API-key scope)"
  - "hub has cloud credentials configured (AWS_REGION / AZURE_KEYVAULT_URL+AZURE_ACCESS_TOKEN / GCP_KMS_KEYRING+GOOGLE_ACCESS_TOKEN)"
- yields:
  - "enumeration of every KMS key in the hub's AWS account/region, Azure vault and GCP key ring (IDs, algorithms, state, rotation)"
  - "cloud account ID, hub IAM role/instance ID, Azure tenant and GCP project identifiers"
  - "ability to drive unbounded cloud API calls on the hub's credentials (throttling/cost)"
- asset: AWS KMS / Azure Key Vault / GCP KMS key metadata; cloud account identifiers; hub cloud API quota
- remediation: Gate `/api/v1/inventory/keys` on a key-read permission (as the `/keys` routes do), replace raw `err.Error()` in `Errors` with a provider plus error-class string, and cache the inventory with a TTL.

### CLOUD-002: AWS KMS keys are created untagged, so hub IAM cannot be scoped below account-wide kms:Sign and kms:ScheduleKeyDeletion. Terraform grants nothing.
- id: CLOUD-002 | severity: MEDIUM | category: cloud | tool: manual | status: REAL
- file: internal/keystore/cloudkms.go:248
- evidence:
  - `client.CreateKey(ctx, &kms.CreateKeyInput{Description: &id, KeyUsage: SIGN_VERIFY, KeySpec: keySpec})`. There are no `Tags` and no `Policy`, so every key gets the default key policy (account root), and no attribute exists for ABAC.
  - Key IDs are random, so `kms:Sign`, `kms:GetPublicKey` (`cloudkms.go:258`, `cloudkms_aws.go:36`) and `kms:ScheduleKeyDeletion` (`destroy_cloud.go:45`) can only be granted on `Resource: "*"` (or `arn:aws:kms:<region>:<acct>:key/*`). That lets the hub sign with, or schedule deletion of, ANY KMS key in the account, including keys that belong to other workloads.
  - `deploy/terraform/modules/compute/main.tf:38-101`: the hub role has only SSM core and two `secretsmanager:GetSecretValue` grants. It has no KMS, ACM or `kms:ListKeys` grant, so the AWS `KRYPTKEEPER_KEY_BACKEND=cloudkms` deployment is non-functional as shipped, and operators will hand-attach a broad policy (likely `kms:*`).
  - Minimal policy the code implies (by code path):
    - keystore generate: `kms:CreateKey` (Resource `*`; this cannot be resource-scoped) plus `kms:GetPublicKey`
    - keystore sign: `kms:Sign`
    - keystore delete: `kms:ScheduleKeyDeletion`
    - key inventory: `kms:ListKeys` (`*`), `kms:DescribeKey`, `kms:GetKeyRotationStatus`
    - cloud scan (ACM): `acm:ListCertificates` (`*`)
    - With tagging fixed: `kms:CreateKey` + `kms:TagResource` conditioned on `aws:RequestTag/kryptkeeper:managed = "true"`, and `kms:Sign`/`GetPublicKey`/`ScheduleKeyDeletion` conditioned on `aws:ResourceTag/kryptkeeper:managed = "true"`. Inventory-only actions stay read-only on `*`.
- preconditions:
  - "code execution or SSRF-to-IMDS on the hub host, or a compromised hub process (e.g. via a plugin or another finding)"
  - "AWS cloudkms backend deployed with an operator-written IAM policy"
- yields:
  - "sign arbitrary data with any asymmetric KMS key in the AWS account"
  - "schedule deletion (7-day window) of any KMS key in the account — destructive DoS against other workloads"
- asset: All AWS KMS keys in the hub's account/region
- remediation: Add `Tags: [{kryptkeeper:managed=true}, {kryptkeeper:id=<id>}]` to `CreateKeyInput`, and ship a Terraform `aws_iam_role_policy` (behind a `enable_cloudkms` variable) that grants the tag-conditioned minimal policy above.

### CLOUD-003: GCP and Azure CA keys are created software-protected, not HSM-backed
- id: CLOUD-003 | severity: MEDIUM | category: cloud | tool: manual | status: REAL
- file: internal/keystore/cloudkms_gcp.go:229
- evidence:
  - `cloudkms_gcp.go:229`: `"protectionLevel": "SOFTWARE"` is hardcoded for every generated key, including `purpose=ca` keys.
  - `cloudkms_azure.go:445-449`: `azureKeyParams` returns `kty` `"EC"`/`"RSA"`, which are software-protected keys. HSM-backed keys are `EC-HSM`/`RSA-HSM` (Premium vault or Managed HSM).
  - AWS KMS default keys are HSM-backed (FIPS 140-3 L3), so the three backends give unequal custody guarantees behind one `cloudkms` setting. Nothing in the API or the UI tells the operator this.
- preconditions:
  - "operator selects KRYPTKEEPER_KEY_BACKEND=cloudkms with provider gcp or azure believing it is HSM custody"
  - "audit/compliance requirement for HSM-held CA keys (WebTrust/CA-B Forum, FIPS 140 L3)"
- yields:
  - "CA private keys held at FIPS 140 L1 software protection — custody/compliance failure; key material resident in provider software rather than an HSM boundary"
- asset: CA signing keys in GCP Cloud KMS / Azure Key Vault
- remediation: Default to `protectionLevel: HSM` (GCP) and `EC-HSM`/`RSA-HSM` (Azure), with an explicit opt-down env, and record the protection level in `cloud_kms_keys` metadata.

### CLOUD-004: Azure and GCP credential sourcing uses long-lived secrets or static bearer tokens in env, with no workload identity
- id: CLOUD-004 | severity: LOW | category: cloud | tool: manual | status: REAL
- file: internal/keystore/cloudkms_azure.go:143
- evidence:
  - `cloudkms_azure.go:143-147` and `internal/cloudinventory/azure_keyvault.go:41-50` require `AZURE_CLIENT_SECRET` (client-credentials flow only). There is no managed identity (IMDS) or federated workload identity, so a long-lived secret has to live in the process environment.
  - `internal/bootstrap/handlers_key_inventory.go:58` reads a static `AZURE_ACCESS_TOKEN`, and `:64` reads `GOOGLE_ACCESS_TOKEN`. `cloudkms_gcp.go:125` and `gcp_certmanager.go` prefer `GOOGLE_ACCESS_TOKEN` over the metadata server. These are bearer tokens that expire in about 1 hour and are never refreshed, which pushes operators toward pasting fresh tokens into env and config files.
  - `cloudkms_gcp.go:136-149`: the metadata token response status is not checked (`gcp_certmanager.go:195` does check it), so a non-200 response produces an empty `Bearer ` header. This fails closed, with a misleading error.
  - `azure_keyvault.go:152` hardcodes `login.microsoftonline.com` and ignores the validated `AZURE_AUTHORITY_HOST`. Sovereign clouds are therefore unsupported, and the two Azure token paths differ.
- preconditions:
  - "read access to the hub process environment (/proc/<pid>/environ, container inspect, orchestration env)"
- yields:
  - "Azure service-principal client secret (long-lived, vault-wide sign/create/delete)"
  - "GCP/Azure bearer token valid up to ~1h"
- asset: Azure service principal secret; GCP/Azure access tokens
- remediation: Support Azure managed identity and workload identity (or `azidentity.DefaultAzureCredential`) and GCP ADC with refresh. Drop the static `*_ACCESS_TOKEN` env paths, and check the metadata response status in `cloudkms_gcp.go`.

### CLOUD-005: Cloud KMS signing and generation calls have no deadline; inventory uses http.DefaultClient
- id: CLOUD-005 | severity: LOW | category: cloud | tool: manual | status: REAL
- file: internal/keystore/cloudkms_aws.go:22
- evidence:
  - `cloudkms_aws.go:22`, `cloudkms.go:241` and `cloudkms_gcp.go:29,48,81,217,233` and `cloudkms_azure.go:33,49,99,377,400` all use `context.Background()`. `crypto.Signer.Sign` carries no context, and the AWS SDK default HTTP client sets no overall request timeout, so a stalled KMS connection blocks the issuing goroutine indefinitely. GCP and Azure keystore calls do use a 30s client timeout (`cloudkms_gcp.go:282`, `cloudkms_azure.go:455`).
  - `keyinventory/azure.go:27-28` and `keyinventory/gcp.go:27-28` default to `http.DefaultClient` (no timeout), and `cloudinventory/azure_keyvault.go:166` uses `http.DefaultClient` for the token call.
  - AWS `LoadDefaultConfig` runs again on every Sign (`cloudkms_aws.go:24`), which repeats credential resolution and IMDS calls on the signing hot path.
- preconditions:
  - "network degradation or a slow/blackholed cloud endpoint"
- yields:
  - "certificate issuance stalls (goroutine/connection pile-up) — availability loss of the CA"
- asset: CA issuance availability
- remediation: Build the KMS client once per store with an `awshttp.NewBuildableClient().WithTimeout(...)`, wrap each cloud call in `context.WithTimeout`, and give the inventory sources a timed `*http.Client`.

### CLOUD-006: Unbounded pagination and N+1 calls in cloud inventory; Azure nextLink loop has no cap
- id: CLOUD-006 | severity: LOW | category: cloud | tool: manual | status: REAL
- file: internal/keyinventory/aws.go:49
- evidence:
  - `keyinventory/aws.go:49-78`: `for {}` over `ListKeys` with no page or item cap, plus 2 extra API calls per key (`:57`, `:68`), and errors from those calls are swallowed.
  - `keyinventory/azure.go:40-82` (`for url != ""`, `url = listing.NextLink`) and `cloudinventory/azure_keyvault.go:68-75` follow the server-supplied `nextLink` with no iteration cap or repeat detection, so a nextLink that loops never terminates.
  - `cloudinventory/aws_acm.go:58-94` and `gcp_certmanager.go` page without a cap. `gcp_certmanager.go:115` appends `pageToken` unescaped (`keyinventory/gcp.go:44` escapes it correctly). Bodies in `cloudinventory/*` and in `cloudkms_gcp.go`/`cloudkms_azure.go` are read with an unbounded `io.ReadAll` (keyinventory uses a LimitReader).
  - `cloud_discovery.go:93-95` caps only the persisted items (200), not the fetch.
- preconditions:
  - "large cloud account, or a misbehaving/compromised provider endpoint; combined with CLOUD-001 any authenticated user can trigger it repeatedly"
- yields:
  - "hub memory/goroutine exhaustion and cloud API throttling of the hub's credentials"
- asset: Hub availability; cloud API quota
- remediation: Add a page cap (for example 100 pages or 10k items) and seen-token detection, use `io.LimitReader` everywhere, escape `pageToken`, and use `DescribeKey` concurrency limits or batch only on demand.

### CLOUD-007: Azure bearer token is sent to whatever host appears in a stored key URI, kid or nextLink (no vault-host pinning)
- id: CLOUD-007 | severity: LOW | category: cloud | tool: manual | status: REAL
- file: internal/keystore/cloudkms_azure.go:48
- evidence:
  - `cloudkms_azure.go:48` builds `signURL := fmt.Sprintf("%s/sign?...", s.config.KeyURI)`, and `destroy_cloud.go:97` sends `DELETE base` with `Authorization: Bearer <vault token>`. `KeyURI` is the `kid` returned by Azure and later read back from the `cloud_kms_keys.key_uri` DB column (`cloudkms.go:146-171`). There is no check that its host equals `AZURE_KEYVAULT_URL`'s host or `*.vault.azure.net`.
  - `keyinventory/azure.go:81,88` and `cloudinventory/azure_keyvault.go:74,101` follow the server-supplied `nextLink`/`kid` URLs with the bearer token attached.
  - `AZURE_KEYVAULT_URL` itself is not validated as https (`cloudkms_azure.go:367`, `azure_keyvault.go:37`).
- preconditions:
  - "write access to the core DB cloud_kms_keys table (e.g. via SQL injection or DB credential theft), OR a malicious/MITM'd Key Vault response, OR operator mis-set AZURE_KEYVAULT_URL"
- yields:
  - "Azure Key Vault bearer token (vault-scoped, ~1h) exfiltrated to attacker host"
  - "SSRF from the hub to an arbitrary URL with an Authorization header"
- asset: Azure Key Vault access token
- remediation: Parse every KeyURI, kid and nextLink, and require `https` plus a host equal to the configured vault host before attaching the token. Validate `AZURE_KEYVAULT_URL` at startup.

### CLOUD-008: Key ID is not validated before it is interpolated into GCP query and Azure path
- id: CLOUD-008 | severity: LOW | category: cloud | tool: manual | status: REAL
- file: internal/keystore/cloudkms_gcp.go:223
- evidence:
  - `internal/bootstrap/handlers_keys.go:81` checks only `strings.TrimSpace(req.ID) == ""`.
  - `cloudkms_gcp.go:223`: `createURL := fmt.Sprintf("%s/%s/cryptoKeys?cryptoKeyId=%s", ..., id)` is unescaped. An id of `x&skipInitialVersionCreation=true` creates a key with no version, the follow-up `getPublicKey` fails, and an orphaned key is left behind. Other query parameters can be injected the same way.
  - `cloudkms_azure.go:399`: `fmt.Sprintf("%s/keys/%s/create?...", vaultURL, id)` is unescaped. An id containing `/`, `?`, `#` or `..` changes the request path and query within the same vault. Whether Azure normalises `..` is unverified, and the impact is bounded to the vault the token already covers.
  - The provider charsets are GCP `[a-zA-Z0-9_-]{1,63}` and Azure `[0-9a-zA-Z-]{1,127}`. AWS uses the id only as `Description` and is unaffected.
- preconditions:
  - "authenticated principal with key.generate permission"
  - "cloudkms backend on gcp or azure"
- yields:
  - "orphaned or malformed cloud keys; request-parameter tampering against the hub's own vault/key ring"
- asset: GCP key ring / Azure vault integrity
- remediation: Validate `id` against `^[A-Za-z0-9-]{1,63}$` in `CloudKMSStore.GenerateKey`, and build URLs with `url.PathEscape` and `url.Values`.

### CLOUD-009: GCP and Azure signers ignore rsa.PSSOptions and hash choice; no CRC32C integrity check
- id: CLOUD-009 | severity: LOW | category: cloud | tool: manual | status: REAL
- file: internal/keystore/cloudkms_azure.go:223
- evidence:
  - `cloudkms_azure.go:223-231`: an RSA key always maps to `RS256/384/512` (PKCS#1 v1.5), even when `opts` is `*rsa.PSSOptions` (PS256 exists). A PSS-requesting caller gets a v1.5 signature under a PSS algorithm identifier.
  - `cloudkms_gcp.go:152-158`: `gcpSigningAlgorithm` returns `""` and validates nothing. `:161-171`: `gcpDigestField` silently defaults any unknown hash to `"sha256"`. GCP keys are fixed at `*_SHA256`/`EC_SIGN_P384_SHA384` (`:267-279`), so an RSA-4096 key asked to sign SHA-384, or any PSS request, fails at GCP or yields a mismatched signature.
  - `cloudkms_gcp.go:43`: `"digestCrc32c": nil`, and the response's `verifiedDigestCrc32c` and `signatureCrc32c` are not checked. Google recommends these checks to detect corruption in transit.
  - This fails closed in most paths (GCP rejects a digest-length mismatch, and the resulting signature does not verify), so the impact is correctness and availability, not forgery.
- preconditions:
  - "CA or signer configured for RSA-PSS or a non-default hash on the gcp/azure cloudkms backend"
- yields:
  - "invalid signatures/certificates issued or issuance failures; undetected in-transit corruption of signatures"
- asset: Certificate signature correctness
- remediation: Reject `*rsa.PSSOptions` (or map it to PS256/384/512 on Azure), make the GCP signer check `opts.HashFunc()` against the key version's algorithm and error on a mismatch, and send and verify CRC32C.

---

## Notes (informational, not findings)

- `CloudKMSConfig.Region`/`ProjectID` are persisted but never used by the AWS keystore. `LoadDefaultConfig` without `WithRegion` depends on `AWS_REGION`, and `Sign` targets the configured region even when the key ARN names another, which fails closed. The ACM connector silently defaults to `us-east-1` (`aws_acm.go:39`).
- AWS deletion uses the minimum 7-day pending window (`destroy_cloud.go:44`), so it is recoverable within the window. GCP destroys only `cryptoKeyVersions/1`.
- `GenerateKey` logs the full key ARN/URI on an orphaned reference (`cloudkms.go:227`). That is operator-log only and acceptable.

---

# Completion Manifest

## Files produced
- `docs/security/CLOUD_FINDINGS_2026-10-09.md` — cloud findings (9 REAL), verified controls, implied minimal AWS IAM policy — ~200 lines

## Files modified
- None (SEMGREP/DEPENDENCY findings read only)

## Decisions made
- Azure was included even though the methodology covers AWS/GCP, because the HANDOFF asked for it.
- CLOUD-001 was rated MEDIUM, not HIGH: the data is key metadata and identifiers, not key material, and authentication is required.
- CLOUD-002 was rated MEDIUM: exploitation needs hub compromise first, but the blast radius is account-wide.

## Known issues / deferred
- Real-cloud UAT not run. Azure `..` path normalisation (CLOUD-008) and the AWS SDK default timeout behaviour (CLOUD-005) were judged from code and docs, not observed.
- Checkov/semgrep cloud packs were not re-run here (covered by the SAST and IaC phases).

## Verify result
- PASS — each finding cites a file:line read in this session; the file exists — evidence: `docs/security/CLOUD_FINDINGS_2026-10-09.md`

## Memory written
- None — nothing durable beyond this report

## Model tier: large — medium context used

Maker: cloud-security-checker
Verifier: attack-chainer (downstream, independent)

## Ready for: attack-chainer

cloud done
