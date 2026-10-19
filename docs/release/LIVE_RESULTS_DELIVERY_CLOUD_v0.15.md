# Live validation W27-32: secrets-manager and cloud LB/CDN delivery plugins - v0.15

Harness: `tests/live/delivery-cloud/run.sh` (README there lists every variable, permission and cleanup item).
Status: **the Vault leg was run for real (local Vault dev server, TLS) and PASSED. Every other leg is PENDING-RUN**: this
machine has no AWS, Azure, GCP or Cloudflare accounts or credentials, so nothing is claimed for them.

## Run metadata

| Field | Value |
|---|---|
| Date of local run | 2026-10-16 |
| Base commit | 5ffaaf75 (branch kk/w27-b) plus the W27-32 harness commit |
| Host | macOS arm64, podman machine (applehv) |
| Vault | `docker.io/hashicorp/vault:1.17` (`server -dev -dev-tls`), KV v2 at `secret/`, throwaway root token, CA trusted through the credential's `tls_ca_pem` |
| Plugins | built from `plugins/<name>` (wasip1/wasm, sha256 pinned in the manifest); installed Critical tier (`receive_private_key`), enabled through the approval queue |
| Providers / regions / accounts (operator legs) | PENDING-RUN |
| Cost incurred | local Vault: none. Operator legs: PENDING-RUN |

## Results

| Leg | Result | New version / serial | Read-back fp == new_fingerprint | Seconds to serve (LB) | Forced-failure result | Secret occurrences (log+audit) |
|---|---|---|---|---|---|---|
| vault | **PASS** | KV v2 version 1 (store was empty: 0 -> 1 versions) | yes (`dfa65558...86d29`) | n/a (secret store) | rolled back: `verify_failed`, `rolled_back=true` audit row, current version still the success-run certificate | 0 |
| akv | PENDING-RUN | PENDING-RUN | PENDING-RUN | n/a | PENDING-RUN | PENDING-RUN |
| gcpsm | PENDING-RUN | PENDING-RUN | PENDING-RUN | n/a | PENDING-RUN | PENDING-RUN |
| aws-sm | PENDING-RUN | PENDING-RUN | PENDING-RUN | n/a | PENDING-RUN | PENDING-RUN |
| aws-alb | PENDING-RUN | PENDING-RUN | n/a | PENDING-RUN | PENDING-RUN | PENDING-RUN |
| aws-cloudfront | PENDING-RUN | PENDING-RUN | n/a | PENDING-RUN | PENDING-RUN | PENDING-RUN |
| azure-appgw | PENDING-RUN | PENDING-RUN | n/a | PENDING-RUN | PENDING-RUN | PENDING-RUN |
| azure-frontdoor | PENDING-RUN | PENDING-RUN | n/a | PENDING-RUN | PENDING-RUN | PENDING-RUN |
| cloudflare | PENDING-RUN | PENDING-RUN | n/a | PENDING-RUN | PENDING-RUN | PENDING-RUN |

The secret-store legs are not blocked: W27-36 added read-back verification and the secret-store manifests declare
`"verification":"readback"`, so `renewal/execute` reaches `installed_verified` by the hub fingerprinting the PEM the store returns.

### Vault leg, what was observed (real output)

`bash tests/live/delivery-cloud/run.sh all` with no environment: only `vault` ran, eight legs printed `SKIP: <leg> needs <VAR>`, exit 0.

* `kryptkeeper.vault-kv` 1.0.0 installed: capability tier critical, trust community. Self-approval of the enable -> 403; second admin -> 200.
* Credential `{base_url, token, tls_ca_pem}` and target `{mount: secret, path: kk-uat-<stamp>/leaf}`; the store read directly before the run:
  0 versions.
* Success run: `renewal/execute` -> 200, `install_outcome=installed_verified`, `verified=true`. The store read directly (Vault HTTP API with the dev CA,
  not through the plugin): version 1, certificate fingerprint equals the response's `new_fingerprint`, version count +1.
* Forced failure: a second leaf renewed with `install.verify_host_port` at an `openssl s_server` presenting another certificate ->
  `install_outcome=verify_failed`, `verified=false`. The plugin's Rollback restored the prior content: the store ended with 3 versions
  (1 = success, 2 = the failed push, 3 = the restore, because KV v2 cannot promote an older version) and its current version carries the
  success-run fingerprint. Audit: 2 `delivery_plugin.push` rows for `kryptkeeper.vault-kv`, one `verified=true`, one `rolled_back=true`.
* Secret scan: the Vault token occurs 0 times in the hub log and in all 18 audit entries; a planted canary is detected, so the scan can fail.

Deviation from the spec text: the renewal API response has no `rolled_back` field (`RenewalExecuteResult` carries `install_outcome`, `install_detail`,
`verified`); the harness reads `rolled_back` from the `delivery_plugin.push` audit row instead.

## Steps for the operator (the owner)

Use dedicated test secrets, listeners, distributions and zones. Credential files live under `$HOME/.config/kryptkeeper-lab/` (mode 600), never in the repo.
Each command prints the table row; paste it above, set the real values, and leave any FAIL as FAIL with its text. `KK_EVIDENCE_DIR=<dir>` writes `results.md`.
After the run, remove the objects listed in `tests/live/delivery-cloud/README.md` (new secret versions, ACM / Key Vault certificates, the Cloudflare custom certificate).

1. **akv**: `KK_AKV_CRED_FILE=... KK_AKV_SECRET_NAME=kk-uat-test bash tests/live/delivery-cloud/run.sh akv`
2. **gcpsm**: `KK_GCP_SA_FILE=<service-account key> KK_GCP_PROJECT=... KK_GCP_SECRET_ID=kk-uat-test bash tests/live/delivery-cloud/run.sh gcpsm`
3. **aws-sm**: `KK_AWS_CRED_FILE=... KK_AWS_REGION=us-east-1 KK_AWS_SECRET_ID=kk-uat-test bash tests/live/delivery-cloud/run.sh aws-sm`
4. **aws-alb / aws-cloudfront** (the endpoint must serve TLS on a name you control; the CloudFront distribution needs the alias and an ACM cert in us-east-1):
   `KK_AWS_CRED_FILE=... KK_AWS_REGION=... KK_AWS_LISTENER_ARN=... KK_AWS_ALB_HOST=<alb name> bash tests/live/delivery-cloud/run.sh aws-alb`
   `KK_AWS_CRED_FILE=... KK_AWS_REGION=... KK_AWS_DISTRIBUTION_ID=... KK_AWS_CF_HOST=<cf alias> bash tests/live/delivery-cloud/run.sh aws-cloudfront`
5. **azure-appgw / azure-frontdoor**:
   `KK_AZ_CRED_FILE=... KK_AZ_SUB=... KK_AZ_RG=... KK_AZ_KV_CERT_NAME=... KK_AZ_GATEWAY=... KK_AZ_SSL_CERT=... KK_AZ_APPGW_HOST=... bash tests/live/delivery-cloud/run.sh azure-appgw`
   `KK_AZ_CRED_FILE=... KK_AZ_SUB=... KK_AZ_RG=... KK_AZ_KV_CERT_NAME=... KK_AZ_PROFILE=... KK_AZ_FD_SECRET=... KK_AZ_FD_HOST=... bash tests/live/delivery-cloud/run.sh azure-frontdoor`
6. **cloudflare**: `KK_CF_CRED_FILE=... KK_CF_ZONE_ID=... KK_CF_HOST=<host in the zone> bash tests/live/delivery-cloud/run.sh cloudflare`
7. For the ALB / CloudFront / App Gateway / Front Door legs, also run the provider-side binding check from the README before and after the forced failure and note it here.

Acceptance to confirm from these runs: each secret store holds a new version whose read-back fingerprint equals the new leaf and the forced failure leaves the
previous version current; AWS, Azure and Cloudflare each serve the new serial at the public endpoint within 900 s and the forced failure restores the old binding.
Watch for the CDN timing risk described in the README (the hub's post-push TLS dial retries only 6 x 250 ms).
