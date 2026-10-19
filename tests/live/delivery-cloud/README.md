# Live-account UAT for secrets-manager and cloud LB/CDN delivery plugins (W27-32)

Drives the hub's real delivery-plugin API end to end for `vault`, `azure-keyvault`, `gcp-secretmanager`,
`aws-secretsmanager`, `aws` (ALB, CloudFront), `azure` (Application Gateway, Front Door) and `cloudflare`.
Results go in `docs/release/LIVE_RESULTS_DELIVERY_CLOUD_v0.15.md`.

```
bash tests/live/delivery-cloud/run.sh [leg ...]
  legs: vault akv gcpsm aws-sm aws-alb aws-cloudfront azure-appgw azure-frontdoor cloudflare | all (default)
```

Exit 0 = every leg that ran passed, 1 = a leg failed, 2 = nothing runnable. A leg lacking prerequisites prints
`SKIP: <leg> needs <VAR>` and is recorded SKIPPED, never PASS. With no environment set, `all` runs only `vault`
(a Vault dev server in podman, no account) and skips the rest.

Every secret variable is a **file path**; Python reads it and posts it to `/api/v1/credentials`. Nothing secret goes in
argv, echo or a trace. Keep the files under `$HOME/.config/kryptkeeper-lab/` (mode 600), never in the repo.

## Per-leg environment

File contents are the plugin's `credential_schema` (from each `plugins/*/manifest.json`).

| Leg (plugin) | Variables | Credential file |
|---|---|---|
| vault (`kryptkeeper.vault-kv`) | none; starts `hashicorp/vault:1.17 -dev -dev-tls` with a throwaway token and trusts its CA through the credential's `tls_ca_pem` | generated: `base_url`, `token`, `tls_ca_pem` |
| akv (`azure-keyvault`) | `KK_AKV_CRED_FILE`, `KK_AKV_SECRET_NAME` | JSON `vault_url`, `tenant_id`, `client_id`, `client_secret` |
| gcpsm (`gcp-secretmanager`) | `KK_GCP_SA_FILE`, `KK_GCP_PROJECT`, `KK_GCP_SECRET_ID` | raw service-account key JSON (sent as `service_account_json`; `project_id` added) |
| aws-sm (`aws-secretsmanager`) | `KK_AWS_CRED_FILE`, `KK_AWS_REGION`, `KK_AWS_SECRET_ID` | JSON `access_key_id`, `secret_access_key`, `session_token`?; `region` added |
| aws-alb (`aws`, mode `acm_alb`) | `KK_AWS_CRED_FILE`, `KK_AWS_REGION`, `KK_AWS_LISTENER_ARN`, `KK_AWS_ALB_HOST` (opt. `KK_AWS_CERT_ARN`) | as aws-sm |
| aws-cloudfront (`aws`, mode `acm_cloudfront`) | `KK_AWS_CRED_FILE`, `KK_AWS_REGION`, `KK_AWS_DISTRIBUTION_ID`, `KK_AWS_CF_HOST` (opt. `KK_AWS_CF_CERT_ARN`) | as aws-sm |
| azure-appgw (`azure`, mode `appgw`) | `KK_AZ_CRED_FILE`, `KK_AZ_SUB`, `KK_AZ_RG`, `KK_AZ_KV_CERT_NAME`, `KK_AZ_GATEWAY`, `KK_AZ_SSL_CERT`, `KK_AZ_APPGW_HOST` | JSON `vault_url`, `tenant_id`, `client_id`, `client_secret` |
| azure-frontdoor (`azure`, mode `frontdoor`) | `KK_AZ_CRED_FILE`, `KK_AZ_SUB`, `KK_AZ_RG`, `KK_AZ_KV_CERT_NAME`, `KK_AZ_PROFILE`, `KK_AZ_FD_SECRET`, `KK_AZ_FD_HOST` | as azure-appgw |
| cloudflare | `KK_CF_CRED_FILE`, `KK_CF_ZONE_ID`, `KK_CF_HOST` (opt. `KK_CF_API_BASE`) | JSON `api_token` (`api_base` defaults to `https://api.cloudflare.com/client/v4`) |

Common: `KK_EVIDENCE_DIR` (copies the forced-failure response, audit when clean, `results.md`), `KK_VAULT_IMAGE`.
The `*_HOST` values must be names whose TLS endpoint you control (the hub issues a leaf for that name from its own CA and
the harness polls `openssl s_client -connect <host>:443 -servername <host>`).

Minimum permissions (from the plugin headers, plus what the harness's direct reader needs): AWS ACM/ELB/CloudFront
`acm:ImportCertificate`, `acm:GetCertificate`, `elasticloadbalancing:DescribeListeners` + `ModifyListener`,
`cloudfront:GetDistributionConfig` + `UpdateDistribution`; Secrets Manager `DescribeSecret`, `PutSecretValue`,
`GetSecretValue`, `UpdateSecretVersionStage` (plugin) and `ListSecretVersionIds` (reader), plus KMS if the secret uses a
customer-managed key. Azure: Key Vault Certificates Officer (or access policy Import/Get/List), Network Contributor on
the gateway, CDN Profile Contributor on the Front Door profile, and the gateway's identity needs Get on the vault's secrets;
for the Key Vault secret leg the principal needs secrets set/get/list/update. GCP: a role on the one secret covering
`secretmanager.secrets.create` (the plugin creates the secret if absent), `versions.add`, `versions.access`, `versions.list`,
`versions.disable`. Cloudflare: a token that can edit custom certificates on the one zone (needs a plan that includes them).

## What each leg does

1. Build the plugin (same commands as `scripts/build-plugins.sh`, one plugin), install it, enable it; the enable is a
   Critical-tier action (`receive_private_key`): self-approval must be refused (403) and a second admin approves.
2. Credential, plugin target, and a leaf issued by the hub CA for the leg's host.
3. **Success run**: `POST /api/v1/renewal/execute`; need 200 and `install_outcome=installed_verified`. Secret stores
   verify by read-back (`"verification":"readback"`); LB/CDN legs by the hub's TLS dial of `<host>:443`.
4. **Secret stores**: `storeread.py` reads the store directly (not through the plugin or hub): current version's certificate
   fingerprint must equal `new_fingerprint` and the version count must rise by exactly 1.
   **LB/CDN**: poll the public endpoint every 20 s, up to 900 s, for the renewed certificate's serial (hub's `serial_number`).
5. **Forced failure**: renew a second leaf with `install.verify_host_port` pointing at a TLS server (`openssl s_server`
   in a container on the run's network) that presents another certificate. Expect `install_outcome=verify_failed`, an audit
   row `delivery_plugin.push ... rolled_back=true`, and the previous certificate current again (secret stores: the store's
   current fingerprint equals the success-run certificate; LB/CDN: the endpoint serves the success-run serial within 900 s).
   Note the API response has no `rolled_back` field; `rolled_back` is read from the audit row.
6. Secret scan: every secret value in the credential files (and each line >= 8 chars of multi-line ones) must appear 0 times
   in the hub log and the full audit trail; a planted canary proves the scanner can fail.

## Optional provider-side binding checks (manual, per leg)

The harness proves the endpoint serves the right serial; to also see the binding the plugin changed, before/after the forced failure:
ALB `aws elbv2 describe-listener-certificates --listener-arn $KK_AWS_LISTENER_ARN`; CloudFront
`aws cloudfront get-distribution-config --id $KK_AWS_DISTRIBUTION_ID` (ViewerCertificate.ACMCertificateArn);
App Gateway `az network application-gateway ssl-cert show -g $KK_AZ_RG --gateway-name $KK_AZ_GATEWAY -n $KK_AZ_SSL_CERT`;
Front Door `az afd secret show -g $KK_AZ_RG --profile-name $KK_AZ_PROFILE --secret-name $KK_AZ_FD_SECRET`.

## Propagation window

For `aws-cloudfront`, `azure-frontdoor` and `cloudflare` the hub verifies with a TLS dial right after the push. These plugins
declare `verify_propagation_seconds` in their manifests (aws 1200, azure 1200, cloudflare 600), so after the 6 quick attempts the
hub keeps polling every 15 s until the new certificate is served or the window ends. A slow CDN is therefore not a failure by
itself; record the seconds it took. `verify_failed` is expected only if propagation outlasts the window. The `delivery_plugin.push`
audit row shows `verify_window=Ns`. Run time can reach the window plus the push, so keep the harness timeout above it.

## Cleanup and cost

The harness deletes nothing at the provider. Left behind by a run, for manual removal: new secret versions (Vault, Key Vault,
Secret Manager, Secrets Manager), ACM certificates imported by the `aws` plugin (it never deletes superseded ones), Key Vault
certificate versions, and the Cloudflare custom certificate. Use dedicated test secrets, listeners, distributions and zones.
Containers, the network and the image created by the run (`kk-uat-<stamp>-*`) are removed on exit.
