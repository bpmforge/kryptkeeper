# Delivery plugin catalogue and submission guide

What is in the tree, what each plugin is allowed to do, and what a plugin
author must show before it is listed here. Operator install steps live in
[DELIVERY_PLUGINS.md](DELIVERY_PLUGINS.md); the author guide is
[../plugins/README.md](../plugins/README.md); the design is
[../design/DELIVERY_PLUGINS.md](../design/DELIVERY_PLUGINS.md).

## Honest status (read this first)

Every plugin below is **shipped in tree**: its source, manifest and
conformance tests are in the repository and pass against recorded or fake
servers. **None has been verified against a real account or device yet.**
Live UAT against real AWS, Azure, GCP, Cloudflare and Vault accounts is
ticket **W27-32** and has not run. F5 and Citrix are additionally labelled
"not yet verified on a real device" in their own manifest names (D-118 needs
one BIG-IP VE or NetScaler VPX run first).

Two further caveats apply to all rows:

- Every checked-in `manifest.json` carries a placeholder
  `artifact.sha256` of 64 zeros. `make plugins` builds the module and pins the
  real digest into the manifest under `dist/plugins/<name>/`; install that
  one, never the file under `plugins/`.
- Trust tier is decided at install time by the signature, not by the manifest
  (see section 1). Until the Kryptkeeper plugin key exists and the build is
  signed with it, an installed first-party plugin shows as `community`.

## Catalogue

Facts below are read from each `plugins/<dir>/manifest.json` (version 1.0.0,
publisher "Kryptkeeper Authors", license Apache-2.0, `api_version`
`kryptkeeper.delivery/v1` for all). Every plugin declares
`receive_private_key` (Critical) and `tls_verify`. The network column is what
the manifest grants; `credential host` means the host comes from the named
credential field.

| Plugin id (directory) | Delivers to | Status | Verification | Network capability | Tracked by |
|---|---|---|---|---|---|
| `kryptkeeper.f5-bigip` (`plugins/f5`) | F5 BIG-IP client-ssl profile | shipped (in tree); not verified on a real device | `tls` (dial) | credential host `base_url`, ports 443, 8443 | W20-22, D-118 |
| `kryptkeeper.citrix-adc` (`plugins/citrix`) | Citrix ADC / NetScaler cert-key pair | shipped (in tree); not verified on a real device | `tls` (dial) | credential host `base_url`, port 443 | W20-22, D-118 |
| `kryptkeeper.example-device` (`plugins/example`) | Reference HTTPS device, not a product | shipped (in tree); example only | `tls` (dial) | credential host `base_url` | W20 (copy to start) |
| `kryptkeeper.vault-kv` (`plugins/vault`) | HashiCorp Vault KV v2 | shipped (in tree); no live Vault yet | **`readback`** | credential host `base_url`, ports 443, 8200 | W27-27, W27-32 |
| `kryptkeeper.azure-keyvault` (`plugins/azure-keyvault`) | Azure Key Vault secret | shipped (in tree); no live account yet | **`readback`** | credential host `vault_url` plus `login.microsoftonline.com` | W27-28, W27-32 |
| `kryptkeeper.gcp-secretmanager` (`plugins/gcp-secretmanager`) | GCP Secret Manager secret | shipped (in tree); no live account yet | **`readback`** | `secretmanager.googleapis.com`, `oauth2.googleapis.com` | W27-28, W27-32 |
| `kryptkeeper.aws-secretsmanager` (`plugins/aws-secretsmanager`) | AWS Secrets Manager secret | shipped (in tree); no live account yet | **`readback`** | `secretsmanager.<region>.amazonaws.com` for 10 listed regions | W27-29, W27-32 |
| `kryptkeeper.aws` (`plugins/aws`) | AWS ACM import, ALB listener or CloudFront binding | shipped (in tree); no live account yet | `tls` (dial) | `cloudfront.amazonaws.com`, plus `acm.<region>` and `elasticloadbalancing.<region>` for 10 listed regions | W27-29, W27-32 |
| `kryptkeeper.azure` (`plugins/azure`) | Azure Application Gateway or Front Door (via Key Vault certificate) | shipped (in tree); no live account yet | `tls` (dial) | credential host `vault_url` plus `login.microsoftonline.com`, `management.azure.com` | W27-30, W27-32 |
| `kryptkeeper.cloudflare-custom-cert` (`plugins/cloudflare`) | Cloudflare custom certificate for a zone hostname | shipped (in tree); no live account yet | `tls` (dial) | credential host `api_base` | W27-31, W27-32 |

The ten regions in the AWS manifests are us-east-1, us-east-2, us-west-1,
us-west-2, eu-west-1, eu-west-2, eu-central-1, ap-southeast-1,
ap-southeast-2 and ap-northeast-1. A region not in the manifest is not
reachable until the manifest is changed and re-installed as a new version.

### Credential and target fields

Declared in the manifests; `secret` fields are encrypted in the credential
store and never returned by the API.

| Plugin | Credential fields (`secret` marked *) | Target fields (required marked +) |
|---|---|---|
| f5, citrix | `base_url`+, `username`+, `password`+* | `client_ssl_profile`+ (f5); `certkey_name`+ (citrix) |
| example | `base_url`+, `token`+* | `listener`+ |
| vault | `base_url`+, `token`+*, `namespace` | `mount` (default `secret`), `path`+ |
| azure-keyvault | `vault_url`+, `tenant_id`+, `client_id`+, `client_secret`+* | `secret_name`+ |
| gcp-secretmanager | `service_account_json`+*, `project_id`+ | `secret_id`+ |
| aws-secretsmanager | `access_key_id`+, `secret_access_key`+*, `session_token`*, `region`+ | `secret_id`+ |
| aws | same four as aws-secretsmanager | `mode`+, `listener_arn`, `distribution_id`, `certificate_arn`, `import_mode` |
| azure | `vault_url`+, `tenant_id`+, `client_id`+, `client_secret`+* | `mode`+, `subscription_id`+, `resource_group`+, `keyvault_cert_name`+, `gateway_name`, `ssl_certificate_name`, `profile_name`, `secret_name` |
| cloudflare | `api_base`+, `api_token`+* | `zone_id`+, `hostname`+, `bundle_method` (default `ubiquitous`) |

### What `readback` means for you

Secret stores have no TLS endpoint to dial. A `readback` plugin declares
`"verification": "readback"`; after the write the hub asks the plugin to
fetch the exact version it wrote (using the push's `rollback_handle`),
parses the PEM and compares the leaf SHA-256 itself. A mismatch is
`verify_failed` and rolls back. Setting `verify_host_port` on the target
forces the TLS dial instead. Details: DELIVERY_PLUGINS.md section 4.

Note what read-back does and does not prove: it proves the store holds the
certificate the hub sent. It does not prove any workload has picked it up.
For the Kubernetes Secret path, which is not a plugin but a built-in
`install_mode=k8s`, see [EXTERNAL_SECRETS.md](EXTERNAL_SECRETS.md).

## 1. Trust tiers

From DELIVERY_PLUGINS.md section 1. The tier comes from the signature on the
install request:

| Signed with | Trust tier |
|---|---|
| the Kryptkeeper plugin key compiled into the hub | `first-party` |
| a key in the file named by `KRYPTKEEPER_PLUGIN_TRUSTED_KEYS` | `verified` |
| nothing | `community` |

A signature that verifies against neither is refused (400), never treated as
community. The tier is a label: it does not change who must approve
enabling the plugin, which follows its capabilities. A newly installed
plugin is always disabled until enabled.

## 2. Capability taxonomy

Copied from the design doc. The UI shows exactly these sentences; manifests
cannot supply their own wording.

| Capability | Tier | What the operator is told |
|---|---|---|
| `receive_private_key` | **Critical** | "This plugin receives the private key of every certificate it delivers." |
| `trust_store` | **Critical** | "This plugin can add certificate authorities to the trust store of the hosts it delivers to." |
| `elevated_exec` | **High** | "This plugin runs commands as an administrator (root/sudo or Windows administrator) on target hosts." |
| `remote_exec` | **High** | "This plugin runs commands on target hosts over SSH or WinRM." |
| `network` (beyond the credential's host) | **High** | "This plugin connects to hosts other than the device you configure: <list>." |
| `network` (credential host only) | High (any network access is at least High) | "This plugin connects to the device address you configure, so it has network access." |
| `file_write` | Standard | "This plugin writes files on target hosts under: <paths>." |
| `tls_verify` | Standard | "This plugin checks which certificate the service presents." |

Every plugin in the catalogue is Critical because it receives the private
key. That is inherent: a key-bearing delivery cannot be done without it.

## 3. Submission checklist

Copy into the pull request description and tick every line. A line that does
not apply gets a one-sentence reason, not a deletion.

- [ ] `manifest.json` has `api_version` `kryptkeeper.delivery/v1`, a unique
      `id`, a `version`, `license` and a `source` URL.
- [ ] `artifact.sha256` equals the SHA-256 of the built module (the build pins
      it; do not commit a hand-typed value).
- [ ] Capabilities are minimal. Each one is justified in the PR text,
      including every host or port under `network`. No wildcard hosts.
- [ ] Builds with `GOOS=wasip1 GOARCH=wasm go build -buildmode=c-shared`.
- [ ] Passes `conformance.Suite` in `tests/plugins/conformance` (see the
      existing `vault_test.go` or `exampledevice_test.go` for the shape).
- [ ] Rollback is proven: a `RollbackHandle` is returned and `RolledBack`
      is reported honestly (true only when the plugin confirmed it).
- [ ] No secrets in logs, errors or returned detail text. Test keys are
      generated in the test, never committed.
- [ ] Credential schema and target schema are documented and mark every
      secret field `"secret": true`.
- [ ] Verification is declared: the default TLS dial, or
      `"verification": "readback"` with a `verify` op that only fetches.
- [ ] For the `verified` tier: the release is signed with cosign (ECDSA
      P-256) and the public key is supplied for
      `KRYPTKEEPER_PLUGIN_TRUSTED_KEYS`.
- [ ] Real-device or real-account evidence is attached, **or** the plugin
      name and PR state "not verified on a real device/account" in plain
      words (as F5 and Citrix do).
- [ ] A row for the plugin is added to the catalogue above with real
      manifest values and an honest status.
