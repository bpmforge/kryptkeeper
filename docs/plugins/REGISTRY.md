# Delivery plugin registry

The plugins this project vouches for. Each row is checked by
[`scripts/check-plugin-index.sh`](../../scripts/check-plugin-index.sh) against the
built, signed release artifacts, so the index cannot drift from what ships. How
plugins are written is in [`README.md`](README.md); how the hub trusts them
(tiers, signatures, approval) is in [`../ops/DELIVERY_PLUGINS.md`](../ops/DELIVERY_PLUGINS.md).

## Verified plugins

Tiers: `first-party` is signed by a key compiled into the hub
(`internal/bootstrap/plugin_signing_keys.txt`); `verified` is signed by a key an
operator trusts. No `verified` row exists yet. The signing key id is the hex
SHA-256 of the DER of the public key; the check script derives it, so never type it
by hand.

A `PENDING-SIGN` module sha256 means no signed release artifact has been
recorded yet. The check warns on it, and fails under `--strict` (use `--strict`
in release gates). Replace it with the hash from the signed `dist/plugins/<name>/manifest.json`
when a release is signed.

None of these plugins is hardware-verified. The F5 and Citrix manifests still
say "not yet verified on a real device"; live status is tracked in the
plugin results docs under [`docs/release/`](../release/), not here.

| Plugin id | Tier | Version | Module sha256 | Capabilities | Signing key id | Source |
|---|---|---|---|---|---|---|
| kryptkeeper.aws | first-party | 1.0.0 | PENDING-SIGN | receive_private_key; network: hosts=21; tls_verify | 5077056a78af2f8affe73660133ec135f370c9d278f99562105b887bd7a4d673 | [plugins/aws](../../plugins/aws) |
| kryptkeeper.aws-secretsmanager | first-party | 1.0.0 | PENDING-SIGN | receive_private_key; network: hosts=10; tls_verify | 5077056a78af2f8affe73660133ec135f370c9d278f99562105b887bd7a4d673 | [plugins/aws-secretsmanager](../../plugins/aws-secretsmanager) |
| kryptkeeper.azure | first-party | 1.0.0 | PENDING-SIGN | receive_private_key; network: hosts_from_credential=vault_url hosts=2; tls_verify | 5077056a78af2f8affe73660133ec135f370c9d278f99562105b887bd7a4d673 | [plugins/azure](../../plugins/azure) |
| kryptkeeper.azure-keyvault | first-party | 1.0.0 | PENDING-SIGN | receive_private_key; network: hosts_from_credential=vault_url hosts=1; tls_verify | 5077056a78af2f8affe73660133ec135f370c9d278f99562105b887bd7a4d673 | [plugins/azure-keyvault](../../plugins/azure-keyvault) |
| kryptkeeper.citrix-adc | first-party | 1.0.0 | PENDING-SIGN | receive_private_key; network: hosts_from_credential=base_url ports=443; tls_verify | 5077056a78af2f8affe73660133ec135f370c9d278f99562105b887bd7a4d673 | [plugins/citrix](../../plugins/citrix) |
| kryptkeeper.cloudflare-custom-cert | first-party | 1.0.0 | PENDING-SIGN | receive_private_key; network: hosts_from_credential=api_base; tls_verify | 5077056a78af2f8affe73660133ec135f370c9d278f99562105b887bd7a4d673 | [plugins/cloudflare](../../plugins/cloudflare) |
| kryptkeeper.f5-bigip | first-party | 1.0.0 | PENDING-SIGN | receive_private_key; network: hosts_from_credential=base_url ports=443,8443; tls_verify | 5077056a78af2f8affe73660133ec135f370c9d278f99562105b887bd7a4d673 | [plugins/f5](../../plugins/f5) |
| kryptkeeper.gcp-secretmanager | first-party | 1.0.0 | PENDING-SIGN | receive_private_key; network: hosts=2; tls_verify | 5077056a78af2f8affe73660133ec135f370c9d278f99562105b887bd7a4d673 | [plugins/gcp-secretmanager](../../plugins/gcp-secretmanager) |
| kryptkeeper.vault-kv | first-party | 1.0.0 | PENDING-SIGN | receive_private_key; network: hosts_from_credential=base_url ports=443,8200; tls_verify | 5077056a78af2f8affe73660133ec135f370c9d278f99562105b887bd7a4d673 | [plugins/vault](../../plugins/vault) |

## Reference (not vouched)

Teaching material, excluded from the hash check.

| Plugin id | Why it is not listed above |
|---|---|
| kryptkeeper.example-device | Starting point for plugin authors ([`plugins/example`](../../plugins/example)); not a supported integration. |

## Add or update a row

1. Open a PR that changes the plugin and its `manifest.json` version.
2. Build and sign from a clean tree: `bash scripts/build-plugins.sh`, then
   `bash scripts/sign-plugins.sh` (needs the plugin key and `cosign`).
3. Put the signed module's sha256 in the row. `bash scripts/check-plugin-index.sh --print-rows`
   drafts a row (with `PENDING-SIGN`) from the source manifest.
4. A `verified` row needs the operator-trusted public key's id and a link to the
   evidence for trusting it in the PR. Do not add one without that.

## Verify locally

```bash
bash scripts/check-plugin-index.sh --self-test              # the checker itself, with a fixture
bash scripts/check-plugin-index.sh --dist dist/plugins      # rows vs signed artifacts
bash scripts/check-plugin-index.sh --dist dist/plugins --strict   # also fail on PENDING-SIGN
```

The script does not rebuild: Go stamps VCS state into each module, so a rebuild
can differ from the signed one. Point `--dist` at the release artifacts.

## No marketplace

This is a reviewed list, not a download service or marketplace. Installation is
still an operator action in the hub.
