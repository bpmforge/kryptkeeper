# Delivery plugins: operator runbook (W20-20)

A delivery plugin pushes renewed certificates to a device Kryptkeeper has no
built-in support for. Design: [`docs/design/DELIVERY_PLUGINS.md`](../design/DELIVERY_PLUGINS.md).
Writing one: [`docs/plugins/README.md`](../plugins/README.md).

Plugins are on whenever the hub has a database.
`KRYPTKEEPER_DELIVERY_PLUGINS=off` is the kill switch:
- no plugin loads;
- the API answers 503;
- plugin targets fail with a plain reason.

## 1. Install

Install as a pki-admin. Send the manifest object and the module as base64:

```bash
curl -X POST "$HUB/api/v1/delivery-plugins" -H "Authorization: Bearer $ADMIN" \
  -H 'Content-Type: application/json' \
  -d "{\"manifest\": $(cat manifest.json), \"wasm_base64\": \"$(base64 < plugin.wasm)\"}"
```

The hub refuses the install in any of these cases:
- a module that doesn't match `artifact.sha256`;
- a module that doesn't compile;
- an unknown manifest field or capability;
- a version that is already installed.

A newly installed plugin is disabled. Its trust tier comes from its
signature (W20-24):

| Signed with | Trust tier |
|---|---|
| the Kryptkeeper plugin key compiled into the hub | `first-party` |
| a key in the file named by `KRYPTKEEPER_PLUGIN_TRUSTED_KEYS` | `verified` |
| nothing | `community` |

A signature that verifies against neither is refused (400), never quietly
treated as community. The tier is a label: it does not change who must
approve enabling the plugin, which follows its capabilities.

To trust a publisher, put their cosign public key(s) (PEM, `-----BEGIN PUBLIC
KEY-----`, ECDSA P-256) in one file, set `KRYPTKEEPER_PLUGIN_TRUSTED_KEYS` to
its path and restart. Lines outside PEM blocks are ignored, so the file can
name each key. A set path that is missing, empty or unparseable stops the hub
at startup. The startup log reports how many first-party and trusted keys
loaded. Removing a key later does not relabel versions already installed;
each version keeps its signature and `signer_key_id` (sha256 of the key) for
review.

To install a signed plugin, include its `.bundle` (or `.sig`) in the install
dialog's Signature field, or send `manifest_base64` (the file's exact bytes)
and `signature` to the API. A signed install must send the exact bytes,
because re-encoding the JSON would change what was signed:

```bash
# The body is built in a pipe: a base64 module is too long for a shell argument.
jq -n --rawfile m <(base64 < manifest.json | tr -d '\n') \
      --rawfile w <(base64 < plugin.wasm | tr -d '\n') \
      --rawfile s manifest.json.bundle \
      '{manifest_base64: $m, wasm_base64: $w, signature: $s}' |
  curl -sf -X POST "$HUB/api/v1/delivery-plugins" -H "Authorization: Bearer $TOKEN" \
    -H 'Content-Type: application/json' --data @-
```

## 2. Enable

```bash
curl -X POST "$HUB/api/v1/delivery-plugins/<id>/versions/<version>/enable" -H "Authorization: Bearer $ADMIN"
```

| The version's capabilities | What happens |
|---|---|
| Standard only | Enabled at once (200). |
| Within the currently enabled version's | Enabled at once (200). |
| High or Critical (receives keys, runs commands, any network access) | 202. A `delivery_plugin.enable` action waits in Approvals. |

A pending enable must be approved by a different pki-admin. The requester
cannot approve it, and an operator's approval is refused. Until then, the
previously enabled version keeps running.

`POST /api/v1/delivery-plugins/<id>/disable` stops a plugin. `DELETE` removes
a disabled plugin and all of its versions.

Network access is always at least High, including a manifest that only names
the device host through a credential field (`hosts_from_credential`): that
value is operator-editable configuration, so such a plugin also waits for a
second approver.

### Elevated commands

A plugin with `remote_exec` but not `elevated_exec` can only run concrete
programs with an argv. The host refuses privilege-escalation programs (`sudo`,
`doas`, `su`, `pkexec`, `runuser`, `setpriv`, `chroot`, `nsenter`, by basename,
including via a path), shells and interpreters run with an inline command
(`sh -c`, `bash -lc`, `python3 -c`, `perl -e`, `ruby -e`, `node -e`, `cmd /c`,
`powershell -Command`), and wrappers that launch either (`env sudo`, `busybox
sh -c`). A plugin that needs a shell must declare `elevated_exec`, which shows
as a High capability the approver reviews. Plugins that used `sh -c` before
this change need `elevated_exec` in their manifest (or an argv rewrite).

## 3. Credential and target

The credential is type `api_token`, and its payload is a JSON object of the
plugin's `credential_schema` fields:

```json
{"name": "edge-lb", "credential_type": "api_token",
 "payload": {"base_url": "https://lb.example.com", "token": "...", "tls_ca_pem": "-----BEGIN CERTIFICATE-----..."}}
```

- Only the fields the schema names are handed to the plugin.
- Required fields must be present. Missing fields refuse the renewal before
  a certificate is issued.
- `tls_ca_pem` is read by the hub, not the plugin. It adds the device's
  internal CA to this target's HTTPS trust, and the plugin cannot change
  trust itself.

The target uses `install_mode` `plugin`, plus `plugin_id` and
`plugin_settings` (the plugin's `target_schema` values, which must not be
secrets):

```json
{"name": "edge-vip", "host": "vip.example.com", "install_mode": "plugin",
 "credential_ref": "<credential id>", "plugin_id": "community.a10-thunder",
 "plugin_settings": {"virtual_server": "vs-443"}}
```

## 4. What renewals do

1. **Issue:** the hub issues the successor certificate.
2. **Deliver:** it runs the enabled plugin version in its sandbox:
   - HTTPS only to the granted hosts and ports;
   - the private key only with `receive_private_key`;
   - a deadline.
3. **Verify:** the hub itself dials `verify_host_port` (default `host:443`)
   and compares fingerprints.
   A secret-store plugin has nothing to dial, so its manifest declares
   `"verification": "readback"` (default and `"tls"` mean the dial; any other
   value refuses the manifest). The hub then calls the plugin's `verify` op
   (`abi.VerifyRequest{name, handle}`, handle = the push's `rollback_handle`,
   so the plugin reads the exact version it wrote), parses the returned PEM
   and compares the leaf SHA-256 itself. The plugin only fetches; a
   mismatch, parse failure or op error is `verify_failed` and rolls back like
   a TLS mismatch. An explicit `verify_host_port` on the target profile
   always forces the TLS dial. Plugins implement `delivery.Verifier`.
   CDN-style targets take minutes to serve a new certificate, so a manifest
   may declare `"verify_propagation_seconds": N` (0..1800, default 0; anything
   else refuses the manifest). Both verify paths make the 6 quick attempts,
   then poll every 15 s until the fingerprint matches or N seconds pass or the
   context ends. The comparison is unchanged; on expiry the usual
   `verify_failed` + rollback runs. Shipped: `aws` 1200, `azure` 1200,
   `cloudflare` 600. The `delivery_plugin.push` audit detail records
   `verify_window=Ns`.
4. **Roll back on a mismatch:** the hub asks the plugin to roll back.
   `rolled_back` is reported true only if the plugin confirms it.

## First-party plugins: F5 and Citrix (W20-22)

The full list of first-party plugins (F5, Citrix, Vault, Azure Key Vault, GCP Secret Manager, AWS ACM/ALB/CloudFront, AWS Secrets Manager, Azure Application Gateway/Front Door, Cloudflare), with capabilities, verification mode and the submission checklist, is in [PLUGIN_CATALOGUE.md](PLUGIN_CATALOGUE.md). For syncing a delivered Kubernetes Secret into workload namespaces with External Secrets Operator, see [EXTERNAL_SECRETS.md](EXTERNAL_SECRETS.md).

`plugins/f5` (`kryptkeeper.f5-bigip`) and `plugins/citrix`
(`kryptkeeper.citrix-adc`) are the built-in F5 and Citrix pushers, ported
onto the plugin ABI. They pass the same conformance kit as any plugin.

- **F5:** installs cert and key objects under a name unique to each
  certificate, then re-points the client-ssl profile. Rollback re-points it
  at the previous objects.
- **Citrix:** uploads files under unique names, then re-points the
  cert-key pair. Rollback re-points it at the previous files. The built-in
  Citrix pusher overwrote files in place and could not roll back at all.

`make plugins` builds both into `dist/plugins/<name>/` with the manifest
pinned. Install them like any plugin. They show as trust tier `community`
until the Kryptkeeper plugin key exists and they are signed with it (see
packaging/SIGNING.md).

**Not yet verified against a real device**, and the plugin names say so.
`install_mode` `f5` and `citrix` still use the built-in pushers. D-118 moves
those modes to the plugins, and deletes the built-ins, only after one
real-device run: a BIG-IP VE trial or NetScaler VPX Express on the hypervisor
lab.

## Not supported yet

Plugins that need `remote_exec` (SSH or WinRM commands) can be installed,
but targets using them fail with "plugin targets do not support remote_exec
yet".

## Audit

Every step is recorded:

| Action | Recorded |
|---|---|
| `delivery_plugin.install`, `.enable_requested`, `.enable`, `.disable`, `.remove` | With version, sha256 and tiers. |
| `action.approve` | The second admin's decision. |
| `delivery_plugin.push` | Per renewal: target, version, sha256, verification (`tls` or `readback`), verify window, outcome, verified, rolled back, refused-call count. |
| `delivery_plugin.refused` | Per host call the sandbox refused. |

The plugin's own log lines go to the hub log, capped and with secrets
redacted.

## Live evidence (2026-10-08)

`tests/live/plugins/run.sh` on the Mac: **20 PASS, 0 FAIL**. It runs the real
hub binary, the example plugin built from source, and a mock appliance with
its own CA.

| Step | Result |
|---|---|
| Install | 201, capability tier critical, trust tier community |
| Enable | 202 pending approval |
| Self-approval | 403 |
| Second admin approves | 200; `enabled_version` set |
| Credential (with the device CA) and plugin target | Created |
| Renew a certificate through the plugin | `installed_verified`, and the device's service port serves the new fingerprint |
| Audit | install, enable_requested, approve, push all present |
| Secrets | The device token appears in neither the hub log nor the audit |
| Kill switch (`KRYPTKEEPER_DELIVERY_PLUGINS=off`) | API 503; renewal refused |
