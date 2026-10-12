# Certificate Delivery Plugins — Design

**Date:** 2026-10-08. **Status:** design accepted; not built. the owner accepted
every recommendation in the last section on 2026-10-08 ("accept all"), now
locked as D-113 to D-120 in `docs/DECISIONS.md`. **Replaces:** W19-11 (UAT of the built-in F5 and Citrix
pushers on real devices). **Ticket:** W20-18.

## The one-line version

Delivery to a device is the long tail of this product: every load balancer,
appliance, CDN and secret store wants its own API. Today each one is a Go
file in `internal/agentinstall` plus a `case` in the renewal executor, and
F5 and Citrix have never touched a real device. This design lets the
community ship a delivery target as a **plugin** without forking the hub. It
also makes what each plugin can do (receive the private key, reach a
network host, run commands, change a trust store) **visible and approved
before it runs**.

## What exists today (built reality)

### The pusher contract

Every delivery path takes the same input and returns the same result.

- **Input:** `PushRequest{Name, CertPEM, KeyPEM, VerifyHostPort,
  ExpectedFingerprint}` (`internal/agentinstall/f5.go:51`).
- **Output:** `InstallResult{Installed, Reloaded, Verified, RolledBack,
  ServedFingerprint, Outcome, Detail}` (`internal/agentinstall/installer.go:85`).
- **Outcome vocabulary:** `installed_verified`, `installed`,
  `config_test_failed`, `reload_failed`, `verify_failed`, `write_failed`
  (`installer.go:96`), plus `cert_import_failed`, `binding_failed` (`iis.go:68`)
  and `trust_failed` (`keychain.go:48`). The hub already records these on
  the renewal result and the target.

### How they touch the world

The pushers reach the outside world through exactly three seams. These
seams are the capability surface this design brokers.

| Seam | Used by | Where |
|---|---|---|
| An injected `*http.Client` (management-plane HTTPS, custom TLS trust) | F5, Citrix, Kubernetes | `f5.go:35`, `citrix.go:38`, `k8s.go` |
| `Verifier` (TLS-dial the service and read the served leaf) | all | `verify.go:21` |
| `Executor{Exists, ReadFile, WriteFile, Run}` (files and commands on a host) | nginx/apache/haproxy (SSH or local sudo), IIS (WinRM), macOS Keychain (SSH + sudo) | `installer.go:50` |

### Dispatch and credentials

- **Dispatch:** `install_mode` is a database CHECK enum on `managed_targets`
  (`managed_target_store.go:171`: agent, ssh, f5, citrix, k8s, iis, keychain,
  cloud, acme) and a `switch` in `pushMaterialToTarget`
  (`renewal_executor.go:658`, `case "f5":` at 678).
- **Credentials:** `resolvePushCredential` picks the credential type by
  install mode (`api_token`, or `windows_password` for IIS). It decrypts the
  target's one referenced credential and unmarshals one shared
  `pushCredentialPayload` (`renewal_executor.go:523`), which carries
  per-vendor fields side by side (`client_ssl_profile` for F5, `certkey_name`
  for Citrix, `namespace` for k8s, and so on). Adding a vendor today means
  editing this struct, the enum, the switch and a migration.

### Rules the pushers already follow, which plugins must keep

- **Verify after push**, against the expected SHA-256 of the new leaf.
- **Rollback honesty:** `RolledBack` is true only when the restore actually
  succeeded (`f5.go:151`). A false "rolled back" is worse than none.
- **Bounded device output:** device error bodies are cut to 300 bytes
  (`truncateBody`, `f5.go:89`) before they reach logs or the API.

### Not built, despite the docs

`docs/sdlc/phase-3-design/ARCHITECTURE.md` §3 describes a generic
`Registry[T]` in `pkg/registry/registry.go`, with "f5, citrix" as V2+
connectors that register themselves. **No such package exists.** That
section describes in-tree, compile-time extension. This document is about
something different: code that is not in this repository and was not
written by us. It should be corrected the way D-008 was, recording built
reality.

## Goals and non-goals

**Goals**

1. A third party can add a delivery target (e.g. A10, Fortinet, Akamai,
   Cloudflare, HashiCorp Vault, a custom appliance) without a hub release or
   a fork.
2. Before a plugin runs, an operator sees in plain language what it can do.
   An elevated capability needs an explicit, audited approval by someone
   other than the person who asked for it.
3. A plugin cannot quietly gain new capabilities on upgrade.
4. F5 and Citrix become the first two plugins, so the contract is proven on
   real code, not a toy.
5. The renewal loop is unchanged: renew once, push many, verify, roll back
   honestly. Results use the same outcome vocabulary.

**Non-goals (v1)**

- A public marketplace or remote registry. The repo is private until
  release, and an online registry is a supply-chain service of its own.
- Discovery plugins, issuer plugins, notification plugins. Same pattern
  later, if this one works.
- Device-side key generation. That is a different product change (D-115).

## The plugin contract

### Manifest

Every plugin ships `manifest.json` next to its module. The hub reads it
before loading anything else. It is JSON, so the hub needs no YAML parser.
Unknown fields, including unknown capability names, refuse the manifest.
Built in W20-19 as `abi.ParseManifest`.

```json
{
  "api_version": "kryptkeeper.delivery/v1",
  "id": "community.a10-thunder",
  "name": "A10 Thunder ADC",
  "version": "1.2.0",
  "publisher": "Jane Doe <jane@example.com>",
  "license": "Apache-2.0",
  "source": "https://example.com/kk-a10",
  "artifact": {"file": "a10-thunder.wasm", "sha256": "3f1c..."},
  "capabilities": {
    "receive_private_key": true,
    "network": {"hosts_from_credential": "base_url", "ports": [443]},
    "tls_verify": true
  },
  "credential_schema": {
    "base_url": {"type": "url", "required": true},
    "username": {"type": "string", "required": true},
    "password": {"type": "string", "required": true, "secret": true},
    "partition": {"type": "string", "default": "Common"}
  },
  "target_schema": {"virtual_server": {"type": "string", "required": true}}
}
```

- `artifact.sha256` is checked on every load.
- `network` without `ports` means 443 only.
- `file_write` lists absolute path prefixes; it also bounds the read and
  exists calls.
- `elevated_exec` and `trust_store` need `remote_exec`.

### Calls

The hub calls three operations. They use the same shapes as today, so the
renewal executor does not care whether a target is built-in or a plugin.

- `validate(credential, target_settings) -> ok | error`: called when a
  target is saved. It checks reachability and permissions without changing
  anything on the device ("test connection").
- `push(PushRequest) -> InstallResult`: upload, bind, and roll back on
  failure. The plugin may not set `Verified`; see the next point.
- **Verification is the hub's job, not the plugin's.** After `push`, the
  hub dials `VerifyHostPort` itself and compares fingerprints. If they
  differ, it calls `rollback(handle)` and records whether the rollback
  succeeded. A plugin can never mark its own work verified.

### Host functions (the brokered seams)

A plugin never gets a raw socket, a shell or the credential store. It gets
brokered versions of the three seams above, each one checked against the
declared capabilities.

| Host function | Brokers | Checked against |
|---|---|---|
| `http.do(method, url, headers, body)` | the injected `http.Client` | `network`: the URL host must be the credential's `base_url` host, or one listed in the manifest. TLS trust comes from the hub (system roots plus the target's CA bundle) and cannot be switched off by the plugin. |
| `exec.run`, `exec.write_file`, `exec.read_file`, `exec.exists` | `Executor` over SSH or WinRM | `remote_exec`, plus `elevated_exec` if any call uses sudo. File paths must fall under the manifest's `paths`. |
| `log(level, msg)` | hub logging | always allowed. Capped at 300 bytes per line and scanned so PEM blocks are refused (the key-boundary law). Rate limited. |

The credential is resolved by the hub. The plugin receives only the
decrypted fields its schema declared, for the one target being pushed.

## Capabilities and how they are flagged to users

### Taxonomy

Each capability has a tier and one plain sentence. The UI shows exactly
that sentence; manifests cannot supply their own wording.

| Capability | Tier | What the operator is told |
|---|---|---|
| `receive_private_key` | **Critical** | "This plugin receives the private key of every certificate it delivers." |
| `trust_store` | **Critical** | "This plugin can add certificate authorities to the trust store of the hosts it delivers to." |
| `elevated_exec` | **High** | "This plugin runs commands as an administrator (root/sudo or Windows administrator) on target hosts." |
| `remote_exec` | **High** | "This plugin runs commands on target hosts over SSH or WinRM." |
| `network` (beyond the credential's host) | **High** | "This plugin connects to hosts other than the device you configure: <list>." |
| `network` (credential host only) | High (SUP-A08-1: any network access is at least High) | "This plugin connects to the device address you configure, so it has network access." |
| `file_write` | Standard | "This plugin writes files on target hosts under: <paths>." |
| `tls_verify` | Standard | "This plugin checks which certificate the service presents." |

`receive_private_key` is Critical because of the repository's first law:
private keys never leave their boundary without someone deciding they
should. F5 and Citrix need it; a CDN that accepts a CSR would not.

### Where capabilities are surfaced

1. **Install** (Settings, then Delivery plugins, then Add): the manifest is
   shown before anything is stored. The display has four parts:
   - publisher, source, version and SHA-256;
   - the trust tier (first-party, verified or community; D-117);
   - every capability as its sentence, grouped by tier, with Critical items
     in red and High in amber;
   - whether each capability is **enforced** or only **declared** (next
     section).
2. **Enable:** a plugin is installed disabled. Enabling it is a separate
   action, and any High or Critical capability makes it a **pending action**
   in the existing approval queue. The proposer may not approve it
   (`handlers_pending_actions.go:36` already forbids self-approval). The
   approval records each capability that was granted.
3. **Targets:** every managed target using a plugin shows the plugin's
   badge and its highest tier on the targets list, the target detail and
   the renewal preview. So does every certificate delivered through it,
   with "Delivered by community.a10-thunder 1.2.0 (receives private key)".
4. **Upgrade:** a new version with the same or fewer capabilities replaces
   the old one after a normal confirmation. A new version that adds a
   capability, raises a tier, or widens network hosts or file paths goes
   back to pending approval. The old version keeps running until the new one
   is approved.
5. **Audit:** each of these writes an audit row naming the plugin, its
   version, its SHA-256 and the capability set:
   - install, enable, approve, upgrade, disable and remove;
   - every `push`, `validate` and `rollback`.

   A delivery can be traced back to the exact code and grants that did it.
6. **Kill switch:** `KRYPTKEEPER_DELIVERY_PLUGINS=off` disables all plugins
   at startup. A single plugin can be disabled from the UI or API at any
   time; in-flight pushes finish and no new ones start.

### Declared versus enforced: the honest table

Whether the hub can **enforce** a capability, or can only **show** it,
depends on the execution model (D-113). The UI must say which, per
capability. It must never imply a sandbox that does not exist.

| Capability | WASM with host functions | Subprocess (any language) | In-tree Go |
|---|---|---|---|
| `receive_private_key` | enforced (key is passed only if granted) | enforced at handover; afterwards the process can do anything with it | not applicable (reviewed code) |
| `network` host scoping | **enforced** (only `http.do`) | declared only (real network stack) | reviewed |
| `remote_exec` / `elevated_exec` | **enforced** (only `exec.*`, sudo checked) | declared only | reviewed |
| `file_write` paths | **enforced** | declared only | reviewed |
| `trust_store` | enforced when trust changes go through a dedicated host call | declared only | reviewed |
| Secrets in logs | enforced (host-side `log`) | partial (stdout/stderr capped and scanned) | reviewed |
| CPU/memory/time limits | enforced: a deadline closes the instance, and memory is capped at 128 MiB (wazero has no instruction metering, so CPU is bounded by time) | OS limits (timeout, rlimits) | none |

## Execution model options (D-113)

| | A. WASM (e.g. wazero, pure Go) | B. Subprocess over stdio (JSON-RPC, like Terraform providers) | C. In-tree Go only |
|---|---|---|---|
| Capabilities | enforced | declared, shown and audited, not enforced | code review |
| Plugin languages | TinyGo, Rust, AssemblyScript, Go (wasip1) | any | Go |
| Install without a hub release | yes | yes | no (needs a PR and a release) |
| Hub dependency | one new pure-Go module (approval-gated in this repo) | none new (or hashicorp/go-plugin) | none |
| Isolation | memory-safe sandbox in-process | OS process; same user as the hub | none |
| Cost to build | highest: host ABI, SDK, conformance kit | medium | lowest |

**Recommendation: A (WASM).** It is the only option where "this plugin
only talks to your F5" is a property the hub guarantees rather than a
promise in a YAML file, and that guarantee is the reason to flag
capabilities at all. B is a reasonable fallback if language reach matters
more than enforcement. C is not a community plugin system.

## The ABI (built, W20-19)

A plugin is a wasip1 reactor module. It exports `kk_alloc(size) -> ptr` and
`kk_invoke(op, in) -> result`, and imports one host function,
`kryptkeeper.kk_host(op, in) -> reply`. Every payload is JSON, typed in
`sdk/delivery-go/abi`, so the hub and the SDK share one definition.

- **Instances:** each operation runs in a fresh instance.
- **WASI:** no filesystem, environment or arguments.
- **Network:** wazero's preview1 has no sockets, so the only network is
  `http.do`. It allows only https, only granted hosts and ports, uses the
  hub's TLS trust, refuses redirects off the grant, and caps bodies at
  1 MiB.
- **Output:** stdout and stderr go through the same log path as `log` calls:
  300 bytes per line, PEM blocks withheld, secrets redacted.

| Piece | Where |
|---|---|
| Manifest and ABI types | `sdk/delivery-go/abi` (module `github.com/bpmforge/kryptkeeper/sdk/delivery-go`) |
| Go SDK for authors | `sdk/delivery-go/delivery` |
| Hub runtime: load, enforce, deliver, verify, roll back | `internal/plugins/delivery` |
| Reference plugin | `plugins/example` |
| Conformance kit | `tests/plugins/conformance` (`Suite` grades any plugin against a mock `Device`) |

## Where plugins run (D-114)

The hub, not the agent. F5, Citrix, Kubernetes, IIS and Keychain already
run from the hub, and the agent's privilege model is a narrow sudoers
allowlist (`cmd/kryptkeeper-agent/main.go:404`, `KK_INSTALL`). Running
third-party code under that allowlist would widen it invisibly. Agent-side
plugins can come later with their own allowlist entries.

## Migrating F5 and Citrix (D-118)

1. Freeze the plugin ABI and build a **conformance kit**. The kit is a mock
   device harness plus scripted failures: upload fails, bind fails, verify
   mismatch, rollback fails. Any plugin can be graded against it, and
   today's `f5_test.go` and `citrix_test.go` cases become kit cases.
2. Port F5 and Citrix to plugins as **first-party reference plugins**,
   signed with the release key. Both declare `receive_private_key`,
   `network` (credential host) and `tls_verify`.
3. Keep `install_mode: f5|citrix` working by mapping it to the reference
   plugins, so existing targets need no edit. Delete the built-in code once
   the plugins pass the kit and one real-device run.
4. **W19-11 becomes:**
   - both reference plugins pass the conformance kit (CI);
   - at least one is proven on a real device or trial VM, on the UAT lab
     (BIG-IP VE 30-day trial, NetScaler VPX Express), whenever that is
     available.

   Until then, the plugin card says "Not yet verified against a real
   device".

## Data model changes

- `managed_targets.install_mode` accepts `plugin`, and the target names
  its plugin in `plugin_id` (built, migration 000068; this is simpler than
  the `plugin:<id>` first sketched).
- A new `managed_targets.plugin_settings` JSON column for `target_schema`
  values. Secrets stay in the credential store.
- **New `delivery_plugins` table:** id, version, sha256, manifest JSON,
  trust tier, state (installed, pending, enabled or disabled), the approved
  capability set, approved_by and approved_at. The artifact bytes are stored
  under the data directory, keyed by SHA-256.
- **Credentials:** an `api_token` credential whose payload is a JSON object
  of the plugin's `credential_schema` fields (built in W20-20). A separate
  `plugin` type would have needed another table rebuild for no gain. The
  fields are checked against the schema at renewal, before any certificate
  is issued. This replaces the growing shared `pushCredentialPayload` for
  plugin targets. The hub reads the reserved field `tls_ca_pem` to trust a
  device's internal CA.

## Threats

| Threat | Mitigation |
|---|---|
| A malicious plugin exfiltrates private keys | Critical capability, explicit second-person approval, WASM network scoping (A), and an audit row for every key handover |
| Tampering with the artifact after approval | SHA-256 pinned at approval, checked on every load; optional signature (D-117) |
| A capability gained by upgrade | Upgrade diff; any widening goes back to approval |
| A plugin lies about success | The hub verifies; `Verified` can only come from the hub |
| A plugin leaks secrets through logs or Detail | Host-side cap and PEM scan; Detail is treated as untrusted data in UI and API |
| A plugin hangs or eats resources | Per-operation deadline that closes the instance, 128 MiB memory cap, fresh instance per operation |
| Cross-tenant use (when MULTI_TENANCY is on) | Plugins are installed globally; enabling one per tenant follows D-025 |

## Rough plan once decided

1. **Plugin ABI and manifest:** spec, Go SDK, conformance kit. No hub
   changes yet.
2. **Hub:** plugin store and API, the capability approval flow through
   pending actions, the host functions, `plugin:<id>` dispatch, audit.
3. **UI:** plugin list and install review, approval, badges on targets and
   certificates.
4. **F5 and Citrix** as reference plugins; `install_mode` mapping; delete
   the built-ins.
5. **Docs:** author guide, operator guide, and the "declared versus
   enforced" table in the operator docs.

## Decisions needed

Locked in `docs/DECISIONS.md` on 2026-10-08: every recommendation below was
accepted. D-117's open point is settled as a separate plugin-signing key.
Built in W20-24: cosign sign-blob over manifest.json; the compiled-in key
makes a plugin first-party, `KRYPTKEEPER_PLUGIN_TRUSTED_KEYS` makes it
verified, a signature that verifies against neither refuses the install, and
the tier never relaxes approval.

| ID | Decision | Options | Recommendation |
|---|---|---|---|
| D-113 | Execution model | A WASM; B subprocess; C in-tree only | A. Capabilities are enforced, not just labelled. Needs approval of one new dependency (for example wazero). |
| D-114 | Where plugins run | hub only; hub and agent | Hub only in v1 |
| D-115 | May plugins receive private keys? | yes, as a Critical capability with second-person approval; no (CSR or device-keygen targets only) | Yes, Critical. F5 and Citrix cannot work otherwise. |
| D-116 | Approval model | pki-admin enables alone; enabling High or Critical goes through the pending-action queue (proposer ≠ approver); every plugin needs approval | High or Critical through the queue; Standard-only plugins are enabled by a pki-admin directly |
| D-117 | Trust and distribution | local upload plus SHA-256 pin only; plus cosign signature (release key, or a separate plugin-signing key); tiers (first-party / verified / community); remote registry | Upload plus pin in v1, signatures verified when present, three tiers shown, no remote registry before the repo is public; a separate plugin-signing key |
| D-118 | Fate of the built-in F5 and Citrix pushers and W19-11 | keep built-in; port to reference plugins and delete; delete without porting | Port to reference plugins; W19-11 is rewritten as above |
| D-119 | Who owns credential shape | plugin-declared schema validated by the hub; reuse the fixed credential types only | Plugin-declared schema |
| D-120 | ABI versioning | `api_version` per manifest, hub supports current and previous; semver on the SDK | As stated; a breaking change gets a new `kryptkeeper.delivery/v2` |
