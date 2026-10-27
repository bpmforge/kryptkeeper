# Kryptkeeper 1.1.1

A security patch for 1.1.0. It fixes three high-severity and eight medium-severity findings from
the v1.1 security review ([report](../security/V1.1_SCAN_2026-10-27.md)), all in code added in
1.1. It also completes the release pipeline: the Helm chart is signed and `latest` now points at
this version. Upgrade if you run 1.1.0. Nothing in the database changes.

## Security fixes

High:

- **C-02: outbound credentials could be sent to a caller-chosen URL.** Creating a connector did
  not check its `credential_ref`, so anyone who could manage discovery could bind a stored
  credential (Vault token, CA API keys, cloud keys, EST/WSTEP passwords) to a base URL of their
  choosing, and the hub would send it there on the next health check. Connectors now check the
  credential's tenant and type the way targets already did (D-330).
- **C-01: the hub's GCP token could be sent to a caller-chosen URL.** A `gcp_cas` connector using
  ambient auth accepted any `base_url` and sent the hub's metadata-server token to it. Ambient
  connectors are now pinned to the provider's own endpoints. Only hubs running on GCP were exposed.
- **B-01: root trust helper temp-file race.** On macOS and Linux the trust-store helper, which
  runs as root, staged each root at a predictable path in a world-writable directory and followed
  symlinks, so a local user could swap in their own root. Staging is now in a private directory
  with no symlink following.

Medium:

- **A-02, A-03, A-05: plugins.** The compiled-plugin cache is per plugin version, so a second
  plugin pinning the same module no longer inherits another's capability grant. An upgrade from
  a different signer needs a second approver even when its capabilities are not wider. Enabling a
  global plugin needs a super-admin under multi-tenancy.
- **B-02: trust bundles.** A newer bundle supersedes an older pending one, so a removed root can no
  longer come back.
- **B-04: trust helper state file.** Written without following symlinks.
- **B-05: agent transport.** The agent no longer follows redirects and requires an `https://` hub
  URL, except on loopback.
- **C-03: ambient cloud connectors** are super-admin only under multi-tenancy.

Low and info: plugin `http.do` redirects are limited to 3 hops and drop custom headers on a host
change (A-06). An Intune certificate withheld with no revoker configured is logged and audited
(C-07). The connector list scrubs upstream error text (C-11).

The remaining findings, including CyberArk CCP mTLS for multi-tenant hubs (A-01), are on the
[roadmap](../ROADMAP.md).

## Other changes

- **Helm chart:** signed with the release identity and checked by the release workflow. The 1.1.0
  chart was published unsigned.
- **`latest`** image tags move to 1.1.1. They stayed on 1.0.0 through 1.1.0.
- **Terraform provider:** built with Go 1.27.3 (was 1.26.2).
- **UI dev dependencies:** body-parser, fast-uri and zod bumped past open advisories. They are
  not shipped in the built UI.

## Upgrade notes

- **Agents need an `https://` hub URL.** An agent configured with `http://` to a non-loopback
  hub now refuses to start. Point it at the hub's HTTPS address.
- **Connectors are checked against their credential.** Creating a connector with a credential
  from another tenant, or of a type the connector cannot use, now fails with 400. Existing
  connectors are not changed.
- **Ambient AWS and GCP connectors** are super-admin only when multi-tenancy is on.
- **Plugin upgrades from a different signer** need a second admin to approve them.
- No migrations, no new settings.

## Verifying this release

The steps are the same as for 1.1.0 ([packaging/SIGNING.md](../../packaging/SIGNING.md)). The chart
now verifies too:

```bash
cosign verify \
  --certificate-identity "https://github.com/bpmforge/kryptkeeper/.github/workflows/release.yml@refs/tags/v1.1.1" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  ghcr.io/bpmforge/charts/kryptkeeper:1.1.1
```
