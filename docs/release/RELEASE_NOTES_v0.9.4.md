# Kryptkeeper v0.9.4

This release packages the agent for Windows and macOS. It also fixes the
agent and ACME problems that live validation of v0.9.3 found. The Windows
agent and the macOS install (Homebrew formula and LaunchDaemon) were
validated live on the release candidate assets before release.

## Packaging

- **Windows agent zip and MSI.** Each release now includes
  `kryptkeeper-agent_<version>_windows_amd64.zip` and a `.msi`. The MSI
  installs per machine and registers the `KryptkeeperAgent` service. Both
  files are listed in the signed `checksums.txt`. The MSI is not
  Authenticode-signed, so SmartScreen warns. Runbook:
  `docs/ops/WINDOWS_AGENT.md`.
- **Homebrew formula.** Each release includes `kryptkeeper.rb`, with its own
  keyless cosign signature (`.sig` / `.pem`). The formula is generated from
  the signed checksums. It supports Apple Silicon only. There is no tap
  repository; `packaging/README.md` gives the local-tap install steps that
  Homebrew 7 requires.
- **macOS agent as a LaunchDaemon.** See
  `packaging/macos/com.kryptkeeper.agent.plist` and the runbook
  `docs/ops/MACOS_AGENT.md`.

## Agent fixes

- **Renewals run one at a time.** The agent used to re-dispatch a pending
  renewal on every poll, so a second ACME order competed with the first for
  port 80. A failing renewal now backs off from 1 minute to 1 hour, with
  jitter, and the agent reports the error to the hub.
- **Port 80 is checked before ordering.** The agent checks IPv4 and IPv6
  separately, so a listener on `0.0.0.0:80` is no longer missed on Windows.
  If the port is in use or not permitted, the agent says so instead of
  failing later with an unclear ACME error. The challenge server listens on
  both IPv4 and IPv6.
- **The Windows agent refuses install tasks up front.** It no longer tries
  `sudo`; it reports the error to the hub. Use agentless WinRM/IIS on Windows
  in v0.9.

## ACME fixes

- **dns-01 works where outbound port 53 is blocked.** The propagation check
  is now configurable per connector with `dns_propagation`: `auto`
  (default), `authoritative`, `resolver`, `doh` or `none`. `auto` keeps the
  authoritative check and falls back to DNS-over-HTTPS, then to the
  resolver, when no nameserver answers. See `docs/ops/ACME_UPSTREAM.md`.
- **`POST /api/v1/renewal/execute` always answers.** On a slow dns-01
  renewal it could return an empty reply. Its deadline now covers the
  longest propagation wait, and the response is always JSON.
- **Failed challenges say why.** The hub's ACME server now includes the
  reason in a failed http-01 or dns-01 challenge's `error`, for example the
  URL and status. Before, clients showed `authorization error for X:` with
  nothing after the colon.

## Upgrade notes

There are no database migrations and no breaking API changes. ACME
connector `config_json` gains the optional `dns_*` fields described above.
Existing ACME connectors use `dns_propagation: auto`. On networks where
port 53 works, `auto` behaves as before.

## Install and upgrade

Replace the binary or image with `0.9.4` and restart. Docker Compose: set the
image tag to `0.9.4` (or pull `0.9`), then run `docker compose up -d`.
Agents: install the new agent binary, zip or MSI, then restart the agent.

## Verify the release

`checksums.txt`, `kryptkeeper.rb` and the image manifests are signed
keyless with cosign through the release workflow's GitHub OIDC identity.

```bash
V=0.9.4
curl -fsSLO https://github.com/bpmforge/kryptkeeper/releases/download/v$V/checksums.txt
curl -fsSLO https://github.com/bpmforge/kryptkeeper/releases/download/v$V/checksums.txt.sig
curl -fsSLO https://github.com/bpmforge/kryptkeeper/releases/download/v$V/checksums.txt.pem

cosign verify-blob \
  --certificate-identity "https://github.com/bpmforge/kryptkeeper/.github/workflows/release.yml@refs/tags/v$V" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  --signature checksums.txt.sig --certificate checksums.txt.pem checksums.txt

sha256sum --ignore-missing -c checksums.txt   # after downloading an archive

cosign verify \
  --certificate-identity "https://github.com/bpmforge/kryptkeeper/.github/workflows/release.yml@refs/tags/v$V" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  ghcr.io/bpmforge/kryptkeeper:$V
```

Full list of changes: [CHANGELOG](https://github.com/bpmforge/kryptkeeper/blob/v0.9.4/CHANGELOG.md).
