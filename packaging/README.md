# Distribution packaging (W10-12 / D-101 / FR-P63)

Install paths for a Kryptkeeper release, all produced by
`.github/workflows/release.yml` on a `v*` tag push:

| Format | Built by | Artifact |
|---|---|---|
| deb / rpm | `packaging/nfpm/` (nfpm) | `dist/*.deb`, `dist/*.rpm` on the GitHub Release |
| Homebrew | `packaging/homebrew/` | signed `kryptkeeper.rb` formula on the GitHub Release (arm64 + amd64, no tap) |
| Windows agent | `.goreleaser.yaml` + `packaging/windows/` | `.zip` and `.msi` on the GitHub Release |
| Helm repo | `charts/kryptkeeper*` published two ways | see below |
| One-command installer | `packaging/install.sh` | `install.sh` release asset, listed in the cosign-signed `checksums.txt` |

Container-image signing (cosign, keyed vs. keyless) is covered separately in
[`SIGNING.md`](./SIGNING.md) — that's the other half of this ticket's
acceptance criteria (D-101).

## deb / rpm

apt/yum repo at https://pkg.kryptkeeper.io: see packaging/repo/README.md

`packaging/nfpm/nfpm.yaml` packages the **Hub** binary only (not the agent —
see "Scope" below). Built in CI by the `package-linux` job in
`release.yml`, one run per `linux/{amd64,arm64}`, using
[nfpm](https://nfpm.goreleaser.com) (`go install
github.com/goreleaser/nfpm/v2/cmd/nfpm@v2.41.0`, pinned per this repo's
convention of pinning CI tool versions).

To build locally:

```bash
go install github.com/goreleaser/nfpm/v2/cmd/nfpm@v2.41.0
GOOS=linux GOARCH=amd64 go build -o /tmp/kryptkeeper-linux-amd64 ./cmd/kryptkeeper/
NFPM_ARCH=amd64 NFPM_VERSION=1.2.3 NFPM_HUB_BINARY=/tmp/kryptkeeper-linux-amd64 \
  "$(go env GOPATH)/bin/nfpm" package --config packaging/nfpm/nfpm.yaml --packager deb --target /tmp/
```

(`NFPM_VERSION` must not have a leading `v` — nfpm's version field isn't a Go
module tag. `release.yml` strips it via `${GITHUB_REF_NAME#v}`.)

The package installs `/usr/bin/kryptkeeper`, a systemd unit
(`packaging/nfpm/systemd/kryptkeeper.service`), and
`/etc/kryptkeeper/env.example`. `postinstall.sh` creates the `kryptkeeper`
system user/group, seeds `/etc/kryptkeeper/env` from the example **only on
first install** (never overwrites an operator's edits), and does not
auto-start the service — matches `docs/deployment.md`'s existing bare-metal
procedure (configure `APP_BOOTSTRAP_TOKEN` /
`KRYPTKEEPER_KEYSTORE_PASSPHRASE` first, then `systemctl enable --now`).
`preremove.sh` stops/disables the service but never deletes
`/var/lib/kryptkeeper` or `/etc/kryptkeeper` — removal isn't destruction.

Verified locally end-to-end (both `.deb` and `.rpm` built and their
`data.tar`/control scripts inspected — see the ticket's commit history for
the exact commands) since neither `nfpm` nor a target distro is part of this
repo's own gate.

## Homebrew

There is no tap repository. Each release attaches a ready-to-install
`kryptkeeper.rb` formula (plus `kryptkeeper.rb.sig` / `kryptkeeper.rb.pem`,
a keyless cosign signature) to the GitHub Release. The `homebrew-formula` job
in `release.yml` produces it after goreleaser finishes: it downloads and
cosign-verifies the release's `checksums.txt`, and
`packaging/homebrew/render-formula.sh` fills
`packaging/homebrew/kryptkeeper.rb.tmpl` with the signed sha256 of
`kryptkeeper_<version>_darwin_arm64.tar.gz` and `..._darwin_amd64.tar.gz`. (goreleaser's own `brews` pipe
is deprecated and runs after checksumming, so it cannot do this.)

**Apple Silicon and Intel.** Releases build `darwin/arm64` and `darwin/amd64`;
the formula selects the matching archive and sha256 with `on_arm` / `on_intel`.

Verify the formula before installing it. It is signed on its own (keyless
cosign), and its archive sha256 values come from the signed `checksums.txt`:

```bash
TAG=v0.9.4   # set to the release you are installing
gh release download "$TAG" --repo bpmforge/kryptkeeper \
  --pattern kryptkeeper.rb --pattern kryptkeeper.rb.sig --pattern kryptkeeper.rb.pem
cosign verify-blob \
  --certificate kryptkeeper.rb.pem --signature kryptkeeper.rb.sig \
  --certificate-identity-regexp '^https://github\.com/bpmforge/kryptkeeper/\.github/workflows/release\.yml@refs/tags/v' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  kryptkeeper.rb
brew install --formula ./kryptkeeper.rb
brew test kryptkeeper     # runs `kryptkeeper --version`
```

If your Homebrew refuses a formula file outside a tap, install it from a
throwaway local tap instead:

```bash
brew tap-new local/kryptkeeper
cp kryptkeeper.rb "$(brew --repository local/kryptkeeper)/Formula/"
brew install local/kryptkeeper/kryptkeeper

# remove
brew uninstall kryptkeeper && brew untap local/kryptkeeper
```

The formula installs only the hub binary (`kryptkeeper`); the agent has its
own archive.

## Windows agent (zip + MSI)

Each release ships the Windows agent two ways, both built by goreleaser
(build `kryptkeeper-agent-windows`, `windows/amd64` only) and both listed in
the cosign-signed `checksums.txt`:

- `kryptkeeper-agent_<version>_windows_amd64.zip` -- `kryptkeeper-agent.exe`
  plus LICENSE/README/CHANGELOG.
- `kryptkeeper-agent_<version>_windows_amd64.msi` -- per-machine installer
  that registers the auto-start `KryptkeeperAgent` service, installs to
  `C:\Program Files\Kryptkeeper Agent`, and drops `agent.env.example` there.
  Built from `packaging/windows/kryptkeeper-agent.wxs` by `wixl` (msitools),
  run from a post-build hook in `.goreleaser.yaml`, so the MSI embeds the exact
  exe in the zip. Its ProductVersion is the tag's `MAJOR.MINOR.PATCH`
  (MSI versions are numeric; an `-rc.N` tag maps to its base version).

```powershell
# elevated PowerShell; silent install, silent uninstall
msiexec /i kryptkeeper-agent_0.9.4_windows_amd64.msi /qn
msiexec /x kryptkeeper-agent_0.9.4_windows_amd64.msi /qn
```

The service does **not** start on first install: it needs
`%ProgramData%\Kryptkeeper\agent.env` first. Copy `agent.env.example` there,
set `KRYPTKEEPER_HUB_URL` and `KRYPTKEEPER_AGENT_ENROLLMENT_SECRET`, restrict
the file's ACL to SYSTEM and Administrators, then `Start-Service
KryptkeeperAgent` (it auto-starts after reboots from then on). Full runbook:
`docs/ops/WINDOWS_AGENT.md`. The MSI is not Authenticode-signed (SmartScreen
warns); the cosign signature on `checksums.txt` is the integrity check.

Local build: `make agent-windows-msi` (single exe) or `make release-snapshot`
(the whole release set into `dist/`; needs goreleaser v2, syft and wixl).

## Helm repo

Two publish paths, both wired into the `helm-publish` job:

1. **Classic index.yaml repo via GitHub Pages** (`helm/chart-releaser-action`,
   targeting this repo's own `charts/` dir and `gh-pages` branch) — this is
   the shape `docs/deployment.md` already documents (`helm repo add
   kryptkeeper https://...`). **Requires a one-time manual step no workflow
   can perform**: a repo admin must enable GitHub Pages (Settings → Pages →
   Source: `gh-pages` branch) before this path serves anything. Until that's
   done, `chart-releaser-action` still runs (it pushes packaged charts +
   `index.yaml` to the `gh-pages` branch) but nothing is reachable at a URL.
   **Known drift**: the actual published URL will be
   `https://kryptkeeper.github.io/kryptkeeper/` (this repo's own Pages,
   `<org>.github.io/<repo>`) — `docs/deployment.md` currently says
   `https://kryptkeeper.github.io/helm-charts` (a separate `helm-charts`
   repo that does not exist and that this ticket cannot create). Fixing that
   line is a docs-only follow-up outside this ticket's `write_scope`
   (`docs/deployment.md` is not in it); flagging here rather than leaving it
   to be rediscovered as a broken link.
2. **OCI repo on GHCR** (`helm push ... oci://ghcr.io/bpmforge/charts`) —
   works immediately from CI alone, no manual toggle, using the
   already-granted `packages: write` permission. Install with:

   ```bash
   helm install kryptkeeper oci://ghcr.io/bpmforge/charts/kryptkeeper --version 0.9.0
   ```

Both `charts/kryptkeeper` and `charts/kryptkeeper-certmanager-issuer` are
published by both paths (chart-releaser walks the whole `charts_dir`; the
OCI loop packages every chart under `charts/*/`).

## One-command installer

```bash
curl -fsSL https://github.com/bpmforge/kryptkeeper/releases/latest/download/install.sh | bash
```

`install.sh` is a release asset. Its sha256 is a line of the cosign-signed
`checksums.txt`, so the signed `checksums.txt` is its signature (no separate
`install.sh.sig`). To check it before running:

```bash
TAG=v0.9.4
gh release download "$TAG" --repo bpmforge/kryptkeeper \
  --pattern install.sh --pattern checksums.txt --pattern checksums.txt.sig --pattern checksums.txt.pem
cosign verify-blob \
  --certificate checksums.txt.pem --signature checksums.txt.sig \
  --certificate-identity-regexp '^https://github\.com/bpmforge/kryptkeeper/\.github/workflows/release\.yml@refs/tags/v' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  checksums.txt
grep '  install.sh$' checksums.txt | sha256sum -c -     # shasum -a 256 -c - on macOS
```

The script downloads the Hub archive (or the agent, via
`KRYPTKEEPER_COMPONENT=agent`) for the host's OS/arch plus `checksums.txt`,
`.sig` and `.pem`, then verifies in order: the cosign signature of
`checksums.txt` against the release workflow identity, then the archive's
sha256 against its line in that file. It **fails closed**: a cosign failure, a
missing cosign (unless `KRYPTKEEPER_INSTALL_SKIP_COSIGN=1`, which prints a
WARNING and leaves only the unauthenticated checksum), a missing checksum
entry or a checksum mismatch installs nothing (see `install_test.go`). Env var
overrides are documented in the script's header comment; `install_test.go`
uses `KRYPTKEEPER_INSTALL_BASE_URL` and a fake cosign
(`KRYPTKEEPER_INSTALL_COSIGN`), so the suite needs no live network.

Linux and macOS (amd64/arm64) only; Windows installs are documented
separately in `docs/deployment.md`.

## Upgrading the agent

There is no agent self-update: FR-063 is descoped from v1.0 (D-128). Upgrade
the agent the way it was installed, one canary first.

**Preflight (every path).** Note the running version with
`kryptkeeper-agent --version` and on the Hub's Agents page. Download the new
release, verify the cosign signature on `checksums.txt`, then check the
artifact's SHA-256 against it.

### Linux binary (systemd)

The agent is a single binary at `/usr/local/bin/kryptkeeper-agent` with a unit
from `kryptkeeper-agent --generate-systemd`; there is no agent deb/rpm yet.

```bash
sudo systemctl stop kryptkeeper-agent
sudo cp /usr/local/bin/kryptkeeper-agent /usr/local/bin/kryptkeeper-agent.prev
sudo install -m 0755 kryptkeeper-agent /usr/local/bin/kryptkeeper-agent
sudo systemctl start kryptkeeper-agent
kryptkeeper-agent --version
```

**Rollback:** `sudo systemctl stop kryptkeeper-agent`, then
`sudo mv /usr/local/bin/kryptkeeper-agent.prev /usr/local/bin/kryptkeeper-agent`,
then `sudo systemctl start kryptkeeper-agent`.

### Windows MSI

The MSI has `MajorUpgrade` on, so a newer MSI upgrades in place; it refuses a
downgrade. The service configuration in `%ProgramData%\Kryptkeeper\agent.env`
is not part of the MSI and is kept.

```powershell
msiexec /i kryptkeeper-agent_<new>_windows_amd64.msi /qn
```

The MSI stops the `KryptkeeperAgent` service for the upgrade; if it reports
files in use, run `Stop-Service KryptkeeperAgent` first and retry.

**Rollback:** `msiexec /x kryptkeeper-agent_<new>_windows_amd64.msi /qn`, then
`msiexec /i kryptkeeper-agent_<old>_windows_amd64.msi /qn`, then
`Start-Service KryptkeeperAgent`.

### macOS (launchd)

The agent runs from `packaging/macos/com.kryptkeeper.agent.plist`. Replace the
binary the plist points at the same way as on Linux (keep a `.prev` copy) and
reload the job as described in [MACOS_AGENT.md](../docs/ops/MACOS_AGENT.md).

**Rollback:** restore the `.prev` binary and reload the job.

### Container (`Dockerfile.agent`)

The container agent does discovery and reporting only (no autopilot install).
Pull the new tag and recreate the container with the same environment, pinning
the tag explicitly (never `latest`).

**Rollback:** recreate the container with the previous tag.

### Fleets

Roll out with your config management in batches, canary first. Air-gapped
hubs serve the release from a local package mirror. The Hub shows the new
agent version after the agent's next heartbeat or re-enrolment; a batch is
done when every agent in it reports the new version.

## Scope notes

- **Agent packaging.** `packaging/nfpm/` covers the Hub only. The agent is
  already self-contained via `kryptkeeper-agent --generate-systemd`
  (`docs/deployment.md`, "Satellite agent systemd unit") and doesn't need a
  package manager to install cleanly; adding a `.deb`/`.rpm` for it is a
  natural follow-up, not required by this ticket's acceptance criteria.

## Public release pipeline

`packaging/public/github-release.yml` is the release workflow of the public
repository (`bpmforge/kryptkeeper`). The public snapshot installs it as
`.github/workflows/release.yml`. It builds with goreleaser, signs keyless with
the workflow's GitHub OIDC identity, publishes images and the Helm chart
(`oci://ghcr.io/bpmforge/charts/kryptkeeper`, W37-01) to ghcr, and then
verifies everything it published from a clean job (D-312). This repository's
own `.github/workflows/release.yml` is the internal the self-hosted forge pipeline (D-210).
