# Distribution packaging (W10-12 / D-101 / FR-P63)

Install paths for a Kryptkeeper release, all produced by
`.github/workflows/release.yml` on a `v*` tag push:

| Format | Built by | Artifact |
|---|---|---|
| deb / rpm | `packaging/nfpm/` (nfpm) | `dist/*.deb`, `dist/*.rpm` on the GitHub Release |
| Homebrew | `packaging/homebrew/` | `kryptkeeper.rb` on the GitHub Release (arm64 only, no tap) |
| Windows agent | `.goreleaser.yaml` + `packaging/windows/` | `.zip` and `.msi` on the GitHub Release |
| Helm repo | `charts/kryptkeeper*` published two ways | see below |
| One-command installer | `packaging/install.sh` | run directly from this path in git, not a release asset |

Container-image signing (cosign, keyed vs. keyless) is covered separately in
[`SIGNING.md`](./SIGNING.md) — that's the other half of this ticket's
acceptance criteria (D-101).

## deb / rpm

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
`kryptkeeper_<version>_darwin_arm64.tar.gz`. (goreleaser's own `brews` pipe
is deprecated and runs after checksumming, so it cannot do this.)

**Apple Silicon only.** Releases build `darwin/arm64`; there is no
`darwin/amd64` binary, so the formula has `depends_on arch: :arm64` and
Intel Macs are unsupported.

Homebrew 7 refuses to install a formula file that is not in a tap, so create
a throwaway local tap:

```bash
TAG=v0.9.4   # set to the release you are installing
gh release download "$TAG" --repo bpmforge/kryptkeeper --pattern kryptkeeper.rb
brew tap-new local/kryptkeeper
cp kryptkeeper.rb "$(brew --repository local/kryptkeeper)/Formula/"
brew install local/kryptkeeper/kryptkeeper
brew test local/kryptkeeper/kryptkeeper     # runs `kryptkeeper --version`

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
curl -fsSL https://raw.githubusercontent.com/kryptkeeper/kryptkeeper/main/packaging/install.sh | bash
```

Downloads the Hub binary (or the agent, via `KRYPTKEEPER_COMPONENT=agent`)
for the host's OS/arch, verifies it against the release's `SHA256SUMS.txt`,
and installs it — **fails closed** on any checksum mismatch (nothing is
installed; see `install_test.go`'s
`TestInstallSh_FailsClosedOnChecksumMismatch`, which reproduces a tampered
checksum against the real script and asserts both the non-zero exit and
that no binary is left behind). Env var overrides are documented in the
script's header comment; `install_test.go` uses
`KRYPTKEEPER_INSTALL_BASE_URL` to point the script at a local `httptest`
fixture instead of GitHub, so the test suite needs no live network.

Linux and macOS (amd64/arm64) only — Windows installs are documented
separately in `docs/deployment.md`.

## Scope notes

- **Agent packaging.** `packaging/nfpm/` covers the Hub only. The agent is
  already self-contained via `kryptkeeper-agent --generate-systemd`
  (`docs/deployment.md`, "Satellite agent systemd unit") and doesn't need a
  package manager to install cleanly; adding a `.deb`/`.rpm` for it is a
  natural follow-up, not required by this ticket's acceptance criteria.
