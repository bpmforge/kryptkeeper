# Distribution packaging (W10-12 / D-101 / FR-P63)

Four install paths for a Kryptkeeper release, all produced by
`.github/workflows/release.yml` on a `v*` tag push:

| Format | Built by | Artifact |
|---|---|---|
| deb / rpm | `packaging/nfpm/` (nfpm) | `dist/*.deb`, `dist/*.rpm` on the GitHub Release |
| Homebrew | `packaging/homebrew/` | `kryptkeeper.rb` on the GitHub Release |
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

`packaging/homebrew/kryptkeeper.rb.tmpl` is a template; `render-formula.sh`
fills in the version, download URLs, and per-arch SHA256 from the two
`darwin` release binaries. The `homebrew-formula` job in `release.yml` runs
it and uploads `kryptkeeper.rb` as a release asset.

**Unreachable from this ticket: actually publishing to a tap.** A Homebrew
formula only becomes `brew install kryptkeeper`-able from a tap repository
(`kryptkeeper/homebrew-kryptkeeper` or similar) or `homebrew-core` — both are
separate repositories this environment has no credentials for and this
ticket's `write_scope` cannot create. What ships here is the correctly
-rendered formula file as a release artifact; wiring a push into a tap repo
is a follow-up that needs a `HOMEBREW_TAP_TOKEN`-equivalent secret and a
target repo, named here rather than silently assumed done.

Test a rendered formula locally:

```bash
brew install --build-from-source ./kryptkeeper.rb
brew test kryptkeeper
```

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
- **`ldflags` version injection is a pre-existing no-op.** `release.yml`
  builds with `-ldflags="-X main.version=..."`, but `cmd/kryptkeeper/main.go`
  has no `var version string` for that flag to target — it's silently
  discarded. Out of this ticket's `write_scope` (`cmd/` isn't in it); noted
  here because it means neither the Homebrew formula's `test do` block nor
  any packaged binary can assert a `--version` output — there isn't one.
  The formula's test block checks existence/executability only, which is
  what's actually true of the binary.
