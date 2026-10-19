# Kryptkeeper apt and yum repository

Signed package repositories for the Kryptkeeper hub, served from
`https://pkg.kryptkeeper.io` (Cloudflare Pages project `kryptkeeper-pkg`).
Built by `.github/workflows/pkg-repo.yml` after each Release; the layout is
produced by `build-repo.sh`.

Repository signing key fingerprint: `PENDING-OWNER` (the key is created by
the owner, offline; see `../SIGNING.md`, "Package repository signing"). Compare it
with `gpg --show-keys --fingerprint kryptkeeper.asc` before trusting it.

## Install (Debian / Ubuntu)

```bash
sudo apt-get install -y curl gnupg ca-certificates
sudo mkdir -p /etc/apt/keyrings
sudo curl -fsSL https://pkg.kryptkeeper.io/kryptkeeper.gpg -o /etc/apt/keyrings/kryptkeeper.gpg
echo "deb [signed-by=/etc/apt/keyrings/kryptkeeper.gpg] https://pkg.kryptkeeper.io/apt stable main" \
  | sudo tee /etc/apt/sources.list.d/kryptkeeper.list
sudo apt-get update && sudo apt-get install -y kryptkeeper
```

## Install (RHEL / Rocky / Fedora)

```bash
sudo curl -fsSL https://pkg.kryptkeeper.io/kryptkeeper.repo -o /etc/yum.repos.d/kryptkeeper.repo
sudo dnf install -y kryptkeeper
```

The repo file sets `repo_gpgcheck=1` (repository metadata is verified against
`kryptkeeper.asc`). Individual `.rpm` files are not signed yet, so
`gpgcheck=0`; rpm signing is a tracked follow-up. Their integrity comes from
the signed metadata and, upstream, the cosign-signed `checksums.txt`.

After install, edit `/etc/kryptkeeper/env`, then `systemctl enable --now
kryptkeeper` (the package never starts the service).

## URL layout

```
apt/pool/main/k/kryptkeeper/*.deb
apt/dists/stable/main/binary-{amd64,arm64}/Packages{,.gz}
apt/dists/stable/{Release,Release.gpg,InRelease}
rpm/*.rpm   rpm/repodata/{repomd.xml,repomd.xml.asc,...}
kryptkeeper.asc  kryptkeeper.gpg  kryptkeeper.repo
```

## How publishing works

A Pages deploy replaces the whole site, so each workflow run rebuilds the
repository from the `.deb`/`.rpm` assets of every non-prerelease GitHub
release. Each release's `checksums.txt` is verified with keyless
`cosign verify-blob` (identity: that tag's `release.yml`) and every package is
matched against it before it is signed into the repo. Files over Pages' 25 MiB
limit fail the build loudly instead of deploying a broken repo. If a package
ever exceeds it, move the pool to R2 or another host.

## One-time setup (the owner)

1. Generate the signing key offline (command in `../SIGNING.md`).
2. GitHub repo secrets: `PKG_REPO_GPG_PRIVATE_KEY` (ASCII-armored),
   `PKG_REPO_GPG_PASSPHRASE`, `CLOUDFLARE_API_TOKEN` (Pages: Edit),
   `CLOUDFLARE_ACCOUNT_ID`.
3. Create the Pages project: `npx wrangler@4.144.0 pages project create
   kryptkeeper-pkg --production-branch main`.
4. Add the custom domain `pkg.kryptkeeper.io` to that project (dashboard:
   Workers & Pages > kryptkeeper-pkg > Custom domains).
5. Put the key fingerprint above and in the release notes.
6. Run the workflow once with `workflow_dispatch` for a published tag; its
   `verify` job (Debian 12 and Rocky 9) is the acceptance evidence.

Until these exist the workflow fails at its secrets check by design.

## Testing build-repo.sh

`build_repo_test.go` needs `apt-ftparchive`, `createrepo_c`, `gpg` (and
`rpmbuild` for the rpm half) and skips without them, as on macOS. In a Linux
container (Debian 12: `apt-get install apt-utils gnupg createrepo-c rpm`):

```bash
GOOS=linux GOARCH=$(go env GOARCH) go test -c -o repo.test ./packaging/repo/
podman run --rm -v "$PWD:/w:ro" -w /w/packaging/repo debian:12 /w/repo.test -test.v
```
