# Container image signing model (D-101)

> **Current state (W20-02, v0.9.0): the public release path is keyless again.**
> `release.yml` (driven by `.goreleaser.yaml`) signs `checksums.txt` and the
> image manifests keyless with cosign, using the workflow's GitHub OIDC
> identity. It uses no `COSIGN_KEY`, and there is no public key to distribute
> and no signing key pending. External consumers verify with
> `--certificate-identity-regexp` and
> `--certificate-oidc-issuer https://token.actions.githubusercontent.com`; see
> `docs/deployment.md`, "Install from a signed release".
>
> The keyed model below is **historical for the release path** and is still
> accurate only for the internal pipeline: `release-candidate.yml` signs with
> `COSIGN_KEY`, and `promote-by-digest.yml` / `rollback-by-digest.yml` verify
> with `cosign verify --key`. Those images are internal staging artifacts, not
> the published release. Statements below that `release.yml` signs keyed, or
> that external verification is impossible, no longer apply to tagged
> releases.

FR-P63 / D-101: `.github/workflows/release.yml` and `.github/workflows/release-candidate.yml`
used to sign the `ghcr.io/bpmforge/kryptkeeper` image two different ways —
`release.yml` signed **keyless** (Sigstore/Fulcio, via the workflow's GitHub
OIDC token), `release-candidate.yml` signed **keyed** (a static cosign key
pair held in `COSIGN_KEY`/`COSIGN_PASSWORD`). That inconsistency is resolved
here: **both workflows now sign keyed**, with the same key pair.

## Why keyed won, not keyless

The deciding constraint isn't a style preference, it's that `promote-by-digest.yml`
and `rollback-by-digest.yml` (both out of this ticket's `write_scope`) already
verify with:

```bash
cosign verify --key cosign.pub "$IMAGE_DIGEST"
```

`--key` verification only works against a keyed signature. A Sigstore keyless
signature (Fulcio-issued cert + Rekor transparency-log entry, no static key)
cannot be verified with `cosign verify --key` — the deploy pipeline would
have to switch to `--certificate-identity`/`--certificate-oidc-issuer`
verification instead, and those two files cannot be touched from this
ticket's `write_scope`. Making `release.yml` keyed (matching what the
deploy pipeline already assumes) is the only reconciliation reachable from
here without breaking promotion/rollback. If a future ticket wants to move
the whole pipeline to keyless, it must touch `promote-by-digest.yml` and
`rollback-by-digest.yml` in the same change — signing model and verification
model are one contract, not two independently-versionable things.

**Cost of this choice, stated plainly:** public consumers who pull
`ghcr.io/bpmforge/kryptkeeper` from a tagged release lose Sigstore/Rekor
public-transparency verification (`cosign verify --certificate-identity ...`
against the public log) and instead need Kryptkeeper's public key
out-of-band to verify anything. That is a real regression in the
zero-trust-key story keyless signing gives public OSS consumers, accepted
here because the internal promote/rollback pipeline's `--key`-only
verification is the binding constraint and is out of reach to change.
Revisit if `promote-by-digest.yml`/`rollback-by-digest.yml` are ever
opened for other reasons.

## Key custody

- **Generation.** The key pair is generated once with
  `cosign generate-key-pair` on an operator's local machine (never inside
  CI) — this produces `cosign.key` (encrypted with a password) and
  `cosign.pub`. Do not generate it inside a GitHub Actions job; a job that
  can generate the key can exfiltrate it.
- **Private half custody.** `cosign.key`'s contents go into the GitHub
  Actions repository secret `COSIGN_KEY`; its password goes into
  `COSIGN_PASSWORD`. Both are repo-level encrypted secrets, readable only by
  workflow runs (`sign-and-attest` in `release-candidate.yml`, `docker` in
  `release.yml`) — not by PR-triggered workflows from forks, since neither
  workflow that reads these secrets runs on `pull_request`. Nobody with only
  repo **write** access can read secret values back out through the GitHub
  UI/API; only repo **admins** can update them (rotate) and only by
  overwriting blind (GitHub never displays a stored secret's value). Keep an
  offline copy of `cosign.key` + its password in the org's secret-management
  system (the same tier used for the CA root/HSM key custody documented
  elsewhere, e.g. `docs/DECISIONS.md` D-085/D-089) — GitHub secrets are the
  *runtime* copy, not the *only* copy; losing the GitHub copy without an
  offline backup makes every previously-signed artifact's public key
  unrecoverable-but-still-valid (you can still verify old signatures, you
  just can't produce new ones under the same key without regenerating and
  redistributing a new public key).
- **Public half distribution — the gap keyed-only creates.** A keyless
  signature is self-describing (the Fulcio cert + Rekor log entry travel
  with it); a keyed signature is not — anyone who wants to verify a released
  image needs `cosign.pub` from somewhere they trust. Today that
  "somewhere" is the GitHub Actions secret `COSIGN_PUBLIC_KEY`, used only
  *inside* `promote-by-digest.yml`/`rollback-by-digest.yml` for Kryptkeeper's
  own internal staging/production deploys. There is currently **no public
  distribution channel** for `cosign.pub` for an external consumer of a
  tagged GHCR release to verify against — that is the direct cost of
  dropping keyless for the public release path. Until a public channel
  exists (e.g. publishing `cosign.pub` as a release asset, or in this repo
  under a well-known path), external verification of `v*` release images is
  not possible; say so rather than imply it works. Publishing `cosign.pub`
  as a release asset is a natural, small follow-up (append a step to
  `release.yml`'s `release` job) — not done here because "distribution
  packaging" acceptance criteria are silent on it and this file's job is to
  name the gap accurately, not quietly close it.
- **`COSIGN_PUBLIC_KEY` must be the pair of `COSIGN_KEY`.** These are two
  separately-set GitHub secrets — nothing enforces they came from the same
  `cosign generate-key-pair` run. If they drift (e.g. `COSIGN_KEY` rotated
  without updating `COSIGN_PUBLIC_KEY`), `cosign verify --key` in
  `promote-by-digest.yml`/`rollback-by-digest.yml` fails **closed** — that's
  the correct failure mode (a promotion that can't verify its image's
  signature must not deploy it), but it will look like an unrelated outage
  if the two secrets aren't rotated together. Rotate them in the same
  change, and smoke-test a `workflow_dispatch` promote against a
  known-good digest immediately after.
- **Rotation.** Generate a new pair, add the new public half as
  `COSIGN_PUBLIC_KEY`, and keep both the old and new key material available
  until every image signed under the old key has rolled out of production
  and staging (`promote-by-digest.yml`/`rollback-by-digest.yml` can only
  verify against whichever single public key is currently in
  `COSIGN_PUBLIC_KEY` — there is no multi-key verification today). Update
  `COSIGN_KEY`/`COSIGN_PASSWORD` to the new private half only once nothing
  still needs signing under the old one. A rollback to an image signed
  under a since-rotated-out key will fail signature verification by design
  — keep the previous key pair in offline escrow for exactly this case
  rather than discarding it at rotation time.

## What changed in the workflows

- `release.yml`: `docker` job now runs `cosign sign --yes --key cosign.key`
  (same invocation shape as `release-candidate.yml`'s `sign-and-attest`
  job — `umask 077`, write the key from the secret, `rm -f cosign.key`
  after), gated behind the same "secrets configured" fail-closed check.
  `id-token: write` is removed from workflow-level `permissions` — it was
  only ever there for keyless signing (Fulcio OIDC exchange) and is dead
  permission now.
- `release-candidate.yml`: unchanged behavior (it was already keyed); a
  comment now points here so a future reader doesn't have to reconstruct
  why the two workflows match.

## Delivery plugin signing (W20-24, D-117)

Delivery plugins are signed with a **separate plugin-signing key**, not the
image key above: a leaked plugin key must not be able to sign a hub image,
and the reverse.

- **Scheme.** `cosign sign-blob` over the exact bytes of the plugin's
  `manifest.json`. The manifest pins the module's SHA-256 and declares its
  capabilities, so one signature covers the code and what it may do. The hub
  verifies offline with the Go standard library (ECDSA P-256 over SHA-256);
  there is no Rekor or Fulcio lookup and no network. It accepts the sigstore
  bundle cosign v3 writes by default, or a bare base64 signature. With cosign
  older than v3, use `--output-signature` (the v2 `--bundle` JSON is a
  different format and is refused).
- **Generate** once, on an operator's machine, never in CI:
  `cosign generate-key-pair --output-key-prefix kk-plugin`. This gives
  `kk-plugin.key` (password-encrypted) and `kk-plugin.pub`.
- **Private half custody.** `kk-plugin.key` and its password stay with the
  release owner. They are not a CI secret until a release pipeline signs
  plugins; until then plugins are signed locally. The key file is
  password-encrypted (cosign's scrypt + secretbox), so a copy of the file
  alone cannot sign; the password is the secret to guard.
  - Working copy: `~/.config/kryptkeeper-signing/kk-plugin.key` (mode 600,
    directory 700) on the release owner's Mac. `scripts/sign-plugins.sh`
    reads it from there by default (`KK_PLUGIN_KEY` overrides).
  - Backup: `Bkup/kryptkeeper-signing/` on offline backup storage
    share, with `kk-plugin.pub`. That share is mounted as guest, so treat the
    copy as readable by anyone on the LAN: it is safe only while the
    password is strong and kept elsewhere (a password manager, never next to
    the file).
  - Generated 2026-10-08. Never commit either file: `*.key` is gitignored,
    and the public half lives only in `plugin_signing_keys.txt`.
- **Public half.** `kk-plugin.pub` goes into
  `internal/bootstrap/plugin_signing_keys.txt`, compiled into the hub. Only a
  key in that file makes a plugin `first-party`; operators cannot add one.
  Operators trust other publishers with `KRYPTKEEPER_PLUGIN_TRUSTED_KEYS`
  (tier `verified`); see docs/ops/DELIVERY_PLUGINS.md.
- **Sign** with `scripts/sign-plugins.sh`: it runs `make plugins`, signs
  each `dist/plugins/<name>/manifest.json` (cosign asks for the password),
  and verifies every bundle against the key compiled into the hub, stopping
  on the first mismatch. It refuses to run on a tree with uncommitted
  changes: Go stamps the git state into each module, and plugin builds are
  reproducible only from a clean checkout of a commit (a clean rebuild of
  be88843 reproduced the signed modules' sha256 exactly). Record the commit
  the script prints with the release. By hand, after `make plugins` has
  pinned the manifest:

  ```bash
  cosign sign-blob --key kk-plugin.key --bundle manifest.json.bundle \
    --signing-config scripts/cosign-signing-config.json manifest.json
  ```

  `scripts/cosign-signing-config.json` (made with `cosign signing-config
  create` and no services) names no transparency log or timestamp
  authority, which keeps the signature off the public log while the
  repository is private; the hub does not consult the log either way. It
  replaces `--tlog-upload=false`, which cosign v3 deprecates. Ship
  `manifest.json.bundle` next to `manifest.json` and `plugin.wasm`.
- **Catalogue (W38-11, D-328).** The plugin catalogue (`catalogue.json`) is
  signed with this same key, as `catalogue.json.bundle`, and the hub verifies it
  against the same compiled-in key, so the catalogue adds no trust root. The
  `plugin-catalogue` job in `packaging/public/github-release.yml` is the first CI
  use of the key: it needs repository secrets `PLUGIN_SIGNING_KEY` (the
  `kk-plugin.key` contents) and `PLUGIN_SIGNING_PASSWORD`. Adding them is the
  release owner's decision, since this file previously kept the key out of CI;
  the key file is password-encrypted, so the password is the part to guard.
  Until the secrets exist the job fails with a message and signing stays local.
- **Rotation.** Add the new public key to `plugin_signing_keys.txt` beside
  the old one, sign new releases with the new key, and drop the old key
  after one release. Versions already installed keep their recorded
  `signer_key_id`.
- **Compromise.** Remove the key from `plugin_signing_keys.txt` and ship a
  hub release; disable any plugin version signed by it
  (`signer_key_id` in the plugin API) until it is re-signed and reviewed.


## Package repository signing (apt/yum)

W25-11. The apt and yum repositories at `https://pkg.kryptkeeper.io` (see
`packaging/repo/README.md`) are signed with a dedicated GPG key. This is a
separate trust root from the keyless cosign signatures on release assets:
cosign proves a release artifact came from this repo's `release.yml`; the GPG
key proves the repository metadata (`InRelease`, `Release.gpg`,
`repomd.xml.asc`) was produced by the publisher. The publish workflow checks
the former before it applies the latter, and never weakens either.

- **Generation.** Once, offline, never in CI:
  `gpg --quick-generate-key "Kryptkeeper Package Signing <contact@kryptkeeper.io>" rsa4096 sign 2y`.
  Fingerprint: `PENDING-OWNER` (the key is created by the owner, not by an
  implementer).
- **Private half.** GitHub secrets `PKG_REPO_GPG_PRIVATE_KEY` (ASCII-armored)
  and `PKG_REPO_GPG_PASSPHRASE`; offline backup in the same tier as
  `cosign.key` (see "Key custody" above). The workflow imports it into a
  throwaway `GNUPGHOME`, deletes that directory in an `always()` step, and
  fails rather than publish if the secret is empty. The passphrase is only
  ever fed on stdin (`--passphrase-fd 0`).
- **Public half.** Published as `kryptkeeper.asc` and `kryptkeeper.gpg` at the
  repo root; fingerprint printed in `packaging/repo/README.md` and in the
  release notes. Consumers pin it via apt `signed-by` / dnf `repo_gpgcheck=1`.
- **Hosting credentials.** `CLOUDFLARE_API_TOKEN` (scope: Cloudflare Pages
  Edit on the one account) and `CLOUDFLARE_ACCOUNT_ID` deploy to the
  `kryptkeeper-pkg` Pages project. They can replace the published repo, so
  they are as sensitive as the signing key; rotate on suspected exposure.
- **Scope.** Repository metadata is signed. Individual `.rpm` files are not
  (`gpgcheck=0`, `repo_gpgcheck=1`); rpm signing (`rpmsign --addsign`) is a
  follow-up.
- **Rotation.** Generate a new key, publish a keyring containing old and new
  for one release, then drop the old key.
- **Compromise.** Revoke the key, generate a new one, republish the whole repo
  (the workflow rebuilds it from the verified release assets), and announce
  the new fingerprint.

## Verify a release and reproduce it (W33-09)

Every release is signed keyless by `.github/workflows/release.yml`. The
`release-verify` job re-checks all of it right after publish (identity below,
issuer `https://token.actions.githubusercontent.com`); if it fails, the run
fails and `promote-latest` is skipped, so `:latest` keeps pointing at the
previous release (goreleaser no longer pushes `:latest`; rc/prerelease tags
never get it).

Verify by hand (replace `vX.Y.Z`):

```sh
ID="https://github.com/bpmforge/kryptkeeper/.github/workflows/release.yml@refs/tags/vX.Y.Z"
ISS=https://token.actions.githubusercontent.com
gh release download vX.Y.Z --repo bpmforge/kryptkeeper --dir rel
cosign verify-blob --certificate rel/checksums.txt.pem --signature rel/checksums.txt.sig \
  --certificate-identity "$ID" --certificate-oidc-issuer "$ISS" rel/checksums.txt
(cd rel && sha256sum --check --ignore-missing checksums.txt)
cosign verify --certificate-identity "$ID" --certificate-oidc-issuer "$ISS" ghcr.io/bpmforge/kryptkeeper:X.Y.Z
```

Reproduce the linux/amd64 binaries: `bash scripts/repro-check.sh rebuild`
(needs goreleaser v2.18.3) clones HEAD into two different directories, builds
the four binaries in each and prints a `MATCH`/`DIFF` SHA-256 table. Builds
are reproducible because `-trimpath`, `CGO_ENABLED=0`, `mod_timestamp` and
`main.date` are all derived from the commit time (`{{ .CommitTimestamp }}` /
`{{ .CommitDate }}`), never the wall clock. The `reproducible-build.yml`
workflow runs the same check on every `v*` tag. The Windows agent and MSI are
not reproducible and are not covered.

SBOM completeness: `bash scripts/repro-check.sh sbom <dir>` requires every
module linked into the four shipped commands (`go list -deps`) to appear in
the CycloneDX SBOMs, and reports how many other `go list -m all` modules
(test-only or unlinked) are absent; those cannot appear in a binary SBOM.

## Release signing on the self-hosted forge (D-210)

the self-hosted forge has no OIDC issuer, so releases are signed with a cosign key pair:
`checksums.txt` and `kryptkeeper.rb` get a `.sig`. The public key is
`packaging/cosign.pub`; verify with
`cosign verify-blob --key cosign.pub --signature checksums.txt.sig checksums.txt`.
The private key and its password live only in the the self-hosted forge repo secrets
`COSIGN_PRIVATE_KEY` and `COSIGN_PASSWORD`, plus the owner's offline copy.
