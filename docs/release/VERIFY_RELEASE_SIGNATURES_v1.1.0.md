# Verifying the published v1.1.0 release signatures

Date: 2026-10-27. Run by hand on the maintainer's Mac (Apple silicon, macOS), public internet, cosign 3.1.3 (`cosign version`).
The files came from the public GitHub release `v1.1.0` of `bpmforge/kryptkeeper` into a fresh empty directory.
Nothing was built locally. The commands are the ones in `docs/deployment.md`, "Install from a signed release":
the identity pattern pins this repository's `release.yml` workflow on a `v*` tag, and the issuer is GitHub's
Actions OIDC issuer. The only change is `shasum -a 256 -c` instead of `sha256sum -c`, because macOS has no `sha256sum`.

## What was checked

1. The cosign signature (`checksums.txt.sig`) and certificate (`checksums.txt.pem`) on `checksums.txt`.
2. The macOS arm64 archive `kryptkeeper_1.1.0_darwin_arm64.tar.gz` (15.5 MB) against `checksums.txt`.

## Not checked

- The other archives, the `.deb`/`.rpm` packages, the SBOM files and the container image signatures.
- The Release workflow run on this tag shows failed jobs (Plugin catalogue, Helm chart OCI); the
  `goreleaser release` job that produced and signed these files succeeded. The "Verify signatures" job
  of that workflow was skipped, so this manual run is the first independent check of the signatures.
- That the binary inside the archive runs; it was not unpacked or executed.

## Run record

```
$ cosign verify-blob \
    --certificate-identity-regexp '^https://github\.com/bpmforge/kryptkeeper/\.github/workflows/release\.yml@refs/tags/v' \
    --certificate-oidc-issuer https://token.actions.githubusercontent.com \
    --signature checksums.txt.sig \
    --certificate checksums.txt.pem \
    checksums.txt
Flag --signature has been deprecated, please use --bundle to provide a signature
Flag --certificate has been deprecated, please use --bundle with --trusted-root to provide the public certificate
Verified OK
$ shasum -a 256 -c checksums.txt --ignore-missing
kryptkeeper_1.1.0_darwin_arm64.tar.gz: OK
```

Both commands exited 0. The checksum line that `shasum` checked:

```
289834869d1ba898f61da98206899372b053809980e8e405f6b074f541bc3c41  kryptkeeper_1.1.0_darwin_arm64.tar.gz
```
