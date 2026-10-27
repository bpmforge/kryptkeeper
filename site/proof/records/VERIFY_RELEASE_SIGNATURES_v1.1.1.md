# Verifying the published v1.1.1 release signatures

Date: 2026-10-27. Run by hand on the maintainer's Mac (Apple silicon, macOS), public internet, cosign 3.1.3.
The files came from the public GitHub release `v1.1.1` of `bpmforge/kryptkeeper` into a fresh empty directory
(`gh release download v1.1.1`). Nothing was built locally. The commands are the ones in `docs/deployment.md`,
"Install from a signed release", with `shasum -a 256 -c` instead of `sha256sum -c` because macOS has no `sha256sum`.
The same check on v1.1.0 is in [VERIFY_RELEASE_SIGNATURES_v1.1.0.md](VERIFY_RELEASE_SIGNATURES_v1.1.0.md).

## What was checked

1. The cosign signature (`checksums.txt.sig`) and certificate (`checksums.txt.pem`) on `checksums.txt`.
2. The macOS arm64 archive `kryptkeeper_1.1.1_darwin_arm64.tar.gz` (16.3 MB) against `checksums.txt`.

## Not checked

- The other archives, the `.deb`/`.rpm` packages, the SBOM files and the container image signatures.
- The Release workflow run on this tag (40578561777) passed every job, including its own "Verify signatures"
  job, except "Plugin catalogue", which needs signing secrets the public repository does not have yet.
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
kryptkeeper_1.1.1_darwin_arm64.tar.gz: OK
```

Both commands exited 0. The checksum line that `shasum` checked:

```
e4fd29e30316859001d0f1db4f7193abc2762203a1d9c0241f481abd9f70ff25  kryptkeeper_1.1.1_darwin_arm64.tar.gz
```
