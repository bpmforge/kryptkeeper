# Kryptkeeper Proof Pack

Release: v0.21
Pack version: v0.21-20261017

The proof pack is one versioned unit: the documents below are published together and carry the same release tag. Items that do not exist yet are labelled `pending` or `shortfall` rather than linked.

## Contents and status

| Item | Link | Status |
|---|---|---|
| FIPS statement | [FIPS_STATEMENT.md](FIPS_STATEMENT.md) | published (Go module CMVP #5247, Active) |
| Control mapping | [CONTROL_MAPPING.md](CONTROL_MAPPING.md) | published |
| Competitive matrix | [COMPETITIVE_MATRIX.md](COMPETITIVE_MATRIX.md) | published (all nine competitor columns sourced 2026-10-17; "Not documented" means absent from the cited page, see Method) |
| Reference deployments | [REFERENCES.md](REFERENCES.md) | shortfall (0 of 3 consenting references) |
| Accessibility conformance report (ACR/VPAT) | [ACR_VPAT_v0.21.md](../ACR_VPAT_v0.21.md) | published (manual screen-reader pass PENDING-RUN) |
| Pen-test scope | [PENTEST_SCOPE.md](PENTEST_SCOPE.md) | published as DRAFT scope (no test has happened) |
| Pen-test summary | PENTEST_SUMMARY.md | pending (created only after a signed retest letter exists) |
| SBOM and signing instructions | [SECURITY.md](../../../SECURITY.md), [packaging/SIGNING.md](../../../packaging/SIGNING.md), header comment of [release.yml](../../../.github/workflows/release.yml) | published |
| Security whitepaper | none | pending (not yet published; no document exists) |

## How to verify the pack

Releases are signed keyless with cosign through the release workflow's GitHub OIDC identity. The certificate identity pattern is `https://github.com/bpmforge/kryptkeeper/.github/workflows/release.yml@refs/tags/v*`. Replace `vX.Y.Z` with the v0.21 tag once it is cut (until then the tag does not exist and these commands cannot succeed). Commands as in [packaging/SIGNING.md](../../../packaging/SIGNING.md):

```sh
ID="https://github.com/bpmforge/kryptkeeper/.github/workflows/release.yml@refs/tags/vX.Y.Z"
ISS=https://token.actions.githubusercontent.com
gh release download vX.Y.Z --repo bpmforge/kryptkeeper --dir rel
cosign verify-blob --certificate rel/checksums.txt.pem --signature rel/checksums.txt.sig \
  --certificate-identity "$ID" --certificate-oidc-issuer "$ISS" rel/checksums.txt
(cd rel && sha256sum --check --ignore-missing checksums.txt)
cosign verify --certificate-identity "$ID" --certificate-oidc-issuer "$ISS" ghcr.io/bpmforge/kryptkeeper:X.Y.Z
```

The release also ships CycloneDX SBOMs (see the `release.yml` header comment). `docs/release/RELEASE_NOTES_v0.21.md` does not exist yet; when it does, copy the exact commands from it and update this section.

## Update policy

Re-verify every matrix cell and every status above at each release, and update the `Release:` and `Pack version:` lines at publish. Competitor cells carry an access date; a cell older than the previous release is stale.

## Contact

security@kryptkeeper.io (see [SECURITY.md](../../../SECURITY.md)).
