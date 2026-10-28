# Kryptkeeper 1.1.2

A fix release for people who build Kryptkeeper from source. The released binaries, packages and
images of 1.1.1 were correct; nothing in the hub's code or database changes. Upgrade if you
build the images yourself with Docker Compose.

## Fixed

- **Source builds on x86_64 produced an ARM binary.** `Dockerfile` and `Dockerfile.fips` set
  `TARGETARCH` to `arm64` by default, so `docker compose up` from the README Quick Start built
  an image that failed on any x86_64 host with `exec /kryptkeeper: exec format error`. The
  agent, cert-manager and MCP Dockerfiles had the same bug the other way round on arm64 hosts.
  `TARGETARCH` no longer has a default; a build without it targets the builder's own
  architecture. Released images were never affected, because the release pipeline sets the
  architecture explicitly.
- **The getting-started guide matches the current setup.** It now uses `.env` with the two
  required values, TLS by default with the hub's `ca.pem`, and the current API for creating a
  CA, issuing and revoking. Every step was run on a fresh VM.
- **`scripts/day-one-estate.sh` works against a current hub.** It uses a valid scan type, waits
  for the scan and its certificates before reporting, accepts `CACERT` for a TLS hub, and no
  longer fails when a report is longer than its preview.

## Proof

The day-one estate run was done on a new Ubuntu 24.04 VM: a bulk import, a network scan and an
AD CS export from a real enterprise CA became one risk-scored estate of 29 certificates, with the
estate report, the dashboard and the seeded counts in agreement. Following the 1.1.1 docs took 19
minutes and found the defects above; a rerun with the fixes passed with no workarounds
([`DAY_ONE_RUN_v1.1.md`](DAY_ONE_RUN_v1.1.md)).

## Upgrade notes

- If you build from source, rebuild your images (`docker compose up -d --build`). If you use the
  released images or packages, 1.1.2 is the same code as 1.1.1.
- No migrations, no new settings.

## Verifying this release

The steps are the same as for 1.1.1 ([packaging/SIGNING.md](../../packaging/SIGNING.md)):

```bash
cosign verify \
  --certificate-identity "https://github.com/bpmforge/kryptkeeper/.github/workflows/release.yml@refs/tags/v1.1.2" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  ghcr.io/bpmforge/charts/kryptkeeper:1.1.2
```
