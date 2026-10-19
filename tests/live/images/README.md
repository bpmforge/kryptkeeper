# W25-18: release images pull and run

```
bash tests/live/images/run.sh v0.9.4          # both arches
PLATFORMS=linux/arm64 bash tests/live/images/run.sh v0.9.4
bash tests/live/images/release-fail-closed_test.sh   # static workflow test (AC2)
```

## What `run.sh` does

For each of `ghcr.io/bpmforge/{kryptkeeper,kryptkeeper-agent,kryptkeeper-mcp,kryptkeeper-certmanager}`:

1. Resolves the manifest-list digest for the tag from the registry (anonymous pull token), then the per-arch child digests with `podman manifest inspect`. Everything after that uses `repo@sha256:...`, never a tag.
2. `cosign verify` (keyless) on the list digest with the release workflow identity
   (`https://github.com/bpmforge/kryptkeeper/.github/workflows/release.yml@refs/tags/<tag>`, issuer `https://token.actions.githubusercontent.com`). Must print `cosign: 4/4`.
3. `podman pull --platform` the child digest; asserts `Config.User` is `nonroot:nonroot`.
4. Runs it: hub = image `HEALTHCHECK` binary (`/healthcheck`) against the hub's self-issued CA (verified TLS); agent, mcp, certmanager = `--version`. The agent is also run with no config and must exit non-zero with the `KRYPTKEEPER_HUB_URL` error and no panic.

## Prerequisites

`podman` (a running machine), `cosign`, `curl`, `python3`. Network access to `ghcr.io`, `fulcio`/`rekor` (cosign keyless verification needs the Sigstore TUF root). No registry login: the images are public. The non-native arch runs through the podman machine's emulation and is labelled `emulated` in the table.

Exit status is 1 on any FAIL. Containers are removed on exit.

## Not covered

The distroless images have no shell, so "runs as non-root" is asserted from `Config.User` plus `podman top` on the running hub, not `id -u`.
