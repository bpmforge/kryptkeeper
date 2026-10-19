# UAT W25-18: release images pull and run

Ticket W25-18 (FR-P55, FR-P58). Harness: `tests/live/images/run.sh`. Release tested: **v0.9.4** (latest public release tag; the v0.13 release has not been cut).

- Date: 2026-10-15/16, macOS arm64, podman 6.1.3 (machine arch arm64), cosign 3.1.3.
- arm64 ran natively. amd64 ran under the podman machine's emulation (labelled below).
- Identity verified: `https://github.com/bpmforge/kryptkeeper/.github/workflows/release.yml@refs/tags/v0.9.4`, issuer `https://token.actions.githubusercontent.com` (keyless).

## Command

```
bash tests/live/images/run.sh v0.9.4      # RESULT: PASS (cosign: 4/4)
bash tests/live/images/release-fail-closed_test.sh   # RESULT: PASS
```

## Manifest-list digests (cosign verified, 4 of 4)

| image | list digest |
|---|---|
| kryptkeeper | `sha256:b508f664762395c9ec9e1994b9e2630a5a341183a4dcc10f23696b071736fe19` |
| kryptkeeper-agent | `sha256:bd9e78a127ea2c282f03fa91a42ed0e21797e92c2fd95a51313c329e96bb4113` |
| kryptkeeper-mcp | `sha256:3dcea5a091313bf4b19bb9b3bff5b9842319c36c4dc0cac9ae3408d4598e81bc` |
| kryptkeeper-certmanager | `sha256:25d8f0da2ba5dd59f49206711676ca2bf5a99b6719fddcc86396b40690fde46c` |

## Results (image x arch)

| image | arch | child digest | config user | verify | answers | result |
|---|---|---|---|---|---|---|
| kryptkeeper | amd64 (emulated) | `sha256:bc0234d0b0ff205dd48478cd0760639b416ea331f39b0e3b02f1b6995941a216` | nonroot:nonroot | cosign list ok=4/4 | /healthcheck exit 0 | PASS |
| kryptkeeper-agent | amd64 (emulated) | `sha256:747a07760ce58f01cf333b9be382288d3c2ae213dc7299497ae97af2f7d854bb` | nonroot:nonroot | cosign list ok=4/4 | --version + config-error exit 1 | PASS |
| kryptkeeper-mcp | amd64 (emulated) | `sha256:12f30c246cacb0c48a15bf1641957bf0ae87cbbbaf74e27bb5734b3cea136b53` | nonroot:nonroot | cosign list ok=4/4 | --version | PASS |
| kryptkeeper-certmanager | amd64 (emulated) | `sha256:17bff5af280e360f07a94b29e1e7c076c157ca52d821a8f5b020e81b240554dd` | nonroot:nonroot | cosign list ok=4/4 | --version | PASS |
| kryptkeeper | arm64 (native) | `sha256:b109384a457a20de1b680be3a5e51a6d80f0bc4ec708fa87cf6dd0f6a565620e` | nonroot:nonroot | cosign list ok=4/4 | /healthcheck exit 0 | PASS |
| kryptkeeper-agent | arm64 (native) | `sha256:74406f8cd9873c53add843726231d43947c15128b08216997886ba7706811047` | nonroot:nonroot | cosign list ok=4/4 | --version + config-error exit 1 | PASS |
| kryptkeeper-mcp | arm64 (native) | `sha256:ee5ce65880ad60acee4b1e159f5e23c309e763deeed9f5bed41f35a4052bca74` | nonroot:nonroot | cosign list ok=4/4 | --version | PASS |
| kryptkeeper-certmanager | arm64 (native) | `sha256:90a471095b269ba9b887fcd9bf51307c59001c4313643cc384f78b5df77b47ed` | nonroot:nonroot | cosign list ok=4/4 | --version | PASS |

## Notes and findings

- Hub health: the image `HEALTHCHECK` binary runs with `HEALTHCHECK_URL=https://127.0.0.1:8080/healthz` and `HEALTHCHECK_CA_FILE=/data/tls/ca.pem`, i.e. verified TLS against the hub's own CA (no skip-verify). `podman top` on the running arm64 hub reported user `nonroot`. Data dir is a tmpfs (mode 1777) because the distroless nonroot user cannot write elsewhere.
- Non-root evidence: `Config.User` for all 8 pulled images, plus `podman top` for the running hub. The distroless images have no shell, so no `id -u`.
- Spec decision resolved differently: the spec expected the agent might lack `--version`. In v0.9.4 the agent, mcp and certmanager all print `<name> 0.9.4 (commit 46e1a98..., built 2026-10-15T18:17:54Z)`. The harness asserts `--version` and, as the spec default, also the no-config exit (`exit 1`, `required environment variable KRYPTKEEPER_HUB_URL is not set`, no panic). No follow-up needed for `--version`.
- AC2 (fail-closed release): `tests/live/images/release-fail-closed_test.sh` passes. Images are built in the single `goreleaser` job (`needs: test`); `homebrew-formula` needs `goreleaser`; `release.yml` has 0 `continue-on-error`; `docker_manifests` lists all four images for amd64 and arm64; `docker_signs` is present. Extend the test if a separate image job is ever introduced.
- First run of the harness hit a transient `ghcr.io` TCP timeout inside `podman manifest inspect` (one image/arch row reported FAIL). The harness now retries the child-digest lookup three times; the recorded run above is the full re-run, 0 FAIL.
- Existing gap, not fixed here (W20-01 owns workflows): `promote-by-digest.yml` still verifies with `cosign verify --key`, which cannot validate these keyless signatures (see its header comment).
