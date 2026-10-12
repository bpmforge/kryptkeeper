# Air-Gap / Offline Install

FR-P61 / D-099: a documented offline install for the regulated / ADCS-replacement market — no
external pulls anywhere in the procedure. Built and verified with `scripts/deploy/airgap-bundle.sh`.

`docs/deployment.md`'s "Bare Metal (air-gapped / regulated)" section still `curl`s release binaries
from `github.com` — that is not actually air-gapped, it just runs a Kubernetes-free install. This
document is the real offline procedure: everything the install needs is fetched once, on a
connected host, into a portable bundle, then carried across the gap and pushed into a private
registry mirror you already run inside the air-gapped network.

## What's covered

- The Kryptkeeper **Hub** container image (`ghcr.io/bpmforge/kryptkeeper`), the only image the
  production Helm chart (`charts/kryptkeeper`) deploys (`charts/kryptkeeper/templates/deployment.yaml`).
- The **Helm chart itself**, packaged as a local `.tgz` — `charts/kryptkeeper/Chart.yaml` declares no
  chart `dependencies`, so `helm package`/`helm install` need no chart repository, connected or not.
- Optionally, any **additional image** you want bundled the same way — e.g. `postgres:16-alpine` if
  you want a self-hosted database inside the gap rather than pointing at a Postgres instance you
  already run there (`docker-compose.override.yml` uses that same image tag as its own reference).

## What's NOT covered — read this before you rely on it

- **The Docker Compose path (`docs/deployment.md`'s "Docker Compose" section) is not air-gap-capable
  as written.** Its `ui-build` service runs `npm ci` against the public npm registry on every
  `docker compose up` (`docker-compose.yml`) — that is a separate external-pull problem this ticket's
  `write_scope` (`scripts/deploy/airgap-bundle.sh`, this file) cannot fix. Use the Helm/Kubernetes path
  below for air-gapped installs.
- **No dashboard/UI image is bundled, because the production Helm chart doesn't deploy one.**
  `charts/kryptkeeper/templates/` has no nginx/dashboard template — only Compose's dev/small-team path
  builds and serves `ui/dist` (via the `ui-build` + `dashboard` services). A Helm-deployed Hub exposes
  the API only; serving the dashboard in a regulated Kubernetes environment is a separate, currently
  undocumented problem, not solved here.
- **This script does not cross-build or multi-arch-save.** `docker save`/`podman save` captures
  whatever architecture the build host actually pulled. `manifest.json` records each image's
  `architecture`/`os` so that's visible in the bundle instead of discovered only when a pod fails to
  schedule inside the gap — but you must still run `build` on (or emulate) a host matching your
  air-gapped cluster's node architecture.
- **Only the Hub image is published today.** `Dockerfile.agent`/`Dockerfile.certmanager`/`Dockerfile.mcp`
  exist, but wiring them into release CI is a separate, still-open ticket (W10-13). Until then, build
  those images locally (`docker build -f Dockerfile.agent -t <tag> .`, etc.) and add them to
  `EXTRA_IMAGES` below if your install needs the satellite agent or cert-manager issuer as containers —
  the bare-metal agent path (`docs/deployment.md`'s "Satellite agent systemd unit") needs no container
  image at all, and is the simpler option inside a regulated environment.
- **No cosign signing of the bundle.** Integrity across the gap is checksum-verified (SHA-256, see
  below), not signature-verified. Reconciling the distribution/signing model is D-101, a separate
  ticket.

## Prerequisites

- **A connected build host** (anywhere with internet egress — does not need to be inside or near the
  air-gapped network): `docker` or `podman`, `helm` 3.12+, `jq`, `sha256sum`, a checkout of this repo.
- **The air-gapped target host**: reach to a private container registry mirror you already operate
  inside the gap (Harbor, Zot, `distribution/distribution`, or equivalent — this procedure pushes into
  one, it does not stand one up), reach to the target Kubernetes API, and `docker`/`podman` + `helm` +
  `jq` + `sha256sum` + `kubectl` + `openssl` (steps 4–5 below use `kubectl` and `openssl`). No reach to
  the public internet anywhere in this host's part of the procedure, and **no repo checkout needed** —
  `build` copies `airgap-bundle.sh` itself into the bundle (see step 1), so the transferred directory
  is the only thing this host needs.
- Approved removable media or a secure transfer appliance to carry the bundle across the gap — this
  procedure produces a directory to transfer; how you move bytes across your specific air gap is a
  site-specific control this doc doesn't prescribe.

## Procedure

### 1. Build the bundle (connected host)

```bash
export HUB_IMAGE=ghcr.io/bpmforge/kryptkeeper:v1.2.3   # pin a real release tag, not :latest
# Optional: bundle a self-hosted Postgres too
export EXTRA_IMAGES="docker.io/library/postgres:16-alpine"

scripts/deploy/airgap-bundle.sh build /path/outside/this/checkout/kryptkeeper-airgap-bundle
```

This pulls (or reuses a locally-present) `HUB_IMAGE` and each `EXTRA_IMAGES` entry, saves each as a
tarball, packages `charts/kryptkeeper` (override with `CHART_DIRS` to add
`charts/kryptkeeper-certmanager-issuer` once its image is available — see above), and writes a
`manifest.json` + `SHA256SUMS` covering every artifact **plus a copy of `airgap-bundle.sh` itself** —
the output directory is everything you carry across the gap; the air-gapped host needs no repo
checkout of its own. Image refs must be tag-form (`repo/image:tag`), not digest-form
(`repo/image@sha256:...`) — the script rejects digest refs up front with an explanation, because a
save/load round trip of a digest-only ref comes back locally untagged and step 3 below has nothing
left to retag by name.

### 2. Transfer

Copy the whole bundle directory (as `kryptkeeper-airgap-bundle` below) across the gap via your
approved transfer path.

### 3. Verify + push into the private registry mirror (air-gapped host)

```bash
./kryptkeeper-airgap-bundle/airgap-bundle.sh push ./kryptkeeper-airgap-bundle registry.internal.example.com:5000
```

Run the bundle's own copy of the script — nothing from the build host or this repo needs to have
crossed the gap separately. This verifies `SHA256SUMS` first (including the script's own checksum)
and **fails closed on any mismatch** — it will not push a bundle whose integrity it cannot confirm
crossing the gap. It then loads each image tarball, retags it from its original registry host
(`ghcr.io/...`) onto your mirror (`registry.internal.example.com:5000/...`), and pushes. It prints the
final `original -> mirrored` ref mapping for the next step.

### 4. Install from the mirror + the bundled chart

```bash
helm install kryptkeeper ./kryptkeeper-airgap-bundle/charts/kryptkeeper-*.tgz \
  --namespace kryptkeeper --create-namespace \
  --set image.repository=registry.internal.example.com:5000/kryptkeeper/kryptkeeper \
  --set image.tag=v1.2.3 \
  --set config.dbMode=sqlite \
  --set secrets.bootstrapToken="$(openssl rand -hex 20)" \
  --set secrets.keystorePassphrase="$(openssl rand -hex 32)"
```

`charts/kryptkeeper/values.yaml` defaults `image.repository` to `ghcr.io/bpmforge/kryptkeeper` —
if you forget `--set image.repository=...` here, the pod will try (and fail) to pull from the public
internet from inside the gap. Set `config.dbMode=postgres` and `secrets.databaseURL` instead of
`sqlite` if you bundled and pushed the optional Postgres image and are running it in-cluster.

### 5. Confirm no external pulls happened

```bash
kubectl -n kryptkeeper get pods -o jsonpath='{.items[*].status.containerStatuses[*].image}'
```

Every image reference should resolve to `registry.internal.example.com:5000/...` — nothing at
`ghcr.io` or any other public host. `kubectl describe pod` on any pod stuck in `ImagePullBackOff`
will show exactly which ref it tried and failed to reach; that ref not being under your mirror host is
the signature of a step above being skipped.

## Verified

Exercised end-to-end with `podman` (`docker` unavailable on the host this was written on — see
`docs/STATUS.md`'s W10-06/W10-07 entries for the same disclosed gap on this project): `build` against
a real pulled image, then — from `/tmp`, with no repo checkout in reach — `<bundle>/airgap-bundle.sh
push` against a disposable local `registry:2` container standing in for a private mirror, then, with
the original image and its mirrored copy both deleted locally, a `pull` of only the mirrored ref
succeeded, and `helm template` against the bundled chart with `image.repository` pointed at the
mirror rendered a manifest referencing only the mirror host, nowhere else. Also verified as negative
tests: a digest-form (`@sha256:...`) image ref is rejected by `build` before anything is saved, and a
bundle with a tampered image tarball (or a tampered copy of the script itself) is rejected by `push`'s
checksum verification before any image is loaded or pushed.
