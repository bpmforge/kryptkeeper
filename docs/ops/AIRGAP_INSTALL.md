# Air-Gap / Offline Install

FR-P61 / D-099: a documented offline install for the regulated / ADCS-replacement market — no
external pulls anywhere in the procedure. Built and verified with `scripts/deploy/airgap-bundle.sh`.

`docs/deployment.md`'s "Bare Metal (air-gapped / regulated)" section still `curl`s release binaries
from `github.com` — that is not actually air-gapped, it just runs a Kubernetes-free install. This
document is the real offline procedure: everything the install needs is fetched once, on a
connected host, into a portable bundle, then carried across the gap and pushed into a private
registry mirror you already run inside the air-gapped network.

## What's covered

- The four published container images -- **Hub** (`ghcr.io/bpmforge/kryptkeeper`), **agent**
  (`-agent`), **MCP** (`-mcp`) and **certmanager** (`-certmanager`) -- plus the **dashboard** image
  (`ghcr.io/bpmforge/kryptkeeper-dashboard`, nginx serving the SPA) that the Helm chart's optional
  dashboard Deployment uses (`dashboard.image` in `charts/kryptkeeper/values.yaml`). `build` requires
  all five refs, so a bundle can never silently ship fewer.
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
- **The Docker Compose dashboard path is unchanged.** Helm installs get the dashboard from the
  bundled `kryptkeeper-dashboard` image (`--set dashboard.enabled=true`, with the mirrored
  `dashboard.image.repository`); the Compose `ui-build` service still needs the public npm registry.
- **This script does not cross-build or multi-arch-save.** `docker save`/`podman save` captures
  whatever architecture the build host actually pulled. `manifest.json` records each image's
  `architecture`/`os` so that's visible in the bundle instead of discovered only when a pod fails to
  schedule inside the gap — but you must still run `build` on (or emulate) a host matching your
  air-gapped cluster's node architecture.
- **Signature trust is only as good as the key you verify against.** The bundle ships `cosign.pub`
  for convenience, but a key that travels with the bundle only proves the bundle is internally
  consistent. For origin assurance, pass the publisher key you obtained out-of-band to `push` via
  `COSIGN_PUBKEY` (see step 3).

## Prerequisites

- **A connected build host** (anywhere with internet egress — does not need to be inside or near the
  air-gapped network): `docker` or `podman`, `helm` 3.12+, `jq`, `sha256sum`, `cosign`, a checkout of this repo, and a signing key (`cosign generate-key-pair`) or an OIDC identity for keyless signing.
- **The air-gapped target host**: reach to a private container registry mirror you already operate
  inside the gap (Harbor, Zot, `distribution/distribution`, or equivalent — this procedure pushes into
  one, it does not stand one up), reach to the target Kubernetes API, and `docker`/`podman` + `helm` +
  `jq` + `sha256sum` + `cosign` + `kubectl` + `openssl` (steps 4–5 below use `kubectl` and `openssl`). No reach to
  the public internet anywhere in this host's part of the procedure, and **no repo checkout needed** —
  `build` copies `airgap-bundle.sh` itself into the bundle (see step 1), so the transferred directory
  is the only thing this host needs.
- Approved removable media or a secure transfer appliance to carry the bundle across the gap — this
  procedure produces a directory to transfer; how you move bytes across your specific air gap is a
  site-specific control this doc doesn't prescribe.

## Procedure

### 1. Build the bundle (connected host)

```bash
export HUB_IMAGE=ghcr.io/bpmforge/kryptkeeper:1.2.3   # pin a real release tag, not :latest
export AGENT_IMAGE=ghcr.io/bpmforge/kryptkeeper-agent:1.2.3
export MCP_IMAGE=ghcr.io/bpmforge/kryptkeeper-mcp:1.2.3
export CERTMANAGER_IMAGE=ghcr.io/bpmforge/kryptkeeper-certmanager:1.2.3
export DASHBOARD_IMAGE=ghcr.io/bpmforge/kryptkeeper-dashboard:1.2.3
# Optional: bundle a self-hosted Postgres too
export EXTRA_IMAGES="docker.io/library/postgres:16-alpine"
# Signing is mandatory: a private key (and its .pub, shipped in the bundle as cosign.pub) ...
export COSIGN_KEY=/secure/path/cosign.key COSIGN_PUBKEY=/secure/path/cosign.pub
# ... or keyless: export COSIGN_KEYLESS=1

scripts/deploy/airgap-bundle.sh build /path/outside/this/checkout/kryptkeeper-airgap-bundle
```

This pulls (or reuses a locally-present) `HUB_IMAGE` and each `EXTRA_IMAGES` entry, saves each as a
tarball, packages `charts/kryptkeeper` (override with `CHART_DIRS` to add
`charts/kryptkeeper-certmanager-issuer` once its image is available — see above), and writes a
`manifest.json` (schema 2, with the sha256 of every image and chart file) + `SHA256SUMS` covering every artifact **plus a copy of `airgap-bundle.sh` itself** —
the output directory is everything you carry across the gap; the air-gapped host needs no repo
checkout of its own. Image refs must be tag-form (`repo/image:tag`), not digest-form
(`repo/image@sha256:...`) — the script rejects digest refs up front with an explanation, because a
save/load round trip of a digest-only ref comes back locally untagged and step 3 below has nothing
left to retag by name.

It then signs `manifest.json` with `cosign sign-blob`, writing `manifest.json.sig`,
`manifest.json.bundle` and (key mode) `cosign.pub` into the bundle, and refuses to build at all
without `COSIGN_KEY` or `COSIGN_KEYLESS=1`. Key-based signing does not contact the transparency log.

### 2. Transfer

Copy the whole bundle directory (as `kryptkeeper-airgap-bundle` below) across the gap via your
approved transfer path.

### 3. Verify + push into the private registry mirror (air-gapped host)

```bash
./kryptkeeper-airgap-bundle/airgap-bundle.sh push ./kryptkeeper-airgap-bundle registry.internal.example.com:5000
```

Run the bundle's own copy of the script — nothing from the build host or this repo needs to have
crossed the gap separately. This verifies `SHA256SUMS` first (including the script's own checksum),
then the **cosign signature over `manifest.json`, offline** (`cosign verify-blob --insecure-ignore-tlog=true`
-- the Rekor transparency log is unreachable inside the gap, so trust rests on the signing key alone),
then checks every image/chart file against the sha256 recorded in the signed manifest. Any failure prints
`manifest signature verification failed -- refusing to push` (exit 4) **before any image is loaded or
pushed**; it fails closed and never downgrades to a warning. To pin the publisher key you trust rather
than the bundle's own copy, run with `COSIGN_PUBKEY=/path/to/publisher.pub`. For a keyless bundle set
`COSIGN_CERT_IDENTITY` and `COSIGN_CERT_OIDC_ISSUER` (both required). It then loads each image tarball, retags it from its original registry host
(`ghcr.io/...`) onto your mirror (`registry.internal.example.com:5000/...`), and pushes. It prints the
final `original -> mirrored` ref mapping for the next step.

### 4. Install from the mirror + the bundled chart

```bash
helm install kryptkeeper ./kryptkeeper-airgap-bundle/charts/kryptkeeper-*.tgz \
  --namespace kryptkeeper --create-namespace \
  --set image.repository=registry.internal.example.com:5000/kryptkeeper/kryptkeeper \
  --set image.tag=1.2.3 \
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

## Offline root CA (air-gapped signing)

UC-A02. The root key is generated and kept on a host that is never networked; the hub only ever
holds the root *certificate* (`key_storage_type: external`) plus its own issuing CA key. Importing a
trust anchor and removing one are dual-control actions: a second human with `pki-admin` must approve,
and neither the proposer nor the bootstrap token can. Script of record: `tests/live/ca-offline-root/run.sh`.

Set `H=https://<hub>:8080`, `T=<your pki-admin API key>`, and use `--cacert ca.pem` as in
`PILOT_RUNBOOK.md`. A hub with no CA starts only if told a default CA id:
`KRYPTKEEPER_DEFAULT_CA_ID=offline-root-pending` (the id need not exist). Do not use
`KRYPTKEEPER_BOOTSTRAP_CREATE_ROOT=true` for this flow: it mints a hub-held root key.

1. **Offline host: generate the root.** The key never leaves this host.
   ```bash
   openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-384 -nodes -days 3650 -subj "/CN=Offline Root" \
     -addext basicConstraints=critical,CA:TRUE,pathlen:1 -addext keyUsage=critical,keyCertSign,cRLSign \
     -keyout root.key -out root.pem
   ```
   Carry only `root.pem` across the gap.
2. **Hub: confirm no key is held, then propose the import** (operator A). Expect 202 and an `action_id`.
   ```bash
   curl -fsS --cacert ca.pem -H "Authorization: Bearer $T" $H/api/v1/reports/key-custody | jq '.data.keys'   # null / []
   curl -sS --cacert ca.pem -H "Authorization: Bearer $T" -H 'Content-Type: application/json' -X POST $H/api/v1/cas/import \
     -d "$(jq -n --rawfile c root.pem '{name:"Offline Root",type:"root",key_storage_type:"external",certificate_pem:$c}')"
   ```
3. **Hub: a second human approves** (operator B, different key), then operator A redeems with `approved_action_id`
   (same body plus `"approved_action_id":"<action_id>"`) and receives 201. Self-approval and the bootstrap token get 403.
   ```bash
   curl -fsS --cacert ca.pem -H "Authorization: Bearer $T_B" -X POST $H/api/v1/pending-actions/<action_id>/approve
   ```
4. **Hub: create the issuing CA; it returns a CSR** (`status: pending_certificate`, key generated in the hub keystore).
   ```bash
   curl -sS --cacert ca.pem -H "Authorization: Bearer $T" -H 'Content-Type: application/json' -X POST $H/api/v1/cas \
     -d '{"name":"Offline Issuing","type":"intermediate","parent_ca_id":"<root_id>","algorithm":"ECDSA-P256","subject_cn":"Offline Issuing"}' \
     | jq -r .data.csr_pem > issuing.csr
   ```
5. **Offline host: sign the CSR.** Carry `issuing.csr` in, `issuing.pem` out.
   ```bash
   printf 'basicConstraints=critical,CA:TRUE,pathlen:0\nkeyUsage=critical,keyCertSign,cRLSign\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid\n' > issuing.ext
   openssl x509 -req -in issuing.csr -CA root.pem -CAkey root.key -CAcreateserial -days 1825 -sha384 -extfile issuing.ext -out issuing.pem
   ```
6. **Hub: complete the issuing CA** (200, `status: active`; a second post is 409).
   ```bash
   curl -sS --cacert ca.pem -H "Authorization: Bearer $T" -H 'Content-Type: application/json' -X POST $H/api/v1/cas/<issuing_id>/certificate \
     -d "$(jq -n --rawfile c issuing.pem '{certificate_pem:$c}')"
   ```
7. **Issue the first leaf and verify it against the offline root.**
   ```bash
   openssl verify -CAfile root.pem -untrusted issuing.pem leaf.pem
   ```

**Stays offline:** `root.key`. `GET /api/v1/reports/key-custody` lists only the issuing CA's key; the root
never appears, and issuing directly from the root returns 422 `no signing key available`.
**Time:** the scripted machine time is in the Verified entry below. The human steps (carrying the CSR and
certificate over the gap, and the second approver) are not in that number and depend on your media process.
**Trust-anchor rollback:** removal is a dual-control `DELETE /api/v1/cas/<root_id>` (refused with 409 while an
active child CA exists); it sets the CA to revoked, and re-importing the same certificate reactivates it.

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

**Offline root quickstart** (`tests/live/ca-offline-root/run.sh`): ran green on 2026-10-16T01:30:55Z, commit `ed1e84c1`,
Darwin arm64, Apple M4 Max, 64 GiB RAM, OpenSSL 3.6.5 29 Sep 2026; the hub ran as a local binary on loopback. The whole scripted flow
(hub build, root, dual-control import, CSR, offline sign, complete, first leaf, `openssl verify`) took
**16 s** against a 1800 s budget; `key-custody` showed 0 keys before import and exactly 1 (the issuing
CA) after, never the root. Operator and sneakernet time are excluded.

Added with the v2 bundle (W25-13), verified by `scripts/deploy/airgap-bundle.test.sh` (fake engine, no
network): `build` refuses a missing image ref or unsigned build; `push` exits 4 with zero
`load`/`push` calls on a corrupted `.sig`, `.bundle`, `manifest.json` or image tarball (checksums
recomputed so only the signature layer catches it), and on a wrong pinned key. See
[EGRESS.md](EGRESS.md) for what the hub does when it cannot reach the internet.
