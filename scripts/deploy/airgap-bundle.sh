#!/usr/bin/env bash
set -euo pipefail

# Build and load an air-gap install bundle for Kryptkeeper: container image
# tarballs + the packaged Helm chart, transferred across the gap and pushed
# into a private registry mirror. See docs/ops/AIRGAP_INSTALL.md for the full
# procedure this script implements.
#
# Usage:
#   scripts/deploy/airgap-bundle.sh build <out_dir>
#   scripts/deploy/airgap-bundle.sh push  <bundle_dir> <registry_host>
#
# build (run on an internet-connected host):
#   Required env (all tag-form, a bundle can never silently ship fewer):
#     HUB_IMAGE         - Hub image, e.g. ghcr.io/bpmforge/kryptkeeper:v1.2.3
#     AGENT_IMAGE       - ghcr.io/bpmforge/kryptkeeper-agent:<tag>
#     MCP_IMAGE         - ghcr.io/bpmforge/kryptkeeper-mcp:<tag>
#     CERTMANAGER_IMAGE - ghcr.io/bpmforge/kryptkeeper-certmanager:<tag>
#     DASHBOARD_IMAGE   - ghcr.io/bpmforge/kryptkeeper-dashboard:<tag> (the chart's
#                         dashboard Deployment uses this separate image, so it is
#                         bundled; see charts/kryptkeeper/values.yaml dashboard.image)
#   Signing (exactly one required; an unsigned bundle is refused, exit 2):
#     COSIGN_KEY        - path to a cosign private key; COSIGN_PUBKEY (path to the
#                         matching .pub) is copied into the bundle as cosign.pub
#     COSIGN_KEYLESS=1  - keyless (OIDC) signing; no cosign.pub is shipped
#   Optional env:
#     EXTRA_IMAGES      - additional tag-form image refs to bundle, space-
#                         separated, e.g. "docker.io/library/postgres:16-alpine"
#     CHART_DIRS        - local chart directories to package, space-separated,
#                         relative to the repo root (default: "charts/kryptkeeper")
#     CONTAINER_ENGINE  - "docker" or "podman" (default: auto-detect, docker
#                         preferred)
#
#   Every image ref must be tag-form, not digest-form (image@sha256:...). A
#   save/load round trip of a digest-only ref comes back locally with no
#   repository or tag (verified against podman: `load` reports only
#   "Loaded image: sha256:<id>"), which push then has no name left to retag
#   into the mirror by. Pull or build the image under a tag first.
#
#   Output (in <out_dir> -- this whole directory is everything you carry
#   across the gap; nothing else from the build host is required, including
#   this script -- build copies itself in so <out_dir>/airgap-bundle.sh push
#   is runnable with no repo checkout on the air-gapped side):
#     images/<sanitized-ref>.tar    - one per HUB_IMAGE/EXTRA_IMAGES entry
#     charts/<chart>-<version>.tgz  - one per CHART_DIRS entry
#     manifest.json                  - {schema_version: 2, created_at, images[], charts[], signature}
#                                      (images[]/charts[] carry the sha256 of each file)
#     manifest.json.sig/.bundle      - cosign signature + bundle over manifest.json
#     cosign.pub                     - public key (key-based signing only)
#     airgap-bundle.sh               - a copy of this script
#     SHA256SUMS                     - checksums of every artifact above
#
#   manifest.json records each image's architecture/os (from `image inspect`)
#   so a single-arch build host's limitation is visible in the bundle itself
#   rather than discovered only when a pod fails to start inside the gap.
#   This script does not cross-build or multi-arch-save -- run it on a build
#   host matching your air-gapped cluster's node architecture, or run it once
#   per architecture into separate <out_dir>s.
#
# push (run on the air-gapped host: reach to your private registry mirror,
#       no reach to the public internet):
#   Required positional:
#     <bundle_dir>      - a directory produced by `build` (must contain
#                         manifest.json + SHA256SUMS)
#     <registry_host>   - private registry host[:port] to push into, e.g.
#                         registry.internal.example.com:5000
#   Optional env:
#     CONTAINER_ENGINE  - same as build
#
#   Verifies SHA256SUMS first and fails closed on any mismatch, then verifies
#   the cosign signature over manifest.json OFFLINE (`cosign verify-blob
#   --insecure-ignore-tlog=true`: the Rekor transparency log is unreachable
#   inside the gap, so the check rests on the signing key alone), then checks
#   every image/chart file against the sha256 recorded in the signed manifest.
#   Any failure exits 4 before a single load/push. Key trust: set COSIGN_PUBKEY
#   to a key you obtained out-of-band; otherwise the bundle's own cosign.pub is
#   used, which only proves integrity, not origin. Keyless bundles require
#   COSIGN_CERT_IDENTITY and COSIGN_CERT_OIDC_ISSUER. For each image: loads the tarball, retags it
#   from its original registry host onto <registry_host> (keeping the
#   repository path and tag), and pushes. Prints the final ref mapping so you
#   can fill in `--set image.repository=... --set image.tag=...` for `helm
#   install` from <bundle_dir>/charts/*.tgz.

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

usage() {
  cat <<'USAGE'
Usage:
  scripts/deploy/airgap-bundle.sh build <out_dir>
  scripts/deploy/airgap-bundle.sh push  <bundle_dir> <registry_host>
USAGE
}

resolve_engine() {
  if [[ -n "${CONTAINER_ENGINE:-}" ]]; then
    echo "$CONTAINER_ENGINE"
    return
  fi
  if command -v docker >/dev/null 2>&1; then
    echo docker
    return
  fi
  if command -v podman >/dev/null 2>&1; then
    echo podman
    return
  fi
  echo "ERROR: neither docker nor podman found on PATH (set CONTAINER_ENGINE to override)" >&2
  exit 3
}

sanitize_ref() {
  echo "$1" | tr '/:@' '_'
}

# Rewrite the registry host of an image ref onto $1, keeping the repository
# path and tag. A ref's first path segment is a registry host if it contains
# "." or ":" or is exactly "localhost" (same heuristic docker itself uses to
# tell "ghcr.io/foo/bar" from an implied "docker.io/library/postgres");
# otherwise the whole ref is the repository path under the new registry.
rewrite_registry() {
  local registry_host="$1" ref="$2"
  local first="${ref%%/*}" rest="${ref#*/}"
  if [[ "$ref" == */* && ( "$first" == *.* || "$first" == *:* || "$first" == "localhost" ) ]]; then
    echo "${registry_host}/${rest}"
  else
    echo "${registry_host}/${ref}"
  fi
}

cmd_build() {
  local out_dir="${1:-}"
  if [[ -z "$out_dir" ]]; then
    echo "Usage: $0 build <out_dir>" >&2
    exit 2
  fi
  : "${HUB_IMAGE:?HUB_IMAGE is required (tag-form ref, e.g. ghcr.io/bpmforge/kryptkeeper:v1.2.3)}"
  local v
  for v in AGENT_IMAGE MCP_IMAGE CERTMANAGER_IMAGE DASHBOARD_IMAGE; do
    if [[ -z "${!v:-}" ]]; then
      echo "ERROR: $v is required (tag-form ref); a bundle must ship hub, agent, mcp, certmanager and dashboard images" >&2
      exit 2
    fi
  done
  local sign_mode
  if [[ -n "${COSIGN_KEY:-}" ]]; then
    sign_mode=key
  elif [[ "${COSIGN_KEYLESS:-}" == "1" ]]; then
    sign_mode=keyless
  else
    echo "ERROR: refusing to build an unsigned bundle; set COSIGN_KEY or COSIGN_KEYLESS=1" >&2
    exit 2
  fi
  if [[ "$sign_mode" == key && ( -z "${COSIGN_PUBKEY:-}" || ! -f "$COSIGN_PUBKEY" ) ]]; then
    echo "ERROR: COSIGN_KEY requires COSIGN_PUBKEY (path to the matching .pub) so the bundle can ship cosign.pub" >&2
    exit 2
  fi

  local chart_dirs="${CHART_DIRS:-charts/kryptkeeper}"
  local engine
  engine="$(resolve_engine)"
  command -v helm >/dev/null 2>&1 || { echo "ERROR: helm not found on PATH" >&2; exit 3; }
  command -v jq >/dev/null 2>&1 || { echo "ERROR: jq not found on PATH" >&2; exit 3; }
  command -v sha256sum >/dev/null 2>&1 || { echo "ERROR: sha256sum not found on PATH" >&2; exit 3; }
  command -v cosign >/dev/null 2>&1 || { echo "ERROR: cosign not found on PATH" >&2; exit 3; }

  local all_images=("$HUB_IMAGE" "$AGENT_IMAGE" "$MCP_IMAGE" "$CERTMANAGER_IMAGE" "$DASHBOARD_IMAGE")
  if [[ -n "${EXTRA_IMAGES:-}" ]]; then
    # shellcheck disable=SC2206
    all_images+=(${EXTRA_IMAGES})
  fi

  local ref
  for ref in "${all_images[@]}"; do
    if [[ "$ref" == *@sha256:* ]]; then
      echo "ERROR: '$ref' is a digest-form ref. build needs a tag-form ref -- see the digest-ref note" >&2
      echo "       at the top of this script. Pull or build it under a tag first, e.g.:" >&2
      echo "         $engine tag <ref> myrepo/kryptkeeper:v1.2.3" >&2
      exit 2
    fi
  done

  mkdir -p "$out_dir/images" "$out_dir/charts"

  echo "[airgap-bundle] engine=$engine images=${#all_images[@]} charts=$chart_dirs"

  local image_entries=()
  for ref in "${all_images[@]}"; do
    if "$engine" image inspect "$ref" >/dev/null 2>&1; then
      echo "[airgap-bundle] using local image $ref (already present)"
    else
      echo "[airgap-bundle] pulling $ref..."
      "$engine" pull "$ref"
    fi

    local arch_os arch os file
    arch_os="$("$engine" image inspect "$ref" --format '{{.Architecture}} {{.Os}}')"
    arch="${arch_os%% *}"
    os="${arch_os##* }"
    file="$(sanitize_ref "$ref").tar"

    echo "[airgap-bundle] saving $ref (${os}/${arch}) -> images/$file"
    "$engine" save "$ref" -o "$out_dir/images/$file"

    local sum
    sum="$(sha256sum "$out_dir/images/$file" | cut -d' ' -f1)"
    image_entries+=("$(jq -n --arg ref "$ref" --arg file "images/$file" --arg arch "$arch" --arg os "$os" --arg sum "$sum" \
      '{ref: $ref, file: $file, architecture: $arch, os: $os, sha256: $sum}')")
  done

  local chart_entries=()
  local dir
  for dir in $chart_dirs; do
    local chart_path="$ROOT_DIR/$dir"
    if [[ ! -f "$chart_path/Chart.yaml" ]]; then
      echo "ERROR: $chart_path is not a Helm chart directory (no Chart.yaml)" >&2
      exit 2
    fi
    echo "[airgap-bundle] packaging chart $dir..."
    local pkg_line pkg_file
    pkg_line="$(helm package "$chart_path" -d "$out_dir/charts")"
    pkg_file="$(basename "${pkg_line##*saved it to: }")"
    chart_entries+=("$(jq -n --arg file "charts/$pkg_file" --arg sum "$(sha256sum "$out_dir/charts/$pkg_file" | cut -d' ' -f1)" \
      '{file: $file, sha256: $sum}')")
  done

  local images_json charts_json created_at
  images_json="$(printf '%s\n' "${image_entries[@]}" | jq -s '.')"
  charts_json="$(printf '%s\n' "${chart_entries[@]}" | jq -s '.')"
  created_at="$(date -u +%Y%m%dT%H%M%SZ)"

  jq -n --arg created_at "$created_at" --argjson images "$images_json" --argjson charts "$charts_json" \
    '{schema_version: 2, created_at: $created_at, images: $images, charts: $charts,
      signature: {file: "manifest.json.sig", bundle: "manifest.json.bundle"}}' \
    > "$out_dir/manifest.json"

  echo "[airgap-bundle] signing manifest.json (mode=$sign_mode)..."
  local sign_args=(sign-blob --yes --bundle "$out_dir/manifest.json.bundle" --output-signature "$out_dir/manifest.json.sig")
  if [[ "$sign_mode" == key ]]; then
    sign_args+=(--key "$COSIGN_KEY")
    # Key-based bundles are verified offline with --insecure-ignore-tlog, so do
    # not contact Rekor/TUF at sign time either (cosign 3.x flag; absent in 2.x).
    if cosign sign-blob --help 2>&1 | grep -q -- '--use-signing-config'; then
      sign_args+=(--use-signing-config=false --tlog-upload=false)
    fi
    cp "$COSIGN_PUBKEY" "$out_dir/cosign.pub"
  fi
  cosign "${sign_args[@]}" "$out_dir/manifest.json"
  # cosign 3.x ignores --output-signature when writing the new-format bundle;
  # the raw signature is the bundle's messageSignature, so emit it ourselves.
  if [[ ! -s "$out_dir/manifest.json.sig" ]]; then
    jq -er '.messageSignature.signature' "$out_dir/manifest.json.bundle" > "$out_dir/manifest.json.sig"
  fi

  # Copy this script itself into the bundle so the air-gapped side (no reach
  # back to this repo checkout) has `push` available -- the bundle is
  # everything you carry across the gap, nothing else.
  cp "${BASH_SOURCE[0]}" "$out_dir/airgap-bundle.sh"
  chmod +x "$out_dir/airgap-bundle.sh"

  local extra_sums=(manifest.json.sig manifest.json.bundle)
  [[ -f "$out_dir/cosign.pub" ]] && extra_sums+=(cosign.pub)
  ( cd "$out_dir" && sha256sum images/*.tar charts/*.tgz manifest.json airgap-bundle.sh "${extra_sums[@]}" > SHA256SUMS )

  echo "[airgap-bundle] bundle written to $out_dir ($(du -sh "$out_dir" | cut -f1))"
  echo "[airgap-bundle] transfer $out_dir across the gap, then on the other side run:"
  echo "[airgap-bundle]   $out_dir/airgap-bundle.sh push $out_dir <registry_host>"
}

cmd_push() {
  local bundle_dir="${1:-}" registry_host="${2:-}"
  if [[ -z "$bundle_dir" || -z "$registry_host" ]]; then
    echo "Usage: $0 push <bundle_dir> <registry_host>" >&2
    exit 2
  fi
  if [[ "$registry_host" == *"://"* ]]; then
    echo "ERROR: registry_host must be host[:port], not a URL (got '$registry_host')" >&2
    exit 2
  fi
  if [[ ! -f "$bundle_dir/manifest.json" ]]; then
    echo "ERROR: $bundle_dir/manifest.json not found -- not a bundle produced by '$0 build'" >&2
    exit 2
  fi

  local engine
  engine="$(resolve_engine)"
  command -v jq >/dev/null 2>&1 || { echo "ERROR: jq not found on PATH" >&2; exit 3; }
  command -v sha256sum >/dev/null 2>&1 || { echo "ERROR: sha256sum not found on PATH" >&2; exit 3; }
  command -v cosign >/dev/null 2>&1 || { echo "ERROR: cosign not found on PATH" >&2; exit 3; }

  echo "[airgap-bundle] verifying checksums..."
  ( cd "$bundle_dir" && sha256sum -c SHA256SUMS )

  echo "[airgap-bundle] verifying manifest signature offline..."
  local verify_args=(verify-blob --bundle "$bundle_dir/manifest.json.bundle" --insecure-ignore-tlog=true)
  local pubkey="${COSIGN_PUBKEY:-$bundle_dir/cosign.pub}"
  if [[ -n "${COSIGN_PUBKEY:-}" || -f "$bundle_dir/cosign.pub" ]]; then
    verify_args+=(--key "$pubkey")
  else
    if [[ -z "${COSIGN_CERT_IDENTITY:-}" || -z "${COSIGN_CERT_OIDC_ISSUER:-}" ]]; then
      echo "ERROR: keyless bundle: COSIGN_CERT_IDENTITY and COSIGN_CERT_OIDC_ISSUER are required" >&2
      exit 2
    fi
    verify_args+=(--certificate-identity "$COSIGN_CERT_IDENTITY" --certificate-oidc-issuer "$COSIGN_CERT_OIDC_ISSUER")
  fi
  local raw_ok=1
  if [[ " ${verify_args[*]} " == *" --key "* ]]; then
    # Key-based bundle: the detached signature must verify too, not just the bundle.
    cosign verify-blob --key "$pubkey" --signature "$bundle_dir/manifest.json.sig" \
      --insecure-ignore-tlog=true "$bundle_dir/manifest.json" || raw_ok=0
  fi
  if [[ $raw_ok -ne 1 || ! -f "$bundle_dir/manifest.json.bundle" ]] || ! cosign "${verify_args[@]}" "$bundle_dir/manifest.json"; then
    echo "ERROR: manifest signature verification failed -- refusing to push" >&2
    exit 4
  fi

  if [[ "$(jq -r '.schema_version' "$bundle_dir/manifest.json")" != "2" ]]; then
    echo "ERROR: unsupported manifest schema_version (need 2) -- rebuild the bundle" >&2
    exit 4
  fi

  # SHA256SUMS is unsigned; bind every payload file to the signed manifest.
  local efile esum
  while IFS=$'\t' read -r efile esum; do
    if [[ -z "$esum" || "$(sha256sum "$bundle_dir/$efile" | cut -d' ' -f1)" != "$esum" ]]; then
      echo "ERROR: $efile does not match the sha256 in the signed manifest -- refusing to push" >&2
      exit 4
    fi
  done < <(jq -r '(.images + .charts)[] | [.file, (.sha256 // "")] | @tsv' "$bundle_dir/manifest.json")

  local count
  count="$(jq '.images | length' "$bundle_dir/manifest.json")"
  echo "[airgap-bundle] pushing $count image(s) into $registry_host..."

  local mapping=()
  local i
  for (( i = 0; i < count; i++ )); do
    local ref file target
    ref="$(jq -r ".images[$i].ref" "$bundle_dir/manifest.json")"
    file="$(jq -r ".images[$i].file" "$bundle_dir/manifest.json")"
    target="$(rewrite_registry "$registry_host" "$ref")"

    echo "[airgap-bundle] loading $file..."
    "$engine" load -i "$bundle_dir/$file"

    echo "[airgap-bundle] $ref -> $target"
    "$engine" tag "$ref" "$target"
    "$engine" push "$target"

    mapping+=("$ref -> $target")
  done

  echo "[airgap-bundle] done. Image mapping:"
  local m
  for m in "${mapping[@]}"; do
    echo "[airgap-bundle]   $m"
  done
  echo "[airgap-bundle] chart(s) available in $bundle_dir/charts/*.tgz -- install with, e.g.:"
  echo "[airgap-bundle]   helm install kryptkeeper $bundle_dir/charts/kryptkeeper-*.tgz \\"
  echo "[airgap-bundle]     --set image.repository=<mirrored-hub-repo> --set image.tag=<tag> ..."
}

MODE="${1:-}"
[[ $# -gt 0 ]] && shift

case "$MODE" in
  build) cmd_build "$@" ;;
  push) cmd_push "$@" ;;
  -h|--help) usage; exit 0 ;;
  "")
    usage >&2
    exit 2
    ;;
  *)
    echo "ERROR: unknown subcommand '$MODE'" >&2
    usage
    exit 2
    ;;
esac
