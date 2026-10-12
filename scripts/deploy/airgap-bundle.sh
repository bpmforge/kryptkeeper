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
#   Required env:
#     HUB_IMAGE        - tag-form ref of the Kryptkeeper Hub image, e.g.
#                         ghcr.io/bpmforge/kryptkeeper:v1.2.3
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
#     manifest.json                  - {schema_version, created_at, images[], charts[]}
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
#   Verifies SHA256SUMS first and fails closed on any mismatch -- never
#   pushes an unverified bundle. For each image: loads the tarball, retags it
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

  local chart_dirs="${CHART_DIRS:-charts/kryptkeeper}"
  local engine
  engine="$(resolve_engine)"
  command -v helm >/dev/null 2>&1 || { echo "ERROR: helm not found on PATH" >&2; exit 3; }
  command -v jq >/dev/null 2>&1 || { echo "ERROR: jq not found on PATH" >&2; exit 3; }
  command -v sha256sum >/dev/null 2>&1 || { echo "ERROR: sha256sum not found on PATH" >&2; exit 3; }

  local all_images=("$HUB_IMAGE")
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

    image_entries+=("$(jq -n --arg ref "$ref" --arg file "images/$file" --arg arch "$arch" --arg os "$os" \
      '{ref: $ref, file: $file, architecture: $arch, os: $os}')")
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
    chart_entries+=("$(jq -n --arg file "charts/$pkg_file" '{file: $file}')")
  done

  local images_json charts_json created_at
  images_json="$(printf '%s\n' "${image_entries[@]}" | jq -s '.')"
  charts_json="$(printf '%s\n' "${chart_entries[@]}" | jq -s '.')"
  created_at="$(date -u +%Y%m%dT%H%M%SZ)"

  jq -n --arg created_at "$created_at" --argjson images "$images_json" --argjson charts "$charts_json" \
    '{schema_version: 1, created_at: $created_at, images: $images, charts: $charts}' \
    > "$out_dir/manifest.json"

  # Copy this script itself into the bundle so the air-gapped side (no reach
  # back to this repo checkout) has `push` available -- the bundle is
  # everything you carry across the gap, nothing else.
  cp "${BASH_SOURCE[0]}" "$out_dir/airgap-bundle.sh"
  chmod +x "$out_dir/airgap-bundle.sh"

  ( cd "$out_dir" && sha256sum images/*.tar charts/*.tgz manifest.json airgap-bundle.sh > SHA256SUMS )

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

  echo "[airgap-bundle] verifying checksums..."
  ( cd "$bundle_dir" && sha256sum -c SHA256SUMS )

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
