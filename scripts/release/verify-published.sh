#!/usr/bin/env bash
# W37-09 / D-312: verify a published release from the outside. Downloads the
# release assets from the public GitHub release, then checks
#   1. checksums.txt carries a valid keyless cosign signature (release.yml identity),
#   2. every file listed in checksums.txt exists and matches its sha256,
#   3. the four images and the OCI chart carry a keyless cosign signature.
# Every failure is collected and named; the exit status is 1 if there is any.
#
# Usage: verify-published.sh <tag> [--repo OWNER/NAME] [--local DIR] [--skip-cosign]
#   --local DIR    verify a directory of already-downloaded assets (offline:
#                  implies --skip-cosign, no network at all). Used by the test.
#   --skip-cosign  run only the checksum comparison.
# Environment: IDENTITY_REGEXP, OIDC_ISSUER (see helm-oci.sh), IMAGE_BASE
# (default ghcr.io/bpmforge), CHART_REF (default $IMAGE_BASE/charts/kryptkeeper).
set -euo pipefail

IDENTITY_REGEXP="${IDENTITY_REGEXP:-^https://github\\.com/bpmforge/kryptkeeper/\\.github/workflows/release\\.yml@refs/tags/v}"
OIDC_ISSUER="${OIDC_ISSUER:-https://token.actions.githubusercontent.com}"
IMAGE_BASE="${IMAGE_BASE:-ghcr.io/bpmforge}"
CHART_REF="${CHART_REF:-$IMAGE_BASE/charts/kryptkeeper}"
repo="bpmforge/kryptkeeper"
local_dir=""
skip_cosign=0
tag=""

while [ $# -gt 0 ]; do
  case "$1" in
    --repo) repo="${2:?--repo needs a value}"; shift ;;
    --local) local_dir="${2:?--local needs a directory}"; skip_cosign=1; shift ;;
    --skip-cosign) skip_cosign=1 ;;
    -h|--help) sed -n '2,15p' "$0"; exit 0 ;;
    -*) echo "unknown flag: $1" >&2; exit 2 ;;
    *) tag="$1" ;;
  esac
  shift
done
[ -n "$tag" ] || { echo "usage: verify-published.sh <tag> [--repo O/N] [--local DIR] [--skip-cosign]" >&2; exit 2; }
version="${tag#v}"

failures=()
fail() { failures+=("$1"); echo "FAIL: $1" >&2; }

sha256_of() {
  if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | awk '{print $1}'
  else shasum -a 256 "$1" | awk '{print $1}'; fi
}

if [ -n "$local_dir" ]; then
  dir="$local_dir"
  [ -d "$dir" ] || { echo "error: $dir is not a directory" >&2; exit 2; }
else
  dir="$(mktemp -d)"
  echo "==> downloading $repo $tag assets to $dir"
  gh release download "$tag" --repo "$repo" --dir "$dir" || fail "could not download release assets for $tag from $repo"
fi

# 1. checksums.txt signature
if [ ! -s "$dir/checksums.txt" ]; then
  fail "checksums.txt is missing or empty"
elif [ "$skip_cosign" = 1 ]; then
  echo "SKIP: cosign verify-blob checksums.txt (offline or --skip-cosign)"
elif ! command -v cosign >/dev/null 2>&1; then
  fail "cosign is not installed, cannot verify checksums.txt signature"
else
  for f in checksums.txt.sig checksums.txt.pem; do
    [ -s "$dir/$f" ] || fail "$f is missing from the release"
  done
  cosign verify-blob \
    --certificate-identity-regexp "$IDENTITY_REGEXP" \
    --certificate-oidc-issuer "$OIDC_ISSUER" \
    --signature "$dir/checksums.txt.sig" \
    --certificate "$dir/checksums.txt.pem" \
    "$dir/checksums.txt" >/dev/null 2>&1 || fail "cosign verify-blob rejected checksums.txt (signature, certificate or identity)"
fi

# 2. every listed asset against checksums.txt
checked=0
if [ -s "$dir/checksums.txt" ]; then
  while read -r want name; do
    [ -n "${want:-}" ] || continue
    name="${name#\*}"
    if [ ! -f "$dir/$name" ]; then
      fail "asset $name is listed in checksums.txt but missing from the release"
      continue
    fi
    got="$(sha256_of "$dir/$name")"
    if [ "$got" != "$want" ]; then
      fail "sha256 mismatch for $name (checksums.txt $want, asset $got)"
    fi
    checked=$((checked + 1))
  done < "$dir/checksums.txt"
  [ "$checked" -gt 0 ] || fail "checksums.txt lists no verifiable assets"
  echo "checked sha256 of $checked asset(s)"
fi

# 3. images and chart
if [ "$skip_cosign" = 1 ]; then
  echo "SKIP: cosign verify of images and chart (offline or --skip-cosign)"
elif command -v cosign >/dev/null 2>&1; then
  for img in kryptkeeper kryptkeeper-agent kryptkeeper-certmanager kryptkeeper-mcp; do
    cosign verify --certificate-identity-regexp "$IDENTITY_REGEXP" --certificate-oidc-issuer "$OIDC_ISSUER" \
      "$IMAGE_BASE/$img:$version" >/dev/null 2>&1 || fail "cosign verify failed for image $IMAGE_BASE/$img:$version"
  done
  cosign verify --certificate-identity-regexp "$IDENTITY_REGEXP" --certificate-oidc-issuer "$OIDC_ISSUER" \
    "$CHART_REF:$version" >/dev/null 2>&1 || fail "cosign verify failed for chart $CHART_REF:$version"
fi

if [ "${#failures[@]}" -gt 0 ]; then
  echo "verification of $tag FAILED (${#failures[@]}):" >&2
  printf '  - %s\n' "${failures[@]}" >&2
  exit 1
fi
echo "release $tag verified"
