#!/usr/bin/env bash
# Render packaging/homebrew/kryptkeeper.rb.tmpl into the formula for one
# release. Called from the `homebrew-formula` job in
# .github/workflows/release.yml; also runnable by hand.
#
# Usage: render-formula.sh <checksums.txt> <tag>
#   <checksums.txt>  the release's goreleaser checksums.txt (the cosign-signed
#                    one), so the formula's sha256 is the signed value and no
#                    tarball needs downloading
#   <tag>            release tag, e.g. v1.2.3
#
# Both darwin archives must be present: the formula is two-arch.
#
# Prints the rendered formula to stdout.
set -euo pipefail

if [ "$#" -ne 2 ]; then
  echo "usage: render-formula.sh <checksums.txt> <tag>" >&2
  exit 1
fi

checksums="$1"
tag="$2"
version="${tag#v}"
# D-210: RELEASE_BASE_URL points the asset URLs at the forge hosting the release.
base_url="${RELEASE_BASE_URL:-https://github.com/bpmforge/kryptkeeper/releases/download}"

lookup_sha() {
  local archive="$1" sha
  sha="$(awk -v n="$archive" '$2 == n { print $1 }' "$checksums")"
  if ! [[ "$sha" =~ ^[0-9a-f]{64}$ ]]; then
    echo "render-formula.sh: no sha256 for $archive in $checksums" >&2
    exit 1
  fi
  printf '%s' "$sha"
}

sha_arm64="$(lookup_sha "kryptkeeper_${version}_darwin_arm64.tar.gz")"
sha_amd64="$(lookup_sha "kryptkeeper_${version}_darwin_amd64.tar.gz")"

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

sed \
  -e "s/__VERSION__/${version}/g" \
  -e "s|__BASE_URL__|${base_url}|g" \
  -e "s/__TAG__/${tag}/g" \
  -e "s/__SHA256_DARWIN_ARM64__/${sha_arm64}/g" \
  -e "s/__SHA256_DARWIN_AMD64__/${sha_amd64}/g" \
  "$script_dir/kryptkeeper.rb.tmpl"
