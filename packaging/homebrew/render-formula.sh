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
# Prints the rendered formula to stdout.
set -euo pipefail

if [ "$#" -ne 2 ]; then
  echo "usage: render-formula.sh <checksums.txt> <tag>" >&2
  exit 1
fi

checksums="$1"
tag="$2"
version="${tag#v}"

archive="kryptkeeper_${version}_darwin_arm64.tar.gz"
sha="$(awk -v n="$archive" '$2 == n { print $1 }' "$checksums")"
if ! [[ "$sha" =~ ^[0-9a-f]{64}$ ]]; then
  echo "render-formula.sh: no sha256 for $archive in $checksums" >&2
  exit 1
fi

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

sed \
  -e "s/__VERSION__/${version}/g" \
  -e "s/__TAG__/${tag}/g" \
  -e "s/__SHA256_DARWIN_ARM64__/${sha}/g" \
  "$script_dir/kryptkeeper.rb.tmpl"
