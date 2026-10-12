#!/usr/bin/env bash
# Render packaging/homebrew/kryptkeeper.rb.tmpl into a real formula for one
# release. Called from .github/workflows/release.yml; also runnable by hand
# for local testing.
#
# Usage: render-formula.sh <darwin_binaries_dir> <tag>
#   <darwin_binaries_dir>  directory containing kryptkeeper-darwin-amd64 and
#                          kryptkeeper-darwin-arm64 (as published in the
#                          GitHub release, e.g. downloaded release artifacts)
#   <tag>                  release tag, e.g. v1.2.3
#
# Prints the rendered formula to stdout.
set -euo pipefail

if [ "$#" -ne 2 ]; then
  echo "usage: render-formula.sh <darwin_binaries_dir> <tag>" >&2
  exit 1
fi

bin_dir="$1"
tag="$2"
version="${tag#v}"

amd64_bin="$bin_dir/kryptkeeper-darwin-amd64"
arm64_bin="$bin_dir/kryptkeeper-darwin-arm64"

for f in "$amd64_bin" "$arm64_bin"; do
  if [ ! -f "$f" ]; then
    echo "render-formula.sh: missing $f" >&2
    exit 1
  fi
done

sha256_tool() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
  else
    shasum -a 256 "$1" | awk '{print $1}'
  fi
}

sha_amd64="$(sha256_tool "$amd64_bin")"
sha_arm64="$(sha256_tool "$arm64_bin")"

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
template="$script_dir/kryptkeeper.rb.tmpl"

sed \
  -e "s/__VERSION__/${version}/g" \
  -e "s/__TAG__/${tag}/g" \
  -e "s/__SHA256_DARWIN_AMD64__/${sha_amd64}/g" \
  -e "s/__SHA256_DARWIN_ARM64__/${sha_arm64}/g" \
  "$template"
