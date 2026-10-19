#!/usr/bin/env bash
# W32-03: fail a release when docs/openapi.yaml info.version differs from the git tag.
#
# usage: scripts/check-spec-version.sh <tag> [spec-file]
#   <tag>  e.g. v0.20.0 (a leading "v" is optional)
#   exit 0 equal, 1 differ/empty, 2 usage or missing spec file
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TAG="${1:-}"
SPEC="${2:-$ROOT_DIR/docs/openapi.yaml}"

if [ -z "$TAG" ]; then
  echo "usage: $0 <tag> [spec-file]" >&2
  exit 2
fi
if [ ! -f "$SPEC" ]; then
  echo "[spec-version] FAIL spec file not found: $SPEC" >&2
  exit 2
fi

SPEC_VERSION="$(sed -n 's/^  version: "\(.*\)"/\1/p' "$SPEC" | head -1)"
TAG_VERSION="${TAG#v}"

if [ -z "$SPEC_VERSION" ] || [ -z "$TAG_VERSION" ] || [ "$SPEC_VERSION" != "$TAG_VERSION" ]; then
  echo "[spec-version] FAIL spec=${SPEC_VERSION} tag=${TAG_VERSION}" >&2
  exit 1
fi
echo "[spec-version] OK ${SPEC_VERSION}"
