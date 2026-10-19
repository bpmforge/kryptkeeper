#!/usr/bin/env bash
# W32-02: generate Go, TypeScript and Python client SDKs from docs/openapi.yaml.
#
# usage: scripts/gen-sdks.sh [--version X.Y.Z] [--check]
#   SPEC=<path>   override the spec (default docs/openapi.yaml; used by the
#                 duplicate-operationId negative test)
#   --check       also compile/typecheck all three SDKs (what CI runs)
#
# Generator: openapi-generator 7.x (the one tool covering all three languages
# from an OpenAPI 3.1.0 spec). Pinned below. It runs from the pinned jar when a
# working `java` exists (CI ubuntu runners), else from the pinned container
# image via podman/docker (local dev; container is named kkw32-* and removed).
# Fallback if 3.1 handling ever regresses: oapi-codegen (Go),
# openapi-typescript + openapi-fetch (TS), openapi-python-client (Py).
#
# Output: generated SDKs land in sdk/api-{go,ts,py} (git-ignored) and release
# archives in dist/sdk-release/. Spec servers are relative (/api/v1): set the
# client base URL, e.g. BASE_URL = https://hub.example.com/api/v1.
set -euo pipefail

OPENAPI_GENERATOR_VERSION="7.25.0"   # released 2026-08-24
OPENAPI_GENERATOR_JAR_SHA256="41ce4f6b07f196676439d710759fa1ced7a08066d06ff1bf314681470289efae"
OPENAPI_GENERATOR_IMAGE="docker.io/openapitools/openapi-generator-cli:v${OPENAPI_GENERATOR_VERSION}"

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
SPEC="${SPEC:-docs/openapi.yaml}"
VERSION=""
CHECK=0
while [ $# -gt 0 ]; do
  case "$1" in
    --version) VERSION="${2:?--version needs a value}"; shift 2 ;;
    --check) CHECK=1; shift ;;
    *) echo "usage: $0 [--version X.Y.Z] [--check]" >&2; exit 2 ;;
  esac
done
[ -f "$SPEC" ] || { echo "[gen-sdks] FAIL spec not found: $SPEC" >&2; exit 2; }
if [ -z "$VERSION" ]; then
  VERSION="$(sed -n 's/^  version: "\(.*\)"/\1/p' "$SPEC" | head -1)"
fi
[ -n "$VERSION" ] || { echo "[gen-sdks] FAIL cannot determine version" >&2; exit 1; }

# 2. Collision gate first: duplicate operationIds make generators rename methods.
dups="$(grep -o 'operationId: .*' "$SPEC" | sort | uniq -d || true)"
if [ -n "$dups" ]; then
  echo "[gen-sdks] FAIL duplicate operationId(s):" >&2
  echo "$dups" >&2
  exit 1
fi
echo "[gen-sdks] $(grep -c 'operationId:' "$SPEC") operationIds, 0 collisions; version $VERSION"

WORK="$ROOT/dist/sdk-work"
rm -rf "$WORK"
mkdir -p "$WORK/out"
cp "$SPEC" "$WORK/openapi.yaml"

CNAME="kkw32-gen-$$"
cleanup() { [ -n "${RT:-}" ] && "$RT" rm -f "$CNAME" >/dev/null 2>&1 || true; }
trap cleanup EXIT

if java -version >/dev/null 2>&1; then
  JAR="$ROOT/dist/.cache/openapi-generator-cli-${OPENAPI_GENERATOR_VERSION}.jar"
  if [ ! -f "$JAR" ]; then
    mkdir -p "$(dirname "$JAR")"
    curl -fsSL -o "$JAR.tmp" "https://repo1.maven.org/maven2/org/openapitools/openapi-generator-cli/${OPENAPI_GENERATOR_VERSION}/openapi-generator-cli-${OPENAPI_GENERATOR_VERSION}.jar"
    mv "$JAR.tmp" "$JAR"
  fi
  got="$( (sha256sum "$JAR" 2>/dev/null || shasum -a 256 "$JAR") | cut -d' ' -f1)"
  [ "$got" = "$OPENAPI_GENERATOR_JAR_SHA256" ] || { echo "[gen-sdks] FAIL generator jar sha256 mismatch ($got)" >&2; rm -f "$JAR"; exit 1; }
  echo "[gen-sdks] generator: java -jar openapi-generator-cli $OPENAPI_GENERATOR_VERSION"
  gen() { java -jar "$JAR" generate -i "$WORK/openapi.yaml" -o "$WORK/out/$2" -g "$1" --additional-properties="$3" "${@:4}"; }
else
  RT=""
  for c in podman docker; do command -v "$c" >/dev/null 2>&1 && { RT="$c"; break; }; done
  [ -n "$RT" ] || { echo "[gen-sdks] FAIL need java (jar) or podman/docker (container image)" >&2; exit 1; }
  echo "[gen-sdks] generator: $RT $OPENAPI_GENERATOR_IMAGE"
  gen() { "$RT" run --rm --name "$CNAME" -v "$WORK:/local" "$OPENAPI_GENERATOR_IMAGE" generate -i /local/openapi.yaml -o "/local/out/$2" -g "$1" --additional-properties="$3" "${@:4}"; }
fi

# 3. Generate. The go generator has no moduleName option: go.mod is derived from the git ids
# plus packageName, giving github.com/bpmforge/kryptkeeper/sdk/api-go/kryptkeeperapi.
gen go api-go "packageName=kryptkeeperapi,isGoSubmodule=true" \
  --git-host github.com --git-user-id bpmforge --git-repo-id kryptkeeper/sdk/api-go
gen typescript-fetch api-ts "npmName=@bpmforge/kryptkeeper-api,npmVersion=$VERSION,supportsES6=true"
gen python api-py "packageName=kryptkeeper_api,packageVersion=$VERSION"

for l in go ts py; do
  rm -rf "sdk/api-$l.new"
  mkdir -p "sdk/api-$l.new"
  cp -R "$WORK/out/api-$l/." "sdk/api-$l.new/"
  # keep the committed README/.gitignore, replace everything else
  find "sdk/api-$l" -mindepth 1 -maxdepth 1 ! -name README.md ! -name .gitignore -exec rm -rf {} + 2>/dev/null || true
  rm -f "sdk/api-$l.new/README.md" "sdk/api-$l.new/.gitignore"
  cp -R "sdk/api-$l.new/." "sdk/api-$l/"
  rm -rf "sdk/api-$l.new"
done

# 4. Compile/typecheck.
if [ "$CHECK" = 1 ]; then
  (cd sdk/api-go && go mod tidy >/dev/null 2>&1 || true; go build ./...)
  (cd sdk/api-ts && npm install --no-audit --no-fund && npx tsc --noEmit)
  python3 -m compileall -q sdk/api-py
  echo "[gen-sdks] check OK (go build, tsc, compileall)"
fi

# 5. Package for release.
REL="$ROOT/dist/sdk-release"
rm -rf "$REL"
mkdir -p "$REL"
tar -czf "$REL/kryptkeeper-api-go-$VERSION.tar.gz" -C sdk api-go
tar -czf "$REL/kryptkeeper-api-py-$VERSION.tar.gz" -C sdk api-py
(cd sdk/api-ts && npm pack --silent --pack-destination "$REL" >/dev/null)
ls "$REL"/kryptkeeper-api-ts-*.tgz >/dev/null 2>&1 || {
  # npm pack names it after npmName (@bpmforge/kryptkeeper-api -> bpmforge-kryptkeeper-api-X.tgz)
  f="$(ls "$REL"/*.tgz | head -1)"
  mv "$f" "$REL/kryptkeeper-api-ts-$VERSION.tgz"
}
echo "[gen-sdks] OK"; ls "$REL"
