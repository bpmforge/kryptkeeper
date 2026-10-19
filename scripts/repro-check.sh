#!/usr/bin/env bash
# W33-09: reproducible-build and SBOM-completeness checks for releases.
#
#   repro-check.sh rebuild [--snapshot]  build HEAD twice in two clean clones (different
#                                        absolute paths) and compare sha256 of the 4
#                                        linux/amd64 binaries; exit 1 on any DIFF
#   repro-check.sh sbom <dir>            every module linked into the 4 shipped commands
#                                        must appear in <dir>/*.cyclonedx.json
#   repro-check.sh selftest              offline test of the sbom pass/fail logic
#
# Windows agent and MSI are non-reproducible and deliberately excluded.
set -euo pipefail

IDS=(kryptkeeper kryptkeeper-agent kryptkeeper-certmanager kryptkeeper-mcp)
CMDS=(./cmd/kryptkeeper ./cmd/kryptkeeper-agent ./cmd/kryptkeeper-certmanager ./cmd/kryptkeeper-mcp)

sha_of() { if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | cut -d' ' -f1; else shasum -a 256 "$1" | cut -d' ' -f1; fi; }

build_tree() { # build_tree <dir> ; echo sha rows "id sha" to stdout
  local dir="$1" sha id bin
  git clone --quiet "$PWD" "$dir/src" >&2
  git -C "$dir/src" checkout --quiet "$HEAD_SHA" >&2
  mkdir -p "$dir/out"
  for id in "${IDS[@]}"; do
    # --clean wipes dist/ on every run, so collect each binary right after its build
    (cd "$dir/src" && GOOS=linux GOARCH=amd64 goreleaser build --clean --single-target --skip=validate \
      ${SNAPSHOT:+--snapshot} --id "$id" >&2)
    bin=$(find "$dir/src/dist" -type f -path "*/${id}_linux_amd64*/${id}" | head -n1)
    [ -n "$bin" ] || { echo "no binary found for $id in $dir" >&2; return 1; }
    cp "$bin" "$dir/out/$id"
  done
  # go mod tidy (before hook) must leave the clone clean
  git -C "$dir/src" diff --exit-code go.mod go.sum >&2
  for id in "${IDS[@]}"; do
    sha=$(sha_of "$dir/out/$id")
    echo "$id $sha"
  done
}

cmd_rebuild() {
  local SNAPSHOT=""
  if [ "${1:-}" = "--snapshot" ] || [ "${GITHUB_REF_TYPE:-}" != "tag" ]; then SNAPSHOT=1; fi
  HEAD_SHA=$(git rev-parse HEAD)
  local rc=0 out id a b status
  A=$(mktemp -d); B=$(mktemp -d)  # globals: read by the EXIT trap
  trap 'rm -rf "$A" "$B"' EXIT
  local ra rb
  ra=$(build_tree "$A"); rb=$(build_tree "$B")
  out=$(printf '%-26s %-64s %-64s %s\n' binary shaA shaB result)
  for id in "${IDS[@]}"; do
    a=$(echo "$ra" | awk -v i="$id" '$1==i{print $2}')
    b=$(echo "$rb" | awk -v i="$id" '$1==i{print $2}')
    status=MATCH; if [ "$a" != "$b" ]; then status=DIFF; rc=1; fi
    out+=$'\n'$(printf '%-26s %-64s %-64s %s' "$id" "$a" "$b" "$status")
  done
  echo "$out"
  if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then
    { echo '### Reproducible build (linux/amd64)'; echo '```'; echo "$out"; echo '```'; } >> "$GITHUB_STEP_SUMMARY"
  fi
  return $rc
}

# expected_modules prints path@version for every module linked into the shipped commands.
expected_modules() {
  if [ -n "${REPRO_EXPECTED_FILE:-}" ]; then sort -u "$REPRO_EXPECTED_FILE"; return; fi
  # In-repo modules wired in with a local replace (sdk/delivery-go) have the zero
  # pseudo-version and are part of this source tree, not a dependency an SBOM lists.
  go list -deps -f '{{with .Module}}{{.Path}}@{{.Version}}{{end}}' "${CMDS[@]}" | grep -v '@$' \
    | grep -v '@v0\.0\.0-00010101000000-000000000000$' | grep . | sort -u
}

actual_modules() { # actual_modules <dir>
  jq -r '.components[]? | select((.purl // "") | startswith("pkg:golang/")) | .purl' "$1"/*.cyclonedx.json \
    | sed -e 's#^pkg:golang/##' -e 's/%2B/+/g' -e 's/?.*$//' | sort -u
}

cmd_sbom() {
  local dir="${1:?usage: repro-check.sh sbom <dir>}"
  ls "$dir"/*.cyclonedx.json >/dev/null 2>&1 || { echo "no *.cyclonedx.json in $dir" >&2; return 1; }
  local exp act missing total n
  exp=$(expected_modules); act=$(actual_modules "$dir")
  total=$(echo "$exp" | grep -c . || true)
  missing=$(comm -23 <(echo "$exp") <(echo "$act") | grep . || true)
  n=$(echo "$missing" | grep -c . || true)
  echo "missing=$n of $total"
  if [ "$n" -gt 0 ]; then echo "$missing" | sed 's/^/  missing: /'; fi
  if [ -z "${REPRO_EXPECTED_FILE:-}" ]; then # informational: go.mod modules never linked into a shipped binary
    local all absent
    all=$(go list -m all | awk 'NR>1{print $1"@"$2}' | sort -u)
    absent=$(comm -23 <(echo "$all") <(echo "$act") | grep -c . || true)
    echo "info: $absent of $(echo "$all" | grep -c .) 'go list -m all' modules absent from every SBOM (unlinked/test-only; not enforced)"
  fi
  [ "$n" -eq 0 ]
}

cmd_selftest() {
  local t; t=$(mktemp -d); trap 'rm -rf "$t"' RETURN
  cat > "$t/a.cyclonedx.json" <<'JSON'
{"components":[{"purl":"pkg:golang/example.com/a@v1.0.0"},{"purl":"pkg:golang/example.com/b@v1.2.3%2Bincompatible"},{"purl":"pkg:npm/ignored@1.0.0"}]}
JSON
  printf 'example.com/a@v1.0.0\nexample.com/b@v1.2.3+incompatible\n' > "$t/exp-pass"
  printf 'example.com/a@v1.0.0\nexample.com/c@v9.9.9\n' > "$t/exp-fail"
  REPRO_EXPECTED_FILE="$t/exp-pass" cmd_sbom "$t" >/dev/null || { echo "selftest FAIL: pass case failed"; return 1; }
  if REPRO_EXPECTED_FILE="$t/exp-fail" cmd_sbom "$t" >"$t/out"; then echo "selftest FAIL: fail case passed"; return 1; fi
  grep -q 'missing=1 of 2' "$t/out" && grep -q 'example.com/c@v9.9.9' "$t/out" || { echo "selftest FAIL: bad output"; return 1; }
  if cmd_sbom "$t/nonexistent" >/dev/null 2>&1; then echo "selftest FAIL: empty dir passed"; return 1; fi
  echo "selftest OK"
}

case "${1:-}" in
  rebuild) shift; cmd_rebuild "$@" ;;
  sbom) shift; cmd_sbom "$@" ;;
  selftest) cmd_selftest ;;
  *) echo "usage: $0 rebuild [--snapshot] | sbom <dir> | selftest" >&2; exit 2 ;;
esac
