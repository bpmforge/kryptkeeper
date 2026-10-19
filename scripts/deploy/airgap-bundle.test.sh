#!/usr/bin/env bash
# Tests for airgap-bundle.sh (W25-13). No network: a fake container engine
# shim logs every call; cosign keys are generated into a temp dir.
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCRIPT="$HERE/airgap-bundle.sh"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
FAILS=0

command -v cosign >/dev/null || { echo "cosign required"; exit 3; }
command -v helm >/dev/null || { echo "helm required"; exit 3; }

# Fake engine: logs argv; image inspect succeeds; save writes a stub tar.
mkdir -p "$TMP/bin"
cat > "$TMP/bin/docker" <<'SHIM'
#!/usr/bin/env bash
echo "$*" >> "$ENGINE_LOG"
case "$1 $2" in
  "image inspect") echo "amd64 linux" ;;
esac
if [[ "$1" == "save" ]]; then
  while [[ $# -gt 0 ]]; do [[ "$1" == "-o" ]] && { echo "tar-$RANDOM-$2" > "$2"; }; shift; done
fi
exit 0
SHIM
chmod +x "$TMP/bin/docker"
export ENGINE_LOG="$TMP/engine.log"
export CONTAINER_ENGINE=docker
export PATH="$TMP/bin:$PATH"

# sha256sum is absent on stock macOS; shim in the test only.
if ! command -v sha256sum >/dev/null; then
  printf '#!/usr/bin/env bash\nexec shasum -a 256 "$@"\n' > "$TMP/bin/sha256sum"
  chmod +x "$TMP/bin/sha256sum"
fi

export COSIGN_PASSWORD=""
( cd "$TMP" && cosign generate-key-pair >/dev/null 2>&1 )
KEY="$TMP/cosign.key"; PUB="$TMP/cosign.pub"

IMGS=(
  HUB_IMAGE=ghcr.io/bpmforge/kryptkeeper:v0.9.4
  AGENT_IMAGE=ghcr.io/bpmforge/kryptkeeper-agent:v0.9.4
  MCP_IMAGE=ghcr.io/bpmforge/kryptkeeper-mcp:v0.9.4
  CERTMANAGER_IMAGE=ghcr.io/bpmforge/kryptkeeper-certmanager:v0.9.4
  DASHBOARD_IMAGE=ghcr.io/bpmforge/kryptkeeper-dashboard:v0.9.4
)

pass() { echo "PASS $1"; }
fail() { echo "FAIL $1: $2"; FAILS=$((FAILS + 1)); }

# build_bundle <dir> [env...]
build_bundle() { local d="$1"; shift; env "${IMGS[@]}" "$@" bash "$SCRIPT" build "$d" >"$d.log" 2>&1; }
SIGN=(COSIGN_KEY="$KEY" COSIGN_PUBKEY="$PUB")

t=build_requires_all_images
for v in AGENT_IMAGE MCP_IMAGE CERTMANAGER_IMAGE DASHBOARD_IMAGE; do
  env "${IMGS[@]}" "${SIGN[@]}" "$v=" bash "$SCRIPT" build "$TMP/o_$v" >/dev/null 2>&1; rc=$?
  [[ $rc -eq 2 ]] || fail "$t" "unset $v exit=$rc want 2"
done
[[ $FAILS -eq 0 ]] && pass $t

t=build_refuses_unsigned; before=$FAILS
env "${IMGS[@]}" bash "$SCRIPT" build "$TMP/unsigned" >/dev/null 2>&1; rc=$?
[[ $rc -eq 2 ]] || fail $t "exit=$rc want 2"
[[ $FAILS -eq $before ]] && pass $t

t=build_refuses_digest_ref; before=$FAILS
env "${IMGS[@]}" "${SIGN[@]}" MCP_IMAGE=ghcr.io/x/mcp@sha256:abc bash "$SCRIPT" build "$TMP/dig" >/dev/null 2>&1; rc=$?
[[ $rc -eq 2 ]] || fail $t "exit=$rc want 2"
[[ $FAILS -eq $before ]] && pass $t

GOOD="$TMP/good"
t=manifest_lists_all_images; before=$FAILS
if build_bundle "$GOOD" "${SIGN[@]}"; then
  [[ "$(jq '.images|length' "$GOOD/manifest.json")" == 5 ]] || fail $t "images != 5 (4 + dashboard)"
  [[ "$(jq '.schema_version' "$GOOD/manifest.json")" == 2 ]] || fail $t "schema_version != 2"
  [[ "$(jq -r '.signature.file' "$GOOD/manifest.json")" == manifest.json.sig ]] || fail $t "signature field"
  for f in manifest.json.sig manifest.json.bundle cosign.pub; do
    grep -q " $f\$" "$GOOD/SHA256SUMS" || fail $t "$f not in SHA256SUMS"
  done
else
  fail $t "build failed: $(tail -5 "$GOOD.log")"
fi
[[ $FAILS -eq $before ]] && pass $t

t=verify_blob_passes_offline; before=$FAILS
HTTPS_PROXY=http://127.0.0.1:9 HTTP_PROXY=http://127.0.0.1:9 cosign verify-blob --key "$GOOD/cosign.pub" \
  --bundle "$GOOD/manifest.json.bundle" --insecure-ignore-tlog=true "$GOOD/manifest.json" >/dev/null 2>&1 \
  || fail $t "verify-blob failed"
[[ $FAILS -eq $before ]] && pass $t

t=push_succeeds_on_good_bundle; before=$FAILS
: > "$ENGINE_LOG"
HTTPS_PROXY=http://127.0.0.1:9 bash "$SCRIPT" push "$GOOD" reg.internal:5000 >"$TMP/push_good.log" 2>&1 \
  || fail $t "push failed: $(tail -5 "$TMP/push_good.log")"
[[ "$(grep -c '^push ' "$ENGINE_LOG")" == 5 ]] || fail $t "expected 5 pushes"
[[ $FAILS -eq $before ]] && pass $t

# tamper <label> <file-to-corrupt>: copy good bundle, flip a byte, fix SHA256SUMS
tamper_case() {
  local t="$1" victim="$2" d="$TMP/bad_$1" before=$FAILS
  cp -R "$GOOD" "$d"
  printf 'X' | dd of="$d/$victim" bs=1 seek=10 conv=notrunc 2>/dev/null
  ( cd "$d" && sha256sum images/*.tar charts/*.tgz manifest.json airgap-bundle.sh manifest.json.sig manifest.json.bundle cosign.pub > SHA256SUMS )
  : > "$ENGINE_LOG"
  bash "$SCRIPT" push "$d" reg.internal:5000 >"$d.log" 2>&1; rc=$?
  [[ $rc -eq 4 ]] || fail "$t" "exit=$rc want 4"
  grep -q 'signature verification failed\|signed manifest' "$d.log" || fail "$t" "no refusal message"
  [[ ! -s "$ENGINE_LOG" ]] || fail "$t" "engine called: $(cat "$ENGINE_LOG")"
  [[ $FAILS -eq $before ]] && pass "$t"
}
tamper_case push_aborts_on_bad_signature manifest.json.sig
tamper_case push_aborts_on_bad_bundle manifest.json.bundle
tamper_case push_aborts_on_tampered_manifest manifest.json
first_tar="$(cd "$GOOD" && find images -name "*.tar" | head -1)"
tamper_case push_aborts_on_tampered_image "$first_tar"

t=push_rejects_wrong_pinned_key; before=$FAILS
( mkdir "$TMP/k2" && cd "$TMP/k2" && cosign generate-key-pair >/dev/null 2>&1 )
: > "$ENGINE_LOG"
COSIGN_PUBKEY="$TMP/k2/cosign.pub" bash "$SCRIPT" push "$GOOD" reg.internal:5000 >/dev/null 2>&1; rc=$?
[[ $rc -eq 4 ]] || fail $t "exit=$rc want 4"
[[ ! -s "$ENGINE_LOG" ]] || fail $t "engine called"
[[ $FAILS -eq $before ]] && pass $t

echo "failures: $FAILS"
[[ $FAILS -eq 0 ]]
