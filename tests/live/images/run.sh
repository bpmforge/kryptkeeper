#!/usr/bin/env bash
# W25-18: prove the published release images pull by digest, verify (cosign
# keyless), run as non-root and answer on amd64 and arm64.
#
#   bash tests/live/images/run.sh v0.9.4
#
# Everything is verified against the PUBLIC registry: no docker login, no
# insecure flags. The hub is probed by the image's own HEALTHCHECK binary
# (/healthcheck) against the hub's self-issued CA -- the same verified path an
# operator gets. Cross-arch runs go through the podman machine's emulation and
# are labelled "emulated" in the table.
. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/../lib/podman.sh"
set -u
set -o pipefail

TAG="${1:-}"
[ -n "$TAG" ] || { echo "usage: run.sh <tag>  (e.g. v0.9.4)"; exit 2; }
VER="${TAG#v}"
REG="ghcr.io/bpmforge"
IMAGES="kryptkeeper kryptkeeper-agent kryptkeeper-mcp kryptkeeper-certmanager"
PLATFORMS="${PLATFORMS:-linux/amd64 linux/arm64}"
# Same identity the release job signs with (release.yml, docker_signs in .goreleaser.yaml).
ID_RE="^https://github.com/bpmforge/kryptkeeper/\\.github/workflows/release\\.yml@refs/tags/${TAG//./\\.}\$"
ISSUER="https://token.actions.githubusercontent.com"
HOST_ARCH="$(podman info --format '{{.Host.Arch}}' 2>/dev/null || echo unknown)"

FAILED=0
STEP() { echo; echo "== $* =="; }
PASS() { echo "PASS: $*"; }
FAIL() { echo "FAIL: $*"; FAILED=1; }

WORK="$(mktemp -d "${TMPDIR:-/tmp}/kk-uat-images.XXXXXX")"
CTRS=""
cleanup() {
  # shellcheck disable=SC2086
  [ -n "$CTRS" ] && kk_rm $CTRS
  rm -rf "$WORK"
}
trap cleanup EXIT

for tool in podman cosign curl python3; do
  command -v "$tool" >/dev/null || { echo "FAIL: $tool not on PATH"; exit 2; }
done

# list_digest <image>: manifest-list digest for the tag, from the registry.
list_digest() {
  local tok
  tok="$(curl -fsS "https://ghcr.io/token?scope=repository:bpmforge/$1:pull" | python3 -c 'import json,sys; print(json.load(sys.stdin)["token"])')" || return 1
  curl -fsSI -H "Authorization: Bearer $tok" \
    -H "Accept: application/vnd.oci.image.index.v1+json,application/vnd.docker.distribution.manifest.list.v2+json" \
    "https://ghcr.io/v2/bpmforge/$1/manifests/$VER" | tr -d '\r' | awk -F': ' 'tolower($1)=="docker-content-digest"{print $2}'
}

# child_digest <ref@list> <arch>: per-platform digest inside the list.
child_digest() {
  local t
  for t in 1 2 3; do
    child_digest_once "$@" && return 0
    sleep $((t * 3))
  done
  return 1
}
child_digest_once() {
  podman manifest inspect "$1" 2>/dev/null | python3 -c '
import json,sys
arch=sys.argv[1]
for m in json.load(sys.stdin)["manifests"]:
    p=m.get("platform",{})
    if p.get("os")=="linux" and p.get("architecture")==arch:
        print(m["digest"]); break' "$2" 2>/dev/null | grep .
}

ROWS=""
row() { ROWS="${ROWS}| $1 | $2 | $3 | $4 | $5 | $6 | $7 |"$'\n'; }

STEP "resolve digests and cosign verify ($TAG)"
OKCOUNT=0
for img in $IMAGES; do
  d="$(list_digest "$img")"
  if [ -z "$d" ]; then FAIL "$img: could not resolve digest for tag $VER"; continue; fi
  echo "$REG/$img@$d" >"$WORK/ref-$img"
  if cosign verify "$REG/$img@$d" --certificate-identity-regexp "$ID_RE" \
       --certificate-oidc-issuer "$ISSUER" >"$WORK/cosign-$img.json" 2>"$WORK/cosign-$img.err"; then
    PASS "$img@$d cosign verify (keyless)"; OKCOUNT=$((OKCOUNT+1))
  else
    FAIL "$img@$d cosign verify: $(tail -2 "$WORK/cosign-$img.err")"
  fi
done
echo "cosign: ${OKCOUNT}/4"
[ "$OKCOUNT" -eq 4 ] || FAIL "cosign verified ${OKCOUNT}/4 images"

hub_check() { # <ref> <platform> <name>
  local ref="$1" plat="$2" name="$3" hc="" status=""
  CTRS="$CTRS $name"
  podman run -d --name "$name" --platform "$plat" --tmpfs /data:rw,mode=1777 \
    -e APP_BOOTSTRAP_TOKEN=uat-img-token -e AUTH_MODE=bootstrap \
    -e APP_CERTIFICATE_PROVIDER=ca -e APP_DISCOVERY_PROVIDER=db -e APP_NOTIFICATION_PROVIDER=file \
    -e KRYPTKEEPER_DATA_DIR=/data -e APP_BIND_ADDR=0.0.0.0 \
    -e KRYPTKEEPER_BOOTSTRAP_CREATE_ROOT=true -e KRYPTKEEPER_CA_NAME="UAT Image CA" \
    -e APP_CREDENTIAL_STORE_PASSPHRASE='uat-image-cred-passphrase-32-bytes!' \
    -e KRYPTKEEPER_KEYSTORE_PASSPHRASE='uat-image-keystore-passphrase-32-by!' \
    -e HEALTHCHECK_URL=https://127.0.0.1:8080/healthz -e HEALTHCHECK_CA_FILE=/data/tls/ca.pem \
    "$ref" >/dev/null 2>"$WORK/$name.err" || { echo "run failed: $(cat "$WORK/$name.err")"; return 1; }
  for _ in $(seq 1 45); do
    if podman healthcheck run "$name" >/dev/null 2>&1; then hc=healthy; break; fi
    sleep 2
  done
  status="$(podman top "$name" user 2>/dev/null | tail -1 | tr -d ' ')"
  echo "running-user(podman top): ${status:-?}"
  [ "$hc" = healthy ] || { podman logs "$name" 2>&1 | tail -5; return 1; }
  [ -n "$status" ] && [ "$status" != root ] && [ "$status" != 0 ]
}

for plat in $PLATFORMS; do
  arch="${plat#linux/}"
  mode=native; [ "$arch" = "$HOST_ARCH" ] || [ "$arch/$HOST_ARCH" = "amd64/x86_64" ] || mode=emulated
  for img in $IMAGES; do
    STEP "$img $plat ($mode)"
    list="$(cat "$WORK/ref-$img" 2>/dev/null)"
    if [ -z "$list" ]; then FAIL "$img: no digest"; row "$img" "$arch ($mode)" "-" "-" "-" "-" "FAIL"; continue; fi
    cd_="$(child_digest "$list" "$arch")"
    if [ -z "$cd_" ]; then FAIL "$img: no $arch child in $list"; row "$img" "$arch ($mode)" "-" "-" "-" "-" "FAIL"; continue; fi
    ref="$REG/$img@$cd_"
    if ! podman pull -q --platform "$plat" "$ref" >/dev/null 2>"$WORK/pull.err"; then
      FAIL "pull $ref: $(tail -1 "$WORK/pull.err")"; row "$img" "$arch ($mode)" "-" "-" "-" "-" "FAIL"; continue
    fi
    PASS "pulled by digest $ref"
    user="$(podman image inspect --format '{{.Config.User}}' "$ref")"
    case "$user" in nonroot:nonroot|65532|65532:65532) PASS "config user $user" ;; *) FAIL "config user '$user' (want nonroot:nonroot)" ;; esac
    rowstate=PASS; ans=""
    case "$img" in
      kryptkeeper)
        if hub_check "$ref" "$plat" "kk-uat-img-$arch-$$"; then PASS "hub healthy via image /healthcheck (verified TLS, CA from /data/tls/ca.pem)"; ans="/healthcheck exit 0"
        else FAIL "hub did not become healthy"; rowstate=FAIL; ans="unhealthy"; fi ;;
      kryptkeeper-agent)
        out="$(podman run --rm --platform "$plat" "$ref" --version 2>&1)"; rc=$?
        if [ $rc -eq 0 ] && printf '%s' "$out" | grep -q "^kryptkeeper-agent $VER "; then PASS "--version: $out"; ans="--version"; else FAIL "--version rc=$rc: $out"; rowstate=FAIL; fi
        out="$(podman run --rm --platform "$plat" "$ref" 2>&1)"; rc=$?
        if [ $rc -ne 0 ] && ! printf '%s' "$out" | grep -qi 'panic\|goroutine' && printf '%s' "$out" | grep -q 'KRYPTKEEPER_HUB_URL'; then PASS "no config: exit $rc with clear error, no panic"; ans="$ans + config-error exit $rc"; else FAIL "no-config run rc=$rc: $out"; rowstate=FAIL; fi ;;
      kryptkeeper-mcp|kryptkeeper-certmanager)
        out="$(podman run --rm --platform "$plat" "$ref" --version 2>&1)"; rc=$?
        if [ $rc -eq 0 ] && printf '%s' "$out" | grep -q "$img $VER "; then PASS "--version: $out"; ans="--version"; else FAIL "--version rc=$rc: $out"; rowstate=FAIL; ans="rc=$rc"; fi ;;
    esac
    case "$user" in nonroot:nonroot|65532|65532:65532) ;; *) rowstate=FAIL ;; esac
    row "$img" "$arch ($mode)" "\`$cd_\`" "$user" "cosign list ok=$OKCOUNT/4" "$ans" "$rowstate"
  done
done

STEP "results table"
echo "| image | arch | child digest | config user | verify | answers | result |"
echo "|---|---|---|---|---|---|---|"
printf '%s' "$ROWS"
echo
if [ "$FAILED" -ne 0 ]; then echo "RESULT: FAIL"; exit 1; fi
echo "RESULT: PASS (cosign: ${OKCOUNT}/4)"
