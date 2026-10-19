#!/usr/bin/env bash
# W23-32: smoke for the FIPS image (Dockerfile.fips).
#   leg 1: hub starts, /api/v1/meta reports the live FIPS posture
#   leg 2: CA role on a software keystore is refused at boot (NFR-011)
# Usage: scripts/fips-smoke.sh [image]   (CONTAINER_ENGINE=podman|docker)
set -euo pipefail

ENGINE="${CONTAINER_ENGINE:-docker}"
IMAGE="${1:-kryptkeeper-fips:local}"
NAME="kkfips-smoke-$$"
PORT="${FIPS_SMOKE_PORT:-18080}"

cleanup() { "$ENGINE" rm -f "$NAME" >/dev/null 2>&1 || true; }
trap cleanup EXIT

echo "== leg 1: posture reported by /api/v1/meta"
"$ENGINE" run -d --name "$NAME" -p "$PORT:8080" \
  -e APP_BOOTSTRAP_TOKEN=smoke-token-1 -e KRYPTKEEPER_TLS_DISABLE=true -e APP_BIND_ADDR=0.0.0.0 "$IMAGE" >/dev/null
for _ in $(seq 1 30); do
  curl -sf "http://127.0.0.1:$PORT/healthz" >/dev/null && break
  sleep 1
done
curl -sf "http://127.0.0.1:$PORT/healthz" >/dev/null || { "$ENGINE" logs "$NAME" >&2; echo "FAIL: hub did not become healthy" >&2; exit 1; }
meta="$(curl -sf "http://127.0.0.1:$PORT/api/v1/meta")"
echo "$meta" | jq -c '.fips'
echo "$meta" | jq -e '.fips.mode_140_3 == true and (.fips.module_version|length>0) and .fips.root_hsm_required == true' >/dev/null \
  || { echo "FAIL: /api/v1/meta does not report fips mode_140_3, module_version and root_hsm_required" >&2; exit 1; }
echo "enforced (fips140=only) = $(echo "$meta" | jq -r '.fips.enforced') (the image default is fips140=on)"
cleanup

echo "== leg 2: software root key refused under FIPS (NFR-011)"
set +e
out="$("$ENGINE" run --rm --tmpfs /tmp:rw,mode=1777 \
  -e APP_CERTIFICATE_PROVIDER=ca -e KRYPTKEEPER_KEY_BACKEND=software \
  -e KRYPTKEEPER_DATA_DIR=/tmp/kk -e KRYPTKEEPER_KEYSTORE_DIR=/tmp/kk/keys \
  -e KRYPTKEEPER_KEYSTORE_PASSPHRASE=smoke-pass-phrase-xyz \
  -e APP_BOOTSTRAP_TOKEN=smoke-token-1 "$IMAGE" 2>&1)"
rc=$?
set -e
if [ "$rc" -eq 0 ]; then
  echo "FAIL: container exited 0 with a software root key under FIPS" >&2; exit 1
fi
echo "$out" | grep -q "NFR-011" || { echo "$out" >&2; echo "FAIL: exit $rc but output does not name NFR-011" >&2; exit 1; }
echo "refused (exit $rc): $(echo "$out" | grep -m1 NFR-011)"
echo "fips-smoke: PASS"
