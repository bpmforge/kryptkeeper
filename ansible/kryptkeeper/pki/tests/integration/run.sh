#!/usr/bin/env bash
# Integration run for kryptkeeper.pki against a real hub.
#
# Brings up deploy/try (compose, hub + seeded demo data) with locally built
# images, then runs targets/certificate/playbook.yml against it: issue, re-run
# (changed=false), renew via renew_before_days, revoke, revoke again.
#
# Needs: podman or docker with a compose provider, python3 with ansible-core
# and cryptography on PATH (or set PYTHON_BIN), openssl, curl.
# Everything it creates carries the unique RUN_ID and is removed on exit.
#   RUN_ID=abc KEEP=1 tests/integration/run.sh     # KEEP=1 leaves the hub up
#   KK_HUB_URL=http://127.0.0.1:3000 KK_TOKEN=... tests/integration/run.sh   # use a running hub
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
collection="$(cd "$here/../.." && pwd)"
repo="$(cd "$collection/../../.." && pwd)"
RUN_ID="${RUN_ID:-$(date +%s)$$}"
CONTAINER_CLI="${CONTAINER_CLI:-podman}"
PY="${PYTHON_BIN:-python3}"
work="$(mktemp -d "${TMPDIR:-/tmp}/kk-ans-$RUN_ID.XXXXXX")"
project="kk-ans-$RUN_ID"
hub_image="$project-hub:local"
dash_image="$project-dash:local"
token="trial-only-bootstrap-token-0123456789abcdef"
compose=("$CONTAINER_CLI" compose -f "$repo/deploy/try/compose.yaml" -f "$repo/deploy/try/compose.build.yaml" -f "$work/images.yaml")
started=0

cleanup() {
  status=$?
  if [ "$started" = 1 ] && [ "${KEEP:-0}" != 1 ]; then
    KK_PROJECT="$project" "${compose[@]}" down -v >/dev/null 2>&1 || true
    "$CONTAINER_CLI" rmi "$hub_image" "$dash_image" >/dev/null 2>&1 || true
  fi
  rm -rf "$work"
  exit $status
}
trap cleanup EXIT

if [ -z "${KK_HUB_URL:-}" ]; then
  port="$("$PY" -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1]); s.close()')"
  # Unique image names so a parallel run on the same machine cannot clobber ours.
  cat >"$work/images.yaml" <<EOF
services:
  hub:
    image: $hub_image
  seeder:
    image: $hub_image
  console:
    image: $dash_image
EOF
  started=1
  KK_PROJECT="$project" KK_UI_PORT="$port" "${compose[@]}" up -d --build
  KK_HUB_URL="http://127.0.0.1:$port"
  KK_TOKEN="$token"
fi
: "${KK_TOKEN:?set KK_TOKEN for an existing hub}"

api() { curl -fsS -H "Authorization: Bearer $KK_TOKEN" "$KK_HUB_URL/api/v1$1"; }

echo "waiting for the hub to be seeded"
for _ in $(seq 1 150); do
  total="$(api '/certificates?limit=1' 2>/dev/null | "$PY" -c 'import json,sys; print(json.load(sys.stdin)["meta"]["total"])' 2>/dev/null || echo 0)"
  [ "$total" -ge 40 ] && break
  sleep 2
done
[ "${total:-0}" -ge 40 ] || { echo "hub never reached 40 certificates"; exit 1; }

ca_id="$(api /cas | "$PY" -c 'import json,sys; print([c["id"] for c in json.load(sys.stdin)["data"] if c["name"]=="Demo Issuing CA"][0])')"
tpl_id="$(api /templates | "$PY" -c 'import json,sys; print([t["id"] for t in json.load(sys.stdin)["data"] if t["name"]=="demo-tls-server"][0])')"

openssl ecparam -name prime256v1 -genkey -noout -out "$work/key.pem"
openssl req -new -key "$work/key.pem" -subj "/CN=ansible-$RUN_ID.demo.example" \
  -addext "subjectAltName=DNS:ansible-$RUN_ID.demo.example" -out "$work/req.csr"

mkdir -p "$work/collections/ansible_collections/kryptkeeper"
ln -s "$collection" "$work/collections/ansible_collections/kryptkeeper/pki"

ANSIBLE_COLLECTIONS_PATH="$work/collections" ANSIBLE_LOCALHOST_WARNING=False \
ANSIBLE_INVENTORY_UNPARSED_WARNING=False KRYPTKEEPER_TOKEN="$KK_TOKEN" \
ANSIBLE_PYTHON_INTERPRETER="$("$PY" -c 'import sys; print(sys.executable)')" \
  "$("$PY" -c 'import os,sys; print(os.path.join(os.path.dirname(sys.executable), "ansible-playbook"))')" \
  -i localhost, -c local "$here/targets/certificate/playbook.yml" \
  -e "hub_url=$KK_HUB_URL ca_id=$ca_id template_id=$tpl_id csr_path=$work/req.csr work=$work"

echo "kryptkeeper.pki integration run passed"
