#!/usr/bin/env bash
# W20-20 live proof: a real hub binary, the real delivery plugin API and
# approval queue, the example plugin built from source, and a mock appliance
# (mockdevice) with its own internal CA.
#
#   1. install the example plugin (Critical: it receives private keys)
#   2. enable -> 202 pending; self-approval -> 403; a second admin approves
#   3. credential (api_token JSON + the device's CA) and a plugin target
#   4. issue a certificate, renew it through the plugin; the hub verifies by
#      dialing the device's service port; audit rows recorded
#   5. signed install (W20-24, needs cosign): trusted key -> verified, a
#      signature over other bytes -> 400, a missing trusted-keys file stops startup
#   6. kill switch: KRYPTKEEPER_DELIVERY_PLUGINS=off -> API 503, renewal refused
#
# The hub and the device each run in a container on a per-run podman network,
# and the hub reaches the device by container name. The hub's post-install
# verify dial (like the rest of its egress guard) refuses loopback, so a
# host-loopback device is not a legitimate environment; a private network is.
#
# PASS/FAIL per step, non-zero exit on any FAIL, cleans up on exit.
. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/../lib/podman.sh"
set -u
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$HERE/../../.." && pwd)"
WORK="$(mktemp -d /tmp/kk-uat-plugins.XXXXXX)"
# podman machine only virtiofs-mounts $HOME; bind-mounted files live there.
MOUNT_DIR="$(mktemp -d "$HOME/.kk-uat-plugins.XXXXXX")"
# Per-run id, free ports and names so concurrent runs never collide.
RUN_ID="$(openssl rand -hex 3)"
free_port() { python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1]); s.close()'; }
HUB_PORT="$(free_port)"; MGMT_PORT="$(free_port)"; SERVICE_PORT="$(free_port)"; SERVICE_HOST_PORT="$(free_port)"
HUB="http://127.0.0.1:$HUB_PORT"
NET="kk-uat-plug-net-$RUN_ID"
HUB_IMAGE="localhost/kk-uat-plugins-hub:$RUN_ID"
DEV_IMAGE="localhost/kk-uat-plugins-dev:$RUN_ID"
CTR_HUB="kkhub-plug-$RUN_ID"; CTR_DEV="mockdev-$RUN_ID"
TOKEN="uat-plugins-bootstrap-token"
DEVICE_TOKEN="uat-device-token-$RANDOM$RANDOM"
FAILED=0

STEP() { echo; echo "=== $* ==="; }
PASS() { echo "PASS: $*"; }
FAIL() { echo "FAIL: $*"; FAILED=1; }
DIE()  { echo "FAIL: $*"; FAILED=1; exit 1; }
cleanup() {
  if [ "$FAILED" = 1 ]; then echo "--- hub log (last 30) ---"; hublog | tail -30; fi
  kk_rm "$CTR_HUB" "$CTR_DEV"
  podman network rm "$NET" >/dev/null 2>&1
  podman rmi -f "$HUB_IMAGE" "$DEV_IMAGE" >/dev/null 2>&1
  rm -rf "$WORK" "$MOUNT_DIR"
}
hublog() { podman logs "$CTR_HUB" 2>&1; }
trap cleanup EXIT
api() { local tok="$1"; shift; curl -sS -H "Authorization: Bearer $tok" -H 'Content-Type: application/json' "$@"; }
code() { local tok="$1"; shift; curl -sS -o "$WORK/last.json" -w '%{http_code}' -H "Authorization: Bearer $tok" -H 'Content-Type: application/json' "$@"; }
jget() { python3 -c "import json,sys; d=json.load(sys.stdin); print(eval(sys.argv[1]))" "$1"; }

STEP "build hub, mock device, example plugin"
GOARCH="$(kk_goarch)"
mkdir -p "$WORK/hubctx" "$WORK/devctx"
(cd "$REPO_ROOT" && GOOS=linux GOARCH=$GOARCH CGO_ENABLED=0 go build -o "$WORK/hubctx/kryptkeeper" ./cmd/kryptkeeper \
  && GOOS=linux GOARCH=$GOARCH CGO_ENABLED=0 go build -o "$WORK/devctx/mockdevice" ./tests/live/plugins/mockdevice) \
  || DIE "go build failed"
cp "$REPO_ROOT/tests/live/autopilot/hub.Containerfile" "$WORK/hubctx/Containerfile"
cp "$HERE/device.Containerfile" "$WORK/devctx/Containerfile"
podman build -t "$HUB_IMAGE" "$WORK/hubctx" >"$WORK/build-hub.log" 2>&1 || DIE "hub image build, see $WORK/build-hub.log"
podman build -t "$DEV_IMAGE" "$WORK/devctx" >"$WORK/build-dev.log" 2>&1 || DIE "device image build, see $WORK/build-dev.log"
(cd "$REPO_ROOT/plugins/example" && GOOS=wasip1 GOARCH=wasm GOFLAGS=-mod=mod go build -buildmode=c-shared -o "$WORK/plugin.wasm" .) \
  || DIE "plugin build failed"
PASS "built"
# The operator's manifest for this device: the example plugin, declaring the
# device's management port (only 443 is allowed when a manifest names none).
python3 - "$REPO_ROOT/plugins/example/manifest.json" "$WORK" "$MGMT_PORT" <<'PY'
import hashlib, json, sys, base64
src, work, port = sys.argv[1], sys.argv[2], int(sys.argv[3])
m = json.load(open(src))
wasm = open(f"{work}/plugin.wasm", "rb").read()
m["artifact"]["sha256"] = hashlib.sha256(wasm).hexdigest()
m["version"] = "1.0.0-live"
m["capabilities"]["network"]["ports"] = [port]
json.dump({"manifest": m, "wasm_base64": base64.b64encode(wasm).decode()}, open(f"{work}/install.json", "w"))
PY

# Second pki-admin for the approval step, provisioned before the hub starts.
ADMIN2_SECRET="$(openssl rand -hex 24)"
ADMIN2_VERIFIER="$(printf '%s' "$ADMIN2_SECRET" | openssl dgst -sha256 -hmac 'uat-pepper-32-characters-minimum!!' -hex | awk '{print $NF}')"
ADMIN2_KEYS_JSON="[{\"name\":\"second-admin\",\"kid\":\"uatadmin2\",\"secret_verifier\":\"$ADMIN2_VERIFIER\",\"principal_id\":\"second-admin\",\"role\":\"pki-admin\",\"active\":true}]"
ADMIN2="kk_uatadmin2_${ADMIN2_SECRET}"

STEP "start mock device and hub"
podman network create "$NET" >/dev/null || DIE "network create"
mkdir -p "$MOUNT_DIR/dev" "$MOUNT_DIR/data" "$MOUNT_DIR/keys"
podman run -d --name "$CTR_DEV" --network "$NET" -p "127.0.0.1:$SERVICE_HOST_PORT:$SERVICE_PORT" -v "$MOUNT_DIR/dev:/out" "$DEV_IMAGE" \
  -mgmt "0.0.0.0:$MGMT_PORT" -service "0.0.0.0:$SERVICE_PORT" -token "$DEVICE_TOKEN" -ca-out /out/device-ca.pem -san "$CTR_DEV" >/dev/null \
  || DIE "start device"
cat >"$WORK/hub.env" <<EOF
APP_BOOTSTRAP_TOKEN=$TOKEN
AUTH_MODE=bootstrap
APP_CERTIFICATE_PROVIDER=ca
APP_API_KEY_PEPPER=uat-pepper-32-characters-minimum!!
APP_API_KEY_AUTH_ENABLED=true
APP_API_KEYS_JSON=$ADMIN2_KEYS_JSON
APP_CREDENTIAL_STORE_PASSPHRASE=uat-cred-passphrase-32-bytes-long!!
KRYPTKEEPER_KEYSTORE_PASSPHRASE=uat-keystore-passphrase-32-bytes!!
KRYPTKEEPER_DATA_DIR=/data
KRYPTKEEPER_KEYSTORE_DIR=/data/keystore
APP_CA_FILE=/data/cas.json
APP_TEMPLATE_FILE=/data/templates.json
APP_CERTIFICATE_FILE=/data/certificates.json
APP_AUDIT_FILE=/data/audit.json
APP_CERTS_SUMMARY_FILE=/data/certs_summary.json
KRYPTKEEPER_BOOTSTRAP_CREATE_ROOT=true
KRYPTKEEPER_CA_NAME=UAT Root CA
APP_BIND_ADDR=0.0.0.0
PORT=$HUB_PORT
KRYPTKEEPER_TLS_DISABLE=true
EOF
# Extra "-e KEY=VAL" arguments override the base env for one start. Each start
# is a fresh container over the same bind-mounted data dir, so podman logs
# holds exactly that start's output.
start_hub() {
  kk_rm "$CTR_HUB"
  podman run -d --name "$CTR_HUB" --network "$NET" -p "127.0.0.1:$HUB_PORT:$HUB_PORT" --env-file "$WORK/hub.env" \
    -v "$MOUNT_DIR/data:/data" -v "$MOUNT_DIR/keys:/keys:ro" "$@" "$HUB_IMAGE" >/dev/null || return 1
  for _ in $(seq 1 60); do
    curl -sf "$HUB/healthz" >/dev/null 2>&1 && return 0
    [ "$(podman inspect -f '{{.State.Running}}' "$CTR_HUB" 2>/dev/null)" = true ] || return 1
    sleep 0.5
  done
  return 1
}
start_hub || DIE "hub did not start"
for _ in $(seq 1 20); do [ -s "$MOUNT_DIR/dev/device-ca.pem" ] && break; sleep 0.25; done
cp "$MOUNT_DIR/dev/device-ca.pem" "$WORK/device-ca.pem" || DIE "no device CA"
hublog | grep -q "delivery plugins: on" && PASS "hub up, delivery plugins on" || FAIL "startup log does not say plugins are on"

STEP "second admin"
# The second approver is a separately provisioned identity (APP_API_KEYS_JSON),
# not a key minted with the bootstrap token: since FG-2 a key resolves to the
# human who minted it, so a bootstrap-minted key is the proposer again and the
# approval is (correctly) refused.
[ -n "$ADMIN2" ] && PASS "second pki-admin provisioned via APP_API_KEYS_JSON" || DIE "no second admin"

STEP "install and enable through the approval queue"
c=$(code "$TOKEN" -X POST "$HUB/api/v1/delivery-plugins" --data @"$WORK/install.json")
[ "$c" = 201 ] && PASS "install -> 201 ($(jget '"capability tier "+d["data"]["capability_tier"]+", trust "+d["data"]["trust_tier"]' <"$WORK/last.json"))" || DIE "install -> $c $(cat "$WORK/last.json")"
c=$(code "$TOKEN" -X POST "$HUB/api/v1/delivery-plugins/kryptkeeper.example-device/versions/1.0.0-live/enable")
ACTION="$(jget 'd["data"].get("pending_action_id","")' <"$WORK/last.json")"
[ "$c" = 202 ] && [ -n "$ACTION" ] && PASS "enable -> 202 pending approval ($ACTION)" || DIE "enable -> $c $(cat "$WORK/last.json")"
c=$(code "$TOKEN" -X POST "$HUB/api/v1/pending-actions/$ACTION/approve")
[ "$c" = 403 ] && PASS "self-approval refused (403)" || FAIL "self-approval -> $c"
c=$(code "$ADMIN2" -X POST "$HUB/api/v1/pending-actions/$ACTION/approve")
[ "$c" = 200 ] && PASS "second admin approved (200)" || DIE "approve -> $c $(cat "$WORK/last.json")"
EN="$(api "$TOKEN" "$HUB/api/v1/delivery-plugins/kryptkeeper.example-device" | jget 'd["data"]["enabled_version"]')"
[ "$EN" = "1.0.0-live" ] && PASS "enabled_version=$EN" || FAIL "enabled_version=$EN"

STEP "credential and plugin target"
python3 - "$WORK" "$MGMT_PORT" "$DEVICE_TOKEN" "$CTR_DEV" <<'PY'
import json, sys
work, port, tok, host = sys.argv[1:5]
payload = {"base_url": f"https://{host}:{port}", "token": tok, "tls_ca_pem": open(f"{work}/device-ca.pem").read()}
json.dump({"name": "mock-device", "credential_type": "api_token", "payload": payload}, open(f"{work}/cred.json", "w"))
PY
CRED="$(api "$TOKEN" -X POST "$HUB/api/v1/credentials" --data @"$WORK/cred.json" | jget 'd["data"]["id"]')"
[ -n "$CRED" ] && PASS "credential $CRED" || DIE "credential create failed"
TGT="$(api "$TOKEN" -X POST "$HUB/api/v1/targets" -d "{\"name\":\"edge-vip\",\"host\":\"$CTR_DEV\",\"discovery_mode\":\"none\",\"install_mode\":\"plugin\",\"renewal_method\":\"manual\",\"credential_ref\":\"$CRED\",\"plugin_id\":\"kryptkeeper.example-device\",\"plugin_settings\":{\"listener\":\"vip-443\"}}" | jget 'd["data"]["id"]')"
[ -n "$TGT" ] && PASS "plugin target $TGT" || DIE "target create failed"

STEP "issue a certificate and renew it through the plugin"
CA_ID="$(api "$TOKEN" "$HUB/api/v1/cas" | jget 'd["data"][0]["id"]')"
TPL_ID="$(api "$TOKEN" -X POST "$HUB/api/v1/templates" -d '{"name":"uat-plugin","display_name":"UAT plugin","validity_period":"P90D","key_usage":["digitalSignature","keyEncipherment"],"extended_key_usage":["serverAuth"],"allowed_algorithms":["ECDSA"],"active":true}' | jget 'd["data"]["id"]')"
openssl ecparam -name prime256v1 -genkey -noout -out "$WORK/leaf.key" 2>/dev/null
openssl req -new -key "$WORK/leaf.key" -subj "/CN=edge-vip.uat.example" -addext "subjectAltName=DNS:edge-vip.uat.example" -out "$WORK/leaf.csr" 2>/dev/null
python3 -c "import json,sys; json.dump({'ca_id':sys.argv[1],'template_id':sys.argv[2],'csr_pem':open(sys.argv[3]).read()}, open(sys.argv[4],'w'))" "$CA_ID" "$TPL_ID" "$WORK/leaf.csr" "$WORK/issue.json"
FP="$(api "$TOKEN" -X POST "$HUB/api/v1/certificates" --data @"$WORK/issue.json" | jget 'd["data"]["fingerprint_sha256"]')"
[ -n "$FP" ] && PASS "issued $FP" || DIE "issuance failed"
c=$(code "$TOKEN" -X POST "$HUB/api/v1/renewal/execute" -d "{\"fingerprint\":\"$FP\",\"target_id\":\"$TGT\",\"install\":{\"verify_host_port\":\"$CTR_DEV:$SERVICE_PORT\"}}")
OUT="$(jget 'str(d["data"].get("install_outcome"))+" verified="+str(d["data"].get("verified"))+" new="+str(d["data"].get("new_fingerprint"))' <"$WORK/last.json" 2>/dev/null)"
case "$c:$OUT" in 200:installed_verified\ verified=True*) PASS "renewed and delivered: $OUT" ;; *) FAIL "renewal -> $c $(cat "$WORK/last.json")" ;; esac
NEWFP="$(jget 'd["data"].get("new_fingerprint","")' <"$WORK/last.json" 2>/dev/null | tr -d ':' | tr 'A-Z' 'a-z')"
SERVED="$(openssl s_client -connect "127.0.0.1:$SERVICE_HOST_PORT" </dev/null 2>/dev/null | openssl x509 -outform DER 2>/dev/null | openssl dgst -sha256 -r | cut -d' ' -f1)"
[ -n "$SERVED" ] && [ "$SERVED" = "$NEWFP" ] && PASS "the device serves the renewed certificate ($SERVED)" || FAIL "device serves $SERVED, renewed $NEWFP"
AUDIT="$(api "$TOKEN" "$HUB/api/v1/audit?limit=100" | python3 -c 'import json,sys; d=json.load(sys.stdin)["data"]; rows=d if isinstance(d,list) else d.get("entries",d.get("items",[])); print(" ".join(r["action"]+":"+r["outcome"] for r in rows if r["action"].startswith(("delivery_plugin","action."))))')"
for want in delivery_plugin.install:success delivery_plugin.enable_requested:success action.approve:success delivery_plugin.push:success; do
  case " $AUDIT " in *" $want "*) PASS "audit $want" ;; *) FAIL "audit lacks $want: [$AUDIT]" ;; esac
done
# Read the whole trail through the API (works for the DB and file stores) and
# insist it is non-empty: a grep over zero entries proves nothing.
if python3 - "$HUB" "$TOKEN" "$WORK/audit-dump.json" <<'PY'
import json, sys, urllib.request
hub, token, out = sys.argv[1:4]
rows, cursor = [], ""
while True:
    url = hub + "/api/v1/audit?limit=100" + ("&cursor=" + cursor if cursor else "")
    d = json.load(urllib.request.urlopen(urllib.request.Request(url, headers={"Authorization": "Bearer " + token})))
    rows += d["data"]
    cursor = (d.get("meta") or {}).get("next_cursor") or ""
    if not cursor:
        break
json.dump(rows, open(out, "w"))
sys.exit(0 if rows else 1)
PY
then PASS "read the full audit trail through the API ($(python3 -c 'import json,sys; print(len(json.load(open(sys.argv[1]))))' "$WORK/audit-dump.json") entries)"
else FAIL "could not read a non-empty audit trail through the API"; : >"$WORK/audit-dump.json"; fi
hublog >"$WORK/hub.log"
grep -q "$DEVICE_TOKEN" "$WORK/hub.log" "$WORK/audit-dump.json" 2>/dev/null && FAIL "the device token appears in the hub log or audit" || PASS "device token in neither hub log nor audit"

STEP "signed install (W20-24): cosign key trusted via KRYPTKEEPER_PLUGIN_TRUSTED_KEYS"
if ! command -v cosign >/dev/null 2>&1 || ! command -v jq >/dev/null 2>&1; then
  echo "SKIP: cosign or jq not installed"
else
  # A throwaway key: its password guards nothing and dies with $WORK.
  mkdir -p "$WORK/sign"
  (cd "$WORK/sign" && COSIGN_PASSWORD=uat-throwaway cosign generate-key-pair --output-key-prefix uat >/dev/null 2>&1) || DIE "cosign generate-key-pair failed"
  cp "$WORK/sign/uat.pub" "$WORK/trusted.txt"
  python3 - "$WORK" <<'PY'
import json, sys
work = sys.argv[1]
m = json.load(open(f"{work}/install.json"))["manifest"]
for v in ("1.0.1-live", "1.0.2-live"):
    m["version"] = v
    open(f"{work}/sign/manifest-{v}.json", "w").write(json.dumps(m, indent=2) + "\n")
PY
  COSIGN_PASSWORD=uat-throwaway cosign sign-blob --yes --key "$WORK/sign/uat.key" --bundle "$WORK/sign/manifest.bundle" \
    --signing-config "$REPO_ROOT/scripts/cosign-signing-config.json" "$WORK/sign/manifest-1.0.1-live.json" >/dev/null 2>&1 || DIE "cosign sign-blob failed"
  python3 -c 'import base64,json,sys; open(sys.argv[2],"wb").write(base64.b64decode(json.load(open(sys.argv[1]))["wasm_base64"]))' \
    "$WORK/install.json" "$WORK/sign/plugin.wasm"
  # The same pipeline docs/ops/DELIVERY_PLUGINS.md gives operators.
  signed_body() {
    jq -n --rawfile m <(base64 < "$WORK/sign/manifest-$1.json" | tr -d '\n') \
          --rawfile w <(base64 < "$WORK/sign/plugin.wasm" | tr -d '\n') \
          --rawfile s "$WORK/sign/manifest.bundle" \
          '{manifest_base64: $m, wasm_base64: $w, signature: $s}'
  }

  cp "$WORK/trusted.txt" "$MOUNT_DIR/keys/trusted.txt"
  if start_hub -e KRYPTKEEPER_PLUGIN_TRUSTED_KEYS=/keys/missing-keys.txt; then
    FAIL "hub started with a missing trusted-keys file"
  else
    hublog | grep -q "KRYPTKEEPER_PLUGIN_TRUSTED_KEYS" && PASS "a missing trusted-keys file stops startup, and says why" || FAIL "hub did not start, but the log does not say why"
  fi
  start_hub -e KRYPTKEEPER_PLUGIN_TRUSTED_KEYS=/keys/trusted.txt || DIE "hub did not restart with trusted keys"
  # One first-party key is compiled in (packaging/SIGNING.md); the trusted
  # file adds one more.
  hublog >"$WORK/hub.log"
  grep -q "signing keys: 1 first-party, 1 trusted" "$WORK/hub.log" && PASS "startup log: 1 first-party, 1 trusted key" || FAIL "startup log does not report the keys: $(grep -o 'signing keys: [^)]*' "$WORK/hub.log" | tail -1)"

  # Bodies go through files: a base64 module is longer than ARG_MAX allows.
  signed_body 1.0.1-live >"$WORK/signed-1.json"; signed_body 1.0.2-live >"$WORK/signed-2.json"
  c=$(code "$TOKEN" -X POST "$HUB/api/v1/delivery-plugins" --data @"$WORK/signed-1.json")
  T="$(jget 'd["data"]["trust_tier"]+" signer="+d["data"].get("signer_key_id","")[:12]' <"$WORK/last.json" 2>/dev/null)"
  case "$c:$T" in 201:verified\ signer=?*) PASS "cosign-signed install -> 201, trust $T" ;; *) FAIL "signed install -> $c $(cat "$WORK/last.json")" ;; esac
  c=$(code "$TOKEN" -X POST "$HUB/api/v1/delivery-plugins" --data @"$WORK/signed-2.json")
  [ "$c" = 400 ] && PASS "signature over another manifest -> 400 ($(jget 'd.get("message", d.get("error",""))' <"$WORK/last.json" 2>/dev/null))" || FAIL "mismatched signature -> $c $(cat "$WORK/last.json")"
  c=$(code "$TOKEN" "$HUB/api/v1/delivery-plugins/kryptkeeper.example-device")
  [ "$c" = 200 ] && ! grep -q '"1.0.2-live"' "$WORK/last.json" && PASS "the refused version was not stored" || FAIL "refused version stored? $c"
fi

STEP "kill switch"
# A broken plugin config must not stop a hub whose plugins are switched off.
start_hub -e KRYPTKEEPER_DELIVERY_PLUGINS=off -e KRYPTKEEPER_PLUGIN_TRUSTED_KEYS=/keys/missing-keys.txt || DIE "hub with plugins off did not start despite a bad trusted-keys path"
PASS "plugins off: hub starts even with a bad trusted-keys path"
c=$(code "$TOKEN" "$HUB/api/v1/delivery-plugins")
[ "$c" = 503 ] && PASS "plugins off: API 503" || FAIL "plugins off: API $c"
api "$TOKEN" -X POST "$HUB/api/v1/certificates" --data @"$WORK/issue.json" >"$WORK/issue2.out"
FP2="$(jget 'd["data"]["fingerprint_sha256"]' <"$WORK/issue2.out" 2>/dev/null)"
[ -n "$FP2" ] || DIE "plugins off: could not issue the certificate to renew: $(cat "$WORK/issue2.out")"
c=$(code "$TOKEN" -X POST "$HUB/api/v1/renewal/execute" -d "{\"fingerprint\":\"$FP2\",\"target_id\":\"$TGT\",\"install\":{\"verify_host_port\":\"$CTR_DEV:$SERVICE_PORT\"}}")
case "$c" in 2*) FAIL "plugins off: renewal still ran ($c $(cat "$WORK/last.json"))" ;; *) PASS "plugins off: renewal refused ($c: $(jget 'd.get("message", d.get("error",""))' <"$WORK/last.json" 2>/dev/null))" ;; esac

echo
[ "$FAILED" = 0 ] && echo "ALL STEPS PASSED" || echo "ONE OR MORE STEPS FAILED"
exit "$FAILED"
