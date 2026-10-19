#!/usr/bin/env bash
# W32-06 live proof of the first-party F5 BIG-IP and Citrix ADC delivery
# plugins against a REAL appliance / vendor VM.
#
#   bash tests/live/plugins/vendor/run.sh --vendor f5|citrix
#
# Reuses the flow of tests/live/plugins/run.sh (hub container, approval queue,
# credential, plugin target, renewal) but points the target at the appliance
# in VENDOR_BASE_URL instead of tests/live/plugins/mockdevice. See README.md.
#
# Exit codes: 0 all checks passed, 1 a check failed, 2 usage / missing env
# (nothing was started). Writes last-run-<vendor>.json next to this script.
# The appliance password is read from VENDOR_PASS_FILE at run time and is never
# echoed; the hub log and a full audit dump are grepped for it at the end.
. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/../../lib/podman.sh"
set -u
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$HERE/../../../.." && pwd)"

VENDOR=""
while [ $# -gt 0 ]; do
  case "$1" in
    --vendor) VENDOR="${2:-}"; shift 2 ;;
    -h|--help) sed -n 2,14p "${BASH_SOURCE[0]}"; exit 0 ;;
    *) echo "usage: run.sh --vendor f5|citrix" >&2; exit 2 ;;
  esac
done
case "$VENDOR" in
  f5)     PLUGIN_DIR=f5;     PLUGIN_ID=kryptkeeper.f5-bigip;   FIELD=client_ssl_profile
          TARGET_VALUE="${F5_CLIENT_SSL_PROFILE:-}";             MISMATCH_VALUE="${F5_MISMATCH_CLIENT_SSL_PROFILE:-}"
          VERSION_PATH=/mgmt/tm/sys/version ;;
  citrix) PLUGIN_DIR=citrix; PLUGIN_ID=kryptkeeper.citrix-adc; FIELD=certkey_name
          TARGET_VALUE="${CITRIX_CERTKEY_NAME:-}";               MISMATCH_VALUE="${CITRIX_MISMATCH_CERTKEY_NAME:-}"
          VERSION_PATH=/nitro/v1/config/nsversion ;;
  *) echo "usage: run.sh --vendor f5|citrix" >&2; exit 2 ;;
esac

missing=""
for v in VENDOR_BASE_URL VENDOR_USER VENDOR_PASS_FILE VENDOR_TLS_CA_FILE VENDOR_VERIFY_HOST_PORT; do
  [ -n "${!v:-}" ] || missing="$missing $v"
done
[ -n "$TARGET_VALUE" ] || missing="$missing $([ "$VENDOR" = f5 ] && echo F5_CLIENT_SSL_PROFILE || echo CITRIX_CERTKEY_NAME)"
if [ -n "$missing" ]; then
  echo "NOT RUN: required environment not set:$missing" >&2
  echo "See tests/live/plugins/vendor/README.md and vendor.env.example (needs a real $VENDOR appliance/VM)." >&2
  exit 2
fi
[ -r "$VENDOR_PASS_FILE" ] || { echo "NOT RUN: VENDOR_PASS_FILE is not readable" >&2; exit 2; }
[ -r "$VENDOR_TLS_CA_FILE" ] || { echo "NOT RUN: VENDOR_TLS_CA_FILE is not readable" >&2; exit 2; }
for t in podman go openssl python3 curl; do
  command -v "$t" >/dev/null 2>&1 || { echo "NOT RUN: $t not installed" >&2; exit 2; }
done
CERT_CN="${VENDOR_CERT_CN:-vendor-vip.uat.example}"

WORK="$(mktemp -d /tmp/kkw32-plugvendor.XXXXXX)"
MOUNT_DIR="$(mktemp -d "$HOME/.kkw32-plugvendor.XXXXXX")"   # podman machine only mounts $HOME
RUN_ID="$(openssl rand -hex 3)"
HUB_PORT="$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1]); s.close()')"
HUB="http://127.0.0.1:$HUB_PORT"
NET="kkw32-plugv-net-$RUN_ID"
HUB_IMAGE="localhost/kkw32-plugv-hub:$RUN_ID"
CTR_HUB="kkw32-plugv-hub-$RUN_ID"
TOKEN="uat-plugvendor-bootstrap-token"
RESULTS="$WORK/results.tsv"; : >"$RESULTS"
FAILED=0
SUMMARY="$HERE/last-run-$VENDOR.json"

STEP() { echo; echo "=== $* ==="; }
rec()  { printf '%s\t%s\t%s\n' "$1" "$2" "$3" >>"$RESULTS"; }
PASS() { echo "PASS: $2"; rec "$1" PASS "$2"; }
FAIL() { echo "FAIL: $2"; rec "$1" FAIL "$2"; FAILED=1; }
PEND() { echo "PENDING-RUN: $2"; rec "$1" PENDING-RUN "$2"; }
hublog() { podman logs "$CTR_HUB" 2>&1; }
APPLIANCE_VERSION="unknown"; PLUGIN_VERSION="unknown"; PLUGIN_SHA="unknown"
finish() {
  [ "$FAILED" = 1 ] && { echo "--- hub log (last 30) ---"; hublog | tail -30 | sed "s/$(printf '%s' "$(cat "$VENDOR_PASS_FILE")" | sed 's/[][\.*^$/]/\\&/g')/<redacted>/g"; }
  python3 - "$RESULTS" "$SUMMARY" "$VENDOR" "$APPLIANCE_VERSION" "$PLUGIN_ID" "$PLUGIN_VERSION" "$PLUGIN_SHA" "$FAILED" "$(git -C "$REPO_ROOT" rev-parse --short HEAD 2>/dev/null)" <<'PY'
import json, sys, datetime
res, out, vendor, appver, pid, pver, psha, failed, commit = sys.argv[1:10]
checks = [dict(zip(("check", "result", "detail"), l.rstrip("\n").split("\t", 2))) for l in open(res)]
json.dump({"date": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"), "vendor": vendor,
           "appliance_version": appver, "plugin_id": pid, "plugin_version": pver, "plugin_manifest_sha256": psha,
           "hub_commit": commit, "overall": "FAIL" if failed == "1" else "PASS", "checks": checks}, open(out, "w"), indent=2)
print("summary written:", out)
PY
  kk_rm "$CTR_HUB"
  podman network rm "$NET" >/dev/null 2>&1
  podman rmi -f "$HUB_IMAGE" >/dev/null 2>&1
  rm -rf "$WORK" "$MOUNT_DIR"
}
DIE() { echo "FAIL: $*"; rec abort FAIL "$*"; FAILED=1; exit 1; }
trap finish EXIT

api()  { local tok="$1"; shift; curl -sS -H "Authorization: Bearer $tok" -H 'Content-Type: application/json' "$@"; }
code() { local tok="$1"; shift; curl -sS -o "$WORK/last.json" -w '%{http_code}' -H "Authorization: Bearer $tok" -H 'Content-Type: application/json' "$@"; }
jget() { python3 -c "import json,sys; d=json.load(sys.stdin); print(eval(sys.argv[1]))" "$1"; }
served_sha() { # sha256 of the leaf the VIP serves right now
  openssl s_client -connect "$VENDOR_VERIFY_HOST_PORT" -servername "${VENDOR_VERIFY_HOST_PORT%%:*}" </dev/null 2>/dev/null \
    | openssl x509 -outform DER 2>/dev/null | openssl dgst -sha256 -r | cut -d' ' -f1
}

STEP "appliance version (recorded, management TLS verified against VENDOR_TLS_CA_FILE)"
VBODY="$(curl -sS --cacert "$VENDOR_TLS_CA_FILE" -u "$VENDOR_USER:$(cat "$VENDOR_PASS_FILE")" "${VENDOR_BASE_URL%/}$VERSION_PATH" 2>"$WORK/ver.err")"
APPLIANCE_VERSION="$(printf '%s' "$VBODY" | python3 -c '
import json, sys
try:
    d = json.load(sys.stdin)
except ValueError:
    print("unparsed"); raise SystemExit
def find(o):
    if isinstance(o, dict):
        for k, v in o.items():
            if k in ("version", "Version") and isinstance(v, (str, int, float)): return str(v)
            r = find(v)
            if r: return r
        for v in o.values():
            r = find(v)
            if r: return r
    if isinstance(o, list):
        for v in o:
            r = find(v)
            if r: return r
print(find(d) or "unparsed")' 2>/dev/null)"
if [ -n "$APPLIANCE_VERSION" ] && [ "$APPLIANCE_VERSION" != unparsed ]; then PASS appliance-version "appliance version: $APPLIANCE_VERSION"
else DIE "could not read the appliance version from $VERSION_PATH (see credentials, CA, reachability)"; fi

STEP "build hub image and the $VENDOR plugin"
GOARCH="$(kk_goarch)"
mkdir -p "$WORK/hubctx"
(cd "$REPO_ROOT" && GOOS=linux GOARCH=$GOARCH CGO_ENABLED=0 go build -o "$WORK/hubctx/kryptkeeper" ./cmd/kryptkeeper) || DIE "hub build failed"
cp "$REPO_ROOT/tests/live/autopilot/hub.Containerfile" "$WORK/hubctx/Containerfile"
podman build -t "$HUB_IMAGE" "$WORK/hubctx" >"$WORK/build-hub.log" 2>&1 || DIE "hub image build, see $WORK/build-hub.log"
bash "$REPO_ROOT/scripts/build-plugins.sh" >"$WORK/build-plugins.log" 2>&1 || DIE "scripts/build-plugins.sh failed, see $WORK/build-plugins.log"
PLUGIN_OUT="$REPO_ROOT/dist/plugins/$PLUGIN_DIR"
[ -s "$PLUGIN_OUT/plugin.wasm" ] && [ -s "$PLUGIN_OUT/manifest.json" ] || DIE "no built plugin in $PLUGIN_OUT"
# Install JSON from the built artefact. The manifest's network ports are widened
# ONLY to include the appliance management port when it is not already allowed.
python3 - "$PLUGIN_OUT" "$WORK" "$VENDOR_BASE_URL" <<'PY'
import base64, json, sys, urllib.parse
out, work, base = sys.argv[1:4]
m = json.load(open(f"{out}/manifest.json"))
wasm = open(f"{out}/plugin.wasm", "rb").read()
port = urllib.parse.urlparse(base).port or 443
ports = m["capabilities"]["network"].get("ports", [])
if port not in ports:
    m["capabilities"]["network"]["ports"] = ports + [port]
json.dump({"manifest": m, "wasm_base64": base64.b64encode(wasm).decode()}, open(f"{work}/install.json", "w"))
print(m["version"], m["artifact"]["sha256"])
PY
PLUGIN_VERSION="$(jget 'd["manifest"]["version"]' <"$WORK/install.json")"
PLUGIN_SHA="$(jget 'd["manifest"]["artifact"]["sha256"]' <"$WORK/install.json")"
PASS build "built hub + $PLUGIN_ID $PLUGIN_VERSION (artifact sha256 $PLUGIN_SHA)"

ADMIN2_SECRET="$(openssl rand -hex 24)"
ADMIN2_VERIFIER="$(printf '%s' "$ADMIN2_SECRET" | openssl dgst -sha256 -hmac 'uat-pepper-32-characters-minimum!!' -hex | awk '{print $NF}')"
ADMIN2="kk_uatadmin2_${ADMIN2_SECRET}"

STEP "start hub"
podman network create "$NET" >/dev/null || DIE "network create"
mkdir -p "$MOUNT_DIR/data"
cat >"$WORK/hub.env" <<ENVEOF
APP_BOOTSTRAP_TOKEN=$TOKEN
AUTH_MODE=bootstrap
APP_CERTIFICATE_PROVIDER=ca
APP_API_KEY_PEPPER=uat-pepper-32-characters-minimum!!
APP_API_KEY_AUTH_ENABLED=true
APP_API_KEYS_JSON=[{"name":"second-admin","kid":"uatadmin2","secret_verifier":"$ADMIN2_VERIFIER","principal_id":"second-admin","role":"pki-admin","active":true}]
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
ENVEOF
start_hub() {
  kk_rm "$CTR_HUB"
  podman run -d --name "$CTR_HUB" --network "$NET" -p "127.0.0.1:$HUB_PORT:$HUB_PORT" --env-file "$WORK/hub.env" \
    -v "$MOUNT_DIR/data:/data" "$@" "$HUB_IMAGE" >/dev/null || return 1
  for _ in $(seq 1 60); do
    curl -sf "$HUB/healthz" >/dev/null 2>&1 && return 0
    [ "$(podman inspect -f '{{.State.Running}}' "$CTR_HUB" 2>/dev/null)" = true ] || return 1
    sleep 0.5
  done
  return 1
}
start_hub || DIE "hub did not start"
hublog | grep -q "delivery plugins: on" && PASS hub-up "hub up, delivery plugins on" || FAIL hub-up "startup log does not say plugins are on"

STEP "install and enable $PLUGIN_ID through the approval queue"
c=$(code "$TOKEN" -X POST "$HUB/api/v1/delivery-plugins" --data @"$WORK/install.json")
[ "$c" = 201 ] && PASS install "install -> 201" || DIE "install -> $c $(cat "$WORK/last.json")"
c=$(code "$TOKEN" -X POST "$HUB/api/v1/delivery-plugins/$PLUGIN_ID/versions/$PLUGIN_VERSION/enable")
ACTION="$(jget 'd["data"].get("pending_action_id","")' <"$WORK/last.json")"
[ "$c" = 202 ] && [ -n "$ACTION" ] && PASS enable-pending "enable -> 202 pending approval" || DIE "enable -> $c $(cat "$WORK/last.json")"
c=$(code "$TOKEN" -X POST "$HUB/api/v1/pending-actions/$ACTION/approve")
[ "$c" = 403 ] && PASS self-approval-refused "self-approval refused (403)" || FAIL self-approval-refused "self-approval -> $c"
c=$(code "$ADMIN2" -X POST "$HUB/api/v1/pending-actions/$ACTION/approve")
[ "$c" = 200 ] && PASS approve "second admin approved" || DIE "approve -> $c $(cat "$WORK/last.json")"

STEP "credential and managed target for the real appliance"
python3 - "$WORK" "$VENDOR_BASE_URL" "$VENDOR_USER" "$VENDOR_PASS_FILE" "$VENDOR_TLS_CA_FILE" <<'PY'
import json, sys
work, base, user, passfile, ca = sys.argv[1:6]
payload = {"base_url": base, "username": user, "password": open(passfile).read().rstrip("\n"), "tls_ca_pem": open(ca).read()}
json.dump({"name": "vendor-appliance", "credential_type": "api_token", "payload": payload}, open(f"{work}/cred.json", "w"))
PY
CRED="$(api "$TOKEN" -X POST "$HUB/api/v1/credentials" --data @"$WORK/cred.json" | jget 'd["data"]["id"]')"
[ -n "$CRED" ] && PASS credential "credential $CRED" || DIE "credential create failed"
VHOST="${VENDOR_VERIFY_HOST_PORT%%:*}"
mk_target() { # name field-value
  api "$TOKEN" -X POST "$HUB/api/v1/targets" -d "{\"name\":\"$1\",\"host\":\"$VHOST\",\"discovery_mode\":\"none\",\"install_mode\":\"plugin\",\"renewal_method\":\"manual\",\"credential_ref\":\"$CRED\",\"plugin_id\":\"$PLUGIN_ID\",\"plugin_settings\":{\"$FIELD\":\"$2\"}}" | jget 'd["data"]["id"]'
}
TGT="$(mk_target vendor-vip "$TARGET_VALUE")"
[ -n "$TGT" ] && PASS target "plugin target $TGT ($FIELD=$TARGET_VALUE)" || DIE "target create failed"

STEP "issue a certificate and renew it through the plugin"
CA_ID="$(api "$TOKEN" "$HUB/api/v1/cas" | jget 'd["data"][0]["id"]')"
TPL_ID="$(api "$TOKEN" -X POST "$HUB/api/v1/templates" -d '{"name":"uat-vendor","display_name":"UAT vendor","validity_period":"P90D","key_usage":["digitalSignature","keyEncipherment"],"extended_key_usage":["serverAuth"],"allowed_algorithms":["ECDSA"],"active":true}' | jget 'd["data"]["id"]')"
issue() { # name -> prints fingerprint
  openssl ecparam -name prime256v1 -genkey -noout -out "$WORK/$1.key" 2>/dev/null
  openssl req -new -key "$WORK/$1.key" -subj "/CN=$CERT_CN" -addext "subjectAltName=DNS:$CERT_CN" -out "$WORK/$1.csr" 2>/dev/null
  python3 -c "import json,sys; json.dump({'ca_id':sys.argv[1],'template_id':sys.argv[2],'csr_pem':open(sys.argv[3]).read()}, open(sys.argv[4],'w'))" "$CA_ID" "$TPL_ID" "$WORK/$1.csr" "$WORK/$1.json"
  api "$TOKEN" -X POST "$HUB/api/v1/certificates" --data @"$WORK/$1.json" | jget 'd["data"]["fingerprint_sha256"]'
}
renew() { # fp target -> http code, body in last.json
  code "$TOKEN" -X POST "$HUB/api/v1/renewal/execute" -d "{\"fingerprint\":\"$1\",\"target_id\":\"$2\",\"install\":{\"verify_host_port\":\"$VENDOR_VERIFY_HOST_PORT\"}}"
}
FP1="$(issue leaf1)"; [ -n "$FP1" ] && PASS issue "issued $FP1" || DIE "issuance failed"
c=$(renew "$FP1" "$TGT")
OUT="$(jget 'str(d["data"].get("install_outcome"))+" verified="+str(d["data"].get("verified"))' <"$WORK/last.json" 2>/dev/null)"
NEWFP="$(jget 'd["data"].get("new_fingerprint","")' <"$WORK/last.json" 2>/dev/null | tr -d ':' | tr 'A-Z' 'a-z')"
case "$c:$OUT" in
  200:installed_verified\ verified=True*) PASS push-verify "renewed, pushed and verified by the hub: $OUT" ;;
  *) FAIL push-verify "renewal -> $c $(cat "$WORK/last.json")" ;;
esac
SERVED1="$(served_sha)"
[ -n "$SERVED1" ] && [ "$SERVED1" = "$NEWFP" ] && PASS served-serial "live listener $VENDOR_VERIFY_HOST_PORT serves the renewed certificate ($SERVED1)" \
  || FAIL served-serial "listener serves '$SERVED1', renewed '$NEWFP'"

STEP "forced mismatch -> rollback leaves the previous certificate served"
if [ -z "$MISMATCH_VALUE" ]; then
  PEND rollback "rollback leg not run: set $([ "$VENDOR" = f5 ] && echo F5_MISMATCH_CLIENT_SSL_PROFILE || echo CITRIX_MISMATCH_CERTKEY_NAME) (a second profile/certkey NOT bound to the VIP)"
else
  TGT2="$(mk_target vendor-mismatch "$MISMATCH_VALUE")"
  [ -n "$TGT2" ] || DIE "mismatch target create failed"
  FP2="$(issue leaf2)"; [ -n "$FP2" ] || DIE "second issuance failed"
  c=$(renew "$FP2" "$TGT2")
  echo "  renewal response ($c): $(python3 -c 'import json; print(json.dumps(json.load(open("'"$WORK/last.json"'")))[:600])')"
  ROLLED="$(jget 'str(d.get("data",{}).get("rolled_back"))+" "+str(d.get("data",{}).get("install_outcome"))+" "+str(d.get("message",""))' <"$WORK/last.json" 2>/dev/null)"
  SERVED2="$(served_sha)"
  if case "$c" in 200) grep -q '"installed_verified"' "$WORK/last.json" ;; *) false ;; esac; then
    FAIL rollback "mismatch was NOT detected: hub reported verified ($ROLLED)"
  else
    PASS rollback-detected "hub refused the mismatched install ($c; $ROLLED)"
  fi
  [ -n "$SERVED2" ] && [ "$SERVED2" = "$SERVED1" ] \
    && PASS rollback-previous-served "previous certificate still served after the forced mismatch (serial/sha256 $SERVED2)" \
    || FAIL rollback-previous-served "listener served $SERVED1 before, $SERVED2 after the forced mismatch"
fi

STEP "kill switch and credential non-leak"
hublog >"$WORK/hub.log"
python3 - "$HUB" "$TOKEN" "$WORK/audit-dump.json" <<'PY' || { FAIL audit-read "could not read a non-empty audit trail"; : >"$WORK/audit-dump.json"; }
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
if grep -qF -- "$(cat "$VENDOR_PASS_FILE")" "$WORK/hub.log" "$WORK/audit-dump.json" 2>/dev/null; then
  FAIL credential-nonleak "the appliance password appears in the hub log or the audit trail"
else
  PASS credential-nonleak "appliance password in neither hub log nor audit trail"
fi
start_hub -e KRYPTKEEPER_DELIVERY_PLUGINS=off || DIE "hub with plugins off did not start"
c=$(code "$TOKEN" "$HUB/api/v1/delivery-plugins")
[ "$c" = 503 ] && PASS kill-switch-api "plugins off: API 503" || FAIL kill-switch-api "plugins off: API $c"
FP3="$(issue leaf3)"
c=$(renew "$FP3" "$TGT")
case "$c" in 2*) FAIL kill-switch-renewal "plugins off: renewal still ran ($c)" ;; *) PASS kill-switch-renewal "plugins off: renewal refused ($c)" ;; esac

echo
[ "$FAILED" = 0 ] && echo "ALL EXECUTED STEPS PASSED (see PENDING-RUN lines for anything not run)" || echo "ONE OR MORE STEPS FAILED"
exit "$FAILED"
