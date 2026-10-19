# shellcheck shell=bash
# Shared functions for tests/live/delivery-cloud/run.sh (W27-32).
# Sourced, never executed. See README.md for the per-leg environment.

. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/../lib/podman.sh"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$HERE/../../.." && pwd)"
HUBAPI="$HERE/hubapi.py"
STOREREAD="$HERE/storeread.py"
VAULT_IMAGE="${KK_VAULT_IMAGE:-docker.io/hashicorp/vault:1.17}"
STAMP="$(date -u +%Y%m%d%H%M%S)"
RUN_ID="$(openssl rand -hex 3)"
PFX="kk-uat-$STAMP"            # every object we create (secret paths, names) starts with this
FAILED=0
HUB_BOOTED=0
RESULTS=""
INSTALLED_PLUGINS=" "

STEP() { echo; echo "=== $* ==="; }
PASS() { echo "PASS: $*"; }
INFO() { echo "INFO: $*"; }
FAIL() { echo "FAIL: $*"; FAILED=1; }
DIE()  { echo "FAIL: $*"; FAILED=1; exit 1; }
free_port() { python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1]); s.close()'; }
jget() { python3 -c "import json,sys; d=json.load(sys.stdin); print(eval(sys.argv[1]))" "$1"; }

kk_init() {
  WORK="$(mktemp -d /tmp/kk-uat-delivery.XXXXXX)"
  # podman machine only virtiofs-mounts $HOME; bind-mounted files live there.
  MOUNT_DIR="$(mktemp -d "$HOME/.kk-uat-delivery.XXXXXX")"
  HUB_PORT="$(free_port)"; VAULT_PORT="$(free_port)"
  HUB="http://127.0.0.1:$HUB_PORT"
  TOKEN="uat-delivery-bootstrap-token"
  HUB_IMAGE="localhost/$PFX-hub:$RUN_ID"
  NET="$PFX-net-$RUN_ID"
  HUB_CTR="$PFX-hub-$RUN_ID"; VAULT_CTR="$PFX-vault-$RUN_ID"; MM_CTR="$PFX-mismatch-$RUN_ID"
  trap kk_cleanup EXIT
}

# Removes only what this run created (kk-uat-<stamp> prefix). Provider-side
# objects (secret versions, ACM/Key Vault certificates, ...) are NOT deleted:
# the README lists them for manual cleanup.
kk_cleanup() {
  if [ "$FAILED" = 1 ] && [ "$HUB_BOOTED" = 1 ]; then echo "--- hub log (last 25) ---"; podman logs "$HUB_CTR" 2>&1 | tail -25; fi
  kk_rm "$HUB_CTR" "$VAULT_CTR" "$MM_CTR"
  podman network rm "$NET" >/dev/null 2>&1
  podman rmi -f "$HUB_IMAGE" >/dev/null 2>&1
  rm -rf "$WORK" "$MOUNT_DIR"
}

api() { curl -sS -m "${CURL_MAX:-30}" -H "Authorization: Bearer $1" -H 'Content-Type: application/json' "${@:2}"; }
code() { local tok="$1"; shift; curl -sS -m "${CURL_MAX:-30}" -o "$WORK/last.json" -w '%{http_code}' -H "Authorization: Bearer $tok" -H 'Content-Type: application/json' "$@"; }

start_hub() {
  STEP "build and start the hub"
  local goarch
  goarch="$(kk_goarch)"
  mkdir -p "$WORK/hubctx"
  (cd "$REPO_ROOT" && GOOS=linux GOARCH=$goarch CGO_ENABLED=0 go build -o "$WORK/hubctx/kryptkeeper" ./cmd/kryptkeeper) || DIE "go build failed"
  cp "$REPO_ROOT/tests/live/autopilot/hub.Containerfile" "$WORK/hubctx/Containerfile"
  podman build -q -t "$HUB_IMAGE" "$WORK/hubctx" >"$WORK/build-hub.log" 2>&1 || DIE "hub image build failed: $(tail -5 "$WORK/build-hub.log")"
  podman network create "$NET" >/dev/null || DIE "network create failed"
  # A second pki-admin for the approval step (a bootstrap-minted key resolves to the proposer again).
  local s2 v2
  s2="$(openssl rand -hex 24)"
  v2="$(printf '%s' "$s2" | openssl dgst -sha256 -hmac 'uat-pepper-32-characters-minimum!!' -hex | awk '{print $NF}')"
  ADMIN2="kk_uatadmin2_${s2}"
  cat >"$WORK/hub.env" <<EOF
APP_BOOTSTRAP_TOKEN=$TOKEN
AUTH_MODE=bootstrap
APP_CERTIFICATE_PROVIDER=ca
APP_API_KEY_PEPPER=uat-pepper-32-characters-minimum!!
APP_API_KEY_AUTH_ENABLED=true
APP_API_KEYS_JSON=[{"name":"second-admin","kid":"uatadmin2","secret_verifier":"$v2","principal_id":"second-admin","role":"pki-admin","active":true}]
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
  podman run -d --name "$HUB_CTR" --network "$NET" -p "127.0.0.1:$HUB_PORT:$HUB_PORT" --env-file "$WORK/hub.env" "$HUB_IMAGE" >/dev/null || DIE "hub container did not start"
  HUB_BOOTED=1
  for _ in $(seq 1 60); do curl -sf "$HUB/healthz" >/dev/null 2>&1 && break; sleep 0.5; done
  curl -sf "$HUB/healthz" >/dev/null || DIE "hub did not start"
  local plog; plog="$(podman logs "$HUB_CTR" 2>&1)"
  case "$plog" in *"delivery plugins: on"*) PASS "hub up, delivery plugins on" ;; *) FAIL "startup log does not say plugins are on" ;; esac

  # one CA + template for every leaf
  CA_ID="$(api "$TOKEN" "$HUB/api/v1/cas" | jget 'd["data"][0]["id"]')"
  TPL_ID="$(api "$TOKEN" -X POST "$HUB/api/v1/templates" -d '{"name":"uat-delivery","display_name":"UAT delivery","validity_period":"P90D","key_usage":["digitalSignature","keyEncipherment"],"extended_key_usage":["serverAuth"],"allowed_algorithms":["ECDSA"],"active":true}' | jget 'd["data"]["id"]')"
  [ -n "$CA_ID" ] && [ -n "$TPL_ID" ] || DIE "no CA or template"
}

# The forced-failure verify target: a TLS server that presents a certificate
# which is never the one the hub delivered.
start_mismatch_server() {
  mkdir -p "$MOUNT_DIR/mm"
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 2 -keyout "$MOUNT_DIR/mm/k.pem" -out "$MOUNT_DIR/mm/c.pem" \
    -subj "/CN=kk-uat-mismatch" >/dev/null 2>&1
  podman run -d --name "$MM_CTR" --network "$NET" -v "$MOUNT_DIR/mm:/m:ro" --entrypoint openssl "$HUB_IMAGE" \
    s_server -accept 8443 -cert /m/c.pem -key /m/k.pem -www >/dev/null || DIE "mismatch TLS server did not start"
}

start_vault() {
  STEP "local Vault (dev server, -dev-tls)"
  mkdir -p "$MOUNT_DIR/vault"
  chmod 777 "$MOUNT_DIR/vault"
  VAULT_TOKEN_VALUE="kk-uat-$(openssl rand -hex 12)"
  podman run -d --name "$VAULT_CTR" --network "$NET" -p "127.0.0.1:$VAULT_PORT:8200" -v "$MOUNT_DIR/vault:/certs" \
    --cap-add=IPC_LOCK "$VAULT_IMAGE" server -dev -dev-tls -dev-tls-cert-dir=/certs -dev-tls-san="$VAULT_CTR" \
    -dev-root-token-id="$VAULT_TOKEN_VALUE" -dev-listen-address=0.0.0.0:8200 >/dev/null || DIE "vault did not start"
  for _ in $(seq 1 40); do [ -s "$MOUNT_DIR/vault/vault-ca.pem" ] && curl -sf --cacert "$MOUNT_DIR/vault/vault-ca.pem" "https://127.0.0.1:$VAULT_PORT/v1/sys/health" >/dev/null 2>&1 && break; sleep 0.5; done
  curl -sf --cacert "$MOUNT_DIR/vault/vault-ca.pem" "https://127.0.0.1:$VAULT_PORT/v1/sys/health" >/dev/null || DIE "vault not healthy over TLS: $(podman logs "$VAULT_CTR" 2>&1 | tail -3)"
  # Credential payload exactly as an operator would supply it (base_url, token, tls_ca_pem); the
  # host-side reader gets the same token against the published port.
  python3 - "$WORK" "$MOUNT_DIR/vault/vault-ca.pem" "$VAULT_CTR" "$VAULT_PORT" "$VAULT_TOKEN_VALUE" <<'PY'
import json, os, sys
work, ca, ctr, port, tok = sys.argv[1:6]
def w(path, obj):
    with os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600), "w") as f:
        json.dump(obj, f)
w(f"{work}/vault-cred.json", {"base_url": f"https://{ctr}:8200", "token": tok, "tls_ca_pem": open(ca).read()})
w(f"{work}/vault-reader.json", {"base_url": f"https://127.0.0.1:{port}", "token": tok})
PY
  PASS "Vault dev server up (TLS, KV v2 at secret/); CA trusted via the credential's tls_ca_pem"
}

# ---- legs ---------------------------------------------------------------------
need_var() {
  local leg="$1" v val; shift
  for v in "$@"; do
    eval "val=\${$v:-}"
    if [ -z "$val" ]; then echo "SKIP: $leg needs $v"; return 2; fi
    case "$v" in *_FILE) [ -s "$val" ] || { echo "SKIP: $leg needs $v (file '$val' missing or empty)"; return 2; } ;; esac
  done
}
leg_need_vault()          { return 0; }
leg_need_akv()            { need_var akv KK_AKV_CRED_FILE KK_AKV_SECRET_NAME; }
leg_need_gcpsm()          { need_var gcpsm KK_GCP_SA_FILE KK_GCP_PROJECT KK_GCP_SECRET_ID; }
leg_need_aws_sm()         { need_var aws-sm KK_AWS_CRED_FILE KK_AWS_REGION KK_AWS_SECRET_ID; }
leg_need_aws_alb()        { need_var aws-alb KK_AWS_CRED_FILE KK_AWS_REGION KK_AWS_LISTENER_ARN KK_AWS_ALB_HOST; }
leg_need_aws_cloudfront() { need_var aws-cloudfront KK_AWS_CRED_FILE KK_AWS_REGION KK_AWS_DISTRIBUTION_ID KK_AWS_CF_HOST; }
leg_need_azure_appgw()    { need_var azure-appgw KK_AZ_CRED_FILE KK_AZ_SUB KK_AZ_RG KK_AZ_KV_CERT_NAME KK_AZ_GATEWAY KK_AZ_SSL_CERT KK_AZ_APPGW_HOST; }
leg_need_azure_frontdoor(){ need_var azure-frontdoor KK_AZ_CRED_FILE KK_AZ_SUB KK_AZ_RG KK_AZ_KV_CERT_NAME KK_AZ_PROFILE KK_AZ_FD_SECRET KK_AZ_FD_HOST; }
leg_need_cloudflare()     { need_var cloudflare KK_CF_CRED_FILE KK_CF_ZONE_ID KK_CF_HOST; }

# Sets the L_* variables: plugin dir, kind, credential file/args, plugin_settings JSON,
# certificate/target host, secret files to scan, and (secret stores) the direct reader.
leg_setup() {
  L_READ_PROVIDER=""; L_READ_CRED=""; L_READ_ARGS=""; L_CAFILE=""; L_CRED_ARGS=""
  case "$1" in
    vault)
      L_PLUGIN=vault; L_KIND=secret; L_CRED_FILE="$WORK/vault-cred.json"; L_SECRETS="$WORK/vault-cred.json"
      L_HOST="$PFX-vault.uat.example"
      L_SETTINGS='{"mount":"secret","path":"'"$PFX"'/leaf"}'
      L_READ_PROVIDER=vault; L_READ_CRED="$WORK/vault-reader.json"; L_READ_ARGS="--set mount=secret --set path=$PFX/leaf"; L_CAFILE="$MOUNT_DIR/vault/vault-ca.pem" ;;
    akv)
      L_PLUGIN=azure-keyvault; L_KIND=secret; L_CRED_FILE="$KK_AKV_CRED_FILE"; L_SECRETS="$KK_AKV_CRED_FILE"; L_HOST="$PFX-akv.uat.example"
      L_SETTINGS='{"secret_name":"'"$KK_AKV_SECRET_NAME"'"}'
      L_READ_PROVIDER=akv; L_READ_CRED="$KK_AKV_CRED_FILE"; L_READ_ARGS="--set secret_name=$KK_AKV_SECRET_NAME" ;;
    gcpsm)
      L_PLUGIN=gcp-secretmanager; L_KIND=secret; L_CRED_FILE="$KK_GCP_SA_FILE"; L_SECRETS="$KK_GCP_SA_FILE"; L_HOST="$PFX-gcpsm.uat.example"
      L_CRED_ARGS="--raw-key service_account_json --set project_id=$KK_GCP_PROJECT"
      L_SETTINGS='{"secret_id":"'"$KK_GCP_SECRET_ID"'"}'
      L_READ_PROVIDER=gcpsm; L_READ_CRED="$KK_GCP_SA_FILE"; L_READ_ARGS="--set project_id=$KK_GCP_PROJECT --set secret_id=$KK_GCP_SECRET_ID" ;;
    aws-sm)
      L_PLUGIN=aws-secretsmanager; L_KIND=secret; L_CRED_FILE="$KK_AWS_CRED_FILE"; L_SECRETS="$KK_AWS_CRED_FILE"; L_HOST="$PFX-awssm.uat.example"
      L_CRED_ARGS="--set region=$KK_AWS_REGION"
      L_SETTINGS='{"secret_id":"'"$KK_AWS_SECRET_ID"'"}'
      L_READ_PROVIDER=aws-sm; L_READ_CRED="$KK_AWS_CRED_FILE"; L_READ_ARGS="--set region=$KK_AWS_REGION --set secret_id=$KK_AWS_SECRET_ID" ;;
    aws-alb)
      L_PLUGIN=aws; L_KIND=lb; L_CRED_FILE="$KK_AWS_CRED_FILE"; L_SECRETS="$KK_AWS_CRED_FILE"; L_HOST="$KK_AWS_ALB_HOST"; L_CRED_ARGS="--set region=$KK_AWS_REGION"
      L_SETTINGS='{"mode":"acm_alb","listener_arn":"'"$KK_AWS_LISTENER_ARN"'"'"${KK_AWS_CERT_ARN:+,\"certificate_arn\":\"$KK_AWS_CERT_ARN\"}"'}' ;;
    aws-cloudfront)
      L_PLUGIN=aws; L_KIND=lb; L_CRED_FILE="$KK_AWS_CRED_FILE"; L_SECRETS="$KK_AWS_CRED_FILE"; L_HOST="$KK_AWS_CF_HOST"; L_CRED_ARGS="--set region=$KK_AWS_REGION"
      L_SETTINGS='{"mode":"acm_cloudfront","distribution_id":"'"$KK_AWS_DISTRIBUTION_ID"'"'"${KK_AWS_CF_CERT_ARN:+,\"certificate_arn\":\"$KK_AWS_CF_CERT_ARN\"}"'}' ;;
    azure-appgw)
      L_PLUGIN=azure; L_KIND=lb; L_CRED_FILE="$KK_AZ_CRED_FILE"; L_SECRETS="$KK_AZ_CRED_FILE"; L_HOST="$KK_AZ_APPGW_HOST"
      L_SETTINGS='{"mode":"appgw","subscription_id":"'"$KK_AZ_SUB"'","resource_group":"'"$KK_AZ_RG"'","keyvault_cert_name":"'"$KK_AZ_KV_CERT_NAME"'","gateway_name":"'"$KK_AZ_GATEWAY"'","ssl_certificate_name":"'"$KK_AZ_SSL_CERT"'"}' ;;
    azure-frontdoor)
      L_PLUGIN=azure; L_KIND=lb; L_CRED_FILE="$KK_AZ_CRED_FILE"; L_SECRETS="$KK_AZ_CRED_FILE"; L_HOST="$KK_AZ_FD_HOST"
      L_SETTINGS='{"mode":"frontdoor","subscription_id":"'"$KK_AZ_SUB"'","resource_group":"'"$KK_AZ_RG"'","keyvault_cert_name":"'"$KK_AZ_KV_CERT_NAME"'","profile_name":"'"$KK_AZ_PROFILE"'","secret_name":"'"$KK_AZ_FD_SECRET"'"}' ;;
    cloudflare)
      L_PLUGIN=cloudflare; L_KIND=lb; L_CRED_FILE="$KK_CF_CRED_FILE"; L_SECRETS="$KK_CF_CRED_FILE"; L_HOST="$KK_CF_HOST"
      L_CRED_ARGS="--set api_base=${KK_CF_API_BASE:-https://api.cloudflare.com/client/v4}"
      L_SETTINGS='{"zone_id":"'"$KK_CF_ZONE_ID"'","hostname":"'"$KK_CF_HOST"'"}' ;;
  esac
}

# Build one plugin like scripts/build-plugins.sh does (wasm + manifest with the sha256 pinned), install it,
# take it through the enable approval with the second admin. Idempotent per hub.
ensure_plugin() {
  local dir="$1" id ver
  case "$INSTALLED_PLUGINS" in *" $dir "*) return 0 ;; esac
  mkdir -p "$WORK/plugins/$dir"
  (cd "$REPO_ROOT/plugins/$dir" && GOOS=wasip1 GOARCH=wasm go build -trimpath -buildmode=c-shared -o "$WORK/plugins/$dir/plugin.wasm" .) \
    || { FAIL "plugin $dir did not build"; return 1; }
  python3 - "$REPO_ROOT/plugins/$dir/manifest.json" "$WORK/plugins/$dir" <<'PY'
import base64, hashlib, json, sys
src, out = sys.argv[1:3]
m = json.load(open(src))
wasm = open(f"{out}/plugin.wasm", "rb").read()
m["artifact"]["sha256"] = hashlib.sha256(wasm).hexdigest()
json.dump({"manifest": m, "wasm_base64": base64.b64encode(wasm).decode()}, open(f"{out}/install.json", "w"))
print(m["id"], m["version"])
PY
  read -r id ver < <(python3 -c 'import json,sys; m=json.load(open(sys.argv[1])); print(m["id"], m["version"])' "$REPO_ROOT/plugins/$dir/manifest.json")
  local c action
  c=$(code "$TOKEN" -X POST "$HUB/api/v1/delivery-plugins" --data @"$WORK/plugins/$dir/install.json")
  [ "$c" = 201 ] || { FAIL "install $id -> $c $(head -c 300 "$WORK/last.json")"; return 1; }
  PASS "installed $id $ver ($(jget '"capability tier "+d["data"]["capability_tier"]+", trust "+d["data"]["trust_tier"]' <"$WORK/last.json"))"
  c=$(code "$TOKEN" -X POST "$HUB/api/v1/delivery-plugins/$id/versions/$ver/enable")
  action="$(jget 'd["data"].get("pending_action_id","")' <"$WORK/last.json" 2>/dev/null)"
  [ "$c" = 202 ] && [ -n "$action" ] || { FAIL "enable $id -> $c $(head -c 300 "$WORK/last.json")"; return 1; }
  c=$(code "$TOKEN" -X POST "$HUB/api/v1/pending-actions/$action/approve")
  [ "$c" = 403 ] && PASS "self-approval of the enable refused (403)" || FAIL "self-approval -> $c"
  c=$(code "$ADMIN2" -X POST "$HUB/api/v1/pending-actions/$action/approve")
  [ "$c" = 200 ] || { FAIL "second admin approval -> $c $(head -c 300 "$WORK/last.json")"; return 1; }
  PASS "enabled $id $ver through the approval queue"
  INSTALLED_PLUGINS="$INSTALLED_PLUGINS$dir "
  PLUGIN_ID="$id"
}

plugin_id_of() { python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["id"])' "$REPO_ROOT/plugins/$1/manifest.json"; }

# issue_leaf CN -> prints the fingerprint of a fresh leaf issued by the hub CA
issue_leaf() {
  local cn="$1" n="$2"
  openssl ecparam -name prime256v1 -genkey -noout -out "$WORK/leaf$n.key" 2>/dev/null
  openssl req -new -key "$WORK/leaf$n.key" -subj "/CN=$cn" -addext "subjectAltName=DNS:$cn" -out "$WORK/leaf$n.csr" 2>/dev/null
  python3 -c "import json,sys; json.dump({'ca_id':sys.argv[1],'template_id':sys.argv[2],'csr_pem':open(sys.argv[3]).read()}, open(sys.argv[4],'w'))" "$CA_ID" "$TPL_ID" "$WORK/leaf$n.csr" "$WORK/issue$n.json"
  api "$TOKEN" -X POST "$HUB/api/v1/certificates" --data @"$WORK/issue$n.json" | jget 'd["data"]["fingerprint_sha256"]'
}

cert_serial_of_fp() { # hub's serial for a fingerprint, normalised: lower hex, no colons, no leading zeros
  api "$TOKEN" "$HUB/api/v1/certificates/$1" | python3 -c 'import json,sys; d=json.load(sys.stdin)["data"]; s=(d.get("serial_number") or d.get("certificate",{}).get("serial_number","")); print(s.replace(":","").lower().lstrip("0"))'
}
served_serial() { # host -> normalised serial the public endpoint presents
  echo | openssl s_client -connect "$1:443" -servername "$1" 2>/dev/null | openssl x509 -noout -serial 2>/dev/null | sed 's/^serial=//' | tr 'A-F' 'a-f' | sed 's/^0*//'
}
wait_serial() { # host want max_seconds -> prints seconds taken, exit 1 on timeout
  local host="$1" want="$2" max="$3" t0 now got
  t0=$(date +%s)
  while :; do
    got="$(served_serial "$host")"
    now=$(( $(date +%s) - t0 ))
    if [ -n "$got" ] && [ "$got" = "$want" ]; then echo "$now"; return 0; fi
    [ "$now" -ge "$max" ] && { echo "$now"; return 1; }
    sleep 20
  done
}

store_state() { # -> JSON line from the direct reader
  # shellcheck disable=SC2086
  python3 "$STOREREAD" --provider "$L_READ_PROVIDER" --cred "$L_READ_CRED" $L_READ_ARGS ${L_CAFILE:+--cafile "$L_CAFILE"}
}

record() { # leg result newver rb_match secs forced occ note
  RESULTS="${RESULTS}$1	$2	$3	$4	$5	$6	$7	$8
"
}

# run_leg LEG
run_leg() {
  local leg="$1"
  local result=PASS newver="-" rbmatch="-" secs="-" forced="-" occ="-" note=""
  LFAIL() { echo "FAIL: $*"; result=FAIL; FAILED=1; note="$note; $*"; }
  STEP "leg: $leg"
  leg_setup "$leg"
  ensure_plugin "$L_PLUGIN" || { record "$leg" FAIL - - - - - "plugin install/enable failed"; return; }
  PLUGIN_ID="$(plugin_id_of "$L_PLUGIN")"

  local cred c tgt fp1 fp2
  # shellcheck disable=SC2086
  cred="$(python3 "$HUBAPI" cred --hub "$HUB" --bearer "$TOKEN" --name "$PFX-$leg" --file "$L_CRED_FILE" $L_CRED_ARGS)" \
    || { LFAIL "credential create failed"; record "$leg" FAIL - - - - - "$note"; return; }
  PASS "credential $cred (secret not shown)"
  c=$(code "$TOKEN" -X POST "$HUB/api/v1/targets" -d "{\"name\":\"$PFX-$leg\",\"host\":\"$L_HOST\",\"discovery_mode\":\"none\",\"install_mode\":\"plugin\",\"renewal_method\":\"manual\",\"credential_ref\":\"$cred\",\"plugin_id\":\"$PLUGIN_ID\",\"plugin_settings\":$L_SETTINGS}")
  [ "$c" = 201 ] || { LFAIL "target -> $c $(head -c 300 "$WORK/last.json")"; record "$leg" FAIL - - - - - "$note"; return; }
  tgt="$(jget 'd["data"]["id"]' <"$WORK/last.json")"
  PASS "plugin target $tgt"

  local before_count=0 before_fp=""
  if [ "$L_KIND" = secret ]; then
    local st; st="$(store_state)" || { LFAIL "cannot read the store before the run: $st"; record "$leg" FAIL - - - - - "$note"; return; }
    before_count="$(echo "$st" | jget 'd["count"]')"; before_fp="$(echo "$st" | jget 'd["fingerprint"]')"
    INFO "store before: versions=$before_count current_fp=${before_fp:-none}"
  fi

  # ---- success run
  fp1="$(issue_leaf "$L_HOST" 1)"; [ -n "$fp1" ] || { LFAIL "issuing the leaf failed"; record "$leg" FAIL - - - - - "$note"; return; }
  c=$(CURL_MAX=900 code "$TOKEN" -X POST "$HUB/api/v1/renewal/execute" -d "{\"fingerprint\":\"$fp1\",\"target_id\":\"$tgt\"}")
  local out newfp1
  out="$(jget 'str(d["data"].get("install_outcome"))+" verified="+str(d["data"].get("verified"))' <"$WORK/last.json" 2>/dev/null)"
  newfp1="$(jget 'd["data"].get("new_fingerprint","")' <"$WORK/last.json" 2>/dev/null | tr -d ':' | tr 'A-F' 'a-f')"
  case "$c:$out" in
    200:installed_verified\ verified=True) PASS "renewed and delivered: $out" ;;
    *) LFAIL "renewal -> $c $(head -c 400 "$WORK/last.json")" ;;
  esac

  local newserial=""
  if [ "$L_KIND" = secret ]; then
    local st2 after_fp after_count after_ver
    st2="$(store_state)" || LFAIL "cannot read the store after the run: $st2"
    after_fp="$(echo "$st2" | jget 'd["fingerprint"]' 2>/dev/null)"; after_count="$(echo "$st2" | jget 'd["count"]' 2>/dev/null)"; after_ver="$(echo "$st2" | jget 'd["version"]' 2>/dev/null)"
    newver="v$after_ver"
    if [ -n "$newfp1" ] && [ "$after_fp" = "$newfp1" ]; then rbmatch=yes; PASS "store read-back fingerprint == new_fingerprint ($after_fp)"; else rbmatch=no; LFAIL "store holds ${after_fp:-nothing}, hub renewed ${newfp1:-none}"; fi
    [ "$after_count" = $(( before_count + 1 )) ] && PASS "version count rose by exactly 1 ($before_count -> $after_count)" || LFAIL "version count $before_count -> $after_count (want +1)"
  else
    newserial="$(cert_serial_of_fp "$newfp1")"
    newver="serial ${newserial:-?}"
    [ -n "$newserial" ] || LFAIL "could not get the renewed certificate's serial from the hub"
    if secs="$(wait_serial "$L_HOST" "$newserial" 900)"; then PASS "$L_HOST serves the new serial after ${secs}s (limit 900s)"; rbmatch=n/a
    else LFAIL "$L_HOST did not serve serial $newserial within ${secs}s"; rbmatch=no; fi
  fi

  # ---- forced failure: the hub's own post-push verification fails against a TLS server presenting another certificate
  start_mismatch_server_once
  fp2="$(issue_leaf "$L_HOST" 2)"
  c=$(CURL_MAX=900 code "$TOKEN" -X POST "$HUB/api/v1/renewal/execute" -d "{\"fingerprint\":\"$fp2\",\"target_id\":\"$tgt\",\"install\":{\"verify_host_port\":\"$MM_CTR:8443\"}}")
  out="$(jget 'str(d["data"].get("install_outcome"))+" verified="+str(d["data"].get("verified"))' <"$WORK/last.json" 2>/dev/null)"
  local forced_ok=1
  case "$out" in verify_failed\ verified=False) PASS "forced failure: hub reports $out" ;; *) forced_ok=0; LFAIL "forced failure: expected verify_failed, got $c $(head -c 400 "$WORK/last.json")" ;; esac
  if [ "$L_KIND" = secret ]; then
    local st3 cur_fp cur_count
    st3="$(store_state)" || LFAIL "cannot read the store after the forced failure"
    cur_fp="$(echo "$st3" | jget 'd["fingerprint"]' 2>/dev/null)"; cur_count="$(echo "$st3" | jget 'd["count"]' 2>/dev/null)"
    if [ -n "$newfp1" ] && [ "$cur_fp" = "$newfp1" ]; then PASS "after the forced failure the store's current version is still the success-run certificate ($cur_fp; versions now $cur_count)"
    else forced_ok=0; LFAIL "after the forced failure the store holds ${cur_fp:-nothing}, expected $newfp1"; fi
  else
    local back
    if back="$(wait_serial "$L_HOST" "$newserial" 900)"; then PASS "forced failure: $L_HOST serves the previous serial again after ${back}s"
    else forced_ok=0; LFAIL "forced failure: $L_HOST not back on serial $newserial after ${back}s"; fi
  fi
  [ "$forced_ok" = 1 ] && forced="rolled back (verify_failed)" || forced="FAIL"

  # ---- audit rows and the secret scan
  local sargs="" f rc
  for f in $L_SECRETS; do sargs="$sargs --secret $f"; done
  podman logs "$HUB_CTR" >"$WORK/hub.log" 2>&1
  # shellcheck disable=SC2086
  python3 "$HUBAPI" scan --hub "$HUB" --bearer "$TOKEN" --hublog "$WORK/hub.log" --audit-out "$WORK/audit-dump.json" $sargs >"$WORK/scan.out" 2>&1; rc=$?
  cat "$WORK/scan.out"
  occ="$(sed -n 's/.*total occurrences: \([0-9]*\).*/\1/p' "$WORK/scan.out")"; [ -z "$occ" ] && occ="SCAN-FAILED"
  if [ $rc = 0 ] && [ "$occ" = 0 ]; then PASS "secrets found 0 times in hub log + audit"; else LFAIL "secret scan: occurrences=$occ"; fi
  # Control: the scanner must find a value we plant (a scan that cannot fail proves nothing).
  printf 'kk-uat-canary-%s' "$RUN_ID" >"$WORK/canary.txt"
  { cat "$WORK/hub.log"; cat "$WORK/canary.txt"; } >"$WORK/hub-canary.log"
  if python3 "$HUBAPI" scan --hub "$HUB" --bearer "$TOKEN" --hublog "$WORK/hub-canary.log" --secret "$WORK/canary.txt" >/dev/null 2>&1; then
    LFAIL "scan control: a planted value was not detected"
  else PASS "scan control: a planted value is detected"; fi
  local rows
  rows="$(python3 - "$WORK/audit-dump.json" "$PLUGIN_ID" <<'PY'
import json, sys
rows = json.load(open(sys.argv[1]))
push = [r for r in rows if r.get("action") == "delivery_plugin.push" and r.get("resource_id") == sys.argv[2]]
ok = sum(1 for r in push if "verified=true" in (r.get("change_summary") or "") )
rb = sum(1 for r in push if "rolled_back=true" in (r.get("change_summary") or ""))
print(f"{len(push)} {ok} {rb}")
PY
)"
  # shellcheck disable=SC2086
  set -- $rows
  if [ "${1:-0}" -ge 2 ] && [ "${3:-0}" -ge 1 ]; then PASS "audit: $1 delivery_plugin.push rows for $PLUGIN_ID ($2 verified, $3 rolled_back=true)"
  else LFAIL "audit: delivery_plugin.push rows=${1:-0} verified=${2:-0} rolled_back=${3:-0} (want >=2 rows incl. one rolled_back=true)"; fi
  [ -n "${KK_EVIDENCE_DIR:-}" ] && { mkdir -p "$KK_EVIDENCE_DIR"; cp "$WORK/last.json" "$KK_EVIDENCE_DIR/$leg-forced-failure-response.json"; [ "$occ" = 0 ] && cp "$WORK/audit-dump.json" "$KK_EVIDENCE_DIR/$leg-audit.json"; }
  record "$leg" "$result" "$newver" "$rbmatch" "$secs" "$forced" "$occ" "$note"
}

MM_STARTED=0
start_mismatch_server_once() { [ "$MM_STARTED" = 1 ] && return 0; start_mismatch_server; MM_STARTED=1; }

print_results() {
  echo; echo "=== results ==="
  local md="| Leg | Result | New version / serial | Read-back fp == new_fingerprint | Seconds to serve (LB) | Forced-failure result | Secret occurrences (log+audit) | Notes |
|---|---|---|---|---|---|---|---|"
  local l r v m s f o n
  while IFS='	' read -r l r v m s f o n; do
    [ -z "$l" ] && continue
    md="$md
| $l | $r | $v | $m | $s | $f | $o | $n |"
  done <<EOF
$RESULTS
EOF
  echo "$md"
  if [ -n "${KK_EVIDENCE_DIR:-}" ]; then mkdir -p "$KK_EVIDENCE_DIR"; echo "$md" >"$KK_EVIDENCE_DIR/results.md"; fi
}
