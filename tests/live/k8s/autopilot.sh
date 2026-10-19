#!/usr/bin/env bash
# W27-06 k8s leg: the hub SCHEDULER (not the API) renews a due certificate into
# a real Kubernetes TLS Secret on a real kind cluster, and a forced failure
# leaves the previous Secret current, byte for byte.
#
# Copies run.sh's cluster/RBAC/tlsecho/credential steps (not sourced, so the two
# scripts stay independently runnable) up to target creation, then only
# observes. Differences from run.sh: unique cluster name and ports per run
# (safe next to run.sh), no cert-manager (discovery is not under test), and the
# hub runs with RENEWAL_POLL_MINUTES=1 and the targets armed auto_renew=true.
#
#   target A  namespace uat-A   Role present   -> scheduler installs, verified
#   target B  namespace uat-B   NO Role        -> write refused (403), the
#             Secret and the served leaf stay byte-identical
#
# Timing note: the hub's own verify retries through kubelet Secret propagation
# (k8sVerifyRetryAttempts, ~2 min), so the scheduled attempt can legitimately
# take that long after the tick; the independent kubectl check reads the Secret
# itself and the served-leaf check waits up to 150 s.
set -u
set -o pipefail
export KIND_EXPERIMENTAL_PROVIDER=podman

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$HERE/../../.." && pwd)"
WORK="$(mktemp -d /tmp/kk-uat-k8sap.XXXXXX)"
RUN_ID="$(openssl rand -hex 3)"
free_port() { python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1]); s.close()'; }
HUB_PORT="$(free_port)"
HUB_BASE="http://127.0.0.1:${HUB_PORT}"
HUB_DIR="$WORK/hub"
TOKEN=uat-token
CLUSTER="kk-ap-$RUN_ID"
NS_A=uat-a; NS_B=uat-b
SECRET=kk-ap-tls
NODEPORT_A=30443; NODEPORT_B=30444
HOSTPORT_A="$(free_port)"; HOSTPORT_B="$(free_port)"
IMAGE="localhost/kk-ap-tlsecho:$RUN_ID"
POLL_SECONDS=60
DEADLINE=$((POLL_SECONDS + 60))
VERIFY_HOST="$(python3 -c "
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.connect(('192.0.2.1', 9))
print(s.getsockname()[0])")"
case "$VERIFY_HOST" in ""|127.*|169.254.*) echo "FAIL: no non-loopback host address for verify"; exit 1;; esac

PASS_N=0; FAIL_N=0
log()  { printf '[%s] %s\n' "$(date '+%H:%M:%S')" "$*"; }
PASS() { PASS_N=$((PASS_N+1)); log "PASS: $*"; }
FAIL() { FAIL_N=$((FAIL_N+1)); log "FAIL: $*"; }
summary() { echo; echo "=== k8s autopilot summary: $PASS_N passed, $FAIL_N failed ==="; }
HUB_PID=""
cleanup() {
  log "cleanup"
  [ -n "$HUB_PID" ] && kill "$HUB_PID" 2>/dev/null
  for _ in 1 2 3; do
    kind delete cluster --name "$CLUSTER" >/dev/null 2>&1
    kind get clusters 2>/dev/null | grep -qx "$CLUSTER" || break
    sleep 2
  done
  podman rmi -f "$IMAGE" >/dev/null 2>&1
  rm -rf "$WORK"
}
trap cleanup EXIT
DIE() { FAIL "$*"; summary; exit 1; }

curlj() { curl -sS -H "Authorization: Bearer ${TOKEN}" -H 'Content-Type: application/json' "$@"; }
jget() { python3 -c "import json,sys
d=json.load(sys.stdin)
for k in sys.argv[1].split('.'):
    d=d[int(k)] if k.isdigit() else d.get(k) if isinstance(d,dict) else None
    if d is None: break
print('' if d is None else d)" "$1" 2>/dev/null; }
served_der_sum() { echo | openssl s_client -connect "$1" 2>/dev/null | openssl x509 -outform DER 2>/dev/null | openssl dgst -sha256 -r | cut -d' ' -f1; }
secret_crt_sum() { kubectl -n "$1" get secret "$SECRET" -o go-template='{{index .data "tls.crt"}}' 2>/dev/null | base64 -d 2>/dev/null | openssl dgst -sha256 -r | cut -d' ' -f1; }
secret_crt_fp() { kubectl -n "$1" get secret "$SECRET" -o go-template='{{index .data "tls.crt"}}' 2>/dev/null | base64 -d 2>/dev/null | openssl x509 -noout -fingerprint -sha256 2>/dev/null | cut -d= -f2 | tr -d ':' | tr 'A-F' 'a-f'; }
audit_json() { curlj "$HUB_BASE/api/v1/audit?limit=200&$1"; }

# --- cluster -----------------------------------------------------------------
cat > "$WORK/kind-config.yaml" <<KIND
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
nodes:
- role: control-plane
  extraPortMappings:
  - containerPort: ${NODEPORT_A}
    hostPort: ${HOSTPORT_A}
    protocol: TCP
  - containerPort: ${NODEPORT_B}
    hostPort: ${HOSTPORT_B}
    protocol: TCP
KIND
kind create cluster --name "$CLUSTER" --config "$WORK/kind-config.yaml" >"$WORK/kind.log" 2>&1 \
  && PASS "kind cluster $CLUSTER up (podman provider)" || { tail -5 "$WORK/kind.log"; DIE "kind create cluster failed"; }
KCTX="kind-$CLUSTER"; kubectl config use-context "$KCTX" >/dev/null

kubectl create namespace "$NS_A" >/dev/null && kubectl create namespace "$NS_B" >/dev/null || DIE "namespaces"
cat > "$WORK/rbac.yaml" <<RBAC
apiVersion: v1
kind: ServiceAccount
metadata: {name: kk-ap-pusher, namespace: ${NS_A}}
---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata: {name: kk-ap-pusher, namespace: ${NS_A}}
rules:
- apiGroups: [""]
  resources: ["secrets"]
  verbs: ["get", "list", "create", "update"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata: {name: kk-ap-pusher, namespace: ${NS_A}}
subjects: [{kind: ServiceAccount, name: kk-ap-pusher, namespace: ${NS_A}}]
roleRef: {kind: Role, name: kk-ap-pusher, apiGroup: rbac.authorization.k8s.io}
RBAC
kubectl apply -f "$WORK/rbac.yaml" >/dev/null || DIE "RBAC apply"
SA_TOKEN="$(kubectl create token kk-ap-pusher -n "$NS_A" --duration=2h)" || DIE "token"
kubectl config view --minify --raw -o yaml > "$WORK/kubeconfig-view.yaml"
APISERVER_URL="$(python3 - "$WORK/kubeconfig-view.yaml" "$WORK/cluster-ca.pem" <<'PYEOF'
import base64, re, sys
text = open(sys.argv[1]).read()
open(sys.argv[2], 'wb').write(base64.b64decode(re.search(r'certificate-authority-data:\s*(\S+)', text).group(1)))
print(re.search(r'server:\s*(\S+)', text).group(1))
PYEOF
)"
[ -n "$APISERVER_URL" ] || DIE "no API server URL"
CODE_A="$(curl -sS -o /dev/null -w '%{http_code}' --cacert "$WORK/cluster-ca.pem" -H "Authorization: Bearer $SA_TOKEN" "$APISERVER_URL/api/v1/namespaces/$NS_A/secrets")"
CODE_B="$(curl -sS -o /dev/null -w '%{http_code}' --cacert "$WORK/cluster-ca.pem" -H "Authorization: Bearer $SA_TOKEN" "$APISERVER_URL/api/v1/namespaces/$NS_B/secrets")"
[ "$CODE_A" = 200 ] && [ "$CODE_B" = 403 ] && PASS "SA token: $NS_A=200, $NS_B=403 (RBAC scoped)" || DIE "SA RBAC check: $NS_A=$CODE_A $NS_B=$CODE_B"

# --- workloads: tlsecho serving each namespace's Secret -----------------------------
PODMAN_ARCH="$(podman info --format '{{.Host.Arch}}' 2>/dev/null || echo arm64)"
mkdir -p "$WORK/tlsctx"
( cd "$REPO_ROOT" && GOOS=linux GOARCH="$PODMAN_ARCH" CGO_ENABLED=0 go build -o "$WORK/tlsctx/tlsecho" ./tests/live/k8s/tlsecho ) || DIE "tlsecho build"
cp "$HERE/tlsecho/Containerfile" "$WORK/tlsctx/Containerfile"
podman build -t "$IMAGE" "$WORK/tlsctx" >"$WORK/build.log" 2>&1 || DIE "tlsecho image build, see $WORK/build.log"
podman save "$IMAGE" -o "$WORK/tlsecho.tar" && kind load image-archive "$WORK/tlsecho.tar" --name "$CLUSTER" >/dev/null 2>&1 \
  && PASS "tlsecho image loaded" || DIE "kind load"
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -keyout "$WORK/ph.key" -out "$WORK/ph.crt" -days 1 -nodes -subj "/CN=placeholder" >/dev/null 2>&1
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -keyout "$WORK/phb.key" -out "$WORK/phb.crt" -days 1 -nodes -subj "/CN=placeholder-b" >/dev/null 2>&1
workload() { # ns nodeport crt key
  local crt key
  crt="$(base64 < "$3" | tr -d '\n')"; key="$(base64 < "$4" | tr -d '\n')"
  cat <<YAML
apiVersion: v1
kind: Secret
metadata: {name: ${SECRET}, namespace: $1}
type: kubernetes.io/tls
data: {tls.crt: "${crt}", tls.key: "${key}"}
---
apiVersion: v1
kind: Pod
metadata: {name: kk-ap-target, namespace: $1, labels: {app: kk-ap-target}}
spec:
  containers:
  - name: tlsecho
    image: ${IMAGE}
    imagePullPolicy: Never
    args: [":8443", "/tls/tls.crt", "/tls/tls.key"]
    ports: [{containerPort: 8443}]
    volumeMounts: [{name: tls, mountPath: /tls, readOnly: true}]
  volumes: [{name: tls, secret: {secretName: ${SECRET}}}]
---
apiVersion: v1
kind: Service
metadata: {name: kk-ap-target, namespace: $1}
spec:
  type: NodePort
  selector: {app: kk-ap-target}
  ports: [{port: 8443, targetPort: 8443, nodePort: $2}]
YAML
}
workload "$NS_A" "$NODEPORT_A" "$WORK/ph.crt" "$WORK/ph.key" | kubectl apply -f - >/dev/null || DIE "workload A"
workload "$NS_B" "$NODEPORT_B" "$WORK/phb.crt" "$WORK/phb.key" | kubectl apply -f - >/dev/null || DIE "workload B"
kubectl -n "$NS_A" wait --for=condition=Ready pod/kk-ap-target --timeout=90s >/dev/null && kubectl -n "$NS_B" wait --for=condition=Ready pod/kk-ap-target --timeout=90s >/dev/null \
  && PASS "both workloads ready" || DIE "pods never ready"
for _ in $(seq 1 30); do [ -n "$(served_der_sum 127.0.0.1:$HOSTPORT_A)" ] && [ -n "$(served_der_sum 127.0.0.1:$HOSTPORT_B)" ] && break; sleep 1; done
[ -n "$(served_der_sum 127.0.0.1:$HOSTPORT_B)" ] || DIE "workloads not reachable via the extraPortMappings"

# --- hub (host process) with a one-minute scheduler -------------------------------------
mkdir -p "$HUB_DIR/data"
( cd "$REPO_ROOT" && go build -o "$HUB_DIR/kryptkeeper" ./cmd/kryptkeeper ) || DIE "hub build"
export APP_BOOTSTRAP_TOKEN="$TOKEN" AUTH_MODE=bootstrap APP_CERTIFICATE_PROVIDER=ca \
  APP_DISCOVERY_PROVIDER=db APP_NOTIFICATION_PROVIDER=file KRYPTKEEPER_TLS_DISABLE=true \
  APP_CREDENTIAL_STORE_PASSPHRASE='uat-k8s-cred-passphrase-32-bytes!' \
  KRYPTKEEPER_KEYSTORE_PASSPHRASE='uat-k8s-keystore-passphrase-32byt' \
  KRYPTKEEPER_DATA_DIR="$HUB_DIR/data" APP_CA_FILE="$HUB_DIR/data/cas.json" \
  APP_TEMPLATE_FILE="$HUB_DIR/data/templates.json" APP_CERTIFICATE_FILE="$HUB_DIR/data/certificates.json" \
  APP_AUDIT_FILE="$HUB_DIR/data/audit.json" APP_CERTS_SUMMARY_FILE="$HUB_DIR/data/certs_summary.json" \
  KRYPTKEEPER_BOOTSTRAP_CREATE_ROOT=true KRYPTKEEPER_CA_NAME="UAT Root CA" \
  APP_BIND_ADDR=127.0.0.1 PORT="$HUB_PORT" RENEWAL_POLL_MINUTES=1
"$HUB_DIR/kryptkeeper" >"$WORK/hub.log" 2>&1 &
HUB_PID=$!
for _ in $(seq 1 40); do curl -sf -o /dev/null "$HUB_BASE/api/v1/cas" -H "Authorization: Bearer ${TOKEN}" && break; sleep 1; done
curl -sf -o /dev/null "$HUB_BASE/api/v1/cas" -H "Authorization: Bearer ${TOKEN}" || DIE "hub never answered, see $WORK/hub.log"
CA_ID="$(curlj "$HUB_BASE/api/v1/cas" | jget data.0.id)"
TPL_ID="$(curlj -X POST "$HUB_BASE/api/v1/templates" -d '{"name":"uat-k8sap","display_name":"k8sap","allowed_algorithms":["ECDSA","RSA-2048"],"key_usage":["digitalSignature","keyEncipherment"],"extended_key_usage":["serverAuth"],"validity_period":"72h","active":true}' | jget data.id)"
[ -n "$CA_ID" ] && [ -n "$TPL_ID" ] || DIE "no CA/template"
PASS "hub up on $HUB_BASE (RENEWAL_POLL_MINUTES=1), 72h template"

mk_target() { # name ns verify_hostport -> target id (credential + target)
  python3 - "$APISERVER_URL" "$SA_TOKEN" "$2" "$SECRET" "$WORK/cluster-ca.pem" "$1" >"$WORK/cred.json" <<'CREDPY'
import json, sys
apiserver, token, ns, secret, capath, name = sys.argv[1:7]
print(json.dumps({'name': name, 'credential_type': 'api_token', 'payload': {
  'base_url': apiserver, 'bearer_token': token.strip(), 'namespace': ns, 'secret_name': secret, 'ca_cert': open(capath).read()}}))
CREDPY
  local cred
  cred="$(curlj -X POST "$HUB_BASE/api/v1/credentials" -d @"$WORK/cred.json" | jget data.id)"; [ -n "$cred" ] || return 1
  curlj -X POST "$HUB_BASE/api/v1/targets" -d "{\"name\":\"$1\",\"host\":\"$1.uat.example\",\"discovery_mode\":\"network\",\"install_mode\":\"k8s\",\"credential_ref\":\"$cred\",\"verify_host_port\":\"$3\",\"auto_renew\":true}" | jget data.id
}
T_A="$(mk_target kk-ap-a "$NS_A" "${VERIFY_HOST}:${HOSTPORT_A}")"; T_B="$(mk_target kk-ap-b "$NS_B" "${VERIFY_HOST}:${HOSTPORT_B}")"
[ -n "$T_A" ] && [ -n "$T_B" ] || DIE "target create failed"
issue() { # cn -> fp
  openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -keyout "$WORK/$1.key" -out "$WORK/$1.csr" -subj "/CN=$1.uat.example" -addext "subjectAltName=DNS:$1.uat.example" >/dev/null 2>&1
  python3 -c "import json,sys; json.dump({'ca_id':sys.argv[1],'template_id':sys.argv[2],'csr_pem':open(sys.argv[3]).read()}, open(sys.argv[4],'w'))" "$CA_ID" "$TPL_ID" "$WORK/$1.csr" "$WORK/$1.issue.json"
  curlj -X POST "$HUB_BASE/api/v1/certificates" --data @"$WORK/$1.issue.json" | jget data.fingerprint_sha256
}
FP_A="$(issue kk-ap-a)"; FP_B="$(issue kk-ap-b)"
[ -n "$FP_A" ] && [ -n "$FP_B" ] || DIE "issue failed"
BCODE="$(curl -sS -o /dev/null -w '%{http_code}' -H "Authorization: Bearer $TOKEN" "$HUB_BASE/api/v1/targets/$T_A/bindings")"
if [ "$BCODE" = 200 ]; then
  ca=$(curl -sS -o /dev/null -w '%{http_code}' -X POST -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' "$HUB_BASE/api/v1/targets/$T_A/bindings" -d "{\"cert_fingerprint\":\"$FP_A\"}")
  cb=$(curl -sS -o /dev/null -w '%{http_code}' -X POST -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' "$HUB_BASE/api/v1/targets/$T_B/bindings" -d "{\"cert_fingerprint\":\"$FP_B\"}")
  case "$ca$cb" in 20[01]20[01]) PASS "certificates bound to their targets (W27-02 bindings)" ;; *) DIE "binding create -> $ca/$cb" ;; esac
else
  log "NOTE: bindings route -> $BCODE; this build predates W27-02"
fi

SUM_A0="$(secret_crt_sum "$NS_A")"; SUM_B0="$(secret_crt_sum "$NS_B")"
DER_B0="$(served_der_sum 127.0.0.1:$HOSTPORT_B)"; FP_SECRET_A0="$(secret_crt_fp "$NS_A")"
[ -n "$SUM_A0" ] && [ -n "$SUM_B0" ] && [ -n "$DER_B0" ] || DIE "could not capture the before state"
PASS "before: Secret A ${SUM_A0:0:16}.. (placeholder), Secret B ${SUM_B0:0:16}.., B serves ${DER_B0:0:16}.."
T0=$SECONDS
log "== setup done; only observing. Deadline ${DEADLINE}s (RENEWAL_POLL_MINUTES=1 + 60) =="

# --- A: the scheduler writes the Secret ------------------------------------------------------
NEW_A=""; while [ $((SECONDS-T0)) -lt $((DEADLINE+180)) ]; do
  fp="$(secret_crt_fp "$NS_A")"; [ -n "$fp" ] && [ "$fp" != "$FP_SECRET_A0" ] && { NEW_A="$fp"; break; }; sleep 3
done
ELAPSED=$((SECONDS-T0))
if [ -n "$NEW_A" ]; then
  [ "$ELAPSED" -le "$DEADLINE" ] && PASS "A: Secret changed after ${ELAPSED}s (limit ${DEADLINE}s): ${FP_SECRET_A0:0:16}.. -> ${NEW_A:0:16}.." \
    || FAIL "A: Secret changed but after ${ELAPSED}s (limit ${DEADLINE}s)"
else
  FAIL "A: Secret never changed (waited $((SECONDS-T0))s)"; tail -20 "$WORK/hub.log"
fi
SERVED_A=""; end=$((SECONDS+150)); while [ $SECONDS -lt $end ]; do
  SERVED_A="$(echo | openssl s_client -connect "127.0.0.1:$HOSTPORT_A" 2>/dev/null | openssl x509 -noout -fingerprint -sha256 2>/dev/null | cut -d= -f2 | tr -d ':' | tr 'A-F' 'a-f')"
  [ -n "$NEW_A" ] && [ "$SERVED_A" = "$NEW_A" ] && break; sleep 3
done
[ -n "$NEW_A" ] && [ "$SERVED_A" = "$NEW_A" ] && PASS "A: the pod serves the new Secret leaf (kubelet propagated)" || FAIL "A: pod serves '$SERVED_A', Secret holds '$NEW_A'"
AJ="$(audit_json "action=certificate.renew_execute&resource_id=$FP_A")"
printf '%s' "$AJ" | python3 -c 'import json,sys
d=json.load(sys.stdin)["data"]
sys.exit(0 if any(e["actor_id"]=="renewal-scheduler" and e["outcome"]=="success" and "install=installed" in e.get("change_summary","") for e in d) else 1)' \
  && PASS "A: certificate.renew_execute by renewal-scheduler, install=installed*" || { FAIL "A: scheduler audit row missing"; echo "$AJ" | head -c 600; }
NHUMAN="$(audit_json "action=certificate.renew_execute" | python3 -c 'import json,sys; print(sum(1 for e in json.load(sys.stdin)["data"] if e["actor_id"]!="renewal-scheduler"))')"
[ "$NHUMAN" = 0 ] && PASS "0 renew_execute audit rows by a human principal" || FAIL "$NHUMAN renew_execute row(s) by a non-scheduler actor"

# --- B: write refused -> previous Secret current, byte for byte ---------------------------------
end=$((SECONDS+DEADLINE+120)); BJ=""
while [ $SECONDS -lt $end ]; do
  BJ="$(audit_json "resource_id=$FP_B")"
  printf '%s' "$BJ" | python3 -c 'import json,sys
d=json.load(sys.stdin)["data"]
sys.exit(0 if any(e["action"] in ("certificate.renew_execute_partial","certificate.renew_execute_failed") for e in d) else 1)' && break
  sleep 3
done
printf '%s' "$BJ" | python3 -c 'import json,sys
d=json.load(sys.stdin)["data"]
sys.exit(0 if any(e["action"] in ("certificate.renew_execute_partial","certificate.renew_execute_failed") and e["outcome"]=="failure" and "attempt=1/5" in e.get("change_summary","") for e in d) else 1)' \
  && PASS "B: failure audit row with attempt=1/5" || { FAIL "B: no partial/failed row with attempt=1/5"; printf '%s' "$BJ" | head -c 800; }
[ "$(secret_crt_sum "$NS_B")" = "$SUM_B0" ] && PASS "B: Secret tls.crt byte-identical before and after (sha256 $SUM_B0)" || FAIL "B: Secret tls.crt changed"
DER_B1="$(served_der_sum 127.0.0.1:$HOSTPORT_B)"
[ "$DER_B1" = "$DER_B0" ] && PASS "B: served leaf byte-identical before and after (sha256 $DER_B0)" || FAIL "B: served leaf changed"

# --- secrets: 0 occurrences ------------------------------------------------------------------------
python3 - "$HUB_BASE" "$TOKEN" "$WORK/audit-dump.json" <<'PY'
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
[ $? -eq 0 ] && PASS "read the full audit trail ($(python3 -c 'import json,sys; print(len(json.load(open(sys.argv[1]))))' "$WORK/audit-dump.json") entries)" || { FAIL "empty audit trail"; : >"$WORK/audit-dump.json"; }
n_tok=$(cat "$WORK/hub.log" "$WORK/audit-dump.json" | grep -c -e "$SA_TOKEN" -e "PRIVATE KEY")
[ "$n_tok" = 0 ] && PASS "SA bearer token and private-key markers: 0 occurrences in hub log and audit" || FAIL "$n_tok line(s) contain the SA token or a key marker"

summary
[ "$FAIL_N" -eq 0 ] && echo "K8S-AUTOPILOT: ALL PASS" || echo "K8S-AUTOPILOT: FAILED"
[ "$FAIL_N" -eq 0 ]
