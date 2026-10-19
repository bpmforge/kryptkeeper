#!/usr/bin/env bash
# W19-03: prove the hub's k8s push install writes a renewed certificate into
# a real Kubernetes TLS Secret and verifies it against a real workload, and
# that k8s-certmanager discovery reads cert-manager Certificates from a real
# cluster -- against a real "kind" cluster on podman.
#
# Idempotent, PASS/FAIL per step, non-zero exit on any FAIL, cleans up its
# own cluster/containers/state on exit (trap). No real key material is ever
# committed: the cluster CA, SA token, and issued certs are all generated at
# run time into a temp dir.
set -u
set -o pipefail

export KIND_EXPERIMENTAL_PROVIDER=podman

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$HERE/../../.." && pwd)"
WORK="$(mktemp -d /tmp/kk-uat-k8s.XXXXXX)"
HUB_DIR=/tmp/kk-uat-k8s-hub
HUB_PORT=8093
HUB_BASE="http://127.0.0.1:${HUB_PORT}"
TOKEN=uat-token
CLUSTER=kk-uat
CLUSTER_B=kk-uat-b   # W24-24 second cluster
CTX_A="kind-${CLUSTER}"
CTX_B="kind-${CLUSTER_B}"
NAMESPACE=uat
TARGET_SECRET=kk-uat-target-tls
NODEPORT=30443
PROXY_PORT=8099
IMAGE=localhost/kk-uat-tlsecho:latest
# RC1-A-04 (7c8df355): the hub's post-install verify dial refuses loopback and
# link-local addresses (security control, not relaxed here). The kind NodePort is
# published on all host interfaces, so verify through the host's primary
# non-loopback (RFC1918) address -- the one the default route uses.
VERIFY_HOST="$(python3 -c "
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.connect(('192.0.2.1', 9))  # UDP connect: selects a route, sends nothing
print(s.getsockname()[0])")"
case "$VERIFY_HOST" in ""|127.*|169.254.*) echo "FAIL: no non-loopback host address for verify"; exit 1;; esac
VERIFY_HOSTPORT="${VERIFY_HOST}:${NODEPORT}"

FAILED=0
STEP() { echo; echo "== $* =="; }
PASS() { echo "PASS: $*"; }
FAIL() { echo "FAIL: $*"; FAILED=1; }
DIE()  { echo "FAIL: $*"; cleanup; exit 1; }

HUB_PID=""
PROXY_PID=""
cleanup() {
  STEP "cleanup"
  [ -n "$HUB_PID" ] && kill "$HUB_PID" 2>/dev/null || true
  [ -n "$PROXY_PID" ] && kill "$PROXY_PID" 2>/dev/null || true
  kind delete cluster --name "$CLUSTER" >/dev/null 2>&1 || true
  # retried and verified: a leaked kind cluster survived one run's cleanup
  for _ in 1 2 3; do
    kind delete cluster --name "$CLUSTER_B" >/dev/null 2>&1
    kind get clusters 2>/dev/null | grep -qx "$CLUSTER_B" || break
    sleep 2
  done
  rm -rf "$WORK" "$HUB_DIR" /tmp/kk-uat-k8s-multi-hub
}
trap cleanup EXIT

curlj() { curl -sS -H "Authorization: Bearer ${TOKEN}" -H 'Content-Type: application/json' "$@"; }

# ---------------------------------------------------------------------------
# 1. kind cluster + cert-manager + a real cert-manager-issued Certificate.
# ---------------------------------------------------------------------------
STEP "kind cluster"
kind delete cluster --name "$CLUSTER" >/dev/null 2>&1 || true
# The hub's Secret push (since 723a3d42, "guard hub-side F5/Citrix/K8s push with
# the egress policy") refuses loopback, and kind's default apiServerAddress is
# 127.0.0.1, so the push failed with "egress: destination blocked: 127.0.0.1".
# The guard stays on: publish cluster A's API server on a private (RFC1918) host
# address, which the policy allows. kind adds the address to the serving cert
# SANs, so TLS verification still runs against the cluster CA. Override with
# KK_K8S_API_ADDR when VERIFY_HOST (default-route address) is the wrong one.
API_ADDR="${KK_K8S_API_ADDR:-$VERIFY_HOST}"
cat > "$WORK/kind-config.yaml" <<EOF
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
networking:
  apiServerAddress: "${API_ADDR}"
nodes:
- role: control-plane
  extraPortMappings:
  - containerPort: ${NODEPORT}
    hostPort: ${NODEPORT}
    protocol: TCP
EOF
kind create cluster --name "$CLUSTER" --config "$WORK/kind-config.yaml" \
  && PASS "kind cluster $CLUSTER up (podman provider)" || DIE "kind create cluster failed"

STEP "install cert-manager"
kubectl apply -f https://github.com/cert-manager/cert-manager/releases/latest/download/cert-manager.yaml >"$WORK/certmanager-apply.log" 2>&1 \
  && PASS "cert-manager manifests applied" || DIE "cert-manager apply failed, see $WORK/certmanager-apply.log"
kubectl wait --for=condition=Available deployment --all -n cert-manager --timeout=180s \
  && PASS "cert-manager deployments available" || DIE "cert-manager never became available"
CM_IMAGE="$(kubectl get deploy -n cert-manager cert-manager -o go-template='{{(index .spec.template.spec.containers 0).image}}' 2>/dev/null)"

kubectl create namespace "$NAMESPACE" >/dev/null 2>&1 || true

cat > "$WORK/issuer-cert.yaml" <<EOF
apiVersion: cert-manager.io/v1
kind: ClusterIssuer
metadata:
  name: uat-selfsigned
spec:
  selfSigned: {}
---
apiVersion: cert-manager.io/v1
kind: Certificate
metadata:
  name: uat-leaf
  namespace: ${NAMESPACE}
spec:
  secretName: uat-leaf-tls
  dnsNames:
  - uat-leaf.example.com
  issuerRef:
    name: uat-selfsigned
    kind: ClusterIssuer
EOF
# Deployments Available does not mean the CRDs are discoverable or the webhook
# is serving yet (found live 2026-10-15: "no matches for kind Certificate").
tries=30
until kubectl apply -f "$WORK/issuer-cert.yaml" >"$WORK/issuer-apply.log" 2>&1; do
  tries=$((tries - 1)); [ $tries -le 0 ] && { cat "$WORK/issuer-apply.log"; DIE "issuer/cert apply failed"; }
  sleep 3
done
PASS "ClusterIssuer + Certificate applied"
kubectl -n "$NAMESPACE" wait --for=condition=Ready certificate/uat-leaf --timeout=60s \
  && PASS "cert-manager issued uat-leaf-tls" || DIE "cert-manager never made uat-leaf Ready"

# ---------------------------------------------------------------------------
# 2. ServiceAccount + RBAC scoped to the uat namespace; mint a token; export
#    the API server URL and cluster CA for direct (non-proxied) callers.
# ---------------------------------------------------------------------------
STEP "RBAC: ServiceAccount + Role + RoleBinding in $NAMESPACE"
cat > "$WORK/rbac.yaml" <<EOF
apiVersion: v1
kind: ServiceAccount
metadata:
  name: kk-uat-pusher
  namespace: ${NAMESPACE}
---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: kk-uat-pusher
  namespace: ${NAMESPACE}
rules:
- apiGroups: [""]
  resources: ["secrets"]
  verbs: ["get", "list", "create", "update"]
- apiGroups: ["cert-manager.io"]
  resources: ["certificates"]
  verbs: ["get", "list"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: kk-uat-pusher
  namespace: ${NAMESPACE}
subjects:
- kind: ServiceAccount
  name: kk-uat-pusher
  namespace: ${NAMESPACE}
roleRef:
  kind: Role
  name: kk-uat-pusher
  apiGroup: rbac.authorization.k8s.io
EOF
kubectl apply -f "$WORK/rbac.yaml" >/dev/null && PASS "RBAC applied" || DIE "RBAC apply failed"

kubectl create token kk-uat-pusher -n "$NAMESPACE" --duration=2h > "$WORK/sa-token.txt" \
  && PASS "minted SA token" || DIE "kubectl create token failed"
SA_TOKEN="$(cat "$WORK/sa-token.txt")"

kubectl config view --minify --raw -o yaml > "$WORK/kubeconfig-view.yaml"
python3 - "$WORK/kubeconfig-view.yaml" "$WORK/cluster-ca.pem" > "$WORK/apiserver-url.txt" <<'PYEOF'
import base64, re, sys
cfgpath, capath = sys.argv[1], sys.argv[2]
text = open(cfgpath).read()
ca_b64 = re.search(r'certificate-authority-data:\s*(\S+)', text).group(1)
open(capath, 'wb').write(base64.b64decode(ca_b64))
print(re.search(r'server:\s*(\S+)', text).group(1))
PYEOF
APISERVER_URL="$(cat "$WORK/apiserver-url.txt")"
[ -n "$APISERVER_URL" ] && PASS "API server: $APISERVER_URL" || DIE "could not read API server URL"

# Empirical proof the SA token + RBAC are real (not just declared): the SA
# can list secrets in uat (200) and is denied in default (403) when talking
# DIRECTLY to the API server with the exported cluster CA. This is the RBAC
# assertion the push flow itself cannot make (see README: the pusher's
# transport goes through `kubectl proxy`, which authenticates as the
# kubeconfig admin user, not the SA token -- K8sConfig has no CA-trust
# mechanism for a private cluster CA, see internal/agentinstall/k8s.go and
# internal/bootstrap/renewal_executor.go's nil pushClient).
STEP "verify SA token + RBAC directly against the API server"
SA_UAT_CODE="$(curl -sS -o "$WORK/sa_uat.json" -w '%{http_code}' --cacert "$WORK/cluster-ca.pem" -H "Authorization: Bearer $SA_TOKEN" "$APISERVER_URL/api/v1/namespaces/${NAMESPACE}/secrets")"
SA_DEFAULT_CODE="$(curl -sS -o "$WORK/sa_default.json" -w '%{http_code}' --cacert "$WORK/cluster-ca.pem" -H "Authorization: Bearer $SA_TOKEN" "$APISERVER_URL/api/v1/namespaces/default/secrets")"
if [ "$SA_UAT_CODE" = "200" ] && [ "$SA_DEFAULT_CODE" = "403" ]; then
  PASS "SA token authenticates + RBAC scoped to $NAMESPACE (uat=200, default=403)"
else
  FAIL "SA RBAC check: uat=$SA_UAT_CODE (want 200) default=$SA_DEFAULT_CODE (want 403)"
fi

# ---------------------------------------------------------------------------
# 3. A real workload that serves the pushed Secret as TLS: tlsecho re-reads
#    cert/key from disk on every handshake, so it "picks up" a push with no
#    reload sidecar -- and no config-reload race to fight.
# ---------------------------------------------------------------------------
STEP "build + load tlsecho workload image"
PODMAN_ARCH="$(podman info --format '{{.Host.Arch}}' 2>/dev/null || echo arm64)"
( cd "$REPO_ROOT" && GOOS=linux GOARCH="$PODMAN_ARCH" CGO_ENABLED=0 go build -o "$HERE/tlsecho/tlsecho" ./tests/live/k8s/tlsecho ) \
  && PASS "tlsecho built ($PODMAN_ARCH)" || DIE "go build tlsecho failed"
podman build -t "$IMAGE" -f "$HERE/tlsecho/Containerfile" "$HERE/tlsecho" >"$WORK/build.log" 2>&1 \
  && PASS "tlsecho image built" || DIE "podman build failed, see $WORK/build.log"
rm -f "$HERE/tlsecho/tlsecho"
podman save "$IMAGE" -o "$WORK/tlsecho.tar" \
  && kind load image-archive "$WORK/tlsecho.tar" --name "$CLUSTER" \
  && PASS "tlsecho image loaded into kind" || DIE "kind load image-archive failed"

STEP "deploy target workload (placeholder secret, real Pod + NodePort Service)"
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -keyout "$WORK/placeholder.key" -out "$WORK/placeholder.crt" -days 1 -nodes -subj "/CN=placeholder" >/dev/null 2>&1
CRT_B64="$(base64 < "$WORK/placeholder.crt" | tr -d '\n')"
KEY_B64="$(base64 < "$WORK/placeholder.key" | tr -d '\n')"
python3 - "$CRT_B64" "$KEY_B64" "$NAMESPACE" "$TARGET_SECRET" "$IMAGE" "$NODEPORT" > "$WORK/target-pod.yaml" <<'PYEOF'
import sys
crt, key, ns, secret, image, nodeport = sys.argv[1:7]
print(f"""apiVersion: v1
kind: Secret
metadata:
  name: {secret}
  namespace: {ns}
type: kubernetes.io/tls
data:
  tls.crt: "{crt}"
  tls.key: "{key}"
---
apiVersion: v1
kind: Pod
metadata:
  name: kk-uat-target
  namespace: {ns}
  labels:
    app: kk-uat-target
spec:
  containers:
  - name: tlsecho
    image: {image}
    imagePullPolicy: Never
    args: [":8443", "/tls/tls.crt", "/tls/tls.key"]
    ports:
    - containerPort: 8443
    volumeMounts:
    - name: tls
      mountPath: /tls
      readOnly: true
  volumes:
  - name: tls
    secret:
      secretName: {secret}
---
apiVersion: v1
kind: Service
metadata:
  name: kk-uat-target
  namespace: {ns}
spec:
  type: NodePort
  selector:
    app: kk-uat-target
  ports:
  - port: 8443
    targetPort: 8443
    nodePort: {nodeport}
""")
PYEOF
kubectl apply -f "$WORK/target-pod.yaml" >/dev/null && PASS "target manifests applied" || DIE "target apply failed"
kubectl -n "$NAMESPACE" wait --for=condition=Ready pod/kk-uat-target --timeout=60s \
  && PASS "kk-uat-target pod ready" || DIE "target pod never became ready"

wait_tcp() {
  local port=$1 tries=30
  while [ $tries -gt 0 ]; do
    (exec 3<>"/dev/tcp/127.0.0.1/$port") 2>/dev/null && { exec 3<&- 3>&-; return 0; }
    sleep 1; tries=$((tries - 1))
  done
  return 1
}
wait_tcp "$NODEPORT" || DIE "NodePort $NODEPORT never reachable from host via kind's extraPortMappings"
PASS "target workload reachable at 127.0.0.1:$NODEPORT"

# ---------------------------------------------------------------------------
# 4. Build and run the hub (push half: default/db discovery provider).
#    W19-17 closed the CA-trust gap this step used to work around: K8sConfig
#    now carries a CACertPEM (credential ca_cert field), so the push client
#    talks HTTPS DIRECTLY to the real API server with the exported kind CA
#    -- no kubectl proxy in front of it, no skip-verify.
# ---------------------------------------------------------------------------
STEP "build + start hub (push half)"
rm -rf "$HUB_DIR"
mkdir -p "$HUB_DIR/data"
( cd "$REPO_ROOT" && go build -o "$HUB_DIR/kryptkeeper" ./cmd/kryptkeeper ) \
  && PASS "hub built" || DIE "go build failed"

# W19-31: KRYPTKEEPER_TLS_DISABLE=true on all three hubs this fixture starts
# -- since W19-14 the hub self-issues a TLS listener by default with
# APP_CERTIFICATE_PROVIDER=ca, which would break every plain-HTTP curl call
# below. The surface under test here is k8s Secret push + cert-manager
# discovery against a real cluster, not the hub's own TLS listener (proven
# separately by tests/live/tls/run.sh and tests/live/compose/run.sh).
export APP_BOOTSTRAP_TOKEN="$TOKEN" AUTH_MODE=bootstrap APP_CERTIFICATE_PROVIDER=ca \
  APP_DISCOVERY_PROVIDER=db APP_NOTIFICATION_PROVIDER=file \
  KRYPTKEEPER_TLS_DISABLE=true \
  APP_CREDENTIAL_STORE_PASSPHRASE='uat-k8s-cred-passphrase-32-bytes!' \
  KRYPTKEEPER_KEYSTORE_PASSPHRASE='uat-k8s-keystore-passphrase-32byt' \
  KRYPTKEEPER_DATA_DIR="$HUB_DIR/data" \
  APP_CA_FILE="$HUB_DIR/data/cas.json" \
  APP_TEMPLATE_FILE="$HUB_DIR/data/templates.json" \
  APP_CERTIFICATE_FILE="$HUB_DIR/data/certificates.json" \
  APP_AUDIT_FILE="$HUB_DIR/data/audit.json" \
  APP_CERTS_SUMMARY_FILE="$HUB_DIR/data/certs_summary.json" \
  KRYPTKEEPER_BOOTSTRAP_CREATE_ROOT=true \
  KRYPTKEEPER_CA_NAME="UAT Root CA" \
  APP_BIND_ADDR=127.0.0.1 PORT="$HUB_PORT"

"$HUB_DIR/kryptkeeper" >"$WORK/hub.log" 2>&1 &
HUB_PID=$!
tries=30
until curl -sS -f -o /dev/null "${HUB_BASE}/api/v1/cas" -H "Authorization: Bearer ${TOKEN}"; do
  tries=$((tries - 1)); [ $tries -le 0 ] && DIE "hub never answered a real /api/v1/cas 200, see $WORK/hub.log"
  sleep 1
done
PASS "hub answering on $HUB_BASE"

CA_ID="$(curlj "${HUB_BASE}/api/v1/cas" | python3 -c 'import json,sys; print(json.load(sys.stdin)["data"][0]["id"])' 2>/dev/null)"
[ -n "$CA_ID" ] && PASS "root CA: $CA_ID" || DIE "no CA found"

STEP "create template"
TEMPLATE_RESP="$(curlj -X POST "${HUB_BASE}/api/v1/templates" -d '{
  "name": "uat-k8s-server",
  "display_name": "UAT k8s server cert",
  "allowed_algorithms": ["ECDSA", "RSA-2048"],
  "key_usage": ["digitalSignature", "keyEncipherment"],
  "extended_key_usage": ["serverAuth"],
  "validity_period": "2160h",
  "active": true
}')"
TEMPLATE_ID="$(echo "$TEMPLATE_RESP" | python3 -c 'import json,sys; print(json.load(sys.stdin)["data"]["id"])' 2>/dev/null)"
[ -n "$TEMPLATE_ID" ] && PASS "template: $TEMPLATE_ID" || DIE "template create failed: $TEMPLATE_RESP"

STEP "create api_token credential (base_url=real API server, ca_cert=kind cluster CA, bearer_token=SA token)"
# Build the FULL request envelope in one python invocation -- a PEM's
# json.dumps escaping (literal backslash-n sequences) does not survive a
# second pass through a python -c triple-quoted string: the interpreter
# unescapes \n into a real newline before json.loads ever sees it,
# producing invalid JSON (a raw control character in a string) that
# crashes silently into an empty CRED_PAYLOAD and a bad_request from the
# API (found live, run4, 2026-09-11).
CRED_PAYLOAD="$(python3 - "$APISERVER_URL" "$SA_TOKEN" "$NAMESPACE" "$TARGET_SECRET" "$WORK/cluster-ca.pem" <<'CREDPY'
import json, sys
apiserver, token, ns, secret, capath = sys.argv[1:6]
print(json.dumps({'name': 'uat-k8s-pusher', 'credential_type': 'api_token', 'payload': {
  'base_url': apiserver,
  'bearer_token': token.strip(),
  'namespace': ns,
  'secret_name': secret,
  'ca_cert': open(capath).read(),
}}))
CREDPY
)"
CRED_RESP="$(curlj -X POST "${HUB_BASE}/api/v1/credentials" -d "$CRED_PAYLOAD")"
CRED_ID="$(echo "$CRED_RESP" | python3 -c 'import json,sys; print(json.load(sys.stdin)["data"]["id"])' 2>/dev/null)"
[ -n "$CRED_ID" ] && PASS "credential: $CRED_ID" || DIE "credential create failed: $CRED_RESP"

STEP "create target (install_mode=k8s)"
TARGET_RESP="$(curlj -X POST "${HUB_BASE}/api/v1/targets" -d "$(python3 -c "import json; print(json.dumps({
  'host': '127.0.0.1',
  'discovery_mode': 'network',
  'install_mode': 'k8s',
  'credential_ref': '${CRED_ID}',
  'name': 'kk-uat-k8s-target',
}))")")"
TARGET_ID="$(echo "$TARGET_RESP" | python3 -c 'import json,sys; print(json.load(sys.stdin)["data"]["id"])' 2>/dev/null)"
[ -n "$TARGET_ID" ] && PASS "target: $TARGET_ID" || DIE "target create failed: $TARGET_RESP"

STEP "issue initial certificate"
openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
  -keyout "$WORK/k8s.key" -out "$WORK/k8s.csr" \
  -subj "/CN=kk-uat-target.local" -addext "subjectAltName=DNS:kk-uat-target.local" >/dev/null 2>&1
CSR_JSON="$(python3 -c "import json; print(json.dumps(open('$WORK/k8s.csr').read()))")"
ISSUE_RESP="$(curlj -X POST "${HUB_BASE}/api/v1/certificates" -d "{\"ca_id\":\"${CA_ID}\",\"template_id\":\"${TEMPLATE_ID}\",\"csr_pem\":${CSR_JSON}}")"
FP="$(echo "$ISSUE_RESP" | python3 -c 'import json,sys; print(json.load(sys.stdin)["data"]["fingerprint_sha256"])' 2>/dev/null)"
[ -n "$FP" ] && PASS "issued: $FP" || DIE "issue failed: $ISSUE_RESP"

STEP "renewal/execute -> k8s push"
EXEC_RESP="$(curlj -X POST "${HUB_BASE}/api/v1/renewal/execute" -d "$(python3 -c "import json; print(json.dumps({
  'fingerprint': '${FP}',
  'target_id': '${TARGET_ID}',
  'install': {'verify_host_port': '${VERIFY_HOSTPORT}'},
}))")")"
OUTCOME="$(echo "$EXEC_RESP" | python3 -c 'import json,sys; print(json.load(sys.stdin).get("data",{}).get("install_outcome",""))' 2>/dev/null)"
NEW_FP="$(echo "$EXEC_RESP" | python3 -c 'import json,sys; print(json.load(sys.stdin).get("data",{}).get("new_fingerprint",""))' 2>/dev/null)"
echo "  outcome=$OUTCOME new_fp=$NEW_FP raw=$EXEC_RESP"
if [ "$OUTCOME" = "installed_verified" ]; then
  PASS "push installed + verified (hub outcome=$OUTCOME)"
else
  FAIL "push install_outcome=$OUTCOME (want installed_verified)"
fi

STEP "independent verification: kubectl get secret + openssl fingerprint"
SERVED_CRT_B64="$(kubectl -n "$NAMESPACE" get secret "$TARGET_SECRET" -o go-template='{{index .data "tls.crt"}}' 2>/dev/null)"
echo "$SERVED_CRT_B64" | base64 -d > "$WORK/served.crt" 2>/dev/null
SERVED_FP="$(openssl x509 -in "$WORK/served.crt" -noout -fingerprint -sha256 2>/dev/null | cut -d= -f2 | tr -d ':' | tr 'A-F' 'a-f')"
WANT_FP="$(echo "$NEW_FP" | tr 'A-F' 'a-f' | tr -d ':')"
if [ -n "$SERVED_FP" ] && [ "$SERVED_FP" = "$WANT_FP" ]; then
  PASS "Secret $TARGET_SECRET in namespace $NAMESPACE holds the new fingerprint ($SERVED_FP)"
else
  FAIL "Secret fingerprint $SERVED_FP != new_fingerprint $WANT_FP"
fi

STEP "negative: wrong namespace -> clear error, no secret written"
NEG_CRED_PAYLOAD="$(python3 - "$APISERVER_URL" "$SA_TOKEN" "$TARGET_SECRET" "$WORK/cluster-ca.pem" <<'NEGPY'
import json, sys
apiserver, token, secret, capath = sys.argv[1:5]
print(json.dumps({'name': 'uat-k8s-pusher-badns', 'credential_type': 'api_token', 'payload': {
  'base_url': apiserver,
  'bearer_token': token.strip(),
  'namespace': 'kk-uat-nonexistent-namespace',
  'secret_name': secret,
  'ca_cert': open(capath).read(),
}}))
NEGPY
)"
NEG_CRED_RESP="$(curlj -X POST "${HUB_BASE}/api/v1/credentials" -d "$NEG_CRED_PAYLOAD")"
NEG_CRED_ID="$(echo "$NEG_CRED_RESP" | python3 -c 'import json,sys; print(json.load(sys.stdin)["data"]["id"])' 2>/dev/null)"
NEG_TARGET_RESP="$(curlj -X POST "${HUB_BASE}/api/v1/targets" -d "$(python3 -c "import json; print(json.dumps({'host':'127.0.0.1','discovery_mode':'network','install_mode':'k8s','credential_ref':'${NEG_CRED_ID}','name':'kk-uat-k8s-badns'}))")")"
NEG_TARGET_ID="$(echo "$NEG_TARGET_RESP" | python3 -c 'import json,sys; print(json.load(sys.stdin)["data"]["id"])' 2>/dev/null)"
openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
  -keyout "$WORK/k8s-neg.key" -out "$WORK/k8s-neg.csr" \
  -subj "/CN=kk-uat-target.local" -addext "subjectAltName=DNS:kk-uat-target.local" >/dev/null 2>&1
NEG_CSR_JSON="$(python3 -c "import json; print(json.dumps(open('$WORK/k8s-neg.csr').read()))")"
NEG_ISSUE_RESP="$(curlj -X POST "${HUB_BASE}/api/v1/certificates" -d "{\"ca_id\":\"${CA_ID}\",\"template_id\":\"${TEMPLATE_ID}\",\"csr_pem\":${NEG_CSR_JSON}}")"
NEG_FP="$(echo "$NEG_ISSUE_RESP" | python3 -c 'import json,sys; print(json.load(sys.stdin)["data"]["fingerprint_sha256"])' 2>/dev/null)"
NEG_EXEC_RESP="$(curlj -X POST "${HUB_BASE}/api/v1/renewal/execute" -d "$(python3 -c "import json; print(json.dumps({'fingerprint':'${NEG_FP}','target_id':'${NEG_TARGET_ID}','install':{'verify_host_port':'${VERIFY_HOSTPORT}'}}))")")"
NEG_OUTCOME="$(echo "$NEG_EXEC_RESP" | python3 -c 'import json,sys; print(json.load(sys.stdin).get("data",{}).get("install_outcome",""))' 2>/dev/null)"
echo "  negative outcome=$NEG_OUTCOME raw=$NEG_EXEC_RESP"
NS_SECRET_CHECK="$(kubectl get secret "$TARGET_SECRET" -n kk-uat-nonexistent-namespace 2>&1)"
if [ "$NEG_OUTCOME" = "write_failed" ] && echo "$NS_SECRET_CHECK" | grep -qi "not found"; then
  PASS "wrong namespace: clear error (install_outcome=write_failed), no secret written"
else
  FAIL "wrong namespace case: outcome=$NEG_OUTCOME, secret check: $NS_SECRET_CHECK"
fi

STEP "stop push-half hub"
kill "$HUB_PID" 2>/dev/null; wait "$HUB_PID" 2>/dev/null
HUB_PID=""

# ---------------------------------------------------------------------------
# 6. Discovery half: k8s-certmanager scan, scanner-mode discovery provider,
#    direct HTTPS to the API server with the exported cluster CA (this path
#    DOES support CA trust: internal/certmanager/connector.go's
#    KRYPTKEEPER_K8S_CA_CERT_FILE).
# ---------------------------------------------------------------------------
STEP "build + start hub (discovery half, APP_DISCOVERY_PROVIDER=scanner)"
DISC_HUB_DIR=/tmp/kk-uat-k8s-disc-hub
DISC_PORT=8094
DISC_BASE="http://127.0.0.1:${DISC_PORT}"
rm -rf "$DISC_HUB_DIR"
mkdir -p "$DISC_HUB_DIR/data"
export APP_BOOTSTRAP_TOKEN="$TOKEN" AUTH_MODE=bootstrap APP_CERTIFICATE_PROVIDER=ca \
  APP_DISCOVERY_PROVIDER=scanner APP_NOTIFICATION_PROVIDER=file \
  KRYPTKEEPER_TLS_DISABLE=true \
  APP_CREDENTIAL_STORE_PASSPHRASE='uat-k8s-cred-passphrase-32-bytes!' \
  KRYPTKEEPER_KEYSTORE_PASSPHRASE='uat-k8s-keystore-passphrase-32byt' \
  KRYPTKEEPER_DATA_DIR="$DISC_HUB_DIR/data" \
  APP_CA_FILE="$DISC_HUB_DIR/data/cas.json" \
  APP_TEMPLATE_FILE="$DISC_HUB_DIR/data/templates.json" \
  APP_CERTIFICATE_FILE="$DISC_HUB_DIR/data/certificates.json" \
  APP_AUDIT_FILE="$DISC_HUB_DIR/data/audit.json" \
  APP_CERTS_SUMMARY_FILE="$DISC_HUB_DIR/data/certs_summary.json" \
  KRYPTKEEPER_BOOTSTRAP_CREATE_ROOT=true \
  KRYPTKEEPER_CA_NAME="UAT Root CA" \
  KRYPTKEEPER_K8S_API_URL="$APISERVER_URL" \
  KRYPTKEEPER_K8S_TOKEN="$SA_TOKEN" \
  KRYPTKEEPER_K8S_CA_CERT_FILE="$WORK/cluster-ca.pem" \
  KRYPTKEEPER_K8S_NAMESPACE="$NAMESPACE" \
  APP_BIND_ADDR=127.0.0.1 PORT="$DISC_PORT"

cp "$HUB_DIR/kryptkeeper" "$DISC_HUB_DIR/kryptkeeper" 2>/dev/null || ( cd "$REPO_ROOT" && go build -o "$DISC_HUB_DIR/kryptkeeper" ./cmd/kryptkeeper )
"$DISC_HUB_DIR/kryptkeeper" >"$WORK/disc-hub.log" 2>&1 &
HUB_PID=$!
tries=30
until curl -sS -f -o /dev/null "${DISC_BASE}/api/v1/cas" -H "Authorization: Bearer ${TOKEN}"; do
  tries=$((tries - 1)); [ $tries -le 0 ] && DIE "discovery hub never answered, see $WORK/disc-hub.log"
  sleep 1
done
PASS "discovery hub answering on $DISC_BASE"

STEP "k8s-certmanager scan via product API (scanner-mode discovery provider)"
SCAN_RESP="$(curlj -X POST "${DISC_BASE}/api/v1/discovery/scans" -d '{"scan_type":"k8s-certmanager"}')"
echo "  scan create response: $SCAN_RESP"
SCAN_HTTP="$(curlj -s -o /dev/null -w '%{http_code}' -X POST "${DISC_BASE}/api/v1/discovery/scans" -d '{"scan_type":"k8s-certmanager"}')"
if [ "$SCAN_HTTP" = "201" ]; then
  PASS "k8s-certmanager scan accepted (201)"
  # Bounded poll, not a fixed sleep: the scan's goroutine does a real
  # TLS-handshake-plus-API call to the cluster, whose first-connection
  # latency is not bounded tightly enough for one fixed sleep to be
  # reliable (found live, run5: a 3s sleep was flaky here).
  ENDPOINTS_RESP=""
  tries=15
  while [ $tries -gt 0 ]; do
    ENDPOINTS_RESP="$(curlj "${DISC_BASE}/api/v1/discovery/endpoints")"
    echo "$ENDPOINTS_RESP" | grep -q "uat-leaf.example.com" && break
    tries=$((tries - 1)); sleep 1
  done
  if echo "$ENDPOINTS_RESP" | grep -q "uat-leaf.example.com"; then
    PASS "discovery/endpoints contains the cert-manager Certificate's common name"
  else
    FAIL "discovery/endpoints does not contain uat-leaf.example.com: $ENDPOINTS_RESP"
  fi
else
  FAIL "k8s-certmanager scan REJECTED by the product API (HTTP $SCAN_HTTP, want 201)"
fi

STEP "k8s-certmanager scan via product API (db-mode discovery provider, W19-17)"
kill "$HUB_PID" 2>/dev/null; wait "$HUB_PID" 2>/dev/null; HUB_PID=""
DBMODE_DIR=/tmp/kk-uat-k8s-dbmode-hub
rm -rf "$DBMODE_DIR"
mkdir -p "$DBMODE_DIR/data"
export APP_BOOTSTRAP_TOKEN="$TOKEN" AUTH_MODE=bootstrap APP_CERTIFICATE_PROVIDER=ca \
  APP_DISCOVERY_PROVIDER=db APP_NOTIFICATION_PROVIDER=file \
  KRYPTKEEPER_TLS_DISABLE=true \
  APP_CREDENTIAL_STORE_PASSPHRASE='uat-k8s-cred-passphrase-32-bytes!' \
  KRYPTKEEPER_KEYSTORE_PASSPHRASE='uat-k8s-keystore-passphrase-32byt' \
  KRYPTKEEPER_DATA_DIR="$DBMODE_DIR/data" \
  APP_CA_FILE="$DBMODE_DIR/data/cas.json" APP_TEMPLATE_FILE="$DBMODE_DIR/data/templates.json" \
  APP_CERTIFICATE_FILE="$DBMODE_DIR/data/certificates.json" APP_AUDIT_FILE="$DBMODE_DIR/data/audit.json" \
  APP_CERTS_SUMMARY_FILE="$DBMODE_DIR/data/certs_summary.json" \
  KRYPTKEEPER_BOOTSTRAP_CREATE_ROOT=true KRYPTKEEPER_CA_NAME="UAT Root CA" \
  KRYPTKEEPER_K8S_API_URL="$APISERVER_URL" KRYPTKEEPER_K8S_TOKEN="$SA_TOKEN" \
  KRYPTKEEPER_K8S_CA_CERT_FILE="$WORK/cluster-ca.pem" KRYPTKEEPER_K8S_NAMESPACE="$NAMESPACE" \
  APP_BIND_ADDR=127.0.0.1 PORT=8095
cp "$HUB_DIR/kryptkeeper" "$DBMODE_DIR/kryptkeeper"
"$DBMODE_DIR/kryptkeeper" >"$WORK/dbmode-hub.log" 2>&1 &
HUB_PID=$!
tries=30
until curl -sS -f -o /dev/null "http://127.0.0.1:8095/api/v1/cas" -H "Authorization: Bearer ${TOKEN}"; do
  tries=$((tries - 1)); [ $tries -le 0 ] && DIE "db-mode hub never answered"
  sleep 1
done
DBMODE_SCAN_RESP="$(curlj -X POST "http://127.0.0.1:8095/api/v1/discovery/scans" -d '{"scan_type":"k8s-certmanager"}')"
echo "  db-mode scan create response: $DBMODE_SCAN_RESP"
DBMODE_JOB_ID="$(echo "$DBMODE_SCAN_RESP" | python3 -c 'import json,sys; print(json.load(sys.stdin)["data"]["scan_job"]["id"])' 2>/dev/null)"
if [ -n "$DBMODE_JOB_ID" ]; then
  PASS "db-mode k8s-certmanager scan accepted: $DBMODE_JOB_ID"
  DBMODE_JOBS_RESP=""
  tries=15
  while [ $tries -gt 0 ]; do
    DBMODE_JOBS_RESP="$(curlj "http://127.0.0.1:8095/api/v1/discovery/scan-jobs?limit=50")"
    echo "$DBMODE_JOBS_RESP" | python3 -c "
import json, sys
data = json.load(sys.stdin)
jobs = data.get('data', {}).get('scan_jobs', [])
job = next((j for j in jobs if j.get('id') == '$DBMODE_JOB_ID'), None)
sys.exit(0 if job and job.get('status') == 'completed' else 1)
" && break
    tries=$((tries - 1)); sleep 1
  done
  if echo "$DBMODE_JOBS_RESP" | python3 -c "
import json, sys
data = json.load(sys.stdin)
jobs = data.get('data', {}).get('scan_jobs', [])
job = next((j for j in jobs if j.get('id') == '$DBMODE_JOB_ID'), None)
sys.exit(0 if job and job.get('status') == 'completed' else 1)
"; then
    PASS "db-mode scan job $DBMODE_JOB_ID completed"
  else
    FAIL "db-mode scan job $DBMODE_JOB_ID did not complete: $DBMODE_JOBS_RESP"
  fi
  DBMODE_JOB_ROW="$(sqlite3 "$DBMODE_DIR/data/kryptkeeper.db" "SELECT results_summary FROM scan_jobs WHERE id='$DBMODE_JOB_ID'" 2>/dev/null)"
  if echo "$DBMODE_JOB_ROW" | grep -q "uat-leaf.example.com"; then
    PASS "db-mode scan_jobs.results_summary contains the cert-manager Certificate's common name"
  else
    FAIL "db-mode scan_jobs.results_summary does not contain uat-leaf.example.com: $DBMODE_JOB_ROW"
  fi
else
  FAIL "db-mode k8s-certmanager scan REJECTED by the product API: $DBMODE_SCAN_RESP"
fi
kill "$HUB_PID" 2>/dev/null; wait "$HUB_PID" 2>/dev/null; HUB_PID=""

# ---------------------------------------------------------------------------
# W24-24: second kind cluster, both registered through the config store
# (discovery.kube_clusters -> api_token credentials); per-cluster tagging is
# proven by fingerprint against kubectl. Additive: runs after every original
# check. Every kubectl call passes --context (the last-created cluster is
# otherwise the silent default).
# ---------------------------------------------------------------------------
STEP "W24-24: second kind cluster + cert-manager"
kind delete cluster --name "$CLUSTER_B" >/dev/null 2>&1 || true
kind create cluster --name "$CLUSTER_B" \
  && PASS "kind cluster $CLUSTER_B up (podman provider)" || DIE "kind create cluster $CLUSTER_B failed"
kubectl --context "$CTX_B" apply -f https://github.com/cert-manager/cert-manager/releases/latest/download/cert-manager.yaml >"$WORK/certmanager-apply-b.log" 2>&1 \
  && PASS "cert-manager manifests applied on $CLUSTER_B" || DIE "cert-manager apply on B failed, see $WORK/certmanager-apply-b.log"
kubectl --context "$CTX_B" wait --for=condition=Available deployment --all -n cert-manager --timeout=240s \
  && PASS "cert-manager available on $CLUSTER_B" || DIE "cert-manager on B never became available"
kubectl --context "$CTX_B" create namespace "$NAMESPACE" >/dev/null 2>&1 || true
# cert-manager's webhook can lag Available by a few seconds: retry the apply.
sed -e 's/uat-leaf\.example\.com/uat-leaf-b.example.com/' -e 's/name: uat-leaf$/name: uat-leaf-b/' -e 's/secretName: uat-leaf-tls/secretName: uat-leaf-b-tls/' "$WORK/issuer-cert.yaml" > "$WORK/issuer-cert-b.yaml"
tries=20
until kubectl --context "$CTX_B" apply -f "$WORK/issuer-cert-b.yaml" >/dev/null 2>&1; do
  tries=$((tries - 1)); [ $tries -le 0 ] && DIE "issuer/cert apply on B failed"; sleep 3
done
kubectl --context "$CTX_B" -n "$NAMESPACE" wait --for=condition=Ready certificate/uat-leaf-b --timeout=90s \
  && PASS "cert-manager issued uat-leaf-b-tls on $CLUSTER_B" || DIE "uat-leaf-b never Ready"

STEP "W24-24: RBAC + token for cluster B"
kubectl --context "$CTX_B" apply -f "$WORK/rbac.yaml" >/dev/null && PASS "RBAC applied on $CLUSTER_B" || DIE "RBAC apply on B failed"
SA_TOKEN_B="$(kubectl --context "$CTX_B" create token kk-uat-pusher -n "$NAMESPACE" --duration=2h)" \
  && PASS "minted SA token for B" || DIE "create token on B failed"
kubectl config view --raw -o yaml --context "$CTX_B" --minify > "$WORK/kubeconfig-view-b.yaml"
APISERVER_URL_B="$(python3 - "$WORK/kubeconfig-view-b.yaml" "$WORK/cluster-ca-b.pem" <<'PYEOF'
import base64, re, sys
text = open(sys.argv[1]).read()
open(sys.argv[2], 'wb').write(base64.b64decode(re.search(r'certificate-authority-data:\s*(\S+)', text).group(1)))
print(re.search(r'server:\s*(\S+)', text).group(1))
PYEOF
)"
[ -n "$APISERVER_URL_B" ] && [ "$APISERVER_URL_B" != "$APISERVER_URL" ] && PASS "API server B: $APISERVER_URL_B (differs from A)" || DIE "bad API server URL for B"

STEP "W24-24: register both clusters via config store"
MULTI_DIR=/tmp/kk-uat-k8s-multi-hub
MULTI_PORT=8096
MULTI_BASE="http://127.0.0.1:${MULTI_PORT}"
rm -rf "$MULTI_DIR"; mkdir -p "$MULTI_DIR/data"
cp "$HUB_DIR/kryptkeeper" "$MULTI_DIR/kryptkeeper"
env -u KRYPTKEEPER_K8S_API_URL -u KRYPTKEEPER_K8S_TOKEN -u KRYPTKEEPER_K8S_CA_CERT_FILE -u KRYPTKEEPER_K8S_NAMESPACE -u KRYPTKEEPER_K8S_CLUSTERS \
  APP_BOOTSTRAP_TOKEN="$TOKEN" AUTH_MODE=bootstrap APP_CERTIFICATE_PROVIDER=ca \
  APP_DISCOVERY_PROVIDER=db APP_NOTIFICATION_PROVIDER=file KRYPTKEEPER_TLS_DISABLE=true \
  APP_CREDENTIAL_STORE_PASSPHRASE='uat-k8s-cred-passphrase-32-bytes!' \
  KRYPTKEEPER_KEYSTORE_PASSPHRASE='uat-k8s-keystore-passphrase-32byt' \
  KRYPTKEEPER_DATA_DIR="$MULTI_DIR/data" KRYPTKEEPER_BOOTSTRAP_CREATE_ROOT=true KRYPTKEEPER_CA_NAME="UAT Root CA" \
  APP_BIND_ADDR=127.0.0.1 PORT="$MULTI_PORT" \
  "$MULTI_DIR/kryptkeeper" >"$WORK/multi-hub.log" 2>&1 &
HUB_PID=$!
tries=30
until curl -sS -f -o /dev/null "${MULTI_BASE}/api/v1/cas" -H "Authorization: Bearer ${TOKEN}"; do
  tries=$((tries - 1)); [ $tries -le 0 ] && DIE "multi-cluster hub never answered, see $WORK/multi-hub.log"
  sleep 1
done
PASS "multi-cluster hub answering on $MULTI_BASE (no KRYPTKEEPER_K8S_API_URL set)"

mkcred() { # name apiserver token cafile
  python3 - "$@" <<'CREDPY'
import json, sys
name, apiserver, token, capath = sys.argv[1:5]
print(json.dumps({'name': name, 'credential_type': 'api_token', 'payload': {
  'base_url': apiserver, 'bearer_token': token.strip(), 'namespace': 'uat', 'ca_cert': open(capath).read()}}))
CREDPY
}
cred_id() { python3 -c 'import json,sys; print(json.load(sys.stdin)["data"]["id"])' 2>/dev/null; }
CRED_A="$(curlj -X POST "${MULTI_BASE}/api/v1/credentials" -d "$(mkcred uat-cluster-a "$APISERVER_URL" "$SA_TOKEN" "$WORK/cluster-ca.pem")" | cred_id)"
CRED_B="$(curlj -X POST "${MULTI_BASE}/api/v1/credentials" -d "$(mkcred uat-cluster-b "$APISERVER_URL_B" "$SA_TOKEN_B" "$WORK/cluster-ca-b.pem")" | cred_id)"
[ -n "$CRED_A" ] && [ -n "$CRED_B" ] && PASS "credentials created: A=$CRED_A B=$CRED_B" || DIE "credential create failed (A='$CRED_A' B='$CRED_B')"

put_clusters() { # credA credB
  python3 -c '
import json, sys
print(json.dumps({"value": json.dumps([{"name": "a", "credential_ref": sys.argv[1]}, {"name": "b", "credential_ref": sys.argv[2]}])}))' "$1" "$2" > "$WORK/clusters-put.json"
  curl -sS -o "$WORK/clusters-put.out" -w '%{http_code}' -X PUT -H "Authorization: Bearer ${TOKEN}" -H 'Content-Type: application/json' \
    -d @"$WORK/clusters-put.json" "${MULTI_BASE}/api/v1/config/discovery.kube_clusters"
}
PUT_CODE="$(put_clusters "$CRED_A" "$CRED_B")"
case "$PUT_CODE" in 2??) PASS "PUT discovery.kube_clusters -> HTTP $PUT_CODE" ;; *) FAIL "PUT discovery.kube_clusters -> HTTP $PUT_CODE: $(cat "$WORK/clusters-put.out")" ;; esac
CFG_JSON="$(curlj "${MULTI_BASE}/api/v1/config")"
if echo "$CFG_JSON" | python3 -c '
import json, sys
d = json.load(sys.stdin)
rows = d["data"] if isinstance(d["data"], list) else d["data"].get("settings", [])
row = next((r for r in rows if r.get("key") == "discovery.kube_clusters"), None)
sys.exit(0 if row and row.get("configured") else 1)'; then
  PASS "GET /api/v1/config shows discovery.kube_clusters configured:true"
else
  FAIL "discovery.kube_clusters not shown configured:true: $CFG_JSON"
fi
echo "$CFG_JSON" | grep -q "$SA_TOKEN_B" && FAIL "config response leaks a bearer token" || PASS "config response carries no token text"

scan_k8s() { # sets MJOB, MSTATUS
  local resp; resp="$(curlj -X POST "${MULTI_BASE}/api/v1/discovery/scans" -d '{"scan_type":"k8s-certmanager"}')"
  MJOB="$(echo "$resp" | python3 -c 'import json,sys; print(json.load(sys.stdin)["data"]["scan_job"]["id"])' 2>/dev/null)"
  [ -n "$MJOB" ] || { echo "scan create: $resp"; MSTATUS=rejected; return; }
  local i; MSTATUS=""
  for i in $(seq 1 60); do
    MSTATUS="$(sqlite3 "$MULTI_DIR/data/kryptkeeper.db" "SELECT status FROM scan_jobs WHERE id='$MJOB'")"
    case "$MSTATUS" in completed|completed_with_errors|failed|cancelled) return ;; esac
    sleep 1
  done
}
mjob_summary() { sqlite3 "$MULTI_DIR/data/kryptkeeper.db" "SELECT results_summary FROM scan_jobs WHERE id='$MJOB'"; }

STEP "W24-24: k8s-certmanager scan across both clusters"
scan_k8s
[ "$MSTATUS" = "completed" ] && PASS "multi-cluster scan $MJOB completed" || FAIL "multi-cluster scan status=$MSTATUS"
mjob_summary > "$WORK/multi-summary.json"
if python3 - "$WORK/multi-summary.json" <<'PY'
import json, sys
s = json.load(open(sys.argv[1]))
by = {i["common_name"]: i for i in s["items"]}
errs = []
if by.get("uat-leaf.example.com", {}).get("cluster") != "a": errs.append("uat-leaf not tagged a")
if by.get("uat-leaf-b.example.com", {}).get("cluster") != "b": errs.append("uat-leaf-b not tagged b")
cl = s.get("clusters") or []
if len(cl) != 2 or any(c.get("error") for c in cl): errs.append("clusters=%r" % cl)
print("; ".join(errs) or "OK"); sys.exit(1 if errs else 0)
PY
then PASS "items tagged with the right cluster (a: uat-leaf, b: uat-leaf-b); 2 clusters, no error"
else FAIL "per-cluster tagging wrong: $(cat "$WORK/multi-summary.json" | head -c 600)"; fi

STEP "W24-24: fingerprint check against kubectl"
fp_of() { # context secret
  kubectl --context "$1" -n "$NAMESPACE" get secret "$2" -o jsonpath='{.data.tls\.crt}' | base64 -d | openssl x509 -noout -fingerprint -sha256 2>/dev/null | cut -d= -f2
}
SECRET_A="$(python3 -c 'import json; print(next(i["secret_name"] for i in json.load(open("'"$WORK"'/multi-summary.json"))["items"] if i["cluster"]=="a" and i["common_name"]=="uat-leaf.example.com"))' 2>/dev/null)"
SECRET_B="$(python3 -c 'import json; print(next(i["secret_name"] for i in json.load(open("'"$WORK"'/multi-summary.json"))["items"] if i["cluster"]=="b" and i["common_name"]=="uat-leaf-b.example.com"))' 2>/dev/null)"
FP_A="$(fp_of "$CTX_A" "$SECRET_A")"; FP_B="$(fp_of "$CTX_B" "$SECRET_B")"
[ "$SECRET_A" = "uat-leaf-tls" ] && [ "$SECRET_B" = "uat-leaf-b-tls" ] && PASS "item secret_name matches the cluster's Secret (a=$SECRET_A, b=$SECRET_B)" || FAIL "secret_name mismatch a='$SECRET_A' b='$SECRET_B'"
[ -n "$FP_A" ] && [ -n "$FP_B" ] && [ "$FP_A" != "$FP_B" ] && PASS "kubectl fingerprints exist and differ (A=$FP_A B=$FP_B)" || FAIL "fingerprints missing or equal: A='$FP_A' B='$FP_B'"
# Cross-check: the Secret named by cluster b's item must NOT exist on cluster a (right cluster, not just right name).
kubectl --context "$CTX_A" -n "$NAMESPACE" get secret "$SECRET_B" >/dev/null 2>&1 \
  && FAIL "cluster a unexpectedly holds Secret $SECRET_B" || PASS "Secret $SECRET_B exists only on cluster b"

STEP "W24-24: failure isolation (cluster b credential with a bogus token)"
BAD_B="$(curlj -X POST "${MULTI_BASE}/api/v1/credentials" -d "$(mkcred uat-cluster-b-bad "$APISERVER_URL_B" "not-a-real-token" "$WORK/cluster-ca-b.pem")" | cred_id)"
[ -n "$BAD_B" ] || DIE "bogus credential create failed"
PUT_CODE="$(put_clusters "$CRED_A" "$BAD_B")"
case "$PUT_CODE" in 2??) PASS "re-registered with bogus cluster b -> HTTP $PUT_CODE" ;; *) FAIL "re-register PUT -> HTTP $PUT_CODE" ;; esac
scan_k8s
mjob_summary > "$WORK/multi-summary2.json"
case "$MSTATUS" in
  completed|completed_with_errors) PASS "scan with one bad cluster did not fail the job (status=$MSTATUS)" ;;
  *) FAIL "scan status=$MSTATUS (want completed or completed_with_errors)" ;;
esac
if python3 - "$WORK/multi-summary2.json" <<'PY'
import json, sys
cl = {c["name"]: c for c in json.load(open(sys.argv[1]))["clusters"]}
errs = []
if cl.get("a", {}).get("error") or cl.get("a", {}).get("certificates", 0) < 1: errs.append("cluster a not ok: %r" % cl.get("a"))
if not cl.get("b", {}).get("error"): errs.append("cluster b has no error: %r" % cl.get("b"))
print("; ".join(errs) or "OK"); sys.exit(1 if errs else 0)
PY
then PASS "cluster a ok, cluster b reports a non-empty error"
else FAIL "failure isolation wrong: $(head -c 600 "$WORK/multi-summary2.json")"; fi
kill "$HUB_PID" 2>/dev/null; wait "$HUB_PID" 2>/dev/null; HUB_PID=""

STEP "result"
if [ "$FAILED" -eq 0 ]; then
  echo "ALL PASS"
  exit 0
else
  echo "ONE OR MORE STEPS FAILED (see FAIL lines above; hub logs kept in $WORK until cleanup)"
  exit 1
fi
