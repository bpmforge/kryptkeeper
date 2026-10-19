#!/usr/bin/env bash
# W23-30: prove the Helm chart installs on a real kind cluster (podman
# provider) at replicaCount=2, both pods go Ready, and a leaf certificate is
# issued through the ClusterIP Service.
#
# Flow: install at replicaCount=1 with KRYPTKEEPER_BOOTSTRAP_CREATE_ROOT=true
# (one root creation only), wait Ready, then `helm upgrade --set
# replicaCount=2` WITHOUT that env. Secrets are generated at run time.
# Idempotent, PASS/FAIL per step, non-zero exit on FAIL, cleans up on exit.
set -u
set -o pipefail

export KIND_EXPERIMENTAL_PROVIDER=podman

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$HERE/../../.." && pwd)"
WORK="$(mktemp -d /tmp/kk-helm-kind.XXXXXX)"
CLUSTER=kk-helm
NS=kk
REL=kk
SVC=kk-kryptkeeper
LPORT=18443
IMAGE_REPO=localhost/kryptkeeper
IMAGE_TAG=kind
N_ISSUE=20

FAILED=0
STEP() { echo; echo "== $* =="; }
PASS() { echo "PASS: $*"; }
FAIL() { echo "FAIL: $*"; FAILED=1; }
PF_PID=""
cleanup() {
  STEP "cleanup"
  [ -n "$PF_PID" ] && kill "$PF_PID" 2>/dev/null || true
  if [ "${KEEP_CLUSTER:-0}" = "1" ]; then echo "KEEP_CLUSTER=1: leaving cluster $CLUSTER and $WORK"; return; fi
  kind delete cluster --name "$CLUSTER" >/dev/null 2>&1 || true
  podman rmi -f "${IMAGE_REPO}:${IMAGE_TAG}" >/dev/null 2>&1 || true
  rm -rf "$WORK"
}
trap cleanup EXIT
DIE() { echo "FAIL: $*"; exit 1; }

for t in kind helm kubectl podman openssl curl python3; do
  command -v "$t" >/dev/null 2>&1 || DIE "$t not found (macOS: brew install kind helm kubernetes-cli podman)"
done

# ---------------------------------------------------------------------------
STEP "no-cluster pre-check: helm lint + template at replicaCount 1 and 2"
helm lint "$REPO_ROOT/charts/kryptkeeper" --set secrets.bootstrapToken=x --set secrets.keystorePassphrase=y --set secrets.databaseURL=postgres://x >/dev/null \
  && PASS "helm lint" || DIE "helm lint failed"
for n in 1 2; do
  helm template "$REL" "$REPO_ROOT/charts/kryptkeeper" --set replicaCount=$n --set secrets.bootstrapToken=x --set secrets.keystorePassphrase=y --set secrets.databaseURL=postgres://x \
    | grep -q "replicas: $n" && PASS "helm template renders replicas: $n" || DIE "helm template replicas: $n missing"
done

# ---------------------------------------------------------------------------
STEP "build image with podman and create kind cluster"
podman build -t "${IMAGE_REPO}:${IMAGE_TAG}" "$REPO_ROOT" >"$WORK/build.log" 2>&1 \
  && PASS "image built" || { tail -20 "$WORK/build.log"; DIE "podman build failed"; }
podman save -o "$WORK/img.tar" "${IMAGE_REPO}:${IMAGE_TAG}" || DIE "podman save failed"
kind delete cluster --name "$CLUSTER" >/dev/null 2>&1 || true
kind create cluster --name "$CLUSTER" --wait 120s >"$WORK/kind.log" 2>&1 \
  && PASS "kind cluster $CLUSTER up (podman provider, single node)" || { tail -20 "$WORK/kind.log"; DIE "kind create cluster failed"; }
kind load image-archive "$WORK/img.tar" --name "$CLUSTER" >"$WORK/load.log" 2>&1 \
  && PASS "image loaded into kind" || { cat "$WORK/load.log"; DIE "kind load image-archive failed"; }
KC="kubectl --context kind-$CLUSTER"

# ---------------------------------------------------------------------------
STEP "BYO Postgres"
PGPW="$(openssl rand -hex 16)"
TOKEN="$(openssl rand -hex 16)"
PASSPHRASE="$(openssl rand -hex 16)"
$KC create namespace $NS >/dev/null
$KC -n $NS create secret generic kk-pg --from-literal=password="$PGPW" >/dev/null
$KC apply -f "$HERE/postgres.yaml" >/dev/null || DIE "postgres apply failed"
$KC -n $NS rollout status deploy/kk-pg --timeout=180s >/dev/null \
  && PASS "postgres Ready" || DIE "postgres never Ready"

# ---------------------------------------------------------------------------
HELM_COMMON=(--kube-context "kind-$CLUSTER" -n $NS
  --set image.repository="$IMAGE_REPO" --set image.tag="$IMAGE_TAG" --set image.pullPolicy=Never
  --set config.dbMode=postgres
  --set "secrets.databaseURL=postgres://kryptkeeper:${PGPW}@kk-pg:5432/kryptkeeper?sslmode=disable"
  --set secrets.bootstrapToken="$TOKEN" --set secrets.keystorePassphrase="$PASSPHRASE"
  --wait --timeout 5m)

STEP "helm install at replicaCount=1 with create-root env (one root only)"
helm install $REL "$REPO_ROOT/charts/kryptkeeper" "${HELM_COMMON[@]}" --set replicaCount=1 \
  --set 'extraEnv[0].name=KRYPTKEEPER_BOOTSTRAP_CREATE_ROOT' --set-string 'extraEnv[0].value=true' >"$WORK/install.log" 2>&1 \
  && PASS "install at replicaCount=1 reached Ready" || { tail -20 "$WORK/install.log"; $KC -n $NS get pods; $KC -n $NS logs deploy/$SVC --tail=30; DIE "helm install failed"; }

STEP "helm upgrade to replicaCount=2 (create-root env removed)"
helm upgrade $REL "$REPO_ROOT/charts/kryptkeeper" "${HELM_COMMON[@]}" --set replicaCount=2 >"$WORK/upgrade.log" 2>&1 \
  && PASS "upgrade to replicaCount=2 reached Ready" || { tail -20 "$WORK/upgrade.log"; $KC -n $NS get pods; $KC -n $NS describe pods -l app.kubernetes.io/name=kryptkeeper | tail -60; $KC -n $NS logs -l app.kubernetes.io/name=kryptkeeper --tail=25 --prefix; DIE "helm upgrade failed"; }

STEP "both replicas Ready, distinct pods"
READY="$($KC -n $NS get deploy $SVC -o jsonpath='{.status.readyReplicas}')"
[ "$READY" = "2" ] && PASS "readyReplicas=2" || FAIL "readyReplicas=$READY"
podlist() { $KC -n $NS get pods -l app.kubernetes.io/instance=$REL,app.kubernetes.io/name=kryptkeeper \
  -o go-template='{{range .items}}{{if not .metadata.deletionTimestamp}}{{.metadata.name}}{{"\n"}}{{end}}{{end}}'; }
# the superseded ReplicaSet's pod may still be Terminating right after upgrade
for i in $(seq 1 60); do PODS="$(podlist)"; [ "$(echo "$PODS" | grep -c .)" = "2" ] && break; sleep 2; done
[ "$(echo "$PODS" | sort -u | wc -l | tr -d ' ')" = "2" ] && PASS "two distinct pods: $(echo $PODS)" || FAIL "pods: $PODS"
echo "$KC -n $NS get pods -o wide:"; $KC -n $NS get pods -o wide

# ---------------------------------------------------------------------------
STEP "export chart CA, port-forward the Service, issue leaves"
# The hub image is distroless (no cat/tar), so read ca.pem through a helper pod
# that mounts the same keys PVC read-only (fine on a single-node kind cluster;
# the PVC is RWO, see README). The helper also serves as the in-cluster client.
$KC -n $NS apply -f - >/dev/null <<YAML
apiVersion: v1
kind: Pod
metadata: {name: curl-probe}
spec:
  containers:
    - name: probe
      image: postgres:16-alpine
      command: ["sleep", "900"]
      volumeMounts: [{name: keys, mountPath: /keys, readOnly: true}]
  volumes:
    - name: keys
      persistentVolumeClaim: {claimName: $SVC-keys, readOnly: true}
YAML
$KC -n $NS wait --for=condition=Ready pod/curl-probe --timeout=90s >/dev/null || DIE "helper pod never Ready"
$KC -n $NS exec curl-probe -- cat /keys/data/tls/ca.pem >"$WORK/ca.pem" 2>/dev/null && [ -s "$WORK/ca.pem" ] \
  && PASS "ca.pem exported ($(wc -c <"$WORK/ca.pem" | tr -d ' ') bytes)" || DIE "could not read ca.pem from the keys PVC"
$KC -n $NS port-forward svc/$SVC $LPORT:8080 >"$WORK/pf.log" 2>&1 &
PF_PID=$!
HUB="https://localhost:$LPORT"
for i in $(seq 1 30); do curl -sS -o /dev/null --cacert "$WORK/ca.pem" "$HUB/readyz" 2>/dev/null && break; sleep 1; done
curl -sS -o /dev/null -w '%{http_code}' --cacert "$WORK/ca.pem" "$HUB/readyz" | grep -q 200 \
  && PASS "GET /readyz 200 over verified TLS via the Service" || DIE "readyz via Service failed"

api() { curl -sS --cacert "$WORK/ca.pem" -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' "$@"; }
jget() { python3 -c "import json,sys; d=json.load(sys.stdin); print(eval(sys.argv[1]))" "$1"; }
CA_ID="$(api "$HUB/api/v1/cas" | jget 'd["data"][0]["id"]')"
[ -n "$CA_ID" ] && PASS "default CA $CA_ID" || DIE "no CA"
TPL_ID="$(api -X POST "$HUB/api/v1/templates" -d '{"name":"helm-kind","display_name":"Helm kind","validity_period":"P90D","key_usage":["digitalSignature","keyEncipherment"],"extended_key_usage":["serverAuth"],"allowed_algorithms":["ECDSA"],"active":true}' | jget 'd["data"]["id"]')"
[ -n "$TPL_ID" ] && PASS "template $TPL_ID" || DIE "template create failed"

ok=0
for i in $(seq 1 $N_ISSUE); do
  openssl ecparam -name prime256v1 -genkey -noout -out "$WORK/l.key" 2>/dev/null
  openssl req -new -key "$WORK/l.key" -subj "/CN=helm-$i.kind.example" -addext "subjectAltName=DNS:helm-$i.kind.example" -out "$WORK/l.csr" 2>/dev/null
  python3 -c "import json,sys; json.dump({'ca_id':sys.argv[1],'template_id':sys.argv[2],'csr_pem':open(sys.argv[3]).read()}, open(sys.argv[4],'w'))" "$CA_ID" "$TPL_ID" "$WORK/l.csr" "$WORK/issue.json"
  c="$(api -o "$WORK/last.json" -w '%{http_code}' -X POST "$HUB/api/v1/certificates" --data @"$WORK/issue.json")"
  [ "$c" = "201" ] && ok=$((ok+1)) || echo "issue $i -> $c $(head -c 200 "$WORK/last.json")"
done
[ "$ok" = "$N_ISSUE" ] && PASS "$ok/$N_ISSUE leaves issued (201) through the Service" || FAIL "only $ok/$N_ISSUE leaves issued"

# A port-forward to a Service pins to ONE pod, so it cannot show balancing.
# Prove each replica independently serves issuance: port-forward each pod,
# issue leaves, and require that pod's own kryptkeeper_cert_issue_total
# counter to move by exactly the number issued.
STEP "each replica issues leaves (per-pod kryptkeeper_cert_issue_total delta)"
kill "$PF_PID" 2>/dev/null; wait "$PF_PID" 2>/dev/null; PF_PID=""
issue_one() { # $1=url base $2=index -> prints http code
  openssl ecparam -name prime256v1 -genkey -noout -out "$WORK/p.key" 2>/dev/null
  openssl req -new -key "$WORK/p.key" -subj "/CN=pod-$2.kind.example" -addext "subjectAltName=DNS:pod-$2.kind.example" -out "$WORK/p.csr" 2>/dev/null
  python3 -c "import json,sys; json.dump({'ca_id':sys.argv[1],'template_id':sys.argv[2],'csr_pem':open(sys.argv[3]).read()}, open(sys.argv[4],'w'))" "$CA_ID" "$TPL_ID" "$WORK/p.csr" "$WORK/pissue.json"
  api -o "$WORK/last.json" -w '%{http_code}' -X POST "$1/api/v1/certificates" --data @"$WORK/pissue.json"
}
issued_counter() { api "$1/metrics" | awk '$1=="kryptkeeper_cert_issue_total"{print $2}'; }
PORT=18500; N_POD=3; SERVING=0
for p in $PODS; do
  PORT=$((PORT+1))
  $KC -n $NS port-forward pod/$p $PORT:8080 >"$WORK/pf-$p.log" 2>&1 & PPID_=$!
  for i in $(seq 1 30); do curl -sS -o /dev/null --cacert "$WORK/ca.pem" "https://localhost:$PORT/readyz" 2>/dev/null && break; sleep 1; done
  before="$(issued_counter "https://localhost:$PORT")"
  good=0; for i in $(seq 1 $N_POD); do [ "$(issue_one "https://localhost:$PORT" "$p-$i")" = "201" ] && good=$((good+1)); done
  after="$(issued_counter "https://localhost:$PORT")"
  kill $PPID_ 2>/dev/null; wait $PPID_ 2>/dev/null
  echo "pod $p: issued $good/$N_POD, kryptkeeper_cert_issue_total ${before:-?} -> ${after:-?}"
  [ "$good" = "$N_POD" ] && [ -n "$before" ] && [ -n "$after" ] && [ "$(( ${after%.*} - ${before%.*} ))" = "$N_POD" ] && SERVING=$((SERVING+1))
done
[ "$SERVING" = "2" ] && PASS "both replicas independently issued leaves (counter delta == $N_POD on each)" || FAIL "only $SERVING/2 replicas proved serving"

STEP "in-cluster: Service ClusterIP answers /readyz"
SERVED=0
for i in $(seq 1 40); do
  $KC -n $NS exec curl-probe -- wget -q --no-check-certificate -O /dev/null "https://$SVC:8080/readyz" 2>/dev/null && SERVED=$((SERVED+1))
done
[ "$SERVED" -ge 38 ] && PASS "$SERVED/40 in-cluster /readyz via Service ClusterIP OK" || FAIL "in-cluster served $SERVED/40"

# ---------------------------------------------------------------------------
STEP "delete one replica; Service keeps answering; pod returns Ready"
VICTIM="$(echo "$PODS" | tail -1)"
$KC -n $NS delete pod "$VICTIM" --wait=false >/dev/null
bad=0
for i in $(seq 1 15); do
  $KC -n $NS exec curl-probe -- wget -q --no-check-certificate -O /dev/null "https://$SVC:8080/readyz" 2>/dev/null || bad=$((bad+1))
  sleep 1
done
[ "$bad" -le 2 ] && PASS "Service answered /readyz during pod replacement ($bad/15 transient failures)" || FAIL "Service failed $bad/15 during replacement"
$KC -n $NS rollout status deploy/$SVC --timeout=180s >/dev/null && [ "$($KC -n $NS get deploy $SVC -o jsonpath='{.status.readyReplicas}')" = "2" ] \
  && PASS "deployment back to readyReplicas=2" || FAIL "deployment did not return to 2 Ready"

echo
if [ "$FAILED" = "0" ]; then echo "ALL CHECKS PASSED"; else echo "SOME CHECKS FAILED"; exit 1; fi
