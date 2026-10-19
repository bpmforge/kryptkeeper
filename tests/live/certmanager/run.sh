#!/usr/bin/env bash
# W26-18: live UAT of the cert-manager external issuer (Dockerfile.certmanager +
# charts/kryptkeeper-certmanager-issuer) on a real kind cluster (podman
# provider) with a PINNED real cert-manager, against a hub built from this
# checkout running on the host.
#
#   1. issue:   Certificate ok-* becomes Ready with a hub-signed cert < 60 s and
#               appears in the hub inventory < 120 s; chain verifies to the hub root
#   2. denial:  a name-policy-violating CSR gets a Denied condition carrying the
#               hub's policy_violation reason; no inventory row appears
#   3. outage:  hub killed, request shows Ready=False/Pending "hub unreachable";
#               hub restarted with the same data dir -> request completes with
#               NO manual action (W26-17 backoff caps at 5 min)
#
# Idempotent, PASS/FAIL per step, non-zero exit on any FAIL, prints
# "ALL STEPS PASSED" and MEASURE lines (copy them into
# docs/release/LIVE_RESULTS_FG2_CERTMANAGER_v0.14.md). Cleans up on exit.
# Needs W26-17 (watch reconcile + Denied/PendingApproval conditions).
#
# Usage:  bash tests/live/certmanager/run.sh
# Env:    HUB_PORT (8197)  CLUSTER (kk-uat-cm)  CERT_MANAGER_VERSION (v1.17.2)
#         HUB_HOST_ADDR (address pods use for the host; auto-detected if unset)
#         KEEP_CLUSTER=1 (leave cluster + hub dir for debugging)
set -u
set -o pipefail

export KIND_EXPERIMENTAL_PROVIDER=podman

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$HERE/../../.." && pwd)"
WORK="$(mktemp -d /tmp/kk-uat-cm.XXXXXX)"
HUB_DIR=/tmp/kk-uat-cm-hub   # fixed so a hub restart keeps its state
HUB_PORT="${HUB_PORT:-8197}"
HUB_BASE="http://127.0.0.1:${HUB_PORT}"
TOKEN="uat-$(openssl rand -hex 12)"
CLUSTER="${CLUSTER:-kk-uat-cm}"
KC="kubectl --context kind-${CLUSTER}"
CERT_MANAGER_VERSION="${CERT_MANAGER_VERSION:-v1.17.2}"
CM_URL="https://github.com/cert-manager/cert-manager/releases/download/${CERT_MANAGER_VERSION}/cert-manager.yaml"
IMAGE_REPO=localhost/kryptkeeper-certmanager
IMAGE_TAG=kind
SYS_NS=kryptkeeper-system
UAT_NS=uat
CURL_IMG=docker.io/curlimages/curl:8.10.1
SUFFIX=".kk-uat.example"
RUN_ID="$RANDOM"
OK_NAME="ok-${RUN_ID}"
BAD_NAME="bad-${RUN_ID}"
REC_NAME="rec-${RUN_ID}"
OK_DNS="ok${RUN_ID}${SUFFIX}"
BAD_DNS="evil${RUN_ID}.example.com"
REC_DNS="rec${RUN_ID}${SUFFIX}"

FAILED=0
STEP() { echo; echo "== $* =="; }
PASS() { echo "PASS: $*"; }
FAIL() { echo "FAIL: $*"; FAILED=1; }
MEASURE() { echo "MEASURE $*"; }
HUB_PID=""
DIE() { echo "FAIL: $*"; exit 1; }

stop_hub() {
  if [ -n "$HUB_PID" ]; then
    kill "$HUB_PID" >/dev/null 2>&1 || true
    wait "$HUB_PID" 2>/dev/null || true
    HUB_PID=""
  fi
}
cleanup() {
  STEP "cleanup"
  if [ "$FAILED" != 0 ]; then
    echo "--- issuer log (last 40) ---"
    $KC -n "$SYS_NS" logs -l app.kubernetes.io/name=kryptkeeper-certmanager-issuer --tail=40 2>/dev/null || true
    echo "--- hub.log (last 30) ---"
    tail -30 "$WORK/hub.log" 2>/dev/null || true
  fi
  stop_hub
  if [ "${KEEP_CLUSTER:-0}" = "1" ]; then echo "KEEP_CLUSTER=1: leaving cluster $CLUSTER, $WORK, $HUB_DIR"; return; fi
  kind delete cluster --name "$CLUSTER" >/dev/null 2>&1 || true
  podman rmi -f "${IMAGE_REPO}:${IMAGE_TAG}" >/dev/null 2>&1 || true
  rm -rf "$WORK" "$HUB_DIR"
}
trap cleanup EXIT

curlj() { curl -sS -H "Authorization: Bearer ${TOKEN}" -H 'Content-Type: application/json' "$@"; }
jget() { python3 -c "import json,sys; d=json.load(sys.stdin); print(eval(sys.argv[1]))" "$1"; }
now() { date +%s; }

# cond_field <certificate-name> <condition type> <field>: that field of the matching
# CertificateRequest condition (cert-manager annotates CRs with certificate-name).
cond_field() { # <cert> <type> <field>
  $KC -n "$UAT_NS" get certificaterequest -o json 2>/dev/null | python3 -c '
import json,sys
cert, ctype, field = sys.argv[1:4]
for cr in json.load(sys.stdin).get("items", []):
    if cr["metadata"].get("annotations", {}).get("cert-manager.io/certificate-name") == cert:
        for c in cr.get("status", {}).get("conditions", []):
            if c.get("type") == ctype:
                print(c.get(field, "")); sys.exit(0)
        break
' "$1" "$2" "$3"
}
inv_total() { # <cn> -> meta.total of the hub inventory for that common name
  curlj "$HUB_BASE/api/v1/certificates?q=$1&limit=5" 2>/dev/null | jget 'd["meta"]["total"]' 2>/dev/null || echo -1
}
cert_yaml() { # <name> <dns>
  cat <<YAML
apiVersion: cert-manager.io/v1
kind: Certificate
metadata:
  name: $1
  namespace: $UAT_NS
spec:
  secretName: $1-tls
  commonName: $2
  dnsNames:
  - $2
  privateKey:
    algorithm: ECDSA   # the hub's Baseline policy rejects cert-manager's default RSA-2048
    size: 256
  issuerRef:
    name: lab-hub
    kind: Issuer
    group: certmanager.kryptkeeper.io
YAML
}

start_hub() {
  stop_hub
  mkdir -p "$HUB_DIR/data"
  ( export APP_BOOTSTRAP_TOKEN="$TOKEN" AUTH_MODE=bootstrap APP_CERTIFICATE_PROVIDER=ca \
      APP_DISCOVERY_PROVIDER=db APP_NOTIFICATION_PROVIDER=file KRYPTKEEPER_TLS_DISABLE=true \
      APP_CREDENTIAL_STORE_PASSPHRASE='uat-cred-passphrase-32-bytes-long!!' \
      KRYPTKEEPER_KEYSTORE_PASSPHRASE='uat-keystore-passphrase-32-bytes!!' \
      KRYPTKEEPER_DATA_DIR="$HUB_DIR/data" APP_CA_FILE="$HUB_DIR/data/cas.json" \
      APP_TEMPLATE_FILE="$HUB_DIR/data/templates.json" APP_CERTIFICATE_FILE="$HUB_DIR/data/certificates.json" \
      APP_AUDIT_FILE="$HUB_DIR/data/audit.json" APP_CERTS_SUMMARY_FILE="$HUB_DIR/data/certs_summary.json" \
      KRYPTKEEPER_BOOTSTRAP_CREATE_ROOT=true KRYPTKEEPER_CA_NAME="UAT CertManager Root CA" \
      APP_BIND_ADDR=0.0.0.0 PORT="$HUB_PORT"
    exec "$WORK/kryptkeeper" ) >>"$WORK/hub.log" 2>&1 &
  HUB_PID=$!
  local _
  for _ in $(seq 1 60); do
    curl -sf "$HUB_BASE/healthz" >/dev/null 2>&1 && return 0
    kill -0 "$HUB_PID" 2>/dev/null || return 1
    sleep 0.5
  done
  return 1
}

# probe_host <addr>: can a pod in the cluster reach the host hub at <addr>?
probe_host() {
  local out
  out="$($KC run "kk-probe-$RANDOM" -n default --image="$CURL_IMG" --image-pull-policy=IfNotPresent \
    --restart=Never --rm -i --quiet --command -- \
    curl -sS -m 6 -o /dev/null -w 'HTTP%{http_code}' "http://$1:${HUB_PORT}/healthz" 2>&1)"
  echo "$out" | grep -q 'HTTP200'
}

# ---------------------------------------------------------------------------
STEP "prerequisites"
for t in kind helm kubectl podman openssl curl python3 go; do
  command -v "$t" >/dev/null 2>&1 || DIE "$t not found (macOS: brew install kind helm kubernetes-cli podman go)"
done
PASS "tools present"
MEASURE "date=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
MEASURE "hub_commit=$(git -C "$REPO_ROOT" rev-parse --short HEAD)"
MEASURE "cert_manager_version=$CERT_MANAGER_VERSION"

# ---------------------------------------------------------------------------
STEP "build and start the hub (host process, plain HTTP, 0.0.0.0:$HUB_PORT)"
(cd "$REPO_ROOT" && CGO_ENABLED=0 go build -o "$WORK/kryptkeeper" ./cmd/kryptkeeper) \
  && PASS "hub built" || DIE "go build ./cmd/kryptkeeper failed"
rm -rf "$HUB_DIR"
start_hub && PASS "hub healthy on $HUB_BASE" || DIE "hub did not start, see $WORK/hub.log"
CA_ID="$(curlj "$HUB_BASE/api/v1/cas" | jget 'd["data"][0]["id"]')"
[ -n "$CA_ID" ] && PASS "root CA id=$CA_ID" || DIE "could not resolve root CA id"

# ---------------------------------------------------------------------------
STEP "template with a name policy (allowed_dns_suffixes [$SUFFIX])"
TPL_RESP="$(curlj -X POST "$HUB_BASE/api/v1/templates" -d "{\"name\":\"uat-certmanager\",\"display_name\":\"UAT cert-manager\",\"validity_period\":\"P30D\",\"key_usage\":[\"digitalSignature\",\"keyEncipherment\"],\"extended_key_usage\":[\"serverAuth\",\"clientAuth\"],\"allowed_algorithms\":[\"RSA\",\"ECDSA\"],\"active\":true,\"name_policy\":{\"allowed_dns_suffixes\":[\"$SUFFIX\"]}}")"
TEMPLATE_ID="$(echo "$TPL_RESP" | jget 'd["data"]["id"]' 2>/dev/null)"
[ -n "$TEMPLATE_ID" ] && PASS "template id=$TEMPLATE_ID" || DIE "template create failed: $TPL_RESP"

# ---------------------------------------------------------------------------
STEP "kind cluster + pinned cert-manager $CERT_MANAGER_VERSION"
kind delete cluster --name "$CLUSTER" >/dev/null 2>&1 || true
kind create cluster --name "$CLUSTER" --wait 120s >"$WORK/kind.log" 2>&1 \
  && PASS "kind cluster $CLUSTER up (podman provider)" || { tail -20 "$WORK/kind.log"; DIE "kind create cluster failed"; }
MEASURE "kind_node_image=$(podman ps --filter "name=${CLUSTER}-control-plane" --format '{{.Image}}' 2>/dev/null | head -1)"
MEASURE "kubernetes_version=$($KC version -o json 2>/dev/null | jget 'd["serverVersion"]["gitVersion"]' 2>/dev/null)"
$KC apply -f "$CM_URL" >"$WORK/cm-apply.log" 2>&1 \
  && PASS "cert-manager manifests applied" || { tail -10 "$WORK/cm-apply.log"; DIE "cert-manager apply failed"; }
$KC wait --for=condition=Available deployment --all -n cert-manager --timeout=180s >/dev/null \
  && PASS "cert-manager deployments Available" || DIE "cert-manager never became Available"
$KC create namespace "$UAT_NS" >/dev/null 2>&1 || true
# Deployments Available does not mean the CRDs are discoverable or the webhook
# is serving (found live 2026-10-15: "no matches for kind Certificate").
tries=30
until $KC apply --dry-run=server -f - >"$WORK/crd-probe.log" 2>&1 <<YAML
$(cert_yaml crd-probe crd-probe${SUFFIX})
YAML
do
  tries=$((tries - 1)); [ $tries -le 0 ] && { cat "$WORK/crd-probe.log"; DIE "cert-manager CRDs/webhook never became usable"; }
  sleep 3
done
PASS "Certificate CRD discoverable and webhook serving"

# ---------------------------------------------------------------------------
STEP "build and load the issuer image"
podman build -f "$REPO_ROOT/Dockerfile.certmanager" -t "${IMAGE_REPO}:${IMAGE_TAG}" "$REPO_ROOT" >"$WORK/build.log" 2>&1 \
  && PASS "issuer image built" || { tail -20 "$WORK/build.log"; DIE "podman build failed"; }
podman save -o "$WORK/img.tar" "${IMAGE_REPO}:${IMAGE_TAG}" || DIE "podman save failed"
kind load image-archive "$WORK/img.tar" --name "$CLUSTER" >"$WORK/load.log" 2>&1 \
  && PASS "issuer image loaded into kind" || { cat "$WORK/load.log"; DIE "kind load image-archive failed"; }

# ---------------------------------------------------------------------------
STEP "pod -> host hub reachability"
HOST_PRIMARY="$(python3 -c "
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.connect(('192.0.2.1', 9))  # UDP connect selects a route, sends nothing
print(s.getsockname()[0])")"
CANDIDATES="${HUB_HOST_ADDR:-} host.containers.internal"
[ "$(uname -s)" = Darwin ] && CANDIDATES="$CANDIDATES 192.168.127.254"
CANDIDATES="$CANDIDATES $HOST_PRIMARY"
HUB_HOST=""
for cand in $CANDIDATES; do
  if probe_host "$cand"; then HUB_HOST="$cand"; break; else echo "  (not reachable from pods: $cand)"; fi
done
[ -n "$HUB_HOST" ] && PASS "pods reach the hub at $HUB_HOST:$HUB_PORT" || DIE "no candidate address reaches the host hub from a pod (tried: $CANDIDATES); set HUB_HOST_ADDR"
MEASURE "hub_host_from_pods=$HUB_HOST"

# ---------------------------------------------------------------------------
STEP "helm install the issuer chart"
$KC create namespace "$SYS_NS" >/dev/null 2>&1 || true
$KC -n "$SYS_NS" create secret generic lab-hub-token --from-literal=token="$TOKEN" >/dev/null \
  && PASS "hub token secret created" || DIE "secret create failed"
helm install kk-issuer "$REPO_ROOT/charts/kryptkeeper-certmanager-issuer" --kube-context "kind-$CLUSTER" -n "$SYS_NS" \
  --set hub.url="http://${HUB_HOST}:${HUB_PORT}" \
  --set hub.tokenSecretRef.name=lab-hub-token \
  --set defaults.caID="$CA_ID" --set defaults.templateID="$TEMPLATE_ID" \
  --set image.repository="$IMAGE_REPO" --set image.tag="$IMAGE_TAG" --set image.pullPolicy=Never \
  >"$WORK/helm.log" 2>&1 && PASS "helm install kk-issuer" || { cat "$WORK/helm.log"; DIE "helm install failed"; }
$KC -n "$SYS_NS" rollout status deploy --timeout=120s >/dev/null \
  && PASS "issuer deployment rolled out" || DIE "issuer deployment never became ready"

# ---------------------------------------------------------------------------
STEP "A. issue: Certificate $OK_NAME Ready < 60 s, in inventory < 120 s"
T0="$(now)"
cert_yaml "$OK_NAME" "$OK_DNS" | $KC apply -f - >/dev/null || DIE "apply $OK_NAME failed"
if $KC -n "$UAT_NS" wait --for=condition=Ready "certificate/$OK_NAME" --timeout=60s >/dev/null 2>&1; then
  READY_S=$(( $(now) - T0 ))
  PASS "Certificate $OK_NAME Ready in ${READY_S}s (limit 60)"
  MEASURE "ok_ready_seconds=$READY_S"
else
  FAIL "Certificate $OK_NAME not Ready within 60 s"
  MEASURE "ok_ready_seconds=TIMEOUT"
fi
INV_S=""
while [ $(( $(now) - T0 )) -le 120 ]; do
  if [ "$(inv_total "$OK_DNS")" -ge 1 ] 2>/dev/null; then INV_S=$(( $(now) - T0 )); break; fi
  sleep 2
done
if [ -n "$INV_S" ]; then
  PASS "$OK_DNS in hub inventory ${INV_S}s after apply (limit 120)"
  MEASURE "ok_inventory_seconds=$INV_S"
else
  FAIL "$OK_DNS not in hub inventory within 120 s"
  MEASURE "ok_inventory_seconds=TIMEOUT"
fi
$KC -n "$UAT_NS" get secret "${OK_NAME}-tls" -o jsonpath='{.data.tls\.crt}' 2>/dev/null | openssl base64 -d -A >"$WORK/leaf.pem" 2>/dev/null
curl -sS -m 5 "$HUB_BASE/.well-known/est/cacerts" -o "$WORK/cacerts.b64" 2>/dev/null \
  && openssl base64 -d -A -in "$WORK/cacerts.b64" -out "$WORK/cacerts.p7" 2>/dev/null \
  && openssl pkcs7 -inform der -in "$WORK/cacerts.p7" -print_certs -out "$WORK/root.pem" 2>/dev/null
if ! grep -q "BEGIN CERTIFICATE" "$WORK/root.pem" 2>/dev/null; then
  curlj "$HUB_BASE/api/v1/cas/$CA_ID/chain?format=pem" -o "$WORK/root.pem" 2>/dev/null
  echo "  (EST cacerts unavailable; used /api/v1/cas/{id}/chain)"
fi
if openssl verify -CAfile "$WORK/root.pem" "$WORK/leaf.pem" >"$WORK/verify.log" 2>&1; then
  PASS "secret tls.crt chains to the hub root: $(tr '\n' ' ' <"$WORK/verify.log")"
else
  FAIL "secret tls.crt does not verify against the hub root: $(cat "$WORK/verify.log")"
fi

# ---------------------------------------------------------------------------
STEP "B. denial: $BAD_DNS violates the template name policy"
cert_yaml "$BAD_NAME" "$BAD_DNS" | $KC apply -f - >/dev/null || DIE "apply $BAD_NAME failed"
DENIED=""
for _ in $(seq 1 30); do
  DENIED="$(cond_field "$BAD_NAME" Denied status)"
  [ "$DENIED" = True ] && break
  sleep 2
done
if [ "$DENIED" = True ]; then
  DMSG="$(cond_field "$BAD_NAME" Denied message)"
  DREASON="$(cond_field "$BAD_NAME" Denied reason)"
  RREADY="$(cond_field "$BAD_NAME" Ready status)"
  PASS "CertificateRequest for $BAD_NAME has Denied=True (reason $DREASON)"
  MEASURE "denied_message=$DMSG"
  case "$DMSG" in *policy_violation*) PASS "denial message carries the hub code policy_violation";; *) FAIL "denial message lacks policy_violation: $DMSG";; esac
  case "$DMSG" in *"name policy"*) PASS "denial message carries the name-policy text";; *) FAIL "denial message lacks the name-policy text: $DMSG";; esac
  [ "$RREADY" = False ] && PASS "Ready=False alongside Denied" || FAIL "Ready condition is '$RREADY', want False"
else
  FAIL "no Denied=True condition on the $BAD_NAME CertificateRequest within 60 s (W26-17 merged? conditions: $(cond_field "$BAD_NAME" Ready message))"
fi
[ "$(inv_total "$BAD_DNS")" = 0 ] && PASS "no inventory row for $BAD_DNS" || FAIL "inventory has a row for $BAD_DNS (total $(inv_total "$BAD_DNS"))"

# ---------------------------------------------------------------------------
STEP "C. outage: hub down, request Pending; hub back, completes without manual action"
stop_hub
curl -sf -m 3 "$HUB_BASE/healthz" >/dev/null 2>&1 && DIE "hub still answering after kill"
PASS "hub stopped"
TR="$(now)"
cert_yaml "$REC_NAME" "$REC_DNS" | $KC apply -f - >/dev/null || DIE "apply $REC_NAME failed"
sleep 20
PR="$(cond_field "$REC_NAME" Ready reason)"; PS="$(cond_field "$REC_NAME" Ready status)"; PM="$(cond_field "$REC_NAME" Ready message)"
if [ "$PS" = False ] && [ "$PR" = Pending ] && case "$PM" in "hub unreachable"*) true;; *) false;; esac; then
  PASS "request shows Ready=False reason=Pending message '$PM'"
else
  FAIL "during outage want Ready=False/Pending/'hub unreachable...', got status='$PS' reason='$PR' message='$PM'"
fi
start_hub && PASS "hub restarted with the same data dir and port" || DIE "hub restart failed, see $WORK/hub.log"
[ "$(curlj "$HUB_BASE/api/v1/cas" | jget 'd["data"][0]["id"]' 2>/dev/null)" = "$CA_ID" ] \
  && PASS "same root CA after restart (state kept)" || FAIL "root CA changed or unreadable after restart"
TH="$(now)"
REC_OK=""
while [ $(( $(now) - TH )) -le 420 ]; do
  if $KC -n "$UAT_NS" wait --for=condition=Ready "certificate/$REC_NAME" --timeout=10s >/dev/null 2>&1; then REC_OK=$(( $(now) - TH )); break; fi
done
if [ -n "$REC_OK" ]; then
  PASS "$REC_NAME Ready ${REC_OK}s after hub recovery (no manual action; limit 420)"
  MEASURE "recovery_seconds_after_hub_restart=$REC_OK"
  MEASURE "recovery_seconds_after_apply=$(( $(now) - TR ))"
else
  FAIL "$REC_NAME never became Ready within 420 s of hub recovery"
  MEASURE "recovery_seconds_after_hub_restart=TIMEOUT"
fi
ISSUER_LOG="$($KC -n "$SYS_NS" logs -l app.kubernetes.io/name=kryptkeeper-certmanager-issuer --tail=-1 2>/dev/null)"
FAILS="$(echo "$ISSUER_LOG" | grep -c "hub unreachable for")"
if echo "$ISSUER_LOG" | grep -q "ALERT certmanager.issuer.unreachable"; then
  MEASURE "unreachable_alert=FIRED consecutive_failure_logs=$FAILS"
  echo "INFO: ALERT certmanager.issuer.unreachable fired ($FAILS failure log lines)"
else
  MEASURE "unreachable_alert=NOT_FIRED consecutive_failure_logs=$FAILS"
  if [ "$FAILS" -ge 5 ]; then FAIL "$FAILS consecutive failures logged but the unreachable alert never fired"; else echo "INFO: alert not fired ($FAILS failures < threshold 5), as expected"; fi
fi

# ---------------------------------------------------------------------------
STEP "summary"
if [ "$FAILED" -eq 0 ]; then
  echo "ALL STEPS PASSED"
else
  echo "ONE OR MORE STEPS FAILED -- see FAIL lines above"
fi
exit "$FAILED"
