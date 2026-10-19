#!/usr/bin/env bash
# W26-19: live UAT of hub-rooted workload identities on kind (podman provider).
#
# Path S (mandatory): the hub's SPIFFE Workload API (gRPC over a hostPath Unix
# socket) issues SVIDs to two pods by kernel-attested UID; the pods run mutual
# TLS (go-spiffe) authorizing each other by SPIFFE ID, and the SVID chain is
# verified to the hub root independently with openssl. An unregistered UID gets
# no SVID. This satisfies both board acceptance items without Istio.
# Path I (Istio plugged-in CA `cacerts`): NOT attempted here (decision in the
# spec: attempted only if a CA-capable template with an exportable intermediate
# key exists; istioctl is not on the lab host). The final PATH_I line says so.
#
# Idempotent, PASS/FAIL per step, non-zero exit on any FAIL, prints
# "ALL STEPS PASSED", MEASURE lines for the results doc, and
# "PATH_I: NOT_ATTEMPTED". Cleans up cluster, images and temp state on exit.
#
# Usage:  bash tests/live/istio-mtls/run.sh
# Env:    CLUSTER (kk-uat-mesh)  LPORT (18199, port-forward to the hub)
#         KEEP_CLUSTER=1 (leave cluster and temp dir for debugging)
set -u
set -o pipefail

export KIND_EXPERIMENTAL_PROVIDER=podman

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$HERE/../../.." && pwd)"
WORK="$(mktemp -d /tmp/kk-uat-mesh.XXXXXX)"
CLUSTER="${CLUSTER:-kk-uat-mesh}"
KC="kubectl --context kind-${CLUSTER}"
NS=uat
LPORT="${LPORT:-18199}"
HUB="http://127.0.0.1:${LPORT}"
HUB_IMAGE=localhost/kryptkeeper:kind
CLIENT_IMAGE=localhost/kk-svidclient:kind
TD=kk-uat.example
ID_SERVER="spiffe://${TD}/ns/uat/sa/server"
ID_CLIENT="spiffe://${TD}/ns/uat/sa/client"
TOKEN="uat-$(openssl rand -hex 12)"
PASSPHRASE="uat-$(openssl rand -hex 16)"

FAILED=0
STEP() { echo; echo "== $* =="; }
PASS() { echo "PASS: $*"; }
FAIL() { echo "FAIL: $*"; FAILED=1; }
MEASURE() { echo "MEASURE $*"; }
DIE() { echo "FAIL: $*"; exit 1; }
PF_PID=""
stop_pf() { if [ -n "$PF_PID" ]; then kill "$PF_PID" 2>/dev/null || true; wait "$PF_PID" 2>/dev/null || true; PF_PID=""; fi; }
cleanup() {
  STEP "cleanup"
  if [ "$FAILED" != 0 ]; then
    for p in lab-hub svid-server svid-client svid-denied; do
      echo "--- $p logs (last 25) ---"; $KC -n "$NS" logs "$p" --all-containers --tail=25 2>&1 || true
    done
  fi
  stop_pf
  if [ "${KEEP_CLUSTER:-0}" = "1" ]; then echo "KEEP_CLUSTER=1: leaving cluster $CLUSTER and $WORK"; return; fi
  kind delete cluster --name "$CLUSTER" >/dev/null 2>&1 || true
  podman rmi -f "$HUB_IMAGE" "$CLIENT_IMAGE" >/dev/null 2>&1 || true
  rm -rf "$WORK"
}
trap cleanup EXIT

curlh() { curl -sS -H "Authorization: Bearer ${TOKEN}" -H 'Content-Type: application/json' "$@"; }
jget() { python3 -c "import json,sys; d=json.load(sys.stdin); print(eval(sys.argv[1]))" "$1"; }
render() { sed -e "s|__HUB_IMAGE__|$HUB_IMAGE|g" -e "s|__CLIENT_IMAGE__|$CLIENT_IMAGE|g" -e "s|__SIGNING_CA_ID__|${1:-pending}|g" "$2"; }
start_pf() {
  stop_pf
  $KC -n "$NS" port-forward pod/lab-hub "$LPORT:8080" >"$WORK/pf.log" 2>&1 &
  PF_PID=$!
  local _
  for _ in $(seq 1 30); do curl -sf "$HUB/healthz" >/dev/null 2>&1 && return 0; sleep 1; done
  return 1
}
# wait_log <pod> <regex> <seconds>
wait_log() {
  local _ n=$(( $3 / 2 ))
  for _ in $(seq 1 "$n"); do $KC -n "$NS" logs "$1" 2>/dev/null | grep -Eq "$2" && return 0; sleep 2; done
  return 1
}

# ---------------------------------------------------------------------------
STEP "prerequisites"
for t in kind kubectl podman openssl curl python3 go; do
  command -v "$t" >/dev/null 2>&1 || DIE "$t not found (macOS: brew install kind kubernetes-cli podman go)"
done
PASS "tools present"
MEASURE "date=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
MEASURE "hub_commit=$(git -C "$REPO_ROOT" rev-parse --short HEAD)"
MEASURE "go_spiffe=$(grep 'go-spiffe/v2 ' "$HERE/svidclient/go.mod" | awk '{print $2}' | head -1)"
(cd "$HERE/svidclient" && go vet ./...) && PASS "go vet svidclient" || DIE "go vet svidclient failed"

# ---------------------------------------------------------------------------
STEP "build the hub and svidclient images, create the kind cluster"
podman build -t "$HUB_IMAGE" "$REPO_ROOT" >"$WORK/build-hub.log" 2>&1 \
  && PASS "hub image built" || { tail -20 "$WORK/build-hub.log"; DIE "hub image build failed"; }
podman build -t "$CLIENT_IMAGE" "$HERE/svidclient" >"$WORK/build-client.log" 2>&1 \
  && PASS "svidclient image built" || { tail -20 "$WORK/build-client.log"; DIE "svidclient image build failed"; }
podman save -o "$WORK/hub.tar" "$HUB_IMAGE" && podman save -o "$WORK/client.tar" "$CLIENT_IMAGE" || DIE "podman save failed"
kind delete cluster --name "$CLUSTER" >/dev/null 2>&1 || true
kind create cluster --name "$CLUSTER" --wait 120s >"$WORK/kind.log" 2>&1 \
  && PASS "kind cluster $CLUSTER up (single node, podman provider)" || { tail -20 "$WORK/kind.log"; DIE "kind create cluster failed"; }
MEASURE "kind_node_image=$(podman ps --filter "name=${CLUSTER}-control-plane" --format '{{.Image}}' 2>/dev/null | head -1)"
MEASURE "kubernetes_version=$($KC version -o json 2>/dev/null | jget 'd["serverVersion"]["gitVersion"]' 2>/dev/null)"
for img in hub client; do
  kind load image-archive "$WORK/$img.tar" --name "$CLUSTER" >"$WORK/load-$img.log" 2>&1 \
    && PASS "$img image loaded into kind" || { cat "$WORK/load-$img.log"; DIE "kind load $img failed"; }
done

# ---------------------------------------------------------------------------
STEP "hub Pod (round 1: create the root CA, learn its id)"
$KC create namespace "$NS" >/dev/null 2>&1 || true
$KC -n "$NS" create secret generic lab-hub-secrets --from-literal=token="$TOKEN" --from-literal=passphrase="$PASSPHRASE" >/dev/null \
  && PASS "hub secrets created" || DIE "secret create failed"
render pending "$HERE/manifests/hub.yaml" | $KC apply -f - >/dev/null || DIE "hub apply failed"
$KC -n "$NS" wait --for=condition=Ready pod/lab-hub --timeout=180s >/dev/null \
  && PASS "hub Pod Ready" || DIE "hub Pod never Ready"
start_pf && PASS "port-forward to the hub on :$LPORT" || DIE "port-forward / healthz failed: $(cat "$WORK/pf.log")"
CA_ID="$(curlh "$HUB/api/v1/cas" | jget 'd["data"][0]["id"]' 2>/dev/null)"
[ -n "$CA_ID" ] && PASS "root CA id=$CA_ID" || DIE "could not read the root CA id"

STEP "hub Pod (round 2: SPIFFE_SIGNING_CA_ID=$CA_ID, same hostPath data)"
stop_pf
$KC -n "$NS" delete pod lab-hub --wait=true >/dev/null || DIE "hub pod delete failed"
render "$CA_ID" "$HERE/manifests/hub.yaml" | $KC apply -f - >/dev/null || DIE "hub re-apply failed"
$KC -n "$NS" wait --for=condition=Ready pod/lab-hub --timeout=180s >/dev/null \
  && PASS "hub Pod Ready again" || DIE "hub Pod never Ready after restart"
start_pf || DIE "port-forward / healthz failed after restart"
[ "$(curlh "$HUB/api/v1/cas" | jget 'd["data"][0]["id"]' 2>/dev/null)" = "$CA_ID" ] \
  && PASS "same root CA after restart" || DIE "root CA changed after the restart (hostPath state lost)"
$KC -n "$NS" logs lab-hub -c hub 2>/dev/null | grep -q "SPIFFE Workload API listening on /run/kk-spiffe/api.sock" \
  && PASS "hub log: Workload API listening on the hostPath socket" || FAIL "hub log lacks 'SPIFFE Workload API listening' (see: $($KC -n "$NS" logs lab-hub -c hub 2>/dev/null | grep -i spiffe | tail -3))"
[ "$(curlh "$HUB/api/v1/spiffe/status" | jget 'd["data"]["enabled"]' 2>/dev/null)" = True ] \
  && PASS "GET /api/v1/spiffe/status enabled=true (trust domain $TD)" || FAIL "SPIFFE not enabled: $(curlh "$HUB/api/v1/spiffe/status")"

# ---------------------------------------------------------------------------
STEP "register workload selectors (UID -> SPIFFE ID)"
for pair in "2001 $ID_SERVER" "2002 $ID_CLIENT"; do
  set -- $pair
  c="$(curlh -o "$WORK/sel.json" -w '%{http_code}' -X POST "$HUB/api/v1/spiffe/workload-selectors" -d "{\"uid\":$1,\"spiffe_id\":\"$2\"}")"
  [ "$c" = 201 ] && PASS "selector uid=$1 -> $2 (201)" || FAIL "selector uid=$1: HTTP $c $(cat "$WORK/sel.json")"
done
N="$(curlh "$HUB/api/v1/spiffe/workload-selectors" | jget 'len(d["data"]["selectors"])' 2>/dev/null)"
[ "$N" = 2 ] && PASS "registry lists 2 selectors (uid 2003 is deliberately absent)" || FAIL "registry lists '$N' selectors, want 2"

# ---------------------------------------------------------------------------
STEP "A. two workloads obtain SVIDs and complete mutual TLS"
render "$CA_ID" "$HERE/manifests/workloads.yaml" | $KC apply -f - >/dev/null || DIE "workloads apply failed"
wait_log svid-server 'LISTENING' 120 \
  && PASS "svid-server (uid 2001) got its SVID and is listening" || { $KC -n "$NS" logs svid-server 2>&1 | tail -5; DIE "svid-server never listened (UID remap? look for 'uid N is not a registered workload')"; }
$KC -n "$NS" wait --for=jsonpath='{.status.phase}'=Succeeded pod/svid-client --timeout=150s >/dev/null 2>&1 \
  && PASS "svid-client (uid 2002) completed the call" || { $KC -n "$NS" logs svid-client 2>&1 | tail -8; DIE "svid-client did not succeed (UID remap? look for 'uid N is not a registered workload')"; }
$KC -n "$NS" logs svid-server >"$WORK/server.log" 2>&1
$KC -n "$NS" logs svid-client >"$WORK/client.log" 2>&1
grep -q "^PEER $ID_CLIENT\$" "$WORK/server.log" && PASS "server saw peer $ID_CLIENT" || FAIL "server log lacks 'PEER $ID_CLIENT'"
grep -q "^CHAIN_OK\$" "$WORK/server.log" && PASS "server: CHAIN_OK (peer chain verified to the bundle)" || FAIL "server log lacks CHAIN_OK"
grep -q "^PEER $ID_SERVER\$" "$WORK/client.log" && PASS "client saw peer $ID_SERVER" || FAIL "client log lacks 'PEER $ID_SERVER'"
grep -q "^CHAIN_OK\$" "$WORK/client.log" && PASS "client: CHAIN_OK" || FAIL "client log lacks CHAIN_OK"
grep -q "^REPLY hello from $ID_SERVER" "$WORK/client.log" && PASS "application data flowed over the mTLS channel" || FAIL "client log lacks the server reply"

# ---------------------------------------------------------------------------
STEP "A2. independent chain verification to the hub root (openssl)"
curlh "$HUB/api/v1/spiffe/bundle" -o "$WORK/root.pem"
grep -q "BEGIN CERTIFICATE" "$WORK/root.pem" && PASS "GET /api/v1/spiffe/bundle returned the trust bundle" || DIE "bundle unavailable: $(cat "$WORK/root.pem")"
sed -n '/^LEAF_PEM_BEGIN$/,/^LEAF_PEM_END$/p' "$WORK/client.log" | grep -v '^LEAF_PEM_' >"$WORK/leaf.pem"
if openssl verify -CAfile "$WORK/root.pem" "$WORK/leaf.pem" >"$WORK/verify.log" 2>&1; then
  PASS "client SVID verifies to the hub root: $(tr '\n' ' ' <"$WORK/verify.log")"
  MEASURE "openssl_verify=$(tr '\n' ' ' <"$WORK/verify.log")"
else
  FAIL "client SVID does not verify to the hub root: $(cat "$WORK/verify.log")"
fi
openssl x509 -in "$WORK/leaf.pem" -noout -ext subjectAltName 2>/dev/null | grep -q "URI:$ID_CLIENT" \
  && PASS "leaf SAN carries URI:$ID_CLIENT" || FAIL "leaf SAN lacks URI:$ID_CLIENT"
ROOT_FP="$(openssl x509 -in "$WORK/root.pem" -noout -fingerprint -sha256 | cut -d= -f2 | tr -d ':' | tr 'A-F' 'a-f')"
grep -q "^BUNDLE_ROOT_SHA256 $ROOT_FP\$" "$WORK/client.log" \
  && PASS "the Workload API bundle root equals the hub root (sha256 $ROOT_FP)" || FAIL "Workload API bundle root differs from the hub root ($ROOT_FP)"
MEASURE "hub_root_sha256=$ROOT_FP"

# ---------------------------------------------------------------------------
STEP "A3. unregistered UID 2003 obtains no SVID"
render "$CA_ID" "$HERE/manifests/denied.yaml" | $KC apply -f - >/dev/null || DIE "denied pod apply failed"
$KC -n "$NS" wait --for=jsonpath='{.status.phase}'=Succeeded pod/svid-denied --timeout=90s >/dev/null 2>&1 || DIE "svid-denied pod did not complete"
$KC -n "$NS" logs svid-denied >"$WORK/denied.log" 2>&1
if grep -q "^RPC_CODE PermissionDenied\$" "$WORK/denied.log" && ! grep -q "^RPC_OK" "$WORK/denied.log"; then
  PASS "uid 2003 refused with PermissionDenied: $(grep '^RPC_MESSAGE' "$WORK/denied.log")"
else
  FAIL "uid 2003 was not refused as expected: $(cat "$WORK/denied.log")"
fi

# ---------------------------------------------------------------------------
STEP "A4. audit trail"
BINDS="$(curlh "$HUB/api/v1/audit?action=spiffe.selector_bind&limit=50" | jget 'len([e for e in d["data"] if e["outcome"]=="success"])' 2>/dev/null)"
[ "${BINDS:-0}" -ge 2 ] && PASS "audit holds $BINDS spiffe.selector_bind success rows" || FAIL "audit holds '${BINDS:-0}' spiffe.selector_bind success rows, want >= 2"
ATT_OK="$(curlh "$HUB/api/v1/audit?action=spiffe.workload_attest&limit=50" | jget 'len([e for e in d["data"] if e["outcome"]=="success"])' 2>/dev/null)"
ATT_DENY="$(curlh "$HUB/api/v1/audit?action=spiffe.workload_attest&limit=50" | jget 'len([e for e in d["data"] if e["outcome"]=="denied"])' 2>/dev/null)"
MEASURE "audit_workload_attest_success=${ATT_OK:-?} audit_workload_attest_denied=${ATT_DENY:-?}"
echo "INFO: spiffe.workload_attest rows: success=${ATT_OK:-?} denied=${ATT_DENY:-?} (recorded, not asserted; the ticket requires selector_bind rows)"

# ---------------------------------------------------------------------------
STEP "summary"
if [ "$FAILED" -eq 0 ]; then
  echo "ALL STEPS PASSED"
else
  echo "ONE OR MORE STEPS FAILED -- see FAIL lines above"
fi
echo "PATH_I: NOT_ATTEMPTED (Istio cacerts needs a CA-capable template with an exportable intermediate key and istioctl, neither verified; see README)"
exit "$FAILED"
