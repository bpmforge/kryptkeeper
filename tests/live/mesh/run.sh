#!/usr/bin/env bash
# W19-09: prove the hub's mesh discovery (internal/discovery/servicemesh.go,
# wired by internal/bootstrap/mesh_discovery_wiring.go's
# MeshDiscoveryScheduler) reads a REAL Linkerd (and, best-effort, Istio)
# control plane's mTLS issuer/root secrets through the Kubernetes API and
# lands them in inventory -- against a real "kind" cluster on podman.
#
# Reuses the W19-03 kind fixture's *pattern* (kind-on-podman, RBAC + minted
# SA token, exported cluster CA, hub-on-host) without modifying
# tests/live/k8s/ itself, per the ticket's write_scope. Idempotent,
# PASS/FAIL per step, non-zero exit on any FAIL, cleans up its own
# cluster/hub/state on exit (trap). No real key material is ever committed:
# the cluster CA, SA tokens, and mesh-issued certs are all generated (by
# Linkerd/Istio's own installers) at run time and live only in the temp
# work dir and the ephemeral kind cluster.
set -u
set -o pipefail

export KIND_EXPERIMENTAL_PROVIDER=podman

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$HERE/../../.." && pwd)"
WORK="$(mktemp -d /tmp/kk-uat-mesh.XXXXXX)"
HUB_DIR=/tmp/kk-uat-mesh-hub
HUB_PORT=8097
HUB_BASE="http://127.0.0.1:${HUB_PORT}"
TOKEN=uat-token
CLUSTER=kk-uat
NAMESPACE=uat

ISTIO_INSTALLED=0
FAILED=0
STEP() { echo; echo "== $* =="; }
PASS() { echo "PASS: $*"; }
FAIL() { echo "FAIL: $*"; FAILED=1; }
DIE()  { echo "FAIL: $*"; cleanup; exit 1; }

HUB_PID=""
cleanup() {
  STEP "cleanup"
  [ -n "$HUB_PID" ] && kill "$HUB_PID" 2>/dev/null || true
  kind delete cluster --name "$CLUSTER" >/dev/null 2>&1 || true
  rm -rf "$WORK" "$HUB_DIR"
}
trap cleanup EXIT

curlj() { curl -sS -H "Authorization: Bearer ${TOKEN}" -H 'Content-Type: application/json' "$@"; }

# ---------------------------------------------------------------------------
# 1. kind cluster (same name/shape as tests/live/k8s/run.sh's fixture; a
#    fresh instance -- fixtures run temporally separate, never concurrently,
#    so reusing the name is "reuse the fixture", not "collide with it").
# ---------------------------------------------------------------------------
STEP "kind cluster"
kind delete cluster --name "$CLUSTER" >/dev/null 2>&1 || true
kind create cluster --name "$CLUSTER" \
  && PASS "kind cluster $CLUSTER up (podman provider)" || DIE "kind create cluster failed"

kubectl create namespace "$NAMESPACE" >/dev/null 2>&1 || true

# ---------------------------------------------------------------------------
# 2. Linkerd: a real control plane, which creates the identity issuer
#    secret (linkerd/linkerd-identity-issuer) and trust-anchor material
#    the discovery code reads.
# ---------------------------------------------------------------------------
STEP "linkerd install"
LINKERD_VERSION="$(linkerd version --client --short 2>/dev/null || echo unknown)"
# Linkerd's CRD set includes Gateway API's HTTPRoute etc; recent linkerd
# refuses to render its own CRDs until Gateway API's are already present
# (found live: "The Gateway API CRDs must be installed prior to
# installing Linkerd").
GATEWAY_API_VERSION=v1.2.1
kubectl apply --server-side -f "https://github.com/kubernetes-sigs/gateway-api/releases/download/${GATEWAY_API_VERSION}/standard-install.yaml" >"$WORK/gatewayapi-apply.log" 2>&1 \
  && PASS "Gateway API $GATEWAY_API_VERSION CRDs applied" || DIE "Gateway API CRD apply failed, see $WORK/gatewayapi-apply.log"
linkerd install --crds 2>"$WORK/linkerd-crds.log" | kubectl apply -f - >"$WORK/linkerd-crds-apply.log" 2>&1 \
  && PASS "linkerd CRDs applied ($LINKERD_VERSION)" || DIE "linkerd install --crds failed, see $WORK/linkerd-crds.log"
linkerd install 2>"$WORK/linkerd-install.log" | kubectl apply -f - >"$WORK/linkerd-apply.log" 2>&1 \
  && PASS "linkerd control plane manifests applied" || DIE "linkerd install failed, see $WORK/linkerd-install.log"
linkerd check --wait 5m >"$WORK/linkerd-check.log" 2>&1 \
  && PASS "linkerd check green" || DIE "linkerd check never went green, see $WORK/linkerd-check.log"

# ---------------------------------------------------------------------------
# 3. Istio: best-effort. A minimal-profile Istio control plane alongside a
#    full Linkerd one on a single-node kind cluster on this Mac's memory
#    budget is the risk the ticket calls out explicitly -- if it doesn't
#    fit or istioctl install times out, Linkerd's proof stands alone and
#    this is reported, not silently retried into a false pass.
# ---------------------------------------------------------------------------
STEP "istio install (best-effort)"
ISTIO_VERSION="$(istioctl version --remote=false --short 2>/dev/null || echo unknown)"
# macOS has no `timeout(1)` by default; istioctl's own --readiness-timeout
# bounds the wait instead (found live: bare `timeout 300 ...` fails with
# "command not found" on this Mac).
if istioctl install --set profile=minimal --readiness-timeout=180s -y >"$WORK/istio-install.log" 2>&1; then
  PASS "istio minimal profile installed ($ISTIO_VERSION)"
  ISTIO_INSTALLED=1
else
  FAIL "istio install did not complete in time/resources (best-effort per ticket) -- see $WORK/istio-install.log"
fi

# ---------------------------------------------------------------------------
# 4. RBAC: two ServiceAccounts.
#      kk-uat-mesh-reader     -- get/list secrets in BOTH linkerd and
#                                 istio-system: the positive path.
#      kk-uat-mesh-reader-neg -- get/list secrets in istio-system ONLY:
#                                 the negative path (no linkerd access).
#    Cluster-scoped "list all TLS secrets" (mesh discovery's step 1, the
#    ingress/gateway sweep) is deliberately NOT granted -- it's optional to
#    the Istio/Linkerd probes (see servicemesh.go: each probe is an
#    independent k8sGet) and granting blanket cluster-wide secret read is
#    more privilege than this fixture's actual assertions need.
# ---------------------------------------------------------------------------
STEP "RBAC: mesh-reader ServiceAccounts"
cat > "$WORK/rbac.yaml" <<EOF
apiVersion: v1
kind: ServiceAccount
metadata:
  name: kk-uat-mesh-reader
  namespace: ${NAMESPACE}
---
apiVersion: v1
kind: ServiceAccount
metadata:
  name: kk-uat-mesh-reader-neg
  namespace: ${NAMESPACE}
---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: kk-uat-secret-reader
  namespace: linkerd
rules:
- apiGroups: [""]
  resources: ["secrets"]
  verbs: ["get", "list"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: kk-uat-secret-reader
  namespace: istio-system
rules:
- apiGroups: [""]
  resources: ["secrets"]
  verbs: ["get", "list"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: kk-uat-mesh-reader-linkerd
  namespace: linkerd
subjects:
- kind: ServiceAccount
  name: kk-uat-mesh-reader
  namespace: ${NAMESPACE}
roleRef:
  kind: Role
  name: kk-uat-secret-reader
  apiGroup: rbac.authorization.k8s.io
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: kk-uat-mesh-reader-istio
  namespace: istio-system
subjects:
- kind: ServiceAccount
  name: kk-uat-mesh-reader
  namespace: ${NAMESPACE}
roleRef:
  kind: Role
  name: kk-uat-secret-reader
  apiGroup: rbac.authorization.k8s.io
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: kk-uat-mesh-reader-neg-istio
  namespace: istio-system
subjects:
- kind: ServiceAccount
  name: kk-uat-mesh-reader-neg
  namespace: ${NAMESPACE}
roleRef:
  kind: Role
  name: kk-uat-secret-reader
  apiGroup: rbac.authorization.k8s.io
EOF
kubectl apply -f "$WORK/rbac.yaml" >/dev/null && PASS "RBAC applied (positive + negative SAs)" || DIE "RBAC apply failed"

kubectl create token kk-uat-mesh-reader -n "$NAMESPACE" --duration=2h > "$WORK/sa-token.txt" \
  && PASS "minted positive SA token" || DIE "kubectl create token (positive) failed"
SA_TOKEN="$(cat "$WORK/sa-token.txt")"
kubectl create token kk-uat-mesh-reader-neg -n "$NAMESPACE" --duration=2h > "$WORK/sa-token-neg.txt" \
  && PASS "minted negative SA token (no linkerd RBAC)" || DIE "kubectl create token (negative) failed"
NEG_SA_TOKEN="$(cat "$WORK/sa-token-neg.txt")"

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

# Empirical proof the RBAC split is real, direct against the API server
# (not through the hub) -- mirrors tests/live/k8s/run.sh's same-shaped
# check.
POS_LINKERD_CODE="$(curl -sS -o /dev/null -w '%{http_code}' --cacert "$WORK/cluster-ca.pem" -H "Authorization: Bearer $SA_TOKEN" "$APISERVER_URL/api/v1/namespaces/linkerd/secrets/linkerd-identity-issuer")"
NEG_LINKERD_CODE="$(curl -sS -o /dev/null -w '%{http_code}' --cacert "$WORK/cluster-ca.pem" -H "Authorization: Bearer $NEG_SA_TOKEN" "$APISERVER_URL/api/v1/namespaces/linkerd/secrets/linkerd-identity-issuer")"
if [ "$POS_LINKERD_CODE" = "200" ] && [ "$NEG_LINKERD_CODE" = "403" ]; then
  PASS "RBAC split confirmed directly against apiserver (positive=200, negative=403)"
else
  FAIL "RBAC split check: positive=$POS_LINKERD_CODE (want 200) negative=$NEG_LINKERD_CODE (want 403)"
fi

# ---------------------------------------------------------------------------
# 5. Independent ground truth: the Linkerd issuer cert's real fingerprint,
#    read directly with kubectl + openssl -- what the hub's answer must
#    match.
# ---------------------------------------------------------------------------
STEP "independent ground truth: linkerd issuer certificate"
kubectl get secret -n linkerd linkerd-identity-issuer -o jsonpath='{.data.crt\.pem}' | base64 -d > "$WORK/linkerd-issuer.crt" 2>/dev/null
WANT_LINKERD_FP="$(openssl x509 -in "$WORK/linkerd-issuer.crt" -noout -fingerprint -sha256 2>/dev/null | cut -d= -f2 | tr -d ':' | tr 'A-F' 'a-f')"
WANT_LINKERD_CN="$(openssl x509 -in "$WORK/linkerd-issuer.crt" -noout -subject -nameopt multiline 2>/dev/null | awk -F' = ' '/commonName/{print $2}')"
[ -n "$WANT_LINKERD_FP" ] && PASS "linkerd issuer fingerprint: $WANT_LINKERD_FP (CN=$WANT_LINKERD_CN)" || DIE "could not read linkerd issuer cert"

WANT_ISTIO_FP=""
if [ "$ISTIO_INSTALLED" = "1" ]; then
  kubectl get secret -n istio-system istio-ca-secret -o jsonpath='{.data.ca-cert\.pem}' 2>/dev/null | base64 -d > "$WORK/istio-ca.crt"
  if [ -s "$WORK/istio-ca.crt" ]; then
    WANT_ISTIO_FP="$(openssl x509 -in "$WORK/istio-ca.crt" -noout -fingerprint -sha256 2>/dev/null | cut -d= -f2 | tr -d ':' | tr 'A-F' 'a-f')"
    [ -n "$WANT_ISTIO_FP" ] && PASS "istio CA fingerprint: $WANT_ISTIO_FP" || FAIL "istio-ca-secret present but cert unparsable"
  else
    FAIL "istio installed but istio-system/istio-ca-secret has no ca-cert.pem (unexpected for this istioctl version, see $WORK/istio-install.log)"
    ISTIO_INSTALLED=0
  fi
fi

# ---------------------------------------------------------------------------
# 6. Build + start the hub with mesh discovery pointed at the real
#    cluster. APP_DISCOVERY_PROVIDER=db so /api/v1/discovery/endpoints
#    reads the SAME SQL store MeshDiscoveryScheduler.tick() writes to
#    (scanner-mode's provider is in-memory and would never see it).
#    KRYPTKEEPER_MESH_SWEEP_MINUTES=1 with no immediate first tick
#    (mesh_discovery_wiring.go's Start(): only ticker.C fires) -- so the
#    poll below is bounded at ~90s, not a few seconds.
#    KRYPTKEEPER_TLS_DISABLE=true: found live re-running this fixture on
#    2026-09-11 (W19-09/W19-22) -- W19-14/W19-05 (landed on main since this
#    fixture was written) made the hub self-issue a TLS listener cert by
#    default whenever APP_CERTIFICATE_PROVIDER=ca and no
#    KRYPTKEEPER_TLS_* var is set (cmd/kryptkeeper/tls.go's
#    resolveTLSMode), so every curlj/curl call below (plain http://)
#    against this fixture's hub now gets a raw-TLS-bytes-as-HTTP 400
#    instead of a real response. Fixture-only fix, not a hub defect: this
#    UAT's own assertions are about mesh discovery, not the listener's
#    TLS posture.
# ---------------------------------------------------------------------------
STEP "build + start hub (mesh discovery)"
rm -rf "$HUB_DIR"
mkdir -p "$HUB_DIR/data"
( cd "$REPO_ROOT" && go build -o "$HUB_DIR/kryptkeeper" ./cmd/kryptkeeper ) \
  && PASS "hub built" || DIE "go build failed"

export APP_BOOTSTRAP_TOKEN="$TOKEN" AUTH_MODE=bootstrap APP_CERTIFICATE_PROVIDER=ca \
  KRYPTKEEPER_TLS_DISABLE=true \
  APP_DISCOVERY_PROVIDER=db APP_NOTIFICATION_PROVIDER=file \
  APP_CREDENTIAL_STORE_PASSPHRASE='uat-mesh-cred-passphrase-32-byte' \
  KRYPTKEEPER_KEYSTORE_PASSPHRASE='uat-mesh-keystore-passphrase-32b' \
  KRYPTKEEPER_DATA_DIR="$HUB_DIR/data" \
  APP_CA_FILE="$HUB_DIR/data/cas.json" \
  APP_TEMPLATE_FILE="$HUB_DIR/data/templates.json" \
  APP_CERTIFICATE_FILE="$HUB_DIR/data/certificates.json" \
  APP_AUDIT_FILE="$HUB_DIR/data/audit.json" \
  APP_CERTS_SUMMARY_FILE="$HUB_DIR/data/certs_summary.json" \
  KRYPTKEEPER_BOOTSTRAP_CREATE_ROOT=true \
  KRYPTKEEPER_CA_NAME="UAT Root CA" \
  KRYPTKEEPER_MESH_K8S_URL="$APISERVER_URL" \
  KRYPTKEEPER_MESH_K8S_TOKEN="$SA_TOKEN" \
  KRYPTKEEPER_MESH_K8S_CA_CERT_FILE="$WORK/cluster-ca.pem" \
  KRYPTKEEPER_MESH_SWEEP_MINUTES=1 \
  APP_BIND_ADDR=127.0.0.1 PORT="$HUB_PORT"

"$HUB_DIR/kryptkeeper" >"$WORK/hub.log" 2>&1 &
HUB_PID=$!
tries=30
until curl -sS -f -o /dev/null "${HUB_BASE}/api/v1/cas" -H "Authorization: Bearer ${TOKEN}"; do
  tries=$((tries - 1)); [ $tries -le 0 ] && DIE "hub never answered a real /api/v1/cas 200, see $WORK/hub.log"
  sleep 1
done
PASS "hub answering on $HUB_BASE (mesh discovery configured against $APISERVER_URL)"

# ---------------------------------------------------------------------------
# 7. Bounded poll for the scheduler's first tick (up to ~100s: a 60s
#    sweep-minute floor doesn't apply since we set it to 1, but there is
#    still no immediate first tick, so budget the full minute plus margin
#    for the k8sGet round trips themselves).
# ---------------------------------------------------------------------------
STEP "wait for mesh discovery sweep + verify Linkerd issuer + trust anchor in inventory"
ENDPOINTS_RESP=""
tries=100
while [ $tries -gt 0 ]; do
  ENDPOINTS_RESP="$(curlj "${HUB_BASE}/api/v1/discovery/endpoints?limit=100")"
  echo "$ENDPOINTS_RESP" | grep -q "linkerd-mesh" && break
  tries=$((tries - 1)); sleep 1
done
echo "  endpoints response: $ENDPOINTS_RESP"

LINKERD_ENDPOINT_JSON="$(echo "$ENDPOINTS_RESP" | python3 -c '
import json, sys
data = json.load(sys.stdin)
for ep in data.get("data", {}).get("endpoints", []):
    if ep.get("protocol") == "linkerd-mesh":
        print(json.dumps(ep))
        break
' 2>/dev/null)"

if [ -n "$LINKERD_ENDPOINT_JSON" ]; then
  GOT_LINKERD_FP="$(echo "$LINKERD_ENDPOINT_JSON" | python3 -c '
import json, sys
ep = json.load(sys.stdin)
certs = ep.get("mapped_certs") or []
print(certs[0]["fingerprint"] if certs else "")
' 2>/dev/null | tr 'A-F' 'a-f')"
  if [ -n "$GOT_LINKERD_FP" ] && [ "$GOT_LINKERD_FP" = "$WANT_LINKERD_FP" ]; then
    PASS "hub inventory holds the Linkerd issuer cert with the correct fingerprint ($GOT_LINKERD_FP), source protocol=linkerd-mesh"
  else
    FAIL "Linkerd endpoint present but fingerprint mismatch: got=$GOT_LINKERD_FP want=$WANT_LINKERD_FP"
  fi
else
  FAIL "no linkerd-mesh endpoint appeared in /api/v1/discovery/endpoints within the poll window: $ENDPOINTS_RESP"
fi

if [ "$ISTIO_INSTALLED" = "1" ] && [ -n "$WANT_ISTIO_FP" ]; then
  ISTIO_ENDPOINT_JSON="$(echo "$ENDPOINTS_RESP" | python3 -c '
import json, sys
data = json.load(sys.stdin)
for ep in data.get("data", {}).get("endpoints", []):
    if ep.get("protocol") == "istio-mesh":
        print(json.dumps(ep))
        break
' 2>/dev/null)"
  if [ -n "$ISTIO_ENDPOINT_JSON" ]; then
    GOT_ISTIO_FP="$(echo "$ISTIO_ENDPOINT_JSON" | python3 -c '
import json, sys
ep = json.load(sys.stdin)
certs = ep.get("mapped_certs") or []
print(certs[0]["fingerprint"] if certs else "")
' 2>/dev/null | tr 'A-F' 'a-f')"
    if [ -n "$GOT_ISTIO_FP" ] && [ "$GOT_ISTIO_FP" = "$WANT_ISTIO_FP" ]; then
      PASS "hub inventory holds the Istio CA cert with the correct fingerprint ($GOT_ISTIO_FP), source protocol=istio-mesh"
    else
      FAIL "Istio endpoint present but fingerprint mismatch: got=$GOT_ISTIO_FP want=$WANT_ISTIO_FP"
    fi
  else
    FAIL "Istio installed but no istio-mesh endpoint appeared in inventory: $ENDPOINTS_RESP"
  fi
else
  echo "  (Istio not installed in this run -- best-effort, documented gap; see docs/STATUS.md)"
fi

# ---------------------------------------------------------------------------
# 8. Negative: point a second hub at the RBAC-restricted (no linkerd
#    access) token. The Linkerd probe must surface a clear permission
#    error -- servicemesh.go's k8sGet returns non-nil err with status 403
#    (not 404, which is treated as "mesh absent"), and
#    mesh_discovery_wiring.go's tick() logs
#    "sweep completed with N source error(s)" -- N must be nonzero, not a
#    silent empty result indistinguishable from "no mesh here".
# ---------------------------------------------------------------------------
STEP "negative: RBAC without linkerd namespace -> clear permission error, not silent empty result"
kill "$HUB_PID" 2>/dev/null; wait "$HUB_PID" 2>/dev/null; HUB_PID=""
NEG_HUB_DIR=/tmp/kk-uat-mesh-neg-hub
NEG_PORT=8098
rm -rf "$NEG_HUB_DIR"
mkdir -p "$NEG_HUB_DIR/data"
cp "$HUB_DIR/kryptkeeper" "$NEG_HUB_DIR/kryptkeeper" 2>/dev/null || ( cd "$REPO_ROOT" && go build -o "$NEG_HUB_DIR/kryptkeeper" ./cmd/kryptkeeper )

export APP_BOOTSTRAP_TOKEN="$TOKEN" AUTH_MODE=bootstrap APP_CERTIFICATE_PROVIDER=ca \
  KRYPTKEEPER_TLS_DISABLE=true \
  APP_DISCOVERY_PROVIDER=db APP_NOTIFICATION_PROVIDER=file \
  APP_CREDENTIAL_STORE_PASSPHRASE='uat-mesh-cred-passphrase-32-byte' \
  KRYPTKEEPER_KEYSTORE_PASSPHRASE='uat-mesh-keystore-passphrase-32b' \
  KRYPTKEEPER_DATA_DIR="$NEG_HUB_DIR/data" \
  APP_CA_FILE="$NEG_HUB_DIR/data/cas.json" \
  APP_TEMPLATE_FILE="$NEG_HUB_DIR/data/templates.json" \
  APP_CERTIFICATE_FILE="$NEG_HUB_DIR/data/certificates.json" \
  APP_AUDIT_FILE="$NEG_HUB_DIR/data/audit.json" \
  APP_CERTS_SUMMARY_FILE="$NEG_HUB_DIR/data/certs_summary.json" \
  KRYPTKEEPER_BOOTSTRAP_CREATE_ROOT=true \
  KRYPTKEEPER_CA_NAME="UAT Root CA" \
  KRYPTKEEPER_MESH_K8S_URL="$APISERVER_URL" \
  KRYPTKEEPER_MESH_K8S_TOKEN="$NEG_SA_TOKEN" \
  KRYPTKEEPER_MESH_K8S_CA_CERT_FILE="$WORK/cluster-ca.pem" \
  KRYPTKEEPER_MESH_SWEEP_MINUTES=1 \
  APP_BIND_ADDR=127.0.0.1 PORT="$NEG_PORT"

"$NEG_HUB_DIR/kryptkeeper" >"$WORK/neg-hub.log" 2>&1 &
HUB_PID=$!
tries=30
until curl -sS -f -o /dev/null "http://127.0.0.1:${NEG_PORT}/api/v1/cas" -H "Authorization: Bearer ${TOKEN}"; do
  tries=$((tries - 1)); [ $tries -le 0 ] && DIE "negative-case hub never answered"
  sleep 1
done

tries=100
while [ $tries -gt 0 ]; do
  grep -q "mesh discovery: sweep completed with" "$WORK/neg-hub.log" 2>/dev/null && break
  tries=$((tries - 1)); sleep 1
done
NEG_LOG_LINE="$(grep "mesh discovery: sweep completed with" "$WORK/neg-hub.log" 2>/dev/null | tail -1)"
NEG_ENDPOINTS_RESP="$(curl -sS -H "Authorization: Bearer ${TOKEN}" "http://127.0.0.1:${NEG_PORT}/api/v1/discovery/endpoints?limit=100")"
echo "  neg-hub log line: $NEG_LOG_LINE"
echo "  neg-hub endpoints: $NEG_ENDPOINTS_RESP"

NEG_LINKERD_ENDPOINT_JSON="$(echo "$NEG_ENDPOINTS_RESP" | python3 -c '
import json, sys
data = json.load(sys.stdin)
for ep in data.get("data", {}).get("endpoints", []):
    if ep.get("protocol") == "linkerd-mesh":
        print(json.dumps(ep))
        break
' 2>/dev/null)"

# W19-22 changed what "fail-closed" means here: a denied source is no
# longer either silently dropped OR fabricated with cert data -- it
# persists as a real endpoint row (visible via this same API a caller of
# the product uses) carrying a "discovery-error: ..." issue and, critically,
# NO mapped_certs (nothing was actually read). The bar this negative case
# proves is "a clear permission error, not a silent empty result, AND not
# a fabricated cert" -- checked directly against this response, not just
# the scheduler's log line.
if echo "$NEG_LOG_LINE" | grep -qE "sweep completed with [1-9][0-9]* source error"; then
  if [ -z "$NEG_LINKERD_ENDPOINT_JSON" ]; then
    FAIL "RBAC-denied sweep logged a source error but no linkerd-mesh endpoint (denial) is visible via GET /api/v1/discovery/endpoints: $NEG_ENDPOINTS_RESP"
  elif echo "$NEG_LINKERD_ENDPOINT_JSON" | python3 -c 'import json,sys; sys.exit(0 if json.load(sys.stdin).get("mapped_certs") else 1)' 2>/dev/null; then
    FAIL "RBAC-denied linkerd-mesh endpoint carries mapped_certs -- a denial must never be indistinguishable from a real read: $NEG_LINKERD_ENDPOINT_JSON"
  elif ! echo "$NEG_LINKERD_ENDPOINT_JSON" | grep -qi "403"; then
    FAIL "RBAC-denied linkerd-mesh endpoint has no issue text identifying the permission error: $NEG_LINKERD_ENDPOINT_JSON"
  else
    PASS "RBAC without linkerd namespace surfaces a clear, counted permission error via BOTH the scheduler log and GET /api/v1/discovery/endpoints (denied endpoint carries a 403 issue, no fabricated certs)"
  fi
else
  FAIL "no nonzero source-error count logged for the RBAC-denied sweep -- looks like a silent empty result, not a clear permission error: $WORK/neg-hub.log"
fi

STEP "result"
if [ "$FAILED" -eq 0 ]; then
  echo "ALL PASS"
  exit 0
else
  echo "ONE OR MORE STEPS FAILED (see FAIL lines above; hub logs kept in $WORK until cleanup)"
  exit 1
fi
