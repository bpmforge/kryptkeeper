#!/usr/bin/env bash
# W25-19: run scripts/deploy/by-digest.sh (the script both promote and rollback
# workflows call) against a kind cluster: deploy digest A, promote B, roll back
# to A, smoke.sh after each. Digests come from two real hub builds pushed to a
# local registry, or from DIGEST_A / DIGEST_B (repo@sha256 form in REPO_OVERRIDE).
. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/../lib/podman.sh"
set -u
set -o pipefail
export KIND_EXPERIMENTAL_PROVIDER=podman

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$HERE/../../.." && pwd)"
# physical path: /tmp is a symlink the podman VM does not mount
WORK="$(cd "$(mktemp -d /tmp/kk-promote.XXXXXX)" && pwd -P)"
CLUSTER=kk-promote
NS=kk-staging
REL=kryptkeeper
NODE="${CLUSTER}-control-plane"
REGISTRY=kk-promote-registry
REG_HOST=localhost:5001
IMG_REPO="$REG_HOST/kryptkeeper"
FWD_PORT=18444

FAILED=0
STEP() { echo; echo "== $* =="; }
PASS() { echo "PASS: $*"; }
FAIL() { echo "FAIL: $*"; FAILED=1; }
cleanup() {
  STEP "cleanup"
  [ -n "${FWD_PID:-}" ] && kill "$FWD_PID" 2>/dev/null
  kind delete cluster --name "$CLUSTER" >/dev/null 2>&1 || true
  kk_rm "$REGISTRY"
  rm -rf "$WORK"
}
DIE() { echo "FAIL: $*"; trap - EXIT; cleanup; exit 1; }
trap cleanup EXIT

for c in kind kubectl helm podman curl openssl; do
  command -v "$c" >/dev/null || DIE "missing prerequisite: $c (this script installs nothing)"
done
podman info >/dev/null 2>&1 || DIE "podman is not reachable (start the podman machine)"
grep -n digest "$REPO/charts/kryptkeeper/values.yaml" | head -2
grep -q '^  digest:' "$REPO/charts/kryptkeeper/values.yaml" || DIE "chart has no image.digest value"

STEP "1. Registry and two hub builds (digest A older, B newer)"
kk_rm "$REGISTRY"
# Start the registry ON the kind network. Rootless podman (4.x) gives a container
# started with a bare -p the slirp4netns mode, which "podman network connect"
# refuses afterwards, so the attach must happen at run time. kind reuses an
# existing "kind" network, so create it first when kind has not yet.
podman network exists kind || podman network create kind >/dev/null || DIE "cannot create the kind network"
podman run -d --name "$REGISTRY" --network kind -p 127.0.0.1:5001:5000 docker.io/library/registry:2 >/dev/null || DIE "registry start failed"
for _ in $(seq 1 20); do curl -fsS "http://$REG_HOST/v2/" >/dev/null 2>&1 && break; sleep 1; done
build_push() { # version -> digest on stdout
  podman build -q --build-arg VERSION="$1" -t "localhost/kryptkeeper-promote:$1" "$REPO" >/dev/null || return 1
  podman push --tls-verify=false --digestfile "$WORK/digest-$1" "localhost/kryptkeeper-promote:$1" "docker://$IMG_REPO:$1" >/dev/null 2>&1 || return 1
  cat "$WORK/digest-$1"
}
if [ -n "${DIGEST_A:-}" ] && [ -n "${DIGEST_B:-}" ]; then
  : "${REPO_OVERRIDE:?DIGEST_A/DIGEST_B need REPO_OVERRIDE=<image repo> they live in}"
  IMG_REPO="$REPO_OVERRIDE"; A="$DIGEST_A"; B="$DIGEST_B"
else
  A="$(build_push 0.0.1-promote-a)" || DIE "build/push A failed"
  B="$(build_push 0.0.2-promote-b)" || DIE "build/push B failed"
fi
echo "A=$A"; echo "B=$B"
[[ "$A" =~ ^sha256:[a-f0-9]{64}$ && "$B" =~ ^sha256:[a-f0-9]{64}$ && "$A" != "$B" ]] \
  && PASS "two distinct digests: A=${A:0:19}... B=${B:0:19}..." || DIE "digests invalid or identical"

STEP "2. kind cluster wired to the registry"
kind delete cluster --name "$CLUSTER" >/dev/null 2>&1 || true
# node boot is occasionally too slow when the podman VM is busy; retry once or twice
KIND_OK=0
for _ in 1 2 3; do
  kind delete cluster --name "$CLUSTER" >/dev/null 2>&1 || true
  kind create cluster --name "$CLUSTER" --config "$HERE/kind-config.yaml" --kubeconfig "$WORK/kubeconfig" >"$WORK/kind.log" 2>&1 && { KIND_OK=1; break; }
done
if [ "$KIND_OK" = 1 ]; then PASS "kind cluster $CLUSTER up"; else tail "$WORK/kind.log"; DIE "kind create failed"; fi
export KUBECONFIG="$WORK/kubeconfig"
REG_IP="$(podman inspect "$REGISTRY" --format '{{(index .NetworkSettings.Networks "kind").IPAddress}}')"
podman exec "$NODE" mkdir -p "/etc/containerd/certs.d/$REG_HOST" || DIE "certs.d mkdir"
printf 'server = "http://%s:5000"\n[host."http://%s:5000"]\n  capabilities = ["pull", "resolve"]\n' "$REG_IP" "$REG_IP" \
  | podman exec -i "$NODE" tee "/etc/containerd/certs.d/$REG_HOST/hosts.toml" >/dev/null || DIE "hosts.toml"
kubectl wait --for=condition=Ready node --all --timeout=120s >/dev/null || DIE "node not ready"
kubectl create namespace "$NS" >/dev/null || DIE "namespace"

# First-install values (sqlite: the Postgres-free mode that starts in kind). The
# release keeps them across every later by-digest.sh run via reset-then-reuse.
cat > "$WORK/values.yaml" <<YAML
replicaCount: 1
config:
  dbMode: sqlite
  trustedProxyCIDRs: ""
secrets:
  bootstrapToken: "$(openssl rand -hex 20)"
  keystorePassphrase: "$(openssl rand -hex 32)"
extraEnv:
  - {name: KRYPTKEEPER_BOOTSTRAP_CREATE_ROOT, value: "true"}
YAML
deploy() { # digest
  RELEASE="$REL" NAMESPACE="$NS" DEPLOY_METHOD=helm CHART_DIR="$REPO/charts/kryptkeeper" HELM_VALUES_FILE="$WORK/values.yaml" \
    bash "$REPO/scripts/deploy/by-digest.sh" staging "$IMG_REPO@$1"
}
smoke() { # label
  [ -n "${FWD_PID:-}" ] && kill "$FWD_PID" 2>/dev/null
  kubectl -n "$NS" port-forward "svc/$REL" "$FWD_PORT:8080" >"$WORK/fwd.log" 2>&1 & FWD_PID=$!
  sleep 3
  KRYPTKEEPER_SMOKE_BASE_URL="https://127.0.0.1:$FWD_PORT" bash "$REPO/scripts/deploy/smoke.sh" staging >"$WORK/smoke-$1.log" 2>&1
  local rc=$?
  cat "$WORK/smoke-$1.log"
  return $rc
}
running_image_id() {
  # helm --wait returns once the new pod is Ready; the old one may still be
  # terminating, so wait until exactly one pod is left before reading its image.
  local _
  for _ in $(seq 1 60); do
    [ "$(kubectl -n "$NS" get pod -l "app.kubernetes.io/instance=$REL" --no-headers 2>/dev/null | wc -l | tr -d ' ')" = 1 ] && break
    sleep 2
  done
  kubectl -n "$NS" get pod -l "app.kubernetes.io/instance=$REL" \
    -o jsonpath='{.items[?(@.status.phase=="Running")].status.containerStatuses[0].imageID}'
}

STEP "3. Baseline: deploy A"
if deploy "$A" >"$WORK/deploy-A.log" 2>&1; then PASS "by-digest.sh deployed A"; else cat "$WORK/deploy-A.log"; kubectl -n "$NS" get pods; DIE "deploy A failed"; fi
if smoke baseline; then PASS "baseline_smoke_green"; else FAIL "baseline_smoke_green"; fi

STEP "4. Promote B"
if deploy "$B" >"$WORK/deploy-B.log" 2>&1; then PASS "by-digest.sh deployed B"; else cat "$WORK/deploy-B.log"; kubectl -n "$NS" get pods; DIE "deploy B failed"; fi
ID="$(running_image_id)"; echo "running imageID: $ID"
case "$ID" in *"$B") PASS "running pod imageID ends with B" ;; *) FAIL "running pod imageID '$ID' does not end with B" ;; esac
if smoke promote; then PASS "promote_B_smoke_green"; else FAIL "promote_B_smoke_green"; fi

STEP "5. Roll back to A"
if deploy "$A" >"$WORK/deploy-A2.log" 2>&1; then PASS "by-digest.sh rolled back to A"; else cat "$WORK/deploy-A2.log"; kubectl -n "$NS" get pods; DIE "rollback to A failed"; fi
ID="$(running_image_id)"; echo "running imageID: $ID"
case "$ID" in *"$A") PASS "running pod imageID ends with A" ;; *) FAIL "running pod imageID '$ID' does not end with A" ;; esac
if smoke rollback; then PASS "rollback_A_smoke_green"; else FAIL "rollback_A_smoke_green"; fi

STEP "6. Zero smoke failures"
N="$(cat "$WORK"/smoke-*.log | grep -c '\[smoke\] FAIL')"
[ "$N" = 0 ] && PASS "zero_smoke_failures: [smoke] FAIL appears $N times across 3 runs" || FAIL "zero_smoke_failures: $N"

STEP "7. Negative: digest format guard"
RELEASE="$REL" NAMESPACE="$NS" bash "$REPO/scripts/deploy/by-digest.sh" staging repo:latest >/dev/null 2>&1
RC=$?
[ "$RC" = 2 ] && PASS "bad_digest_rejected: exit 2" || FAIL "bad_digest_rejected: exit $RC"

echo
[ "$FAILED" = 0 ] && echo "ALL PASS (0 FAIL)" || { echo "SOME FAILED"; exit 1; }
