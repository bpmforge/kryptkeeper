#!/usr/bin/env bash
# W30-23: zero-5xx rolling upgrade of a 2-replica hub under 50 rps for 10 min,
# on a throwaway kind cluster (podman provider). The PREVIOUS release image is
# installed first, the CURRENT tree is rolled in 60 s into the load.
#
#   bash tests/live/k8s/rolling-upgrade.sh [--record] [--prev-ref REF] [--duration SECONDS] [--upgrade-at SECONDS]
#
#   --record      append a row to docs/ops/DR_DRILL_RESULTS.md (review the diff)
#   --prev-ref    git ref of the previous release (default: latest tag, `git describe --tags --abbrev=0`)
#   --duration    load length in seconds (default 600)
#   --upgrade-at  seconds into the load when `helm upgrade` runs (default 60)
#
# Needs: kind helm kubectl podman go openssl python3 git curl. The load generator is
# vegeta (pinned below), cross-compiled for linux with `go install` and run from
# an in-cluster pod: a kubectl port-forward pins ONE pod and would hide the roll.
# Offline hosts: pre-populate the Go module cache (`go install` of the pin once).
#
# Assertions (none weakened): 0 responses in 5xx, 0 transport errors, both pods
# Ready on the new image, 0 duplicate scheduler actions since the load started.
# If the new tree carries a migration the previous image cannot run against, the
# 5xx check fails and that IS the finding; both migration tails are printed.
# shellcheck disable=SC2012,SC2015  # ls|tail for display; A && PASS || FAIL is the harness idiom
set -u
set -o pipefail

export KIND_EXPERIMENTAL_PROVIDER=podman
VEGETA_VERSION="v12.12.0"

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$HERE/../../.." && pwd)"
RESULTS="$REPO_ROOT/docs/ops/DR_DRILL_RESULTS.md"
CLUSTER=kk-upgrade
NS=kk
REL=kk
SVC=kk-kryptkeeper
RATE=50
RECORD=0; PREV_REF=""; DURATION=600; UPGRADE_AT=60
while [ $# -gt 0 ]; do
  case "$1" in
    --record) RECORD=1 ;;
    --prev-ref) PREV_REF="${2:?--prev-ref needs a value}"; shift ;;
    --duration) DURATION="${2:?--duration needs a value}"; shift ;;
    --upgrade-at) UPGRADE_AT="${2:?--upgrade-at needs a value}"; shift ;;
    *) echo "usage: rolling-upgrade.sh [--record] [--prev-ref REF] [--duration N] [--upgrade-at N]"; exit 2 ;;
  esac
  shift
done

FAILED=0
STEP() { echo; echo "== $* =="; }
PASS() { echo "PASS: $*"; }
FAIL() { echo "FAIL: $*"; FAILED=1; }
WORK="$(mktemp -d "$HOME/.kk-upgrade.XXXXXX")"
LOAD_PID=""
cleanup() {
  STEP "cleanup"
  [ -n "$LOAD_PID" ] && kill "$LOAD_PID" 2>/dev/null || true
  if [ "${KEEP_CLUSTER:-0}" = "1" ]; then echo "KEEP_CLUSTER=1: leaving cluster $CLUSTER and $WORK"; return; fi
  kind delete cluster --name "$CLUSTER" >/dev/null 2>&1 || true
  git -C "$REPO_ROOT" worktree remove --force "$WORK/prev" >/dev/null 2>&1 || true
  podman rmi -f "localhost/kryptkeeper:$PREV_TAG" "localhost/kryptkeeper:$NEW_TAG" >/dev/null 2>&1 || true
  rm -rf "$WORK"
}
PREV_TAG="upg-prev"; NEW_TAG="upg-new"
trap cleanup EXIT
DIE() { echo "FAIL: $*"; exit 1; }

for t in kind helm kubectl podman go openssl python3 git curl; do
  command -v "$t" >/dev/null 2>&1 || DIE "$t not found (macOS: brew install kind helm kubernetes-cli podman go)"
done
case "$(uname -m)" in arm64|aarch64) GOARCH=arm64 ;; *) GOARCH=amd64 ;; esac

STEP "vegeta $VEGETA_VERSION (linux/$GOARCH, built for the in-cluster load pod)"
mkdir -p "$WORK/bin"
GOBIN="$WORK/bin" GOOS=linux GOARCH="$GOARCH" CGO_ENABLED=0 go install "github.com/tsenart/vegeta/v12@$VEGETA_VERSION" >"$WORK/vegeta.log" 2>&1 \
  || { tail -5 "$WORK/vegeta.log"; DIE "cannot build vegeta; install hint: GOOS=linux GOARCH=$GOARCH go install github.com/tsenart/vegeta/v12@$VEGETA_VERSION (needs module access or a warm module cache)"; }
[ -x "$WORK/bin/vegeta" ] || DIE "vegeta binary missing after go install (expected $WORK/bin/vegeta)"
PASS "vegeta built"

STEP "previous release and current tree images"
[ -n "$PREV_REF" ] || PREV_REF="$(git -C "$REPO_ROOT" describe --tags --abbrev=0)"
NEW_SHA="$(git -C "$REPO_ROOT" rev-parse --short HEAD)"
git -C "$REPO_ROOT" worktree add --detach "$WORK/prev" "$PREV_REF" >/dev/null 2>&1 || DIE "git worktree add $PREV_REF failed"
PREV_SHA="$(git -C "$WORK/prev" rev-parse --short HEAD)"
podman build -t "localhost/kryptkeeper:$PREV_TAG" --build-arg VERSION="$PREV_REF" --build-arg COMMIT="$PREV_SHA" "$WORK/prev" >"$WORK/build-prev.log" 2>&1 \
  || { tail -20 "$WORK/build-prev.log"; DIE "previous image build failed"; }
podman build -t "localhost/kryptkeeper:$NEW_TAG" --build-arg VERSION="upg-$NEW_SHA" --build-arg COMMIT="$NEW_SHA" "$REPO_ROOT" >"$WORK/build-new.log" 2>&1 \
  || { tail -20 "$WORK/build-new.log"; DIE "current image build failed"; }
PASS "built prev=$PREV_REF ($PREV_SHA) new=$NEW_SHA"
echo "migrations, previous tree ($PREV_REF):"; ls "$WORK/prev/internal/db/migrations/postgres" | tail -4
echo "migrations, current tree ($NEW_SHA):";   ls "$REPO_ROOT/internal/db/migrations/postgres" | tail -4

STEP "kind cluster, images, BYO Postgres"
kind delete cluster --name "$CLUSTER" >/dev/null 2>&1 || true
kind create cluster --name "$CLUSTER" --wait 120s >"$WORK/kind.log" 2>&1 || { tail -20 "$WORK/kind.log"; DIE "kind create cluster failed"; }
for img in "localhost/kryptkeeper:$PREV_TAG" "localhost/kryptkeeper:$NEW_TAG" docker.io/library/postgres:16-alpine docker.io/library/alpine:3.20; do
  f="$WORK/$(echo "$img" | tr '/:' '__').tar"
  podman save -o "$f" "$img" >/dev/null 2>&1 && kind load image-archive "$f" --name "$CLUSTER" >/dev/null 2>&1 \
    || DIE "could not load $img into kind (must exist locally; no registry pulls)"
done
KC="kubectl --context kind-$CLUSTER"
PGPW="$(openssl rand -hex 16)"; TOKEN="$(openssl rand -hex 16)"; PASSPHRASE="$(openssl rand -hex 16)"
$KC create namespace $NS >/dev/null
$KC -n $NS create secret generic kk-pg --from-literal=password="$PGPW" >/dev/null
$KC apply -f "$REPO_ROOT/tests/live/helm-kind/postgres.yaml" >/dev/null || DIE "postgres apply failed"
$KC -n $NS rollout status deploy/kk-pg --timeout=180s >/dev/null && PASS "postgres Ready" || DIE "postgres never Ready"

HELM_COMMON=(--kube-context "kind-$CLUSTER" -n "$NS"
  --set image.repository=localhost/kryptkeeper --set image.pullPolicy=Never
  --set config.dbMode=postgres
  --set "secrets.databaseURL=postgres://kryptkeeper:${PGPW}@kk-pg:5432/kryptkeeper?sslmode=disable"
  --set secrets.bootstrapToken="$TOKEN" --set secrets.keystorePassphrase="$PASSPHRASE"
  --wait --timeout 5m)

STEP "install previous release at replicaCount=1 (create root once), then scale to 2"
helm install $REL "$REPO_ROOT/charts/kryptkeeper" "${HELM_COMMON[@]}" --set image.tag="$PREV_TAG" --set replicaCount=1 \
  --set 'extraEnv[0].name=KRYPTKEEPER_BOOTSTRAP_CREATE_ROOT' --set-string 'extraEnv[0].value=true' >"$WORK/install.log" 2>&1 \
  || { tail -20 "$WORK/install.log"; DIE "install failed"; }
helm upgrade $REL "$REPO_ROOT/charts/kryptkeeper" "${HELM_COMMON[@]}" --set image.tag="$PREV_TAG" --set replicaCount=2 >"$WORK/scale.log" 2>&1 \
  || { tail -20 "$WORK/scale.log"; DIE "scale to 2 failed"; }
PASS "2 replicas on $PREV_REF"

STEP "in-cluster load pod"
$KC -n $NS apply -f - >/dev/null <<YAML
apiVersion: v1
kind: Pod
metadata: {name: loadgen}
spec:
  containers:
    - name: load
      image: docker.io/library/alpine:3.20
      imagePullPolicy: Never
      command: ["sleep", "3600"]
YAML
$KC -n $NS wait --for=condition=Ready pod/loadgen --timeout=90s >/dev/null || DIE "loadgen never Ready"
$KC -n $NS cp "$WORK/bin/vegeta" loadgen:/usr/local/bin/vegeta || DIE "kubectl cp vegeta failed"
$KC -n $NS exec loadgen -- chmod +x /usr/local/bin/vegeta
# Authenticated list, never /readyz: it exercises the DB path through the Service.
$KC -n $NS exec loadgen -- sh -c "printf 'GET https://$SVC:8080/api/v1/certificates?limit=25\nAuthorization: Bearer $TOKEN\n' > /tmp/targets.txt"
CODE="$($KC -n $NS exec loadgen -- sh -c "vegeta attack -targets=/tmp/targets.txt -insecure -rate=1 -duration=1s | vegeta report -type=json" | python3 -c 'import json,sys; print(list(json.load(sys.stdin)["status_codes"]))')"
echo "smoke request status codes: $CODE"
case "$CODE" in *"'200'"*) PASS "authenticated list answers 200 through the Service" ;; *) DIE "smoke request did not return 200: $CODE" ;; esac

STEP "load: ${RATE} rps for ${DURATION}s, helm upgrade at +${UPGRADE_AT}s"
T_START="$(date -u +'%Y-%m-%d %H:%M:%S+00')"
$KC -n $NS exec loadgen -- sh -c "vegeta attack -targets=/tmp/targets.txt -insecure -rate=$RATE -duration=${DURATION}s -max-workers=200 | tee /tmp/results.bin | vegeta report -type=json > /tmp/report.json" >"$WORK/load.log" 2>&1 &
LOAD_PID=$!
sleep "$UPGRADE_AT"
echo "helm upgrade to $NEW_SHA at $(date -u +%H:%M:%S)"
helm upgrade $REL "$REPO_ROOT/charts/kryptkeeper" "${HELM_COMMON[@]}" --set image.tag="$NEW_TAG" --set replicaCount=2 >"$WORK/upgrade.log" 2>&1 \
  && PASS "helm upgrade --wait completed" || { tail -20 "$WORK/upgrade.log"; $KC -n $NS get pods; FAIL "helm upgrade failed or timed out"; }
wait "$LOAD_PID"; LOAD_PID=""

STEP "assertions"
$KC -n $NS exec loadgen -- cat /tmp/report.json >"$WORK/report.json" 2>/dev/null || DIE "no vegeta report produced (see $WORK/load.log)"
python3 - "$WORK/report.json" <<'PY' >"$WORK/summary.txt"
import json, sys
r = json.load(open(sys.argv[1]))
codes = r.get("status_codes", {})
n5 = sum(v for k, v in codes.items() if k.startswith("5"))
print("requests=%d" % r["requests"])
print("codes=%s" % json.dumps(codes, sort_keys=True))
print("fivexx=%d" % n5)
print("errors=%d" % len(r.get("errors") or []))
print("errset=%s" % json.dumps((r.get("errors") or [])[:5]))
print("success=%.4f" % r.get("success", 0))
PY
cat "$WORK/summary.txt"
REQS="$(sed -n 's/^requests=//p' "$WORK/summary.txt")"; N5XX="$(sed -n 's/^fivexx=//p' "$WORK/summary.txt")"; NERR="$(sed -n 's/^errors=//p' "$WORK/summary.txt")"
if [ "${N5XX:-1}" = 0 ]; then PASS "0 responses in 5xx"; else FAIL "$N5XX responses in 5xx"; fi
if [ "${NERR:-1}" = 0 ]; then PASS "0 transport errors"; else FAIL "$NERR distinct transport errors"; fi

READY="$($KC -n $NS get deploy $SVC -o jsonpath='{.status.readyReplicas}')"
IMGS="$($KC -n $NS get pods -l app.kubernetes.io/instance=$REL,app.kubernetes.io/name=kryptkeeper -o go-template='{{range .items}}{{if not .metadata.deletionTimestamp}}{{(index .spec.containers 0).image}}{{"\n"}}{{end}}{{end}}')"
if [ "$READY" = 2 ] && [ "$(echo "$IMGS" | grep -c "kryptkeeper:$NEW_TAG")" = 2 ]; then PASS "both pods Ready on the new image"; else FAIL "readyReplicas=$READY images: $(echo "$IMGS" | tr '\n' ' ')"; fi

PSQL() { $KC -n $NS exec deploy/kk-pg -- env PGPASSWORD="$PGPW" psql -U kryptkeeper -d kryptkeeper -tAc "$1"; }
DUPS="$(PSQL "SELECT resource_id||' '||action||' x'||count(*) FROM audit_log WHERE action IN ('certificate.renew_execute','renewal_notification_sent') AND timestamp > '$T_START' GROUP BY resource_id, action HAVING count(*) > 1")"
if [ -z "$DUPS" ]; then NDUP=0; PASS "0 duplicate scheduler actions since $T_START"; else NDUP="$(echo "$DUPS" | grep -c .)"; FAIL "duplicate scheduler actions: $DUPS"; fi

VERDICT=PASS; [ "$FAILED" = 0 ] || VERDICT=FAIL
echo; echo "ROLLING UPGRADE: $RATE rps, ${DURATION}s, requests=$REQS, 5xx=$N5XX, duplicates=$NDUP -> $VERDICT"
if [ "$RECORD" = 1 ]; then
  ROW="| $(date -u +%Y-%m-%d) | $NEW_SHA | $PREV_REF -> $NEW_SHA | $RATE | ${DURATION}s | $REQS | $N5XX | $NDUP | $VERDICT |"
  python3 - "$RESULTS" "$ROW" <<'PY'
import sys
path, row = sys.argv[1], sys.argv[2]
out, done = [], False
for l in open(path).read().split("\n"):
    if l.strip() == "<!-- UPGRADE-RESULTS-ROWS -->" and not done:
        out.append(row); done = True
    out.append(l)
if not done:
    sys.exit("marker not found in " + path)
open(path, "w").write("\n".join(out))
PY
  echo "row appended to $RESULTS (review the diff)"
fi
[ "$VERDICT" = PASS ] && exit 0 || exit 1
