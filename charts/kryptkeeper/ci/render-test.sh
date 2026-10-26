#!/usr/bin/env bash
# Render assertions for the chart (W25-03 dashboard, W25-04 HA defaults).
# Exits non-zero on the first failure.
set -euo pipefail
cd "$(dirname "$0")/../../.."
CHART=charts/kryptkeeper
VALS=$CHART/ci/dashboard-values.yaml
# Without a secret source secret.yaml fails before anything under test renders.
SEC=(--set secrets.existingSecret=x)

pass() { echo "PASS $*"; }
fail() { echo "FAIL $*" >&2; exit 1; }
count() { grep -c -e "$1" || true; }

# expect_fail <stderr-substring> <helm template args...>
expect_fail() {
  local want=$1; shift
  local err
  if err=$(helm template t "$CHART" "$@" 2>&1 >/dev/null); then fail "render succeeded, expected failure: $*"; fi
  grep -q -- "$want" <<<"$err" || fail "stderr lacks '$want' for: $*"$'\n'"$err"
}

# --- W25-03 dashboard ---
helm lint "$CHART" -f "$VALS" >/dev/null || fail "lint with dashboard values"
helm lint "$CHART" "${SEC[@]}" >/dev/null || fail "default lint"
pass "helm lint (default and dashboard values)"

OUT=$(helm template t "$CHART" -f "$VALS")
for k in Deployment Service ConfigMap; do
  awk -v k="$k" '/^kind:/{kind=$2} /^  name: .*-dashboard$/ && kind==k {f=1} END{exit !f}' <<<"$OUT" \
    || fail "no $k named *-dashboard"
done
pass "dashboard Deployment, Service, ConfigMap rendered"

# Ingress: path "/" backend must be the dashboard service, "/acme" the hub.
ING=$(awk '/^kind: Ingress/{f=1} f' <<<"$OUT")
grep -A8 -- 'path: /$' <<<"$ING" | grep -q 'name: t-kryptkeeper-dashboard' || fail "ingress / does not route to dashboard"
grep -A8 -- 'path: /acme$' <<<"$ING" | grep -q 'name: t-kryptkeeper$' || fail "ingress /acme does not route to hub"
pass "ingress / -> dashboard, /acme -> hub"

# Acceptance 2: the proxy verifies the hub certificate in every location.
CM=$(awk '/^# Source: .*dashboard-configmap.yaml/{f=1;next} /^---/{f=0} f' <<<"$OUT")
[ "$(count 'proxy_ssl_verify on;' <<<"$CM")" = 3 ] || fail "proxy_ssl_verify on != 3"
[ "$(count 'proxy_ssl_verify off' <<<"$CM")" = 0 ] || fail "proxy_ssl_verify off present"
[ "$(count 'proxy_ssl_trusted_certificate /etc/kryptkeeper/tls/ca.pem;' <<<"$CM")" = 3 ] || fail "trusted_certificate != 3"
[ "$(count 'proxy_ssl_name t-kryptkeeper;' <<<"$CM")" = 3 ] || fail "proxy_ssl_name != 3"
pass "dashboard nginx verifies hub TLS (3x verify on, 0x verify off)"

expect_fail "dashboard.hubCA.existingSecret is required" "${SEC[@]}" --set dashboard.enabled=true
pass "dashboard without hubCA fails at render"

expect_fail "routes to the dashboard but dashboard.enabled=false" "${SEC[@]}" \
  --set ingress.enabled=true --set 'ingress.hosts[0].host=h' \
  --set 'ingress.hosts[0].paths[0].path=/' --set 'ingress.hosts[0].paths[0].pathType=Prefix' \
  --set 'ingress.hosts[0].paths[0].backend=dashboard'
pass "ingress dashboard path with dashboard disabled fails"

[ "$(helm template t "$CHART" "${SEC[@]}" | count '-dashboard')" = 0 ] || fail "dashboard objects rendered while disabled"
pass "dashboard disabled renders no -dashboard objects"

# Hub Service/PDB select on name+instance; dashboard pods must not match.
DSEL=$(awk '/^# Source: .*dashboard-service.yaml/{f=1} /^---/{f=0} f' <<<"$OUT" | grep -A3 '^  selector:')
grep -q 'app.kubernetes.io/name: kryptkeeper-dashboard' <<<"$DSEL" || fail "dashboard selector not disjoint from hub"
pass "dashboard pod labels disjoint from hub selector"

# --- W25-04 HA defaults ---
expect_fail "supports exactly one replica" "${SEC[@]}" --set config.dbMode=sqlite --set replicaCount=2
expect_fail "supports exactly one replica" "${SEC[@]}" --set config.dbMode=SQLite --set replicaCount=2
expect_fail "supports exactly one replica" "${SEC[@]}" --set config.dbMode=sqlite \
  --set autoscaling.enabled=true --set autoscaling.maxReplicas=3
pass "sqlite with >1 replica (fixed or autoscaled) fails"

S1=$(helm template t "$CHART" "${SEC[@]}" --set config.dbMode=sqlite --set replicaCount=1)
[ "$(count '^kind: PodDisruptionBudget' <<<"$S1")" = 0 ] || fail "PDB rendered for a single replica"
helm lint "$CHART" "${SEC[@]}" --set config.dbMode=sqlite --set replicaCount=1 >/dev/null || fail "sqlite lint"
pass "sqlite + 1 replica renders with no PDB"

D=$(helm template t "$CHART" "${SEC[@]}")
[ "$(count '^kind: PodDisruptionBudget' <<<"$D")" = 1 ] || fail "default PDB count != 1"
awk '/^kind: Deployment/{f=1} f && /replicas: 2$/{ok=1} END{exit !ok}' <<<"$D" || fail "default replicas != 2"
pass "default render: 1 PDB, replicas 2"

[ "$(grep -c 'until W6-01' $CHART/values.yaml || true)" = 0 ] || fail "stale W6-01 comment remains"
pass "W6-01 comment removed"
# --- W37-08 demo values ---
DEMO=charts/kryptkeeper/values-demo.yaml
helm lint "$CHART" -f "$DEMO" >/dev/null || fail "lint with demo values"
DO=$(helm template t "$CHART" -f "$DEMO")
[ "$(count '^kind: Job' <<<"$DO")" = 1 ] || fail "demo values should render exactly one Job"
grep -q 'helm.sh/hook": post-install' <<<"$DO" || fail "demo seed Job is not a post-install hook"
grep -q -- '- --hub=http://t-kryptkeeper:8080' <<<"$DO" || fail "demo seed Job does not target the hub Service"
grep -q 'KRYPTKEEPER_ENV: "trial"' <<<"$DO" || fail "demo values do not set KRYPTKEEPER_ENV"
[ "$(helm template t "$CHART" "${SEC[@]}" | count '^kind: Job')" = 0 ] || fail "Job rendered while demo is disabled"
expect_fail "demo.enabled requires tls.enabled=false" -f "$DEMO" --set tls.enabled=true
expect_fail "cannot be combined with config.environment=production" -f "$DEMO" --set config.environment=production
pass "demo values: seed Job renders, refuses TLS and production"
echo "ALL PASS"
