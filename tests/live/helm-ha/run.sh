#!/usr/bin/env bash
# W25-05: install the real chart on kind with 2 hub replicas + Postgres, kill
# the scheduler lease holder (graceful and hard), drain the worker against the
# PDB, and check the Prometheus ServiceMonitor target. Real output only.
#
# The "30 s lease TTL" in the board acceptance does not exist: TryAcquire floors
# leases at 1 min (internal/bootstrap/ha_coordinator.go) and the scheduler asks
# for 2*poll. This harness asserts the realistic bounds and records the measured
# numbers; it never edits the lease constants.
set -u
set -o pipefail
export KIND_EXPERIMENTAL_PROVIDER=podman

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$HERE/../../.." && pwd)"
WORK="$(mktemp -d /tmp/kk-helm-ha.XXXXXX)"
CLUSTER=kk-helm-ha
REL=kk
FULL=kk-kryptkeeper
HUB_IMAGE=localhost/kryptkeeper:uat
KPS_VERSION=92.8.0
POLL_MIN=1
LEASE_S=$((2 * POLL_MIN * 60))
GRACEFUL_BOUND=$((POLL_MIN * 60 + 15))
HARD_BOUND=$((2 * POLL_MIN * 60 + POLL_MIN * 60 + 15))
FWD_PORT=21443
PROM_PORT=21090
POD_PORT_A=21444
POD_PORT_B=21445
N_CERTS=5

FAILED=0
STEP() { echo; echo "== $* =="; }
PASS() { echo "PASS: $*"; }
FAIL() { echo "FAIL: $*"; FAILED=1; }
NOTE() { echo "NOTE: $*"; }
cleanup() {
  STEP "cleanup"
  [ -n "${FWD_PID:-}" ] && kill "$FWD_PID" 2>/dev/null
  [ -n "${PROM_PID:-}" ] && kill "$PROM_PID" 2>/dev/null
  [ -n "${SAMPLER_PID:-}" ] && kill "$SAMPLER_PID" 2>/dev/null
  [ -n "${PODFWD_PID:-}" ] && kill "$PODFWD_PID" 2>/dev/null
  if [ "${KEEP_CLUSTER:-0}" != 1 ]; then
    kind delete cluster --name "$CLUSTER" >/dev/null 2>&1 || true
  fi
  rm -rf "$WORK"
}
DIE() { echo "FAIL: $*"; cleanup; exit 1; }
trap cleanup EXIT

for c in kind helm kubectl podman python3 openssl curl; do
  command -v "$c" >/dev/null || DIE "missing prerequisite: $c"
done

TOKEN="$(openssl rand -hex 16)"
PASSPHRASE="$(openssl rand -hex 16)"
PGPASS="$(openssl rand -hex 16)"
now() { python3 -c 'import time;print(int(time.time()))'; }
jq_py() { python3 -c "import json,sys
d=json.load(sys.stdin)
for k in sys.argv[1].split('.'):
    d=d[int(k)] if k.isdigit() else d.get(k) if isinstance(d,dict) else None
    if d is None: break
print('' if d is None else d)" "$1" 2>/dev/null; }
pg() { kubectl exec deploy/kk-pg -- psql -U kk -d kk -Atc "$1"; }
holder() { pg "select holder_id||'|'||(lease_expires_at::timestamptz > now())::text from ha_scheduler_locks where lock_name='renewal-scheduler'" 2>/dev/null; }
ready_count() { kubectl get pods -l app.kubernetes.io/name=kryptkeeper,app.kubernetes.io/instance=$REL \
  -o jsonpath='{range .items[*]}{.status.conditions[?(@.type=="Ready")].status}{"\n"}{end}' 2>/dev/null | grep -c True; }
# In-cluster prober: the hub CA is mounted, so every request verifies the hub's
# certificate against the Service name (no -k anywhere).
probe() { kubectl exec kk-probe -- curl -sS --max-time 5 --cacert /ca/ca.pem "$@"; }
hubapi() { local p="$1"; shift; probe -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' "https://$FULL:8080$p" "$@"; }

# A private kubeconfig: other tools on a shared workstation rewrite
# ~/.kube/config (kind create/delete) and silently drop the current context.
use_private_kubeconfig() {
  kind export kubeconfig --name "$CLUSTER" --kubeconfig "$WORK/kubeconfig" >/dev/null 2>&1 || return 1
  export KUBECONFIG="$WORK/kubeconfig"
}
if [ "${REUSE_CLUSTER:-0}" = 1 ]; then
  use_private_kubeconfig || DIE "REUSE_CLUSTER=1 but cluster $CLUSTER does not exist"
  # Dev loop only: keep cluster, Postgres, Prometheus; reset the hub release and DB.
  helm uninstall "$REL" >/dev/null 2>&1; kubectl delete pvc ${FULL}-keys lab-hub-ca --ignore-not-found >/dev/null 2>&1
  kubectl delete secret lab-hub-ca kk-pg --ignore-not-found >/dev/null; kubectl delete pod kk-probe kk-ca-reader kk-sink --ignore-not-found >/dev/null
  kubectl delete deploy kk-pg --ignore-not-found >/dev/null
  SKIP_BUILD=1
fi
STEP "1. kind cluster and images"
if [ "${SKIP_BUILD:-0}" = 1 ]; then NOTE "REUSE_CLUSTER=1: skipping cluster and image build"; else
kind delete cluster --name "$CLUSTER" >/dev/null 2>&1 || true
kind create cluster --name "$CLUSTER" --config "$HERE/kind-config.yaml" >/dev/null 2>&1 \
  && PASS "kind cluster $CLUSTER up (2 nodes, podman provider)" || DIE "kind create cluster failed"
use_private_kubeconfig || DIE "kubeconfig export failed"
podman build -q -t "$HUB_IMAGE" "$REPO" >/dev/null || DIE "hub image build failed"
podman save "$HUB_IMAGE" -o "$WORK/hub.tar" && kind load image-archive "$WORK/hub.tar" --name "$CLUSTER" >/dev/null 2>&1 \
  && PASS "hub image built from this tree and loaded (never pulled from GHCR)" || DIE "kind load failed"
fi

STEP "2. Postgres, sink, Prometheus"
kubectl create secret generic kk-pg --from-literal=password="$PGPASS" >/dev/null || DIE "pg secret"
kubectl apply -f "$HERE/postgres.yaml" >/dev/null || DIE "postgres apply"
kubectl rollout status deploy/kk-pg --timeout=180s >/dev/null || DIE "postgres not ready"
# Connection sampler: count(*) FROM pg_stat_activity every 3 s for the whole
# run (the sampler's own session is included in every sample). "client" is the
# subset that counts against max_connections (backend_type='client backend').
# psql can refuse connections for a moment after the rollout reports ready.
MAXCONN=""
for _ in $(seq 1 20); do
  MAXCONN="$(pg 'show max_connections' 2>/dev/null | tr -d '[:space:]')"
  case "$MAXCONN" in ''|*[!0-9]*) MAXCONN=""; sleep 3 ;; *) break ;; esac
done
[ -n "$MAXCONN" ] || DIE "could not read postgres max_connections after 20 tries"
echo "  postgres max_connections=$MAXCONN (default 100 expected)"
( while :; do
    r="$(kubectl exec deploy/kk-pg -- psql -U kk -d kk -Atc "select count(*)||' '||count(*) filter (where backend_type='client backend') from pg_stat_activity" 2>/dev/null)"
    [ -n "$r" ] && echo "$(date +%s) $r" >> "$WORK/conn.log"; sleep 3
  done ) & SAMPLER_PID=$!
# Webhook sink: logs one line per request body so duplicate pages are countable.
kubectl apply -f - >/dev/null <<'YAML' || DIE "sink apply"
apiVersion: v1
kind: ConfigMap
metadata: {name: kk-sink-src}
data:
  sink.py: |
    import http.server, sys
    class H(http.server.BaseHTTPRequestHandler):
        def do_POST(self):
            body = self.rfile.read(int(self.headers.get("Content-Length", 0))).decode("utf-8", "replace")
            print("SINK " + body.replace("\n", " "), flush=True)
            self.send_response(200); self.end_headers()
        def log_message(self, *a): pass
    http.server.ThreadingHTTPServer(("0.0.0.0", 8080), H).serve_forever()
---
apiVersion: v1
kind: Pod
metadata: {name: kk-sink, labels: {app: kk-sink}}
spec:
  nodeSelector: {node-role.kubernetes.io/control-plane: ""}
  tolerations: [{key: node-role.kubernetes.io/control-plane, operator: Exists, effect: NoSchedule}]
  containers:
    - name: sink
      image: python:3.12-alpine
      command: [python3, -u, /src/sink.py]
      volumeMounts: [{name: src, mountPath: /src}]
  volumes: [{name: src, configMap: {name: kk-sink-src}}]
---
apiVersion: v1
kind: Service
metadata: {name: kk-sink}
spec:
  selector: {app: kk-sink}
  ports: [{port: 8080, targetPort: 8080}]
YAML
helm repo add prometheus-community https://prometheus-community.github.io/helm-charts >/dev/null 2>&1
helm repo update >/dev/null 2>&1
if [ "${SKIP_BUILD:-0}" != 1 ]; then helm install kps prometheus-community/kube-prometheus-stack --version "$KPS_VERSION" \
  --set grafana.enabled=false,alertmanager.enabled=false,nodeExporter.enabled=false,kubeStateMetrics.enabled=false \
  --set defaultRules.create=false,prometheus.prometheusSpec.serviceMonitorSelectorNilUsesHelmValues=false \
  --set prometheus.prometheusSpec.podMonitorSelectorNilUsesHelmValues=false \
  --set kubeApiServer.enabled=false,kubelet.enabled=false,kubeControllerManager.enabled=false \
  --set coreDns.enabled=false,kubeEtcd.enabled=false,kubeScheduler.enabled=false,kubeProxy.enabled=false \
  --wait --timeout 8m >"$WORK/kps.log" 2>&1 && PASS "kube-prometheus-stack $KPS_VERSION installed" || { tail -20 "$WORK/kps.log"; DIE "prometheus install failed"; }
fi

STEP "3. helm install the chart, then scale to the 2-replica chart default"
# A fresh database has no CA, and every replica with BOOTSTRAP_CREATE_ROOT would
# race to create one. Bring up one replica to create the root, then let the
# chart default (replicaCount=2) take over via upgrade.
cat > "$WORK/values.yaml" <<YAML
extraEnv:
  - {name: RENEWAL_POLL_MINUTES, value: "$POLL_MIN"}
  - {name: WEBHOOK_URL, value: "http://kk-sink:8080/hook"}
  - {name: KRYPTKEEPER_BOOTSTRAP_CREATE_ROOT, value: "true"}
  - {name: KRYPTKEEPER_CA_NAME, value: "UAT HA Root CA"}
YAML
helm install "$REL" "$REPO/charts/kryptkeeper" -f "$WORK/values.yaml" \
  --set image.repository=localhost/kryptkeeper --set image.tag=uat --set image.pullPolicy=Never \
  --set secrets.bootstrapToken="$TOKEN" --set secrets.keystorePassphrase="$PASSPHRASE" \
  --set "secrets.databaseURL=postgres://kk:${PGPASS}@kk-pg:5432/kk?sslmode=disable" \
  --set metrics.serviceMonitor.enabled=true --set config.trustedProxyCIDRs="" --set replicaCount=1 >"$WORK/helm.log" 2>&1 \
  || { cat "$WORK/helm.log"; DIE "helm install failed"; }
kubectl rollout status deploy/$FULL --timeout=300s >/dev/null || { kubectl get pods; DIE "first replica did not become ready"; }
# replicaCount=null drops the override so the chart default (2) applies, and
# reset-then-reuse keeps the other install flags.
helm upgrade "$REL" "$REPO/charts/kryptkeeper" --reset-then-reuse-values --set replicaCount=null >"$WORK/helm-up.log" 2>&1 \
  || { cat "$WORK/helm-up.log"; DIE "helm upgrade to 2 replicas failed"; }
kubectl rollout status deploy/$FULL --timeout=300s >/dev/null || { kubectl get pods; DIE "hub rollout did not finish"; }
[ "$(ready_count)" = 2 ] && PASS "2 replicas Ready (/readyz)" || DIE "expected 2 Ready hub pods, got $(ready_count)"
PDBS="$(kubectl get pdb $FULL -o jsonpath='{.spec.minAvailable}' 2>/dev/null)"
[ "$PDBS" = 1 ] && PASS "PodDisruptionBudget minAvailable=1 present by default" || FAIL "default PDB missing"

STEP "4. Traffic over verified TLS"
# The hub image is distroless (no cat), so a throwaway pod mounts the keystore PVC
# (RWO, same node) to export the self-issued CA.
kubectl apply -f - >/dev/null <<YAML || DIE "ca reader"
apiVersion: v1
kind: Pod
metadata: {name: kk-ca-reader}
spec:
  restartPolicy: Never
  nodeSelector: {kubernetes.io/hostname: ${CLUSTER}-worker}
  containers:
    - {name: r, image: busybox:1.36, command: [sleep, "300"], volumeMounts: [{name: k, mountPath: /k, readOnly: true}]}
  volumes: [{name: k, persistentVolumeClaim: {claimName: ${FULL}-keys, readOnly: true}}]
YAML
kubectl wait --for=condition=Ready pod/kk-ca-reader --timeout=120s >/dev/null || DIE "ca reader not ready"
kubectl exec kk-ca-reader -- cat /k/data/tls/ca.pem > "$WORK/ca.pem" 2>/dev/null
openssl x509 -in "$WORK/ca.pem" -noout -subject >/dev/null 2>&1 || DIE "exported CA is not a certificate"
kubectl delete pod kk-ca-reader --wait=false >/dev/null
kubectl create secret generic lab-hub-ca --from-file=ca.pem="$WORK/ca.pem" >/dev/null || DIE "ca secret"
kubectl apply -f - >/dev/null <<'YAML' || DIE "probe pod"
apiVersion: v1
kind: Pod
metadata: {name: kk-probe}
spec:
  nodeSelector: {node-role.kubernetes.io/control-plane: ""}
  tolerations: [{key: node-role.kubernetes.io/control-plane, operator: Exists, effect: NoSchedule}]
  containers:
    - {name: c, image: "curlimages/curl:8.10.1", command: [sleep, "86400"], volumeMounts: [{name: ca, mountPath: /ca, readOnly: true}]}
  volumes: [{name: ca, secret: {secretName: lab-hub-ca}}]
YAML
kubectl wait --for=condition=Ready pod/kk-probe --timeout=120s >/dev/null || DIE "probe pod not ready"
kubectl port-forward svc/$FULL $FWD_PORT:8080 >"$WORK/fwd.log" 2>&1 & FWD_PID=$!
sleep 3
C="$(curl -sS --cacert "$WORK/ca.pem" --resolve "$FULL:$FWD_PORT:127.0.0.1" -o /dev/null -w '%{http_code}' "https://$FULL:$FWD_PORT/readyz")"
[ "$C" = 200 ] && PASS "port-forward /readyz 200 verified against the pod's CA" || FAIL "port-forward /readyz = $C"
kill "$FWD_PID" 2>/dev/null; FWD_PID=""
BAD=0; for _ in $(seq 1 20); do [ "$(probe -o /dev/null -w '%{http_code}' https://$FULL:8080/readyz)" = 200 ] || BAD=$((BAD+1)); done
[ "$BAD" = 0 ] && PASS "20/20 requests through the Service returned 200 (TLS verified)" || FAIL "$BAD of 20 requests failed"

STEP "5. Seed CA data, 5 certificates, notification rule"
CA_ID="$(hubapi /api/v1/cas | jq_py data.0.id)"
[ -n "$CA_ID" ] || DIE "hub has no CA"
TPL_ID="$(hubapi /api/v1/templates -X POST -d '{"name":"uat-ha","display_name":"ha","allowed_algorithms":["ECDSA","RSA-2048"],"key_usage":["digitalSignature","keyEncipherment"],"extended_key_usage":["serverAuth"],"validity_period":"72h","active":true}' | jq_py data.id)"
[ -n "$TPL_ID" ] || DIE "template create failed"
FPS=()
for i in $(seq 1 $N_CERTS); do
  openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -keyout "$WORK/c$i.key" -out "$WORK/c$i.csr" \
    -subj "/CN=ha$i.uat.example.test" -addext "subjectAltName=DNS:ha$i.uat.example.test" >/dev/null 2>&1
  CSR="$(python3 -c "import json;print(json.dumps(open('$WORK/c$i.csr').read()))")"
  FP="$(hubapi /api/v1/certificates -X POST -d "{\"ca_id\":\"$CA_ID\",\"template_id\":\"$TPL_ID\",\"csr_pem\":$CSR}" | jq_py data.fingerprint_sha256)"
  [ -n "$FP" ] || DIE "certificate $i issue failed"
  FPS+=("$FP")
done
# A days rule whose window (30 d) is at least the certificate lifetime (72 h) never
# fires: ruleCrossed (renewal_scheduler.go) refuses it so a short-lived cert is not
# paged on issue day, and says percent rules cover that case (W30-01). The seeded
# certificates are 72 h, so the rule is "<= 100% of lifetime remaining" instead,
# which every unexpired certificate satisfies, driving the real dispatch path.
RULE="$(hubapi /api/v1/notifications/rules -X POST -d '{"name":"uat-100pct","threshold_pct":100,"channel":"webhook","target":"sink"}' | jq_py data.id)"
[ -n "$RULE" ] && PASS "CA $CA_ID, 72h template, 5 certificates, webhook rule $RULE" || DIE "rule create failed"
# Replicas must see certificates a peer issued WITHOUT any restart (the issued
# certificates used to live in a per-process map). Query each pod directly over
# a port-forward, verifying TLS against the hub CA (the cert is issued for the
# Service name, so --resolve maps it to the forwarded loopback port).
list_pod_fps() { # pod port -> sorted fingerprints on stdout, "ERR" on failure
  local pod="$1" port="$2" out
  kubectl port-forward "pod/$pod" "$port":8080 >"$WORK/podfwd.log" 2>&1 & PODFWD_PID=$!
  sleep 3
  out="$(curl -sS --max-time 10 --cacert "$WORK/ca.pem" --resolve "$FULL:$port:127.0.0.1" \
    -H "Authorization: Bearer $TOKEN" "https://$FULL:$port/api/v1/certificates?limit=100")" || out=""
  kill "$PODFWD_PID" 2>/dev/null; wait "$PODFWD_PID" 2>/dev/null; PODFWD_PID=""
  echo "$out" | python3 -c "import json,sys
try: d=json.load(sys.stdin)['data']
except Exception: print('ERR'); sys.exit()
print(' '.join(sorted(c.get('fingerprint_sha256','') for c in d)))"
}
read -r -a PODS <<<"$(kubectl get pods -l app.kubernetes.io/name=kryptkeeper,app.kubernetes.io/instance=$REL -o jsonpath='{.items[*].metadata.name}')"
[ "${#PODS[@]}" = 2 ] || DIE "expected 2 hub pods, got ${#PODS[@]}"
PORTS=("$POD_PORT_A" "$POD_PORT_B")
for idx in 0 1; do
  p="${PODS[$idx]}"; got=""
  for _ in $(seq 1 10); do   # peer rows merge within the 2 s refresh interval
    got="$(list_pod_fps "$p" "${PORTS[$idx]}")"
    miss=0; for f in "${FPS[@]}"; do case " $got " in *" $f "*) ;; *) miss=$((miss+1));; esac; done
    [ "$got" != ERR ] && [ "$miss" = 0 ] && break; sleep 2
  done
  total="$(echo $got | wc -w | tr -d ' ')"
  echo "  $p lists $total certificates ($N_CERTS seeded via the Service plus the hub's own listener certificate); missing seeded: $miss"
  [ "$got" != ERR ] && [ "$miss" = 0 ] && PASS "$p (direct, TLS verified) lists all $N_CERTS seeded certificates with no restart" \
    || FAIL "$p is missing $miss of $N_CERTS seeded certificates"
done

STEP "6. Pages reach the sink once the scheduler ticks"
for _ in $(seq 1 40); do
  [ "$(kubectl logs kk-sink 2>/dev/null | grep -c '^SINK')" -ge $N_CERTS ] && break; sleep 5
done
SINK0="$(kubectl logs kk-sink | grep -c '^SINK')"
[ "$SINK0" -ge $N_CERTS ] && PASS "sink received $SINK0 pages before any failure" || DIE "only $SINK0 pages reached the sink"

leader_pod() { # the lease holder logs "renewal candidates" every tick; its peers stay silent
  local p out=""
  for p in $(kubectl get pods -l app.kubernetes.io/name=kryptkeeper,app.kubernetes.io/instance=$REL -o jsonpath='{.items[*].metadata.name}'); do
    if kubectl logs "$p" --since=150s 2>/dev/null | grep -q 'renewal candidates'; then out="$out $p"; fi
  done
  echo $out
}
hard_kill() { # pod -> SIGKILL its hub container's main process on the node that runs it
  local pod="$1" node cid pid
  node="${CLUSTER}-worker"
  cid="$(podman exec "$node" crictl ps --label io.kubernetes.pod.name="$pod" --name kryptkeeper -q 2>/dev/null)"
  [ -n "$cid" ] || return 1
  pid="$(podman exec "$node" crictl inspect -o json "$cid" | python3 -c "import json,sys
d=json.load(sys.stdin); d=d[0] if isinstance(d,list) else d
print(d['info']['pid'])")" || return 1
  podman exec "$node" kill -9 "$pid"
}
RESULTS=()
failover() { # mode bound
  local mode="$1" bound="$2" h0 lp t0 t h dl
  for _ in $(seq 1 40); do lp="$(leader_pod)"; [ "$(echo $lp | wc -w | tr -d " ")" = 1 ] && break; sleep 5; done
  [ "$(echo $lp | wc -w | tr -d " ")" = 1 ] || { FAIL "$mode: could not identify a single leader pod (got '$lp')"; return; }
  h0="$(holder)"
  [ -n "$h0" ] || { FAIL "$mode: no lease row"; return; }
  echo "  $mode: leader pod $lp, lease $h0"
  t0="$(now)"
  if [ "$mode" = hard ]; then
    # A forced delete still gives the kubelet's SIGTERM-then-kill path a moment
    # in which the hub releases its lease (measured: 6 s), which is not a crash.
    # SIGKILL the hub process from the node so nothing runs Stop().
    hard_kill "$lp" || { FAIL "hard: could not SIGKILL the hub process of $lp"; return; }
  else kubectl delete pod "$lp" --wait=false >/dev/null 2>&1; fi
  dl=$((t0 + 300))
  while :; do
    h="$(holder)"
    if [ -n "$h" ] && [ "${h%%|*}" != "${h0%%|*}" ] && [ "${h##*|}" = true ]; then t=$(( $(now) - t0 )); break; fi
    [ "$(now)" -ge "$dl" ] && { FAIL "$mode: no failover within 300s"; return; }
    sleep 2
  done
  echo "  $mode: new holder ${h%%|*} after ${t}s (poll resolution about 2s, bound ${bound}s)"
  RESULTS+=("$mode ${t}")
  [ "$t" -le "$bound" ] && PASS "$mode failover ${t}s <= ${bound}s" || FAIL "$mode failover ${t}s exceeds ${bound}s"
  kubectl rollout status deploy/$FULL --timeout=240s >/dev/null
  for _ in $(seq 1 60); do [ "$(ready_count)" = 2 ] && break; sleep 3; done
}

STEP "7. Kill the lease holder: graceful, then hard"
failover graceful "$GRACEFUL_BOUND"
failover hard "$HARD_BOUND"
NOTE "board acceptance asks for failover within a 30 s lease TTL; the code floors every lease at 60 s (scheduler asks for ${LEASE_S}s), so 30 s is NOT met and not achievable without changing lease constants (out of scope)."
# One more full tick so a duplicate page, if any, would have been sent.
sleep $((POLL_MIN * 60 + 20))

STEP "8. Duplicates"
hubapi "/api/v1/audit?action=renewal_notification_sent&outcome=success&limit=100" > "$WORK/audit.json"
# The percent rule matches every unexpired certificate, so besides the seeded ones
# it pages the hub's own listener certificate: allow exactly one extra, and require
# each seeded certificate once.
python3 - "$WORK/audit.json" "${FPS[@]}" <<'PY' && PASS "audit: every (certificate, rule) has exactly one renewal_notification_sent success row (all $N_CERTS seeded certificates, at most the hub's listener certificate besides)" || FAIL "duplicate or missing reminders in the audit log"
import json,sys,collections
d=json.load(open(sys.argv[1]))["data"]
seeded=set(sys.argv[2:])
c=collections.Counter((e.get("resource_id"),e.get("change_summary","")) for e in d)
extra=[k for k in c if k[0] not in seeded]
print("  audit rows:",len(d),"distinct (certificate,rule):",len(c),"| seeded covered:",sum(1 for f in seeded if any(k[0]==f for k in c)),"| extra (listener):",len(extra))
sys.exit(0 if d and all(v==1 for v in c.values()) and all(any(k[0]==f for k in c) for f in seeded) and len(extra)<=1 else 1)
PY
kubectl logs kk-sink | grep '^SINK' > "$WORK/sink.log"
python3 - "$WORK/sink.log" "${FPS[@]}" <<'PY' && PASS "sink: one page per certificate (all $N_CERTS seeded plus at most the hub's listener certificate), none repeated across failovers" || FAIL "sink saw a repeated or missing page"
import re,sys,collections
fps=[m.group(1) for l in open(sys.argv[1]) for m in [re.search(r'Fingerprint: ([0-9a-f]{64})',l)] if m]
c=collections.Counter(fps)
seeded=set(sys.argv[2:])
extra=[f for f in c if f not in seeded]
print("  sink pages:",len(fps),"distinct certificates:",len(c),"| extra (listener):",len(extra))
sys.exit(0 if all(v==1 for v in c.values()) and seeded <= set(c) and len(extra)<=1 else 1)
PY
DELIV="$(hubapi "/api/v1/notifications/deliveries?channel=webhook&limit=100" | jq_py meta.total)"
NOTE "deliveries API webhook total=$DELIV (record-only; carries no certificate id, so the audit log and sink are the per-certificate evidence)"
RENEWED=0
for p in $(kubectl get pods -l app.kubernetes.io/name=kryptkeeper,app.kubernetes.io/instance=$REL -o jsonpath='{.items[*].metadata.name}'); do
  IP="$(kubectl get pod $p -o jsonpath='{.status.podIP}')"
  n="$(probe --resolve "$FULL:8080:$IP" -H "Authorization: Bearer $TOKEN" https://$FULL:8080/metrics | awk '/^kryptkeeper_cert_renewal_success_total/{s+=$2} END{print s+0}')"
  RENEWED=$((RENEWED + n))
done
[ "$RENEWED" = 0 ] && PASS "kryptkeeper_cert_renewal_success_total summed across live pods = 0 (no auto-renew target exists in kind, so no renewals ran; only reminder pages were exercised)" \
  || NOTE "renewal_success_total=$RENEWED unexpectedly non-zero"

STEP "9. PDB drain of the worker"
kubectl drain "${CLUSTER}-worker" --ignore-daemonsets --delete-emptydir-data --timeout=60s >"$WORK/drain.log" 2>&1 &
DRAIN_PID=$!
MIN=99; BADREADY=0; END=$(( $(now) + 65 ))
while [ "$(now)" -lt "$END" ]; do
  r="$(ready_count)"; [ "$r" -lt "$MIN" ] && MIN=$r
  code="$(probe -o /dev/null -w '%{http_code}' https://$FULL:8080/readyz 2>/dev/null)"
  [ "$code" = 200 ] || { BADREADY=$((BADREADY+1)); echo "  bad /readyz probe: http=${code:-none} at +$(( $(now) - END + 65 ))s ready=$r"; }
  sleep 2
done
wait $DRAIN_PID; DRC=$?
tail -3 "$WORK/drain.log"
[ "$MIN" -ge 1 ] && PASS "min Ready hub pods during drain = $MIN (never 0)" || FAIL "Ready count reached $MIN"
[ "$BADREADY" = 0 ] && PASS "/readyz through the Service stayed 200 for the whole drain window" || FAIL "$BADREADY /readyz probes failed during drain"
NOTE "drain exit code $DRC (non-zero expected: PDB blocks the second eviction; single-worker RWO variant)"
kubectl uncordon "${CLUSTER}-worker" >/dev/null
kubectl rollout status deploy/$FULL --timeout=240s >/dev/null
for _ in $(seq 1 60); do [ "$(ready_count)" = 2 ] && break; sleep 3; done
[ "$(ready_count)" = 2 ] && PASS "2 replicas Ready again after uncordon" || FAIL "replicas did not recover"

STEP "10. Prometheus ServiceMonitor target"
kubectl wait --for=condition=Ready pod -l app.kubernetes.io/name=prometheus --timeout=240s >/dev/null 2>&1
kubectl port-forward svc/kps-kube-prometheus-stack-prometheus $PROM_PORT:9090 >"$WORK/prom.log" 2>&1 & PROM_PID=$!
sleep 3
OK=0
for _ in $(seq 1 45); do
  curl -sS "http://127.0.0.1:$PROM_PORT/api/v1/targets?state=active" > "$WORK/targets.json" 2>/dev/null
  UP="$(python3 -c "
import json,sys
try: d=json.load(open('$WORK/targets.json'))['data']['activeTargets']
except Exception: print(0); sys.exit()
print(sum(1 for t in d if '$FULL' in t['labels'].get('job','') and t['health']=='up'))")"
  [ "$UP" = 2 ] && { OK=1; break; }; sleep 2
done
[ "$OK" = 1 ] && PASS "ServiceMonitor job $FULL: 2 targets health=up" || FAIL "ServiceMonitor targets up = ${UP:-0}"
NOTE "ServiceMonitor tlsConfig is empty, so Prometheus scrapes with insecureSkipVerify (chart default); acceptable for this UAT only"

STEP "11. Postgres connections (default max_connections=$MAXCONN)"
python3 - "$WORK/conn.log" "$MAXCONN" <<'PY' && PASS "peak client connections stayed below max_connections" || FAIL "client connections reached max_connections"
import sys
rows=[l.split() for l in open(sys.argv[1]) if len(l.split())==3]
tot=[int(r[1]) for r in rows]; cl=[int(r[2]) for r in rows]
print("  samples:",len(rows),"| pg_stat_activity count(*): peak",max(tot),"| client backends: peak",max(cl))
sys.exit(0 if max(cl) < int(sys.argv[2]) else 1)
PY
echo "  steady-state count(*) now (2 replicas Ready, idle): $(pg 'select count(*) from pg_stat_activity') total, $(pg "select count(*) from pg_stat_activity where backend_type='client backend'") client backends"
echo "  client backends by state: $(pg "select coalesce(state,'-')||'='||n from (select state, count(*) n from pg_stat_activity where backend_type='client backend' group by state) t" | tr '\n' ' ')"
UNAVAIL=0; for p in $(kubectl get pods -l app.kubernetes.io/name=kryptkeeper,app.kubernetes.io/instance=$REL -o jsonpath='{.items[*].metadata.name}'); do
  UNAVAIL=$((UNAVAIL + $(kubectl logs "$p" 2>/dev/null | grep -ci 'db mode unavailable')))
done
[ "$UNAVAIL" = 0 ] && PASS "no 'db mode unavailable' fallbacks in the live replicas' logs" || FAIL "$UNAVAIL 'db mode unavailable' log lines (store fell back off Postgres)"

echo
[ "$FAILED" = 0 ] && { echo "ALL PASS"; echo "failover results (s): ${RESULTS[*]}"; } || { echo "SOME FAILED"; exit 1; }
