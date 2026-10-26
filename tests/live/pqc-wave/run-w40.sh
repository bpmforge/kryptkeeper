#!/usr/bin/env bash
# W40-01 / D-315: live PQC wave delivery to ssh haproxy (combined PEM) and a Kubernetes TLS Secret.
#
# WHAT IT PROVES: a real hub runs a two-principal wave over three members -- an haproxy that takes the
# ML-DSA-65 successor (ep-h), an haproxy whose verify address is misdirected so the install rolls back
# (ep-hf), and a kind cluster whose TLS Secret feeds an OpenSSL 3.5 workload (k8s). Served serials are read
# with `openssl s_client` inside an endpoint container, never from the hub. The nginx/apache legs stay in
# run.sh. Windows, tomcat, F5 and Citrix are not delivered (unit-tested refusals), so there is no leg for them.
#
# Needs podman (running machine), kind, kubectl, Go, python3, curl, ssh-keygen, host openssl (CSRs only).
# Cluster and containers are prefixed kkw40-<random>; only those are removed on exit. Writes docs/release/LIVE_RESULTS_PQC_W40_v1.1.md.
set -u
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FX_PREFIX=kkw40
FX_PORT="${HUB_PORT:-18452}"
RECORD="${RECORD:-$HERE/../../../docs/release/LIVE_RESULTS_PQC_W40_v1.1.md}"
FX_EXTRA_CONTAINERS="kkw40-ep-h kkw40-ep-hf"
. "$HERE/../ca-revoke/fixture.sh"
export KIND_EXPERIMENTAL_PROVIDER=podman
IMAGE="localhost/kkw40-ep:$(openssl rand -hex 3)"
CLUSTER="kkw40-$(openssl rand -hex 3)"
NODEPORT=$((30800 + RANDOM % 100))
KUBECONFIG="$FX_RUN/kubeconfig"; export KUBECONFIG
cleanup() { kind delete cluster --name "$CLUSTER" >/dev/null 2>&1; fx_cleanup; podman rmi -f "$IMAGE" >/dev/null 2>&1; }
trap cleanup EXIT

fx_header "# W40-01 live test: PQC wave delivery to haproxy and a Kubernetes TLS Secret"
mkident alice pki-admin; mkident bob pki-admin
W="$FX_RUN/work"; mkdir -p "$W"

STEP "0. build endpoint image, check haproxy and OpenSSL"
podman build -t "$IMAGE" -f "$HERE/Containerfile.haproxy" "$HERE" >"$FX_RUN/build.log" 2>&1 || { tail -20 "$FX_RUN/build.log"; DIE "image build failed"; }
EP_OSSL="$(podman run --rm --entrypoint openssl "$IMAGE" version | awk '{print $2}')"
HAP_VV="$(podman run --rm --entrypoint haproxy "$IMAGE" -vv 2>&1)"
say "endpoint openssl: $EP_OSSL"; say "haproxy: $(echo "$HAP_VV" | head -1)"
say "$(echo "$HAP_VV" | grep -i 'SSL library version')"
[ "$(printf '%s\n3.5.0\n' "$EP_OSSL" | sort -V | head -1)" = "3.5.0" ] || DIE "endpoint OpenSSL $EP_OSSL < 3.5"
echo "$HAP_VV" | grep -q 'Running on SSL library version : OpenSSL 3\.[5-9]' && PASS "haproxy runs on OpenSSL $EP_OSSL" || FAIL "haproxy is not on OpenSSL >= 3.5"

STEP "1. build hub, Postgres, start hub"
fx_build_and_db
ssh-keygen -t ed25519 -N '' -f "$FX_RUN/id" -C kkw40 >/dev/null
fx_start_hub || DIE "hub did not start"
PASS "hub up at $HUBURL"
code "$T_alice" "$HUBURL/api/v1/cas" >/dev/null
CA_ID="$(jget 'd["data"][0]["id"]' <"$FX_RUN/last.json")"
[ -n "$CA_ID" ] || DIE "no root CA"
check "create template (ECDSA + ML-DSA-65)" 201 "$(code "$T_alice" -X POST "$HUBURL/api/v1/templates" \
  -d '{"name":"wave-tpl","display_name":"wave","validity_period":"P30D","key_usage":["digitalSignature"],"extended_key_usage":["serverAuth"],"allowed_algorithms":["ECDSA","ML-DSA-65"],"active":true}')"
TPL_ID="$(jget 'd["data"]["id"]' <"$FX_RUN/last.json")"

STEP "2. start 2 haproxy endpoints"
AUTHKEY="$(cat "$FX_RUN/id.pub")"
EPS="h hf"
for e in $EPS; do podman run -d --name "kkw40-ep-$e" --network "$FX_NET" -e AUTHORIZED_KEY="$AUTHKEY" "$IMAGE" >/dev/null || DIE "start ep-$e"; done
probe() { # ep-name host:port -> serial (uppercase hex, no leading zeros), probed from inside ep-name
  podman exec "kkw40-ep-$1" sh -c "echo | openssl s_client -connect $2 -servername x 2>/dev/null | openssl x509 -noout -serial" 2>/dev/null \
    | cut -d= -f2 | tr 'a-f' 'A-F' | sed 's/^0*//'
}
norm() { tr 'a-f' 'A-F' | sed 's/^0*//'; }
wait_serial() { local t=${3:-30} s; while [ "$t" -gt 0 ]; do s="$(probe h "$1")"; [ -n "$s" ] && [ "$s" = "$2" ] && return 0; sleep 1; t=$((t-1)); done; return 1; }
for e in $EPS; do
  t=30; until [ -n "$(probe h kkw40-ep-$e:443)" ]; do t=$((t-1)); [ $t -le 0 ] && DIE "ep-$e never served TLS"; sleep 1; done
  t=30; until podman exec "kkw40-ep-$e" sh -c 'nc -z 127.0.0.1 22' >/dev/null 2>&1; do t=$((t-1)); [ $t -le 0 ] && DIE "ep-$e sshd never listened"; sleep 1; done
done
PASS "both haproxy endpoints serve TLS (placeholder ECDSA leaf) and sshd listens"

issue_leaf() { # name cn -> prints fingerprint ; writes serial to $W/<name>.serial
  openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -keyout "$W/$1.key" -out "$W/$1.csr" -subj "/CN=$2" -addext "subjectAltName=DNS:$2" >/dev/null 2>&1
  python3 -c "import json,sys; json.dump({'ca_id':sys.argv[1],'template_id':sys.argv[2],'csr_pem':open(sys.argv[3]).read()}, open(sys.argv[4],'w'))" "$CA_ID" "$TPL_ID" "$W/$1.csr" "$W/$1-issue.json"
  check "[$1] issue ECDSA leaf" 201 "$(code "$T_alice" -X POST "$HUBURL/api/v1/certificates" --data @"$W/$1-issue.json")" >&2
  jget 'd["data"]["fingerprint_sha256"]' <"$FX_RUN/last.json"
}
cert_serial() { code "$T_alice" "$HUBURL/api/v1/certificates/$1" >/dev/null; jget 'format(int(d["data"]["serial_number"]),"X")' <"$FX_RUN/last.json"; }

STEP "3. haproxy: credentials, targets, install a hub-issued ECDSA leaf"
PRIV="$(python3 -c "print(open('$FX_RUN/id').read().replace(chr(10), chr(92)+'n'), end='')")"
declare -A OLD_FP SERIAL_BEFORE TGT NFP NSER
for e in $EPS; do
  host="kkw40-ep-$e"
  hk="$(podman exec "$host" cat /etc/ssh/ssh_host_ed25519_key.pub | awk '{print $1" "$2}')"
  python3 - "$PRIV" "$hk" "$e" >"$W/cred-$e.json" <<'PY'
import json, sys
print(json.dumps({"name": f"w40-ssh-{sys.argv[3]}", "credential_type": "ssh_key",
  "payload": {"user": "root", "private_key_pem": sys.argv[1].replace('\\n', '\n'), "host_public_key": sys.argv[2], "port": 22}}))
PY
  check "[ep-$e] create ssh credential" 201 "$(code "$T_alice" -X POST "$HUBURL/api/v1/credentials" --data @"$W/cred-$e.json")"
  CRED="$(jget 'd["data"]["id"]' <"$FX_RUN/last.json")"
  check "[ep-$e] create haproxy target (combined PEM, no key path)" 201 "$(code "$T_alice" -X POST "$HUBURL/api/v1/targets" -d "{\"host\":\"$host\",\"discovery_mode\":\"network\",\"install_mode\":\"ssh\",\"credential_ref\":\"$CRED\",\"install_server_type\":\"haproxy\",\"install_cert_path\":\"/etc/haproxy/kk.pem\",\"name\":\"$host\"}")"
  TGT[$e]="$(jget 'd["data"]["id"]' <"$FX_RUN/last.json")"
  fp="$(issue_leaf "$e" "$host")"
  check "[ep-$e] renewal/execute installs it over SSH" 200 "$(code "$T_alice" -X POST "$HUBURL/api/v1/renewal/execute" \
    -d "{\"fingerprint\":\"$fp\",\"target_id\":\"${TGT[$e]}\",\"install\":{\"server_type\":\"haproxy\",\"cert_path\":\"/etc/haproxy/kk.pem\",\"verify_host_port\":\"$host:443\"}}")"
  outcome="$(jget 'd["data"].get("install_outcome","")' <"$FX_RUN/last.json")"
  [ "$outcome" = installed_verified ] || FAIL "[ep-$e] install_outcome=$outcome ($(jget 'd["data"].get("install_detail","")' <"$FX_RUN/last.json" | head -c 600))"
  OLD_FP[$e]="$(jget 'd["data"]["new_fingerprint"]' <"$FX_RUN/last.json")"
  hubser="$(cert_serial "${OLD_FP[$e]}")"
  if wait_serial "$host:443" "$hubser" 30; then SERIAL_BEFORE[$e]="$hubser"; PASS "[ep-$e] haproxy serves the hub-issued ECDSA leaf (serial $hubser), the wave member"
  else FAIL "[ep-$e] served serial $(probe h "$host:443") != hub serial $hubser"; fi
done

STEP "4. kind cluster, OpenSSL 3.5 workload on a TLS Secret, k8s target"
VERIFY_HOST="$(python3 -c "
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.connect(('192.0.2.1', 9))
print(s.getsockname()[0])")"
case "$VERIFY_HOST" in ""|127.*|169.254.*) K8S_SKIP="no non-loopback host address";; *) K8S_SKIP="";; esac
K8S_MEMBER=0
if [ -z "$K8S_SKIP" ]; then
  cat >"$W/kind.yaml" <<EOF
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
networking:
  apiServerAddress: "$VERIFY_HOST"
nodes:
- role: control-plane
  extraPortMappings:
  - containerPort: $NODEPORT
    hostPort: $NODEPORT
    protocol: TCP
EOF
  if kind create cluster --name "$CLUSTER" --config "$W/kind.yaml" --kubeconfig "$KUBECONFIG" >"$W/kind.log" 2>&1; then
    PASS "kind cluster $CLUSTER up (podman provider, API on $VERIFY_HOST)"
    podman save "$IMAGE" -o "$W/ep.tar" && kind load image-archive "$W/ep.tar" --name "$CLUSTER" >/dev/null 2>&1 && PASS "workload image loaded into kind" || DIE "kind load failed"
    K8S_MEMBER=1
  else
    tail -5 "$W/kind.log"; K8S_SKIP="kind create cluster failed"
  fi
fi
if [ "$K8S_MEMBER" = 1 ]; then
  K8S_HOST=k8s-w40.kk-uat.local
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 1 -keyout "$W/ph.key" -out "$W/ph.crt" -subj "/CN=placeholder" >/dev/null 2>&1
  kubectl create namespace kkw40 >/dev/null && kubectl -n kkw40 create secret tls kk-w40-tls --cert="$W/ph.crt" --key="$W/ph.key" >/dev/null && PASS "namespace + placeholder TLS Secret created"
  # s_server -naccept 1 in a loop: every connection re-reads the Secret files, so an update needs no reload.
  cat >"$W/pod.yaml" <<EOF
apiVersion: v1
kind: Pod
metadata: {name: kk-w40, namespace: kkw40, labels: {app: kk-w40}}
spec:
  containers:
  - name: tls
    image: $IMAGE
    imagePullPolicy: Never
    command: ["sh", "-c", "while true; do openssl s_server -accept 8443 -cert /tls/tls.crt -key /tls/tls.key -naccept 1 -quiet </dev/null >/dev/null 2>&1; done"]
    volumeMounts: [{name: tls, mountPath: /tls, readOnly: true}]
  volumes: [{name: tls, secret: {secretName: kk-w40-tls}}]
---
apiVersion: v1
kind: Service
metadata: {name: kk-w40, namespace: kkw40}
spec:
  type: NodePort
  selector: {app: kk-w40}
  ports: [{port: 8443, targetPort: 8443, nodePort: $NODEPORT}]
---
apiVersion: v1
kind: ServiceAccount
metadata: {name: kk-w40-pusher, namespace: kkw40}
---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata: {name: kk-w40-pusher, namespace: kkw40}
rules: [{apiGroups: [""], resources: ["secrets"], verbs: ["get", "create", "update"]}]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata: {name: kk-w40-pusher, namespace: kkw40}
subjects: [{kind: ServiceAccount, name: kk-w40-pusher, namespace: kkw40}]
roleRef: {kind: Role, name: kk-w40-pusher, apiGroup: rbac.authorization.k8s.io}
EOF
  # a fresh namespace's default ServiceAccount appears a moment after the namespace itself
  for _ in $(seq 1 20); do kubectl apply -f "$W/pod.yaml" >/dev/null 2>&1 && break; sleep 2; done
  kubectl apply -f "$W/pod.yaml" >/dev/null && kubectl -n kkw40 wait --for=condition=Ready pod/kk-w40 --timeout=90s >/dev/null && PASS "workload pod ready" || DIE "workload pod not ready"
  SA_TOKEN="$(kubectl -n kkw40 create token kk-w40-pusher --duration=2h)"
  kubectl config view --minify --raw -o yaml >"$W/kc.yaml"
  read -r APISERVER < <(python3 - "$W/kc.yaml" "$W/cluster-ca.pem" <<'PY'
import base64, re, sys
t = open(sys.argv[1]).read()
open(sys.argv[2], 'wb').write(base64.b64decode(re.search(r'certificate-authority-data:\s*(\S+)', t).group(1)))
print(re.search(r'server:\s*(\S+)', t).group(1))
PY
)
  python3 - "$APISERVER" "$SA_TOKEN" "$W/cluster-ca.pem" >"$W/cred-k8s.json" <<'PY'
import json, sys
print(json.dumps({"name": "w40-k8s", "credential_type": "api_token", "payload": {
  "base_url": sys.argv[1], "bearer_token": sys.argv[2].strip(), "namespace": "kkw40", "secret_name": "kk-w40-tls",
  "ca_cert": open(sys.argv[3]).read()}}))
PY
  check "[k8s] create api_token credential" 201 "$(code "$T_alice" -X POST "$HUBURL/api/v1/credentials" --data @"$W/cred-k8s.json")"
  KCRED="$(jget 'd["data"]["id"]' <"$FX_RUN/last.json")"
  check "[k8s] create target" 201 "$(code "$T_alice" -X POST "$HUBURL/api/v1/targets" -d "{\"host\":\"$K8S_HOST\",\"discovery_mode\":\"network\",\"install_mode\":\"k8s\",\"credential_ref\":\"$KCRED\",\"verify_host_port\":\"$VERIFY_HOST:$NODEPORT\",\"name\":\"kk-w40-k8s\"}")"
  TGT[k]="$(jget 'd["data"]["id"]' <"$FX_RUN/last.json")"
  fp="$(issue_leaf k "$K8S_HOST")"
  check "[k8s] renewal/execute pushes the ECDSA leaf into the Secret" 200 "$(code "$T_alice" -X POST "$HUBURL/api/v1/renewal/execute" \
    -d "{\"fingerprint\":\"$fp\",\"target_id\":\"${TGT[k]}\",\"install\":{\"verify_host_port\":\"$VERIFY_HOST:$NODEPORT\"}}")"
  outcome="$(jget 'd["data"].get("install_outcome","")' <"$FX_RUN/last.json")"
  [ "$outcome" = installed_verified ] || FAIL "[k8s] install_outcome=$outcome ($(jget 'd["data"].get("install_detail","")' <"$FX_RUN/last.json" | head -c 600))"
  OLD_FP[k]="$(jget 'd["data"]["new_fingerprint"]' <"$FX_RUN/last.json")"
  hubser="$(cert_serial "${OLD_FP[k]}")"
  if wait_serial "$VERIFY_HOST:$NODEPORT" "$hubser" 150; then SERIAL_BEFORE[k]="$hubser"; PASS "[k8s] the workload serves the hub-issued ECDSA leaf (serial $hubser)"
  else FAIL "[k8s] served serial $(probe h "$VERIFY_HOST:$NODEPORT") != hub serial $hubser"; fi
else
  SKIP "k8s leg not run: $K8S_SKIP"
fi

STEP "5. wave: create, add members, accept"
check "create wave" 201 "$(code "$T_alice" -X POST "$HUBURL/api/v1/reports/pqc-waves" -d '{"name":"w40-live","owner":"alice"}')"
WAVE="$(jget 'd["data"]["id"]' <"$FX_RUN/last.json")"
MEMBERS="h hf"; [ "$K8S_MEMBER" = 1 ] && MEMBERS="h hf k"
for e in $MEMBERS; do
  check "add member [$e]" 200 "$(code "$T_alice" -X POST "$HUBURL/api/v1/reports/pqc-waves/$WAVE/members" -d "{\"fingerprint\":\"${OLD_FP[$e]}\"}")"
done
check "accept wave" 200 "$(code "$T_alice" -X POST "$HUBURL/api/v1/reports/pqc-waves/$WAVE/accept")"
declare -A KEYHASH_BEFORE
KEYHASH_BEFORE[hf]="$(podman exec kkw40-ep-hf sha256sum /etc/haproxy/kk.pem | cut -d' ' -f1)"
check "[ep-hf] PATCH verify_host_port -> ep-h:443 (wrong fingerprint after install)" 200 "$(code "$T_alice" -X PATCH "$HUBURL/api/v1/targets/${TGT[hf]}" -d '{"verify_host_port":"kkw40-ep-h:443"}')"

STEP "6. two-principal execute"
check "alice proposes execute" 201 "$(code "$T_alice" -X POST "$HUBURL/api/v1/reports/pqc-waves/$WAVE/execute" -d "{\"template_id\":\"$TPL_ID\"}")"
ACT="$(jget 'd["data"]["id"]' <"$FX_RUN/last.json")"
check "alice cannot approve her own proposal" 403 "$(code "$T_alice" -X POST "$HUBURL/api/v1/reports/pqc-waves/$WAVE/execute/$ACT/approve")"
check "bob approves and the wave runs" 200 "$(code "$T_bob" -X POST "$HUBURL/api/v1/reports/pqc-waves/$WAVE/execute/$ACT/approve")"
cp "$FX_RUN/last.json" "$W/exec.json"
say "execute result: $(python3 -c "import json;d=json.load(open('$W/exec.json'))['data'];print({k:d.get(k) for k in ('migrated','failed','skipped','unsupported','regressed','wave_status')})")"

STEP "7. per-member outcomes as the hub reported them"
for e in $MEMBERS; do
  python3 - "$W/exec.json" "${OLD_FP[$e]}" >"$W/m-$e.txt" <<'PY'
import json, sys
for r in json.load(open(sys.argv[1]))["data"]["results"]:
    if r["fingerprint"] == sys.argv[2]:
        print(r.get("status",""), r.get("delivery",""), r.get("new_fingerprint",""), str(r.get("old_serial_served","")), r.get("reason","").replace("\t"," ").replace("\n"," "), sep="\t")
PY
  IFS=$'\t' read -r st dl nfp oldserved why <"$W/m-$e.txt"
  NFP[$e]="$nfp"
  if [ "$e" = hf ]; then
    [ "$st" = failed ] && [ "$dl" = failed ] && [ "$oldserved" = True ] && PASS "[ep-hf] status=failed delivery=failed old_serial_served=true" || FAIL "[ep-hf] status=$st delivery=$dl old_serial_served=$oldserved reason=$why"
    case "$why" in *"rolled back"*) PASS "[ep-hf] reason reports the rollback: ${why:0:160}";; *) FAIL "[ep-hf] reason lacks rollback: $why";; esac
  else
    [ "$st" = migrated ] && [ "$dl" = verified ] && PASS "[$e] status=migrated delivery=verified" || FAIL "[$e] status=$st delivery=$dl reason=$why"
  fi
  NSER[$e]="$(cert_serial "$nfp")"
  jget 'd["data"].get("key_algorithm_display","")' <"$FX_RUN/last.json" | grep -qx ML-DSA-65 && PASS "[$e] successor ${nfp:0:12} is ML-DSA-65 in the hub inventory" || FAIL "[$e] successor is not ML-DSA-65"
done

STEP "8. what the endpoints actually serve, observed by openssl s_client in a container"
for e in h; do
  host="kkw40-ep-$e:443"
  if wait_serial "$host" "$(echo "${NSER[$e]}" | norm)" 30; then PASS "[ep-$e] haproxy serial ${SERIAL_BEFORE[$e]} -> $(probe h "$host") (the successor)"; else FAIL "[ep-$e] served '$(probe h "$host")' != successor ${NSER[$e]}"; fi
  podman exec kkw40-ep-h sh -c "echo | openssl s_client -connect $host -servername x 2>/dev/null | openssl x509 -noout -text" | grep -q 'Public Key Algorithm: ML-DSA-65' && PASS "[ep-$e] served certificate is ML-DSA-65" || FAIL "[ep-$e] served certificate is not ML-DSA-65"
  podman exec "kkw40-ep-$e" sh -c "haproxy -c -f /etc/haproxy/haproxy.cfg >/dev/null 2>&1" && PASS "[ep-$e] haproxy -c accepts the delivered combined PEM" || FAIL "[ep-$e] haproxy -c rejects it"
done
if wait_serial kkw40-ep-hf:443 "${SERIAL_BEFORE[hf]}" 30; then PASS "[ep-hf] rolled back: old serial ${SERIAL_BEFORE[hf]} still served"; else FAIL "[ep-hf] served '$(probe h kkw40-ep-hf:443)' != old ${SERIAL_BEFORE[hf]}"; fi
[ "$(podman exec kkw40-ep-hf sha256sum /etc/haproxy/kk.pem | cut -d' ' -f1)" = "${KEYHASH_BEFORE[hf]}" ] && PASS "[ep-hf] combined PEM restored byte-for-byte" || FAIL "[ep-hf] combined PEM differs from before the wave"
if [ "$K8S_MEMBER" = 1 ]; then
  if wait_serial "$VERIFY_HOST:$NODEPORT" "$(echo "${NSER[k]}" | norm)" 150; then PASS "[k8s] workload serial ${SERIAL_BEFORE[k]} -> $(probe h "$VERIFY_HOST:$NODEPORT") (the successor)"; else FAIL "[k8s] served '$(probe h "$VERIFY_HOST:$NODEPORT")' != successor ${NSER[k]}"; fi
  podman exec kkw40-ep-h sh -c "echo | openssl s_client -connect $VERIFY_HOST:$NODEPORT -servername x 2>/dev/null | openssl x509 -noout -text" | grep -q 'Public Key Algorithm: ML-DSA-65' && PASS "[k8s] served certificate is ML-DSA-65" || FAIL "[k8s] served certificate is not ML-DSA-65"
  kubectl -n kkw40 get secret kk-w40-tls -o go-template='{{index .data "tls.key"}}' | base64 -d | head -1 | grep -q 'BEGIN PRIVATE KEY' && PASS "[k8s] Secret tls.key is a PKCS#8 PRIVATE KEY PEM" || FAIL "[k8s] Secret tls.key is not a PRIVATE KEY PEM"
fi

STEP "9. wave status and audit trail"
code "$T_alice" "$HUBURL/api/v1/reports/pqc-waves" >/dev/null
WSTAT="$(python3 -c "import json;d=json.load(open('$FX_RUN/last.json'))['data'];w=[x for x in d if x['id']=='$WAVE'][0];print(w['status'],w['migrated'],w['total'])")"
say "wave: status migrated total = $WSTAT"
[ "${WSTAT%% *}" = regressed ] && PASS "wave reported regressed (ep-hf failed)" || FAIL "wave status '${WSTAT%% *}', want regressed"
code "$T_alice" "$HUBURL/api/v1/audit?limit=1000" >/dev/null
AUD="$(cat "$FX_RUN/last.json")"
N="$(echo "$AUD" | grep -o 'key.export_for_delivery' | wc -l | tr -d ' ')"
WANT=$(echo $MEMBERS | wc -w | tr -d ' ')
[ "$N" -ge "$WANT" ] && PASS "audit has $N key.export_for_delivery rows (>= $WANT members)" || FAIL "audit has only $N key.export_for_delivery rows, want $WANT"
echo "$AUD" | grep -q 'PRIVATE KEY' && FAIL "audit trail contains key material" || PASS "audit trail contains no private-key PEM"

STEP "10. summary"
if [ "$FAILED" = 0 ]; then say "ALL PASS"; else say "ONE OR MORE STEPS FAILED"; fi
exit "$FAILED"
