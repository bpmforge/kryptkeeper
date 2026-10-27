#!/usr/bin/env bash
# Gap P13: live PQC wave delivery to an Apache httpd endpoint over SSH (ML-DSA-65), plus a Kubernetes TLS Secret
# rollback after a forced verify failure.
#
# WHAT IT PROVES: a real hub runs a two-principal wave over three members -- an Apache httpd (ep-a) that takes the
# ML-DSA-65 successor, an Apache whose verify address is misdirected so the install rolls back (ep-af), and a kind
# TLS Secret whose target verify address is misdirected to ep-a (a different cert, so the served fingerprint can
# never match) so the hub restores the Secret (k8s). The workload must again serve the previous serial and the
# Secret bytes must be unchanged. Served serials are read with `openssl s_client` inside an endpoint container,
# never from the hub. If httpd cannot load ML-DSA the Apache leg fails honestly (the install rolls back).
#
# Needs podman (running machine), kind, kubectl, Go, python3, curl, ssh-keygen, host openssl (CSRs only).
# Cluster and containers are prefixed kkak8s-<random>; only those are removed on exit. Writes docs/release/LIVE_RESULTS_PQC_APACHE_K8S_ROLLBACK_v1.1.md.
set -u
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FX_PREFIX=kkak8s
FX_PORT="${HUB_PORT:-18462}"
RECORD="${RECORD:-$HERE/../../../docs/release/LIVE_RESULTS_PQC_APACHE_K8S_ROLLBACK_v1.1.md}"
FX_EXTRA_CONTAINERS="kkak8s-ep-a kkak8s-ep-af"
. "$HERE/../ca-revoke/fixture.sh"
export KIND_EXPERIMENTAL_PROVIDER=podman
IMAGE="localhost/kkak8s-ep:$(openssl rand -hex 3)"
CLUSTER="kkak8s-$(openssl rand -hex 3)"
NODEPORT=$((30800 + RANDOM % 100))
KUBECONFIG="$FX_RUN/kubeconfig"; export KUBECONFIG
cleanup() { kind delete cluster --name "$CLUSTER" >/dev/null 2>&1; fx_cleanup; podman rmi -f "$IMAGE" >/dev/null 2>&1; }
trap cleanup EXIT

fx_header "# PQC wave delivery to Apache httpd, and Kubernetes Secret rollback after a failed verify"
mkident alice pki-admin; mkident bob pki-admin
W="$FX_RUN/work"; mkdir -p "$W"

STEP "0. build endpoint image, check Apache httpd and OpenSSL"
podman build -t "$IMAGE" -f "$HERE/Containerfile.apache" "$HERE" >"$FX_RUN/build.log" 2>&1 || { tail -20 "$FX_RUN/build.log"; DIE "image build failed"; }
EP_OSSL="$(podman run --rm --entrypoint openssl "$IMAGE" version | awk '{print $2}')"
HAP_VV="$(podman run --rm --entrypoint httpd "$IMAGE" -V 2>&1; podman run --rm --entrypoint httpd "$IMAGE" -M 2>&1)"
say "endpoint openssl: $EP_OSSL"; say "httpd: $(echo "$HAP_VV" | head -1)"
say "$(echo "$HAP_VV" | grep -i 'ssl_module')"
[ "$(printf '%s\n3.5.0\n' "$EP_OSSL" | sort -V | head -1)" = "3.5.0" ] || DIE "endpoint OpenSSL $EP_OSSL < 3.5"
echo "$HAP_VV" | grep -q 'ssl_module' && PASS "httpd has mod_ssl, linked to the image's system OpenSSL $EP_OSSL" || FAIL "httpd has no mod_ssl"

STEP "1. build hub, Postgres, start hub"
fx_build_and_db
ssh-keygen -t ed25519 -N '' -f "$FX_RUN/id" -C kkak8s >/dev/null
fx_start_hub || DIE "hub did not start"
PASS "hub up at $HUBURL"
code "$T_alice" "$HUBURL/api/v1/cas" >/dev/null
CA_ID="$(jget 'd["data"][0]["id"]' <"$FX_RUN/last.json")"
[ -n "$CA_ID" ] || DIE "no root CA"
check "create template (ECDSA + ML-DSA-65)" 201 "$(code "$T_alice" -X POST "$HUBURL/api/v1/templates" \
  -d '{"name":"wave-tpl","display_name":"wave","validity_period":"P30D","key_usage":["digitalSignature"],"extended_key_usage":["serverAuth"],"allowed_algorithms":["ECDSA","ML-DSA-65"],"active":true}')"
TPL_ID="$(jget 'd["data"]["id"]' <"$FX_RUN/last.json")"

STEP "2. start 2 apache endpoints"
AUTHKEY="$(cat "$FX_RUN/id.pub")"
EPS="a af"
for e in $EPS; do podman run -d --name "kkak8s-ep-$e" --network "$FX_NET" -e AUTHORIZED_KEY="$AUTHKEY" "$IMAGE" >/dev/null || DIE "start ep-$e"; done
probe() { # ep-name host:port -> serial (uppercase hex, no leading zeros), probed from inside ep-name
  podman exec "kkak8s-ep-$1" sh -c "echo | openssl s_client -connect $2 -servername x 2>/dev/null | openssl x509 -noout -serial" 2>/dev/null \
    | cut -d= -f2 | tr 'a-f' 'A-F' | sed 's/^0*//'
}
norm() { tr 'a-f' 'A-F' | sed 's/^0*//'; }
wait_serial() { local t=${3:-30} s; while [ "$t" -gt 0 ]; do s="$(probe a "$1")"; [ -n "$s" ] && [ "$s" = "$2" ] && return 0; sleep 1; t=$((t-1)); done; return 1; }
for e in $EPS; do
  t=30; until [ -n "$(probe a kkak8s-ep-$e:443)" ]; do t=$((t-1)); [ $t -le 0 ] && DIE "ep-$e never served TLS"; sleep 1; done
  t=30; until podman exec "kkak8s-ep-$e" sh -c 'nc -z 127.0.0.1 22' >/dev/null 2>&1; do t=$((t-1)); [ $t -le 0 ] && DIE "ep-$e sshd never listened"; sleep 1; done
done
PASS "both apache endpoints serve TLS (placeholder ECDSA leaf) and sshd listens"

issue_leaf() { # name cn -> prints fingerprint ; writes serial to $W/<name>.serial
  openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -keyout "$W/$1.key" -out "$W/$1.csr" -subj "/CN=$2" -addext "subjectAltName=DNS:$2" >/dev/null 2>&1
  python3 -c "import json,sys; json.dump({'ca_id':sys.argv[1],'template_id':sys.argv[2],'csr_pem':open(sys.argv[3]).read()}, open(sys.argv[4],'w'))" "$CA_ID" "$TPL_ID" "$W/$1.csr" "$W/$1-issue.json"
  check "[$1] issue ECDSA leaf" 201 "$(code "$T_alice" -X POST "$HUBURL/api/v1/certificates" --data @"$W/$1-issue.json")" >&2
  jget 'd["data"]["fingerprint_sha256"]' <"$FX_RUN/last.json"
}
cert_serial() { code "$T_alice" "$HUBURL/api/v1/certificates/$1" >/dev/null; jget 'format(int(d["data"]["serial_number"]),"X")' <"$FX_RUN/last.json"; }

STEP "3. apache: credentials, targets, install a hub-issued ECDSA leaf"
PRIV="$(python3 -c "print(open('$FX_RUN/id').read().replace(chr(10), chr(92)+'n'), end='')")"
declare -A OLD_FP SERIAL_BEFORE TGT NFP NSER
for e in $EPS; do
  host="kkak8s-ep-$e"
  hk="$(podman exec "$host" cat /etc/ssh/ssh_host_ed25519_key.pub | awk '{print $1" "$2}')"
  python3 - "$PRIV" "$hk" "$e" >"$W/cred-$e.json" <<'PY'
import json, sys
print(json.dumps({"name": f"ak8s-ssh-{sys.argv[3]}", "credential_type": "ssh_key",
  "payload": {"user": "root", "private_key_pem": sys.argv[1].replace('\\n', '\n'), "host_public_key": sys.argv[2], "port": 22}}))
PY
  check "[ep-$e] create ssh credential" 201 "$(code "$T_alice" -X POST "$HUBURL/api/v1/credentials" --data @"$W/cred-$e.json")"
  CRED="$(jget 'd["data"]["id"]' <"$FX_RUN/last.json")"
  check "[ep-$e] create apache target (cert + key paths)" 201 "$(code "$T_alice" -X POST "$HUBURL/api/v1/targets" -d "{\"host\":\"$host\",\"discovery_mode\":\"network\",\"install_mode\":\"ssh\",\"credential_ref\":\"$CRED\",\"install_server_type\":\"apache\",\"install_cert_path\":\"/etc/ssl/kk/server.crt\",\"install_key_path\":\"/etc/ssl/kk/server.key\",\"name\":\"$host\"}")"
  TGT[$e]="$(jget 'd["data"]["id"]' <"$FX_RUN/last.json")"
  fp="$(issue_leaf "$e" "$host")"
  check "[ep-$e] renewal/execute installs it over SSH" 200 "$(code "$T_alice" -X POST "$HUBURL/api/v1/renewal/execute" \
    -d "{\"fingerprint\":\"$fp\",\"target_id\":\"${TGT[$e]}\",\"install\":{\"server_type\":\"apache\",\"cert_path\":\"/etc/ssl/kk/server.crt\",\"key_path\":\"/etc/ssl/kk/server.key\",\"verify_host_port\":\"$host:443\"}}")"
  outcome="$(jget 'd["data"].get("install_outcome","")' <"$FX_RUN/last.json")"
  [ "$outcome" = installed_verified ] || FAIL "[ep-$e] install_outcome=$outcome ($(jget 'd["data"].get("install_detail","")' <"$FX_RUN/last.json" | head -c 600))"
  OLD_FP[$e]="$(jget 'd["data"]["new_fingerprint"]' <"$FX_RUN/last.json")"
  hubser="$(cert_serial "${OLD_FP[$e]}")"
  if wait_serial "$host:443" "$hubser" 30; then SERIAL_BEFORE[$e]="$hubser"; PASS "[ep-$e] apache serves the hub-issued ECDSA leaf (serial $hubser), the wave member"
  else FAIL "[ep-$e] served serial $(probe a "$host:443") != hub serial $hubser"; fi
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
  K8S_HOST=k8s-ak8s.kk-uat.local
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 1 -keyout "$W/ph.key" -out "$W/ph.crt" -subj "/CN=placeholder" >/dev/null 2>&1
  kubectl create namespace kkak8s >/dev/null && kubectl -n kkak8s create secret tls kk-ak8s-tls --cert="$W/ph.crt" --key="$W/ph.key" >/dev/null && PASS "namespace + placeholder TLS Secret created"
  # s_server -naccept 1 in a loop: every connection re-reads the Secret files, so an update needs no reload.
  cat >"$W/pod.yaml" <<EOF
apiVersion: v1
kind: Pod
metadata: {name: kk-ak8s, namespace: kkak8s, labels: {app: kk-ak8s}}
spec:
  containers:
  - name: tls
    image: $IMAGE
    imagePullPolicy: Never
    command: ["sh", "-c", "while true; do openssl s_server -accept 8443 -cert /tls/tls.crt -key /tls/tls.key -naccept 1 -quiet </dev/null >/dev/null 2>&1; done"]
    volumeMounts: [{name: tls, mountPath: /tls, readOnly: true}]
  volumes: [{name: tls, secret: {secretName: kk-ak8s-tls}}]
---
apiVersion: v1
kind: Service
metadata: {name: kk-ak8s, namespace: kkak8s}
spec:
  type: NodePort
  selector: {app: kk-ak8s}
  ports: [{port: 8443, targetPort: 8443, nodePort: $NODEPORT}]
---
apiVersion: v1
kind: ServiceAccount
metadata: {name: kk-ak8s-pusher, namespace: kkak8s}
---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata: {name: kk-ak8s-pusher, namespace: kkak8s}
rules: [{apiGroups: [""], resources: ["secrets"], verbs: ["get", "create", "update"]}]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata: {name: kk-ak8s-pusher, namespace: kkak8s}
subjects: [{kind: ServiceAccount, name: kk-ak8s-pusher, namespace: kkak8s}]
roleRef: {kind: Role, name: kk-ak8s-pusher, apiGroup: rbac.authorization.k8s.io}
EOF
  # a fresh namespace's default ServiceAccount appears a moment after the namespace itself
  for _ in $(seq 1 20); do kubectl apply -f "$W/pod.yaml" >/dev/null 2>&1 && break; sleep 2; done
  kubectl apply -f "$W/pod.yaml" >/dev/null && kubectl -n kkak8s wait --for=condition=Ready pod/kk-ak8s --timeout=90s >/dev/null && PASS "workload pod ready" || DIE "workload pod not ready"
  SA_TOKEN="$(kubectl -n kkak8s create token kk-ak8s-pusher --duration=2h)"
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
print(json.dumps({"name": "ak8s-k8s", "credential_type": "api_token", "payload": {
  "base_url": sys.argv[1], "bearer_token": sys.argv[2].strip(), "namespace": "kkak8s", "secret_name": "kk-ak8s-tls",
  "ca_cert": open(sys.argv[3]).read()}}))
PY
  check "[k8s] create api_token credential" 201 "$(code "$T_alice" -X POST "$HUBURL/api/v1/credentials" --data @"$W/cred-k8s.json")"
  KCRED="$(jget 'd["data"]["id"]' <"$FX_RUN/last.json")"
  check "[k8s] create target" 201 "$(code "$T_alice" -X POST "$HUBURL/api/v1/targets" -d "{\"host\":\"$K8S_HOST\",\"discovery_mode\":\"network\",\"install_mode\":\"k8s\",\"credential_ref\":\"$KCRED\",\"verify_host_port\":\"$VERIFY_HOST:$NODEPORT\",\"name\":\"kk-ak8s-k8s\"}")"
  TGT[k]="$(jget 'd["data"]["id"]' <"$FX_RUN/last.json")"
  fp="$(issue_leaf k "$K8S_HOST")"
  check "[k8s] renewal/execute pushes the ECDSA leaf into the Secret" 200 "$(code "$T_alice" -X POST "$HUBURL/api/v1/renewal/execute" \
    -d "{\"fingerprint\":\"$fp\",\"target_id\":\"${TGT[k]}\",\"install\":{\"verify_host_port\":\"$VERIFY_HOST:$NODEPORT\"}}")"
  outcome="$(jget 'd["data"].get("install_outcome","")' <"$FX_RUN/last.json")"
  [ "$outcome" = installed_verified ] || FAIL "[k8s] install_outcome=$outcome ($(jget 'd["data"].get("install_detail","")' <"$FX_RUN/last.json" | head -c 600))"
  OLD_FP[k]="$(jget 'd["data"]["new_fingerprint"]' <"$FX_RUN/last.json")"
  hubser="$(cert_serial "${OLD_FP[k]}")"
  if wait_serial "$VERIFY_HOST:$NODEPORT" "$hubser" 150; then SERIAL_BEFORE[k]="$hubser"; PASS "[k8s] the workload serves the hub-issued ECDSA leaf (serial $hubser)"
  else FAIL "[k8s] served serial $(probe a "$VERIFY_HOST:$NODEPORT") != hub serial $hubser"; fi
else
  SKIP "k8s leg not run: $K8S_SKIP"
fi

STEP "5. wave: create, add members, accept"
check "create wave" 201 "$(code "$T_alice" -X POST "$HUBURL/api/v1/reports/pqc-waves" -d '{"name":"ak8s-live","owner":"alice"}')"
WAVE="$(jget 'd["data"]["id"]' <"$FX_RUN/last.json")"
MEMBERS="a af"; [ "$K8S_MEMBER" = 1 ] && MEMBERS="a af k"
for e in $MEMBERS; do
  check "add member [$e]" 200 "$(code "$T_alice" -X POST "$HUBURL/api/v1/reports/pqc-waves/$WAVE/members" -d "{\"fingerprint\":\"${OLD_FP[$e]}\"}")"
done
check "accept wave" 200 "$(code "$T_alice" -X POST "$HUBURL/api/v1/reports/pqc-waves/$WAVE/accept")"
declare -A KEYHASH_BEFORE
KEYHASH_BEFORE[af]="$(podman exec kkak8s-ep-af cat /etc/ssl/kk/server.crt /etc/ssl/kk/server.key | sha256sum | cut -d' ' -f1)"
if [ "$K8S_MEMBER" = 1 ]; then
  KEYHASH_BEFORE[k]="$(kubectl -n kkak8s get secret kk-ak8s-tls -o go-template='{{index .data "tls.crt"}}{{index .data "tls.key"}}' | sha256sum | cut -d' ' -f1)"
  check "[k8s] PATCH verify_host_port -> ep-a:443 (serves a different cert, so verify can never match)" 200 "$(code "$T_alice" -X PATCH "$HUBURL/api/v1/targets/${TGT[k]}" -d '{"verify_host_port":"kkak8s-ep-a:443"}')"
fi
check "[ep-af] PATCH verify_host_port -> ep-a:443 (wrong fingerprint after install)" 200 "$(code "$T_alice" -X PATCH "$HUBURL/api/v1/targets/${TGT[af]}" -d '{"verify_host_port":"kkak8s-ep-a:443"}')"

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
  if [ "$e" = af ] || [ "$e" = k ]; then
    [ "$st" = failed ] && [ "$dl" = failed ] && [ "$oldserved" = True ] && PASS "[$e] status=failed delivery=failed old_serial_served=true" || FAIL "[$e] status=$st delivery=$dl old_serial_served=$oldserved reason=$why"
    case "$why" in *"rolled back"*) PASS "[$e] reason reports the rollback: ${why:0:160}";; *) FAIL "[$e] reason lacks rollback: $why";; esac
  else
    [ "$st" = migrated ] && [ "$dl" = verified ] && PASS "[$e] status=migrated delivery=verified" || FAIL "[$e] status=$st delivery=$dl reason=$why"
  fi
  NSER[$e]="$(cert_serial "$nfp")"
  jget 'd["data"].get("key_algorithm_display","")' <"$FX_RUN/last.json" | grep -qx ML-DSA-65 && PASS "[$e] successor ${nfp:0:12} is ML-DSA-65 in the hub inventory" || FAIL "[$e] successor is not ML-DSA-65"
done

STEP "8. what the endpoints actually serve, observed by openssl s_client in a container"
for e in a; do
  host="kkak8s-ep-$e:443"
  if wait_serial "$host" "$(echo "${NSER[$e]}" | norm)" 30; then PASS "[ep-$e] apache serial ${SERIAL_BEFORE[$e]} -> $(probe a "$host") (the successor)"; else FAIL "[ep-$e] served '$(probe a "$host")' != successor ${NSER[$e]}"; fi
  podman exec kkak8s-ep-a sh -c "echo | openssl s_client -connect $host -servername x 2>/dev/null | openssl x509 -noout -text" | grep -q 'Public Key Algorithm: ML-DSA-65' && PASS "[ep-$e] served certificate is ML-DSA-65" || FAIL "[ep-$e] served certificate is not ML-DSA-65"
  podman exec "kkak8s-ep-$e" sh -c "httpd -t >/dev/null 2>&1" && PASS "[ep-$e] httpd -t accepts the delivered ML-DSA cert and key" || FAIL "[ep-$e] httpd -t rejects it"
done
if wait_serial kkak8s-ep-af:443 "${SERIAL_BEFORE[af]}" 30; then PASS "[ep-af] rolled back: old serial ${SERIAL_BEFORE[af]} still served"; else FAIL "[ep-af] served '$(probe a kkak8s-ep-af:443)' != old ${SERIAL_BEFORE[af]}"; fi
[ "$(podman exec kkak8s-ep-af cat /etc/ssl/kk/server.crt /etc/ssl/kk/server.key | sha256sum | cut -d' ' -f1)" = "${KEYHASH_BEFORE[af]}" ] && PASS "[ep-af] cert and key files restored byte-for-byte" || FAIL "[ep-af] cert/key files differ from before the wave"
if [ "$K8S_MEMBER" = 1 ]; then
  # The kubelet syncs Secret volumes lazily (tens of seconds), so the pod can still hold the unverified successor
  # when the hub has already restored the Secret. Sample until the previous serial is stable (4 samples, 5s apart),
  # and record every serial seen: the transitions are part of the evidence.
  K_SEEN=""; K_STABLE=0; K_LAST=""; t=60
  while [ "$t" -gt 0 ] && [ "$K_STABLE" -lt 4 ]; do
    s="$(probe a "$VERIFY_HOST:$NODEPORT")"
    [ "$s" != "$K_LAST" ] && K_SEEN="$K_SEEN ${s:-none}" && K_LAST="$s"
    if [ "$s" = "${SERIAL_BEFORE[k]}" ]; then K_STABLE=$((K_STABLE+1)); else K_STABLE=0; fi
    t=$((t-1)); [ "$K_STABLE" -lt 4 ] && sleep 5
  done
  say "[k8s] serials seen by the probe after the wave (in order):$K_SEEN"
  if [ "$K_STABLE" -ge 4 ]; then PASS "[k8s] rolled back: workload stably serves the previous serial ${SERIAL_BEFORE[k]} again"; else FAIL "[k8s] workload did not settle on the previous serial ${SERIAL_BEFORE[k]}"; fi
  K_ALGO="$(podman exec kkak8s-ep-a sh -c "echo | openssl s_client -connect $VERIFY_HOST:$NODEPORT -servername x 2>/dev/null | openssl x509 -noout -text" | grep 'Public Key Algorithm' | head -1 | tr -s ' ')"
  case "$K_ALGO" in *ML-DSA*) FAIL "[k8s] workload serves an ML-DSA certificate after rollback ($K_ALGO)";; *) PASS "[k8s] workload serves a non-ML-DSA certificate after rollback ($K_ALGO)";; esac
  [ "$(kubectl -n kkak8s get secret kk-ak8s-tls -o go-template='{{index .data "tls.crt"}}{{index .data "tls.key"}}' | sha256sum | cut -d' ' -f1)" = "${KEYHASH_BEFORE[k]}" ] && PASS "[k8s] Secret tls.crt and tls.key restored byte-for-byte" || FAIL "[k8s] Secret differs from before the wave"
fi

STEP "9. wave status and audit trail"
code "$T_alice" "$HUBURL/api/v1/reports/pqc-waves" >/dev/null
WSTAT="$(python3 -c "import json;d=json.load(open('$FX_RUN/last.json'))['data'];w=[x for x in d if x['id']=='$WAVE'][0];print(w['status'],w['migrated'],w['total'])")"
say "wave: status migrated total = $WSTAT"
[ "${WSTAT%% *}" = regressed ] && PASS "wave reported regressed (ep-af failed)" || FAIL "wave status '${WSTAT%% *}', want regressed"
code "$T_alice" "$HUBURL/api/v1/audit?limit=1000" >/dev/null
AUD="$(cat "$FX_RUN/last.json")"
N="$(echo "$AUD" | grep -o 'key.export_for_delivery' | wc -l | tr -d ' ')"
WANT=$(echo $MEMBERS | wc -w | tr -d ' ')
[ "$N" -ge "$WANT" ] && PASS "audit has $N key.export_for_delivery rows (>= $WANT members)" || FAIL "audit has only $N key.export_for_delivery rows, want $WANT"
echo "$AUD" | grep -q 'PRIVATE KEY' && FAIL "audit trail contains key material" || PASS "audit trail contains no private-key PEM"

STEP "10. summary"
if [ "$FAILED" = 0 ]; then say "ALL PASS"; else say "ONE OR MORE STEPS FAILED"; fi
exit "$FAILED"
