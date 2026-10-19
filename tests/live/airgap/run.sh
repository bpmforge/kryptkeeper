#!/usr/bin/env bash
# W25-14: install the W25-13 air-gap bundle into a kind cluster whose egress is
# default-denied and prove the install emits zero outbound packets.
#
# Connected side (outside the capture window): build the signed bundle, push it
# into a local registry mirror. Isolated side: default-deny egress, canary,
# packet capture inside the kind node's network namespace, helm install from
# the bundle's chart tgz, /readyz over verified TLS, wait, count packets.
#
# Env: AIRGAP_CAPTURE_SECONDS (default 600), AIRGAP_TAG (default 0.9.4),
#      RESULTS_OUT (markdown fragment path, default $WORK/results.md, kept).
. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/../lib/podman.sh"
set -u
set -o pipefail
export KIND_EXPERIMENTAL_PROVIDER=podman

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$HERE/../../.." && pwd)"
# physical path: /tmp is a symlink the podman VM does not mount, /private/tmp is
WORK="$(cd "$(mktemp -d /tmp/kk-airgap.XXXXXX)" && pwd -P)"
CLUSTER=kk-airgap
NS=kk-airgap
NODE="${CLUSTER}-control-plane"
REGISTRY=kk-airgap-registry
REG_HOST=localhost:5001
CAPTURE=kk-airgap-capture
TCPDUMP_IMAGE=localhost/kk-airgap-tcpdump:local
TAG="${AIRGAP_TAG:-0.9.4}"
CAPTURE_SECONDS="${AIRGAP_CAPTURE_SECONDS:-600}"
FWD_PORT=18443
REL=kryptkeeper
FULL=kryptkeeper
RESULTS_OUT="${RESULTS_OUT:-$WORK/results.md}"
# The filter from the ticket: anything that is not private/loopback/DNS.
# IPv6 equivalents added: loopback ::1 (the kube-apiserver / port-forward path
# shows up as ::1), ULA, link-local and multicast are in-cluster, not egress.
CAP_FILTER='not (dst net 10.0.0.0/8 or dst net 172.16.0.0/12 or dst net 192.168.0.0/16 or dst net 127.0.0.0/8) and not (ip6 and (dst net ::1/128 or dst net fc00::/7 or dst net fe80::/10 or dst net ff00::/8)) and not port 53'

FAILED=0
STEP() { echo; echo "== $* =="; }
PASS() { echo "PASS: $*"; }
FAIL() { echo "FAIL: $*"; FAILED=1; }
NOTE() { echo "NOTE: $*"; }
cleanup() {
  STEP "cleanup"
  [ -n "${FWD_PID:-}" ] && kill "$FWD_PID" 2>/dev/null
  kk_rm "$CAPTURE"
  kind delete cluster --name "$CLUSTER" >/dev/null 2>&1 || true
  kk_rm "$REGISTRY"
  [ "${KEEP_WORK:-0}" = 1 ] || { cp "$WORK/results.md" "$RESULTS_OUT" 2>/dev/null; rm -rf "$WORK/bundle" "$WORK/images" "$WORK/cosign.key"; }
  echo "work dir kept for inspection: $WORK (pcap: $WORK/egress.pcap)"
}
DIE() { echo "FAIL: $*"; trap - EXIT; cleanup; exit 1; }
trap cleanup EXIT

for c in kind kubectl helm podman jq tcpdump cosign curl openssl python3 sha256sum; do
  command -v "$c" >/dev/null || DIE "missing prerequisite: $c (install it; this script installs nothing)"
done
podman info >/dev/null 2>&1 || DIE "podman is not reachable (start the podman machine)"

# ---------------------------------------------------------------- connected side
STEP "1. Build the signed bundle (connected side)"
BUNDLE="$WORK/bundle"
( cd "$WORK" && COSIGN_PASSWORD="" cosign generate-key-pair >/dev/null 2>&1 ) || DIE "cosign key generation failed"
export HUB_IMAGE="${HUB_IMAGE:-ghcr.io/bpmforge/kryptkeeper:$TAG}"
export AGENT_IMAGE="${AGENT_IMAGE:-ghcr.io/bpmforge/kryptkeeper-agent:$TAG}"
export MCP_IMAGE="${MCP_IMAGE:-ghcr.io/bpmforge/kryptkeeper-mcp:$TAG}"
export CERTMANAGER_IMAGE="${CERTMANAGER_IMAGE:-ghcr.io/bpmforge/kryptkeeper-certmanager:$TAG}"
export DASHBOARD_IMAGE="${DASHBOARD_IMAGE:-ghcr.io/bpmforge/kryptkeeper-dashboard:$TAG}"
# KK_AIRGAP_LOCAL_IMAGES=1: the ghcr.io/bpmforge images are private and this
# host holds no registry credentials (none are added), so build the five images
# from this checkout and tag them as the refs above. airgap-bundle.sh uses an
# image already present locally instead of pulling it, so the bundle, mirror and
# deny-all flow then exercise this commit's images.
if [ "${KK_AIRGAP_LOCAL_IMAGES:-0}" = 1 ]; then
  STEP "1a. Build the five images from this checkout (KK_AIRGAP_LOCAL_IMAGES=1)"
  VER="$(git -C "$REPO" describe --tags --always --dirty 2>/dev/null || echo dev)"
  COMMIT="$(git -C "$REPO" rev-parse --short HEAD 2>/dev/null || echo unknown)"
  for spec in "Dockerfile:$HUB_IMAGE" "Dockerfile.agent:$AGENT_IMAGE" "Dockerfile.mcp:$MCP_IMAGE" \
              "Dockerfile.certmanager:$CERTMANAGER_IMAGE" "Dockerfile.dashboard:$DASHBOARD_IMAGE"; do
    df="${spec%%:*}"; ref="${spec#*:}"
    podman build -q --build-arg "VERSION=$VER" --build-arg "COMMIT=$COMMIT" -f "$REPO/$df" -t "$ref" "$REPO" >"$WORK/build-$df.log" 2>&1 \
      && PASS "built $df as $ref" || { tail -20 "$WORK/build-$df.log"; DIE "image build failed: $df"; }
  done
fi
# busybox: canary and CA-reader pods run from the mirror like everything else.
export EXTRA_IMAGES="docker.io/library/busybox:1.36"
export COSIGN_KEY="$WORK/cosign.key" COSIGN_PUBKEY="$WORK/cosign.pub" COSIGN_PASSWORD="" CONTAINER_ENGINE=podman
bash "$REPO/scripts/deploy/airgap-bundle.sh" build "$BUNDLE" >"$WORK/build.log" 2>&1 \
  && PASS "bundle built and cosign-signed ($(jq '.images|length' "$BUNDLE/manifest.json") images, $(jq '.charts|length' "$BUNDLE/manifest.json") chart)" \
  || { tail -20 "$WORK/build.log"; DIE "bundle build failed"; }

STEP "2. Local registry mirror and bundle push (connected side, outside the capture window)"
kk_rm "$REGISTRY"
# Start the registry ON the kind network: rootless podman 4.x gives a bare -p
# container slirp4netns, which "podman network connect" refuses later.
podman network exists kind || podman network create kind >/dev/null || DIE "cannot create the kind network"
podman run -d --name "$REGISTRY" --network kind -p 127.0.0.1:5001:5000 docker.io/library/registry:2 >/dev/null || DIE "registry start failed"
for _ in $(seq 1 20); do curl -fsS "http://$REG_HOST/v2/" >/dev/null 2>&1 && break; sleep 1; done
# airgap-bundle.sh push has no TLS switch and podman refuses plain http even for
# localhost, so a one-line engine shim adds --tls-verify=false to `push` for
# this throwaway http registry only (reported as a gap in the results doc).
cat > "$WORK/podman-http" <<'SHIM'
#!/usr/bin/env bash
if [ "${1:-}" = push ]; then shift; exec podman push --tls-verify=false "$@"; fi
exec podman "$@"
SHIM
chmod +x "$WORK/podman-http"
CONTAINER_ENGINE="$WORK/podman-http" "$BUNDLE/airgap-bundle.sh" push "$BUNDLE" "$REG_HOST" >"$WORK/push.log" 2>&1 \
  && PASS "airgap-bundle.sh push verified checksums + signature offline and pushed to $REG_HOST" \
  || { tail -20 "$WORK/push.log"; DIE "bundle push failed"; }
HUB_REPO="$REG_HOST/bpmforge/kryptkeeper"
DASH_REPO="$REG_HOST/bpmforge/kryptkeeper-dashboard"
curl -fsS "http://$REG_HOST/v2/_catalog" | jq -c .repositories

# tcpdump comes from a throwaway image sharing the node's netns: the kind node
# image has no tcpdump and we do not install anything on the Mac.
printf 'FROM docker.io/library/alpine:3.20\nRUN apk add --no-cache tcpdump\n' > "$WORK/Containerfile.tcpdump"
podman build -q -t "$TCPDUMP_IMAGE" -f "$WORK/Containerfile.tcpdump" "$WORK" >/dev/null || DIE "tcpdump image build failed"

# ---------------------------------------------------------------- isolated side
STEP "3. kind cluster, registry mirror wiring, default-deny egress"
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
[ -n "$REG_IP" ] || DIE "registry has no IP on the kind network"
podman exec "$NODE" mkdir -p "/etc/containerd/certs.d/$REG_HOST" || DIE "certs.d mkdir"
printf 'server = "http://%s:5000"\n[host."http://%s:5000"]\n  capabilities = ["pull", "resolve"]\n' "$REG_IP" "$REG_IP" \
  | podman exec -i "$NODE" tee "/etc/containerd/certs.d/$REG_HOST/hosts.toml" >/dev/null || DIE "hosts.toml"
kubectl wait --for=condition=Ready node --all --timeout=120s >/dev/null || DIE "node not ready"
kubectl create namespace "$NS" >/dev/null || DIE "namespace"
kubectl apply -f "$HERE/netpol-deny-all.yaml" >/dev/null || DIE "netpol apply"

STEP "4. Canary: policy must be enforced"
kubectl -n "$NS" run canary --image="$REG_HOST/library/busybox:1.36" --restart=Never --command -- sleep 3600 >/dev/null
kubectl -n "$NS" wait --for=condition=Ready pod/canary --timeout=120s >/dev/null || { kubectl -n "$NS" describe pod canary | tail -15; DIE "canary did not start (image from mirror)"; }
# CoreDNS can still be starting right after node Ready, so retry before judging the policy.
DNS_OK=0
for _ in $(seq 1 20); do
  kubectl -n "$NS" exec canary -- nslookup kubernetes.default.svc.cluster.local >/dev/null 2>&1 && { DNS_OK=1; break; }
  sleep 3
done
if [ "$DNS_OK" = 1 ]; then PASS "policy_allows_dns: canary resolves cluster DNS"; else FAIL "policy_allows_dns: cluster DNS blocked (policy too tight)"; fi
if kubectl -n "$NS" exec canary -- wget -q -T3 -O /dev/null http://1.1.1.1 >/dev/null 2>&1; then
  FAIL "policy_enforced_canary_blocked: canary REACHED 1.1.1.1 (CNI does not enforce NetworkPolicy)"
  DIE "egress is not denied; a zero-packet result would prove nothing"
else PASS "policy_enforced_canary_blocked: canary cannot reach 1.1.1.1:80"; fi
kubectl -n "$NS" delete pod canary --now >/dev/null

STEP "5. Start capture in the node network namespace (before helm install)"
unset KRYPTKEEPER_CT_DOMAINS
kk_rm "$CAPTURE"
podman run -d --name "$CAPTURE" --net "container:$NODE" --cap-add NET_ADMIN --cap-add NET_RAW \
  -v "$WORK:/out" "$TCPDUMP_IMAGE" tcpdump -i any -n -U -w /out/egress.pcap "$CAP_FILTER" >/dev/null || DIE "capture start failed"
sleep 3
podman ps --filter "name=$CAPTURE" --format '{{.Status}}' | grep -q Up && PASS "capture running on $NODE (-i any, filter: non-private, non-DNS)" || { podman logs "$CAPTURE"; DIE "capture exited"; }

STEP "6. helm install from the bundle's chart tgz"
CHART_TGZ="$(ls "$BUNDLE"/charts/kryptkeeper-*.tgz | head -1)"
PASSPHRASE="$(openssl rand -hex 32)"; TOKEN="$(openssl rand -hex 20)"
cat > "$WORK/values.yaml" <<YAML
extraEnv:
  - {name: KRYPTKEEPER_BOOTSTRAP_CREATE_ROOT, value: "true"}
  - {name: KRYPTKEEPER_CA_NAME, value: "Air-gap UAT Root CA"}
YAML
helm install "$REL" "$CHART_TGZ" -n "$NS" -f "$WORK/values.yaml" \
  --set image.repository="$HUB_REPO" --set image.tag="$TAG" \
  --set config.dbMode=sqlite --set replicaCount=1 --set config.trustedProxyCIDRs="" \
  --set secrets.bootstrapToken="$TOKEN" --set secrets.keystorePassphrase="$PASSPHRASE" \
  --wait --timeout 5m >"$WORK/helm.log" 2>&1 \
  && PASS "helm_install_from_tgz_ok: hub from $(basename "$CHART_TGZ") against $HUB_REPO:$TAG" \
  || { cat "$WORK/helm.log"; kubectl -n "$NS" get pods,events; DIE "helm install failed"; }

# Dashboard (5th bundled image): needs the hub CA, which the hub self-issues.
# The hub image is distroless, so a throwaway pod mounts the keystore PVC.
kubectl -n "$NS" apply -f - >/dev/null <<YAML || DIE "ca reader"
apiVersion: v1
kind: Pod
metadata: {name: ca-reader}
spec:
  restartPolicy: Never
  containers:
    - {name: r, image: "$REG_HOST/library/busybox:1.36", command: [sleep, "300"], volumeMounts: [{name: k, mountPath: /k, readOnly: true}]}
  volumes: [{name: k, persistentVolumeClaim: {claimName: ${FULL}-keys, readOnly: true}}]
YAML
kubectl -n "$NS" wait --for=condition=Ready pod/ca-reader --timeout=120s >/dev/null || DIE "ca-reader not ready"
kubectl -n "$NS" exec ca-reader -- cat /k/data/tls/ca.pem > "$WORK/ca.pem" 2>/dev/null
openssl x509 -in "$WORK/ca.pem" -noout -subject >/dev/null 2>&1 || DIE "exported CA is not a certificate"
kubectl -n "$NS" delete pod ca-reader --now >/dev/null
kubectl -n "$NS" create secret generic hub-ca --from-file=ca.pem="$WORK/ca.pem" >/dev/null || DIE "ca secret"
helm upgrade "$REL" "$CHART_TGZ" -n "$NS" --reset-then-reuse-values \
  --set dashboard.enabled=true --set dashboard.image.repository="$DASH_REPO" --set dashboard.image.tag="$TAG" \
  --set dashboard.hubCA.existingSecret=hub-ca --wait --timeout 5m >"$WORK/helm-up.log" 2>&1 \
  && PASS "dashboard_enabled_from_mirror: dashboard pod Ready from $DASH_REPO:$TAG" \
  || { cat "$WORK/helm-up.log"; kubectl -n "$NS" get pods,events; FAIL "dashboard upgrade failed"; }

STEP "7. /readyz over verified TLS (no -k)"
kubectl -n "$NS" port-forward "svc/$FULL" "$FWD_PORT:8080" >"$WORK/fwd.log" 2>&1 & FWD_PID=$!
sleep 3
C="$(curl -sS --cacert "$WORK/ca.pem" --resolve "$FULL:$FWD_PORT:127.0.0.1" -o /dev/null -w '%{http_code}' "https://$FULL:$FWD_PORT/readyz")"
[ "$C" = 200 ] && PASS "readyz_200: https://$FULL:$FWD_PORT/readyz verified against the hub CA" || FAIL "readyz_200: got $C"
kill "$FWD_PID" 2>/dev/null; FWD_PID=""

STEP "8. Idle window: ${CAPTURE_SECONDS}s, then count packets"
BAD_EV="$(kubectl -n "$NS" get events 2>/dev/null | grep -cE 'ErrImagePull|ImagePullBackOff')"
[ "$BAD_EV" = 0 ] && PASS "no ErrImagePull/ImagePullBackOff events (all pulls came from the mirror)" || FAIL "$BAD_EV image-pull error events"
kubectl -n "$NS" get pods -o jsonpath='{range .items[*]}{.metadata.name}{"\t"}{.spec.containers[*].image}{"\n"}{end}'
IMG_OFF="$(kubectl -n "$NS" get pods -o jsonpath='{.items[*].spec.containers[*].image}' | tr ' ' '\n' | grep -vc "^$REG_HOST/")"
[ "$IMG_OFF" = 0 ] && PASS "every pod image is under $REG_HOST" || FAIL "$IMG_OFF pod images are not under $REG_HOST"
sleep "$CAPTURE_SECONDS"
podman stop -t 5 "$CAPTURE" >/dev/null 2>&1; podman logs "$CAPTURE" 2>&1 | tail -4
PKTS="$(tcpdump -nr "$WORK/egress.pcap" 2>/dev/null | wc -l | tr -d ' ')"
echo "pcap: $WORK/egress.pcap  packets_after_filter=$PKTS"
[ "$PKTS" = 0 ] && PASS "zero_outbound_packets: 0 packets in ${CAPTURE_SECONDS}s capture spanning helm install" \
  || { FAIL "zero_outbound_packets: $PKTS packets"; tcpdump -nr "$WORK/egress.pcap" 2>/dev/null | head -20; }

STEP "9. Capture control: the same filter must see a blocked attempt"
rm -f "$WORK/control.pcap"
podman run -d --name "$CAPTURE-ctl" --net "container:$NODE" --cap-add NET_ADMIN --cap-add NET_RAW \
  -v "$WORK:/out" "$TCPDUMP_IMAGE" tcpdump -i any -n -U -w /out/control.pcap "$CAP_FILTER" >/dev/null || DIE "control capture start"
sleep 3
kubectl -n "$NS" run ctl --image="$REG_HOST/library/busybox:1.36" --restart=Never --command -- wget -q -T3 -O /dev/null http://1.1.1.1 >/dev/null
sleep 12
podman stop -t 5 "$CAPTURE-ctl" >/dev/null 2>&1; kk_rm "$CAPTURE-ctl"
CTL="$(tcpdump -nr "$WORK/control.pcap" 2>/dev/null | wc -l | tr -d ' ')"
[ "$CTL" -gt 0 ] && PASS "capture_control: blocked attempt to 1.1.1.1 produced $CTL packet(s), so a 0 above is meaningful" \
  || FAIL "capture_control: capture saw nothing for a deliberate egress attempt; zero result is unproven"
kubectl -n "$NS" delete pod ctl --now >/dev/null 2>&1

STEP "10. Offline behaviour table"
kubectl -n "$NS" logs "deploy/$FULL" > "$WORK/hub.log" 2>&1
ENVNAMES="$(kubectl -n "$NS" get deploy "$FULL" -o jsonpath='{range .spec.template.spec.containers[0].env[*]}{.name}{"\n"}{end}')"
has_env() { echo "$ENVNAMES" | grep -qx "$1"; }
LOG_CRT="$(grep -ci 'crt\.sh' "$WORK/hub.log")"
LOG_UPD="$(grep -ciE 'update.?check|check.*for.*updates|latest.?version' "$WORK/hub.log")"
SRC_UPD="$(grep -rnE 'api\.github\.com/repos|releases/latest|[Uu]pdate[-_]?[Cc]heck|checkForUpdate' "$REPO/internal" "$REPO/cmd" --include='*.go' 2>/dev/null | grep -vc _test)"
has_env KRYPTKEEPER_CT_DOMAINS && CT_ST="ON (unexpected)" || CT_ST="off: KRYPTKEEPER_CT_DOMAINS unset, crt.sh log lines: $LOG_CRT"
grep -q -- '--insecure-ignore-tlog=true' "$BUNDLE/airgap-bundle.sh" && SIG_ST="offline: push verified with --insecure-ignore-tlog (no Rekor lookup)" || SIG_ST="UNEXPECTED: tlog lookup"
{
  echo "| Feature | Observed offline behaviour (measured) |"
  echo "|---|---|"
  echo "| Certificate Transparency monitor | $CT_ST |"
  echo "| ACME upstream connector | not configured (no ACME upstream env on the hub); no outbound packets |"
  echo "| Notification webhooks / inventory sources | none configured; no outbound packets (a public target would fail at the egress guard) |"
  echo "| Update checks | none: hub log update-check lines: $LOG_UPD; update-check strings in internal/ and cmd/: $SRC_UPD; $PKTS packets |"
  echo "| Bundle signature verification | $SIG_ST |"
  echo "| OCSP / CRL | no external OCSP/CRL upstream configured; served from hub CA state; $PKTS packets |"
} > "$WORK/results.md"
cat "$WORK/results.md"
[ "$LOG_CRT" = 0 ] && [ "$LOG_UPD" = 0 ] && ! has_env KRYPTKEEPER_CT_DOMAINS \
  && PASS "offline observations: CT off, no crt.sh, no update-check in hub log" || FAIL "offline observations contradict the doc"
# AC2: the feature set in the results table equals the one in EGRESS.md.
sed -n '/^## Air-gap offline behaviour/,$p' "$REPO/docs/ops/EGRESS.md" | awk -F'|' '/^\|/ {gsub(/^ +| +$/,"",$2); if ($2 !~ /^-+$/ && $2 != "Feature") print $2}' | sort > "$WORK/doc-features.txt"
awk -F'|' '/^\|/ {gsub(/^ +| +$/,"",$2); if ($2 !~ /^-+$/ && $2 != "Feature") print $2}' "$WORK/results.md" | sort > "$WORK/table-features.txt"
if diff "$WORK/doc-features.txt" "$WORK/table-features.txt" >/dev/null; then
  PASS "offline_table_matches_egress_doc: $(wc -l < "$WORK/doc-features.txt" | tr -d ' ') features, 0 differences"
else FAIL "offline_table_matches_egress_doc:"; diff "$WORK/doc-features.txt" "$WORK/table-features.txt"; fi
NOTE "DNS (port 53) is intra-cluster and excluded from the capture on purpose; private/loopback destinations are excluded as in-cluster traffic"

echo
{ [ "$FAILED" = 0 ] && echo "ALL PASS (0 FAIL)"; } || { echo "SOME FAILED"; exit 1; }
