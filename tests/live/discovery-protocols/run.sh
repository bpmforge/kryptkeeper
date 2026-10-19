#!/usr/bin/env bash
# W24-03: live protocol-scan harness. Real postfix (25, 587), dovecot (143,
# 110), PostgreSQL (5432), OpenLDAP StartTLS (389), xrdp (3389) and sshd (22)
# in ONE container; a containerised hub runs a full scan against it and
# compare.py checks that every served leaf fingerprint (SSH: host-key
# algorithm list) shows up in discovery, per protocol.
#
# Expected values come from the servers' own files, never from the hub.
# Podman only. PASS/FAIL per step, non-zero exit on any FAIL, trap cleanup.
# xrdp is flaky without systemd: if it is not listening in 20 s the harness
# falls back to rdpstub/ and labels the run rdp:stub (RDP_MODE in report.json).
# KK_EVIDENCE_DIR receives report.json.
. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/../lib/podman.sh"
set -u
set -o pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$HERE/../../.." && pwd)"
WORK="$(mktemp -d /tmp/kk-uat-proto.XXXXXX)"
RUN_ID="$(openssl rand -hex 3)"
free_port() { python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1]); s.close()'; }
HUB_PORT="$(free_port)"
HUB_BASE="http://127.0.0.1:${HUB_PORT}"
TOKEN=uat-token
FIX_IMAGE="localhost/kk-uat-proto:$RUN_ID"
HUB_IMAGE="localhost/kk-uat-proto-hub:$RUN_ID"
NET="kk-uat-proto-net-$RUN_ID"
FIX_CTR="kk-uat-proto-fix-$RUN_ID"
HUB_CTR="kk-uat-proto-hub-$RUN_ID"
RDP_MODE=xrdp

FAILED=0
STEP() { echo; echo "== $* =="; }
PASS() { echo "PASS: $*"; }
FAIL() { echo "FAIL: $*"; FAILED=1; }
DIE()  { echo "FAIL: $*"; cleanup; exit 1; }

cleanup() {
  STEP "cleanup"
  kk_rm "$FIX_CTR" "$HUB_CTR"
  podman network rm "$NET" >/dev/null 2>&1 || true
  podman rmi -f "$FIX_IMAGE" "$HUB_IMAGE" >/dev/null 2>&1 || true
  rm -rf "$WORK"
}
trap cleanup EXIT

curlj() { curl -sS -H "Authorization: Bearer ${TOKEN}" -H 'Content-Type: application/json' "$@"; }

port_open() { podman exec "$FIX_CTR" bash -c "exec 3<>/dev/tcp/127.0.0.1/$1" 2>/dev/null; }

STEP "build and start the multi-service fixture"
GOARCH="$(kk_goarch)"
podman build -t "$FIX_IMAGE" "$HERE" >"$WORK/build-fix.log" 2>&1 \
  && PASS "fixture image built" || { tail -20 "$WORK/build-fix.log"; DIE "fixture build failed"; }
podman network create "$NET" >/dev/null && PASS "network $NET" || DIE "network create failed"
podman run -d --name "$FIX_CTR" --network "$NET" "$FIX_IMAGE" >/dev/null \
  && PASS "fixture container up" || DIE "failed to start fixture"

PORTS="22 25 587 110 143 389 5432"
tries=60
while [ $tries -gt 0 ]; do
  missing=""
  for p in $PORTS; do port_open "$p" || missing="$missing $p"; done
  [ -z "$missing" ] && break
  tries=$((tries - 1)); sleep 1
done
if [ -n "$missing" ]; then podman logs "$FIX_CTR" 2>&1 | tail -30; DIE "ports never opened:$missing"; fi
PASS "ports open: $PORTS"

# xrdp: give it 20 s, then fall back to the labelled stub.
tries=20
until port_open 3389; do
  tries=$((tries - 1))
  if [ $tries -le 0 ]; then
    RDP_MODE=stub
    echo "xrdp not listening after 20 s: falling back to rdpstub (labelled rdp:stub)"
    ( cd "$HERE/rdpstub" && CGO_ENABLED=0 GOOS=linux GOARCH=$GOARCH go build -o "$WORK/rdpstub" . ) || DIE "rdpstub build failed"
    podman cp "$WORK/rdpstub" "$FIX_CTR:/usr/local/bin/rdpstub" >/dev/null || DIE "cannot copy rdpstub"
    podman exec -d "$FIX_CTR" /usr/local/bin/rdpstub -cert /etc/kk-certs/rdp.crt -key /etc/kk-certs/rdp.key -listen :3389
    sleep 2
    port_open 3389 || DIE "rdpstub never listened"
    break
  fi
  sleep 1
done
PASS "rdp listening (mode=$RDP_MODE)"

STEP "expected values straight from the servers"
{
  echo '{'
  first=1
  for stem in smtp imap postgres ldap rdp; do
    fp="$(podman exec "$FIX_CTR" openssl x509 -in "/etc/kk-certs/$stem.crt" -noout -fingerprint -sha256 | cut -d= -f2 | tr -d ':' | tr 'A-F' 'a-f')"
    [ -n "$fp" ] || DIE "no fingerprint for $stem"
    [ $first -eq 1 ] || echo ','
    first=0
    printf '"%s": "%s"' "$stem" "$fp"
  done
  algs=""
  for k in ed25519 ecdsa rsa; do
    podman exec "$FIX_CTR" test -f "/etc/ssh/ssh_host_${k}_key.pub" || continue
    case "$k" in ed25519) a=ssh-ed25519 ;; ecdsa) a=ecdsa-sha2-nistp256 ;; rsa) a=rsa-sha2-512 ;; esac
    algs="$algs\"$a\","
  done
  echo ','
  printf '"ssh_algorithms": [%s]\n' "${algs%,}"
  echo '}'
} >"$WORK/fingerprints.json"
python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); print("fingerprints:", {k:(v[:16] if isinstance(v,str) else v) for k,v in d.items()})' "$WORK/fingerprints.json" \
  && PASS "expected fingerprints and SSH host-key algorithms captured" || DIE "bad fingerprints.json"

STEP "build and start hub"
mkdir -p "$WORK/hubctx"
( cd "$REPO_ROOT" && GOOS=linux GOARCH=$GOARCH CGO_ENABLED=0 go build -o "$WORK/hubctx/kryptkeeper" ./cmd/kryptkeeper ) \
  && PASS "hub built (linux/$GOARCH)" || DIE "go build failed"
cp "$REPO_ROOT/tests/live/autopilot/hub.Containerfile" "$WORK/hubctx/Containerfile"
podman build -t "$HUB_IMAGE" "$WORK/hubctx" >"$WORK/build-hub.log" 2>&1 \
  && PASS "hub image built" || DIE "hub image build failed, see $WORK/build-hub.log"
cat >"$WORK/hub.env" <<ENV
APP_BOOTSTRAP_TOKEN=$TOKEN
AUTH_MODE=bootstrap
APP_CERTIFICATE_PROVIDER=ca
APP_DISCOVERY_PROVIDER=db
APP_NOTIFICATION_PROVIDER=file
KRYPTKEEPER_TLS_DISABLE=true
APP_CREDENTIAL_STORE_PASSPHRASE=uat-cred-passphrase-32-bytes-long!!
KRYPTKEEPER_KEYSTORE_PASSPHRASE=uat-keystore-passphrase-32-bytes!!
KRYPTKEEPER_DATA_DIR=/data
APP_CA_FILE=/data/cas.json
APP_TEMPLATE_FILE=/data/templates.json
APP_CERTIFICATE_FILE=/data/certificates.json
APP_AUDIT_FILE=/data/audit.json
APP_CERTS_SUMMARY_FILE=/data/certs_summary.json
KRYPTKEEPER_BOOTSTRAP_CREATE_ROOT=true
KRYPTKEEPER_CA_NAME=UAT Root CA
APP_BIND_ADDR=0.0.0.0
PORT=$HUB_PORT
ENV
podman run -d --name "$HUB_CTR" --network "$NET" -p "127.0.0.1:${HUB_PORT}:${HUB_PORT}" \
  --env-file "$WORK/hub.env" "$HUB_IMAGE" >/dev/null \
  && PASS "hub container up" || DIE "failed to start the hub container"
tries=40
until curl -sS -f -o /dev/null "${HUB_BASE}/api/v1/cas" -H "Authorization: Bearer ${TOKEN}" 2>/dev/null; do
  tries=$((tries - 1)); [ $tries -le 0 ] && { podman logs "$HUB_CTR" 2>&1 | tail -20; DIE "hub never answered /api/v1/cas"; }
  sleep 1
done
PASS "hub answering on $HUB_BASE"

STEP "full scan of the fixture"
FIX_IP="$(podman inspect "$FIX_CTR" | python3 -c 'import json,sys; print(json.load(sys.stdin)[0]["NetworkSettings"]["Networks"][sys.argv[1]]["IPAddress"])' "$NET")"
[ -n "$FIX_IP" ] || DIE "could not read the fixture IP"
JOB="$(curlj -X POST "${HUB_BASE}/api/v1/discovery/scans" -d "{\"scan_type\":\"full\",\"target\":\"$FIX_IP\"}" \
  | python3 -c 'import json,sys; print(json.load(sys.stdin)["data"]["scan_job"]["id"])' 2>/dev/null)"
[ -n "$JOB" ] || DIE "scan was not created"
t0=$(date +%s); st=""
while [ $(( $(date +%s) - t0 )) -lt 300 ]; do
  st="$(curlj "${HUB_BASE}/api/v1/discovery/scan-jobs?limit=20" | python3 -c '
import json,sys
for j in json.load(sys.stdin)["data"]["scan_jobs"]:
    if j["id"]==sys.argv[1]: print(j["status"]); break
' "$JOB" 2>/dev/null)"
  case "$st" in queued|running|"") sleep 2 ;; *) break ;; esac
done
case "$st" in completed|completed_with_errors) PASS "scan of $FIX_IP finished ($st)" ;; *) FAIL "scan ended '$st'" ;; esac

python3 - "$HUB_BASE" "$TOKEN" "$WORK/scan.json" <<'PY'
import json, sys, urllib.request
hub, token, out = sys.argv[1:4]
rows, cursor = [], ""
while True:
    url = hub + "/api/v1/discovery/endpoints?limit=100" + ("&cursor=" + str(cursor) if cursor != "" else "")
    d = json.load(urllib.request.urlopen(urllib.request.Request(url, headers={"Authorization": "Bearer " + token})))
    rows += d["data"]["endpoints"]
    cursor = (d.get("meta") or {}).get("next_cursor")
    if cursor is None:
        break
json.dump(rows, open(out, "w"))
print("paged", len(rows), "endpoints")
PY

STEP "expected vs found per protocol"
python3 "$HERE/compare.py" "$HERE/expected.json" "$WORK/scan.json" "$WORK/fingerprints.json" "$WORK/report.json" "$RDP_MODE" \
  && PASS "every protocol recalled (rdp mode: $RDP_MODE)" || FAIL "protocol recall below 0.95 (see MISS lines)"
if [ -n "${KK_EVIDENCE_DIR:-}" ]; then
  mkdir -p "$KK_EVIDENCE_DIR"; cp "$WORK/report.json" "$WORK/scan.json" "$KK_EVIDENCE_DIR/" 2>/dev/null || true
fi

STEP "result"
if [ "$FAILED" -eq 0 ]; then echo "ALL PASS"; exit 0; fi
echo "ONE OR MORE STEPS FAILED (hub logs: podman logs $HUB_CTR)"; exit 1
