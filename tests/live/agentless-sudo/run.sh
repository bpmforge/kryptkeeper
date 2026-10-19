#!/usr/bin/env bash
# W34-20: agentless scanning and renewal on a hardened Linux host, with a
# sudo-capable account instead of root. Three hosts (one per privilege mode:
# helper, nopasswd raw allowlist, password) from one hardened image: sshd with
# PermitRootLogin no, `Defaults requiretty`, a root-owned 0600 Tomcat JKS under
# a non-root Tomcat, a root-owned 0600 nginx key under a root nginx master.
# A real hub (container) scans and renews over SSH as the `kkscan` user.
#
# Per mode it asserts:
#   1. the unprivileged scan reports INSUFFICIENT_PRIVILEGE naming both paths;
#   2. after installing the hub's own privilege bundle, the privileged scan
#      reads the JKS certificate and stats the nginx key without reading it;
#   3. listener correlation yields tomcat and nginx at high confidence;
#   4. PRIVILEGED_INSTALL_PATH is raised on the JKS;
#   5. a renewal replaces the nginx certificate through privexec, and a failed
#      `nginx -t` rolls back leaving the old certificate served;
#   6. the sudo password / key bytes never appear in hub logs, audit rows or
#      the hub's database file.
#
# Shared-Mac rules: own compose project (kk-w34-sudo), nothing pruned, only this
# project's containers and images are removed. Podman only; PASS/FAIL per step.
# KK_SUDO_VARIANTS narrows the modes (default: helper nopasswd password).
set -u
set -o pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../../.." && pwd)"
PROJECT=kk-w34-sudo
# podman machine on macOS virtiofs-mounts only $HOME, not /tmp.
WORK="$(mktemp -d "$HOME/.kk-w34-sudo.XXXXXX")"
RUN_ID="$(openssl rand -hex 3)"
free_port() { python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1]); s.close()'; }
HUB_PORT="$(free_port)"
HUB_BASE="http://127.0.0.1:${HUB_PORT}"
TOKEN=uat-token
TARGET_IMAGE="localhost/kk-w34-sudo-host:$RUN_ID"
HUB_IMAGE="localhost/kk-w34-sudo-hub:$RUN_ID"
VARIANTS="${KK_SUDO_VARIANTS:-helper nopasswd password}"
# FIXTURE-ONLY sudo password: not a secret, but unique enough to grep for.
SUDO_PW="kkSudoPw-$(openssl rand -hex 6)"
FAILED=0
STEP() { echo; echo "== $* =="; }
PASS() { echo "PASS: $*"; }
FAIL() { echo "FAIL: $*"; FAILED=1; }
DIE()  { echo "FAIL: $*"; exit 1; }

export SUDO_WORK="$WORK" TARGET_IMAGE HUB_IMAGE HUB_PORT
compose() { podman compose -p "$PROJECT" -f "$HERE/compose.yaml" "$@"; }
cleanup() {
  STEP "cleanup"
  compose down --volumes >/dev/null 2>&1 || true
  podman rmi -f "$TARGET_IMAGE" "$HUB_IMAGE" >/dev/null 2>&1 || true
  rm -rf "$WORK"
}
# KK_SUDO_KEEP=1 leaves the stack up for debugging (remove it with: podman compose -p kk-w34-sudo down).
[ "${KK_SUDO_KEEP:-}" = 1 ] || trap cleanup EXIT

curlj() { curl -sS -H "Authorization: Bearer ${TOKEN}" -H 'Content-Type: application/json' "$@"; }
jget() { python3 -c "import json,sys; d=json.load(sys.stdin); print($1)" 2>/dev/null; }
# Container names differ by compose implementation (docker compose and
# podman-compose 1.0.6 use "-" and "_" separators), so resolve by label.
ctr() {
  local svc=$1 ns name
  for ns in io.podman.compose com.docker.compose; do
    name="$(podman ps -a --filter "label=$ns.project=$PROJECT" --filter "label=$ns.service=$svc" --format '{{.Names}}' | head -1)"
    [ -n "$name" ] && { echo "$name"; return 0; }
  done
  echo "${PROJECT}-${svc}-1"
}

STEP "preflight"
command -v podman >/dev/null || DIE "podman is required"
podman system df || true
case "$(podman info --format '{{.Host.Arch}}' 2>/dev/null)" in arm64|aarch64) GOARCH=arm64 ;; *) GOARCH=amd64 ;; esac

STEP "keys, images, hub binary"
ssh-keygen -t ed25519 -N '' -f "$WORK/id_ed25519" -C kk-sudo >/dev/null && cp "$WORK/id_ed25519.pub" "$WORK/authorized_keys" \
  && printf '%s' "$SUDO_PW" > "$WORK/kkscan.pw" && PASS "keypair and password material generated" || DIE "keygen failed"
podman build -t "$TARGET_IMAGE" -f "$HERE/Dockerfile.hardened" "$HERE" >"$WORK/build-host.log" 2>&1 \
  && PASS "hardened host image built" || { tail -20 "$WORK/build-host.log"; DIE "host image build failed"; }
mkdir -p "$WORK/hubctx"
( cd "$ROOT" && GOOS=linux GOARCH=$GOARCH CGO_ENABLED=0 go build -o "$WORK/hubctx/kryptkeeper" ./cmd/kryptkeeper ) \
  && cp "$ROOT/tests/live/autopilot/hub.Containerfile" "$WORK/hubctx/Containerfile" \
  && podman build -t "$HUB_IMAGE" "$WORK/hubctx" >"$WORK/build-hub.log" 2>&1 \
  && PASS "hub image built (linux/$GOARCH)" || DIE "hub build failed"
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

STEP "start the hosts and the hub ($PROJECT)"
compose up -d >"$WORK/up.log" 2>&1 && PASS "compose up" || { tail -20 "$WORK/up.log"; DIE "compose up failed"; }
tries=60
until curl -sS -f -o /dev/null "${HUB_BASE}/api/v1/cas" -H "Authorization: Bearer ${TOKEN}" 2>/dev/null; do
  tries=$((tries - 1)); [ $tries -le 0 ] && { podman logs "$(ctr hub)" 2>&1 | tail -20; DIE "hub never answered"; }
  sleep 1
done
PASS "hub answering on $HUB_BASE"
host_key() {
  local c=$1 tries=60 k
  while [ $tries -gt 0 ]; do
    k="$(podman exec "$c" cat /etc/ssh/ssh_host_ed25519_key.pub 2>/dev/null | awk '{print $1" "$2}')"
    [ -n "$k" ] && podman exec "$c" pgrep -x sshd >/dev/null 2>&1 && { echo "$k"; return 0; }
    sleep 1; tries=$((tries - 1))
  done
  return 1
}
for v in $VARIANTS; do
  for _ in $(seq 1 60); do
    podman exec "$(ctr "$v")" sh -c 'ss -ltn | grep -q ":8443 " && ss -ltn | grep -q ":443 "' 2>/dev/null && break; sleep 1
  done
  podman exec "$(ctr "$v")" sh -c 'ss -ltn | grep -q ":8443 " && ss -ltn | grep -q ":443 "' 2>/dev/null \
    && PASS "[$v] nginx (443) and tomcat (8443) are listening" || { podman logs "$(ctr "$v")" 2>&1 | tail; FAIL "[$v] services never listened"; }
done

CA_ID="$(curlj "${HUB_BASE}/api/v1/cas" | jget 'd["data"][0]["id"]')"
TEMPLATE_ID="$(curlj -X POST "${HUB_BASE}/api/v1/templates" -d '{"name":"uat-sudo","display_name":"UAT sudo","allowed_algorithms":["ECDSA","RSA-2048"],"key_usage":["digitalSignature","keyEncipherment"],"extended_key_usage":["serverAuth"],"validity_period":"2160h","active":true}' | jget 'd["data"]["id"]')"
[ -n "$CA_ID" ] && [ -n "$TEMPLATE_ID" ] && PASS "CA $CA_ID and template $TEMPLATE_ID" || DIE "CA/template setup failed"

mkcred() { # name sudo_mode [sudo_password] [helper_sha256]
  python3 - "$WORK/id_ed25519" "$1" "$2" "${3:-}" "${4:-}" "$HOSTKEY" <<'PY' | curlj -X POST "${HUB_BASE}/api/v1/credentials" -d @- | jget 'd["data"]["id"]'
import json, sys
key, name, mode, pw, sha, hk = sys.argv[1:7]
payload = {"user": "kkscan", "private_key_pem": open(key).read(), "host_public_key": hk, "port": 22, "sudo_mode": mode}
if pw: payload["sudo_password"] = pw
if sha: payload["helper_sha256"] = sha
print(json.dumps({"name": name, "credential_type": "ssh_key", "payload": payload}))
PY
}
mktarget() { # name host cred_id
  python3 - "$1" "$2" "$3" "$HOSTKEY" <<'PY' | curlj -X POST "${HUB_BASE}/api/v1/targets" -d @- | jget 'd["data"]["id"]'
import json, sys
name, host, cred, hk = sys.argv[1:5]
print(json.dumps({"name": name, "host": host, "discovery_mode": "network", "install_mode": "ssh", "credential_ref": cred,
  "install_server_type": "nginx", "install_cert_path": "/etc/nginx/ssl/web.crt", "install_key_path": "/etc/nginx/ssl/web.key",
  "ssh_host_key": hk}))
PY
}
scan_job() { # scan_type target -> status
  local id st t0
  id="$(curlj -X POST "${HUB_BASE}/api/v1/discovery/scans" -d "{\"scan_type\":\"$1\",\"target\":\"$2\"}" | jget 'd["data"]["scan_job"]["id"]')"
  [ -n "$id" ] || { echo submit_failed; return 1; }
  t0=$(date +%s)
  while [ $(( $(date +%s) - t0 )) -lt 120 ]; do
    st="$(curlj "${HUB_BASE}/api/v1/discovery/scan-jobs?limit=100" | python3 -c '
import json,sys
for j in json.load(sys.stdin)["data"]["scan_jobs"]:
    if j["id"]==sys.argv[1]: print(j["status"]); break' "$id" 2>/dev/null)"
    case "$st" in queued|running|"") sleep 2 ;; *) echo "$st"; return 0 ;; esac
  done
  echo timeout; return 1
}
dump_endpoints() {
  python3 - "$HUB_BASE" "$TOKEN" "$1" <<'PY'
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
PY
}
issue_cert() { # cn -> fingerprint
  openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -keyout "$WORK/$1.key" -out "$WORK/$1.csr" -subj "/CN=$1" -addext "subjectAltName=DNS:$1" >/dev/null 2>&1
  local csr; csr="$(python3 -c "import json; print(json.dumps(open('$WORK/$1.csr').read()))")"
  curlj -X POST "${HUB_BASE}/api/v1/certificates" -d "{\"ca_id\":\"${CA_ID}\",\"template_id\":\"${TEMPLATE_ID}\",\"csr_pem\":${csr}}" | jget 'd["data"]["fingerprint_sha256"]'
}
renew() { # fingerprint target_id host
  curlj -X POST "${HUB_BASE}/api/v1/renewal/execute" -d "{\"fingerprint\":\"$1\",\"target_id\":\"$2\",\"install\":{\"server_type\":\"nginx\",\"cert_path\":\"/etc/nginx/ssl/web.crt\",\"key_path\":\"/etc/nginx/ssl/web.key\",\"verify_host_port\":\"$3:443\"}}"
}
served_fp() { # container -> sha256 of the leaf nginx serves (read from inside the host's own network namespace)
  podman exec "$1" sh -c "echo | openssl s_client -connect 127.0.0.1:443 2>/dev/null | openssl x509 -noout -fingerprint -sha256" 2>/dev/null | cut -d= -f2 | tr -d ':' | tr 'A-F' 'a-f'
}

for V in $VARIANTS; do
  C="$(ctr "$V")"
  STEP "[$V] host facts from the container"
  HOSTKEY="$(host_key "$C")" || { FAIL "[$V] no host key"; continue; }
  JKS_FP="$(podman exec "$C" keytool -list -v -storepass changeit -keystore /opt/ssl/keystore.jks 2>/dev/null | awk '/SHA256:/{print $2; exit}' | tr -d ':' | tr 'A-F' 'a-f')"
  P12_FP="$(podman exec "$C" keytool -list -v -storepass changeit -keystore /opt/ssl/app.p12 2>/dev/null | awk '/SHA256:/{print $2; exit}' | tr -d ':' | tr 'A-F' 'a-f')"
  KEY_LINE="$(podman exec "$C" sed -n 2p /etc/nginx/ssl/web.key)"
  KEY_STAT="$(podman exec "$C" stat -c '%U:%a' /etc/nginx/ssl/web.key)"
  [ -n "$JKS_FP" ] && [ -n "$P12_FP" ] && [ -n "$KEY_LINE" ] && PASS "[$V] JKS sha256 ${JKS_FP:0:16}..., nginx key is $KEY_STAT, tomcat runs as $(podman exec "$C" ps -o user= -C java | head -1)" || { FAIL "[$V] could not read host facts"; continue; }
  [ "$KEY_STAT" = "root:600" ] && PASS "[$V] key is root:600" || FAIL "[$V] key is $KEY_STAT"

  STEP "[$V] unprivileged scan (credential without sudo)"
  CRED0="$(mkcred "uat-$V-none" none)"; T0="$(mktarget "t-$V-none" "$C" "$CRED0")"
  [ -n "$CRED0" ] && [ -n "$T0" ] && PASS "[$V] credential $CRED0 target $T0" || { FAIL "[$V] cred/target create"; continue; }
  st="$(scan_job ssh "$T0")"; echo "  scan status: $st"
  dump_endpoints "$WORK/ep-$V-none.json"
  python3 - "$WORK/ep-$V-none.json" "$C" <<'PY' && PASS "[$V] INSUFFICIENT_PRIVILEGE names the unreadable keystores and the fix" || FAIL "[$V] unprivileged finding"
import json, sys
rows = [e for e in json.load(open(sys.argv[1])) if e.get("hostname") == sys.argv[2] and e.get("port") == 22]
if not rows: print("  no ssh endpoint row"); sys.exit(1)
issues = rows[0].get("issues") or []
hit = [i for i in issues if i.startswith("INSUFFICIENT_PRIVILEGE")]
print("  issues:", [i[:160] for i in issues][:6])
if not hit: sys.exit(1)
text = hit[0]
# The nginx key is stat'ed, never read, so it is not "unreadable"; the JKS is
# the file this account must read and cannot.
missing = [p for p in ("/opt/ssl/keystore.jks", "/opt/ssl/app.p12") if p not in text]
if missing: print("  missing paths:", missing); sys.exit(1)
PY

  STEP "[$V] install the hub's own privilege bundle on the host"
  case "$V" in
    helper) MODE=helper ;; nopasswd) MODE=nopasswd ;; password) MODE=password ;;
  esac
  curlj "${HUB_BASE}/api/v1/targets/$T0/privilege-bundle?mode=$MODE&user=kkscan&scan_paths=/opt/ssl" >"$WORK/bundle-$V.json"
  python3 - "$WORK/bundle-$V.json" "$WORK" "$V" <<'PY' || { FAIL "[$V] bundle fetch"; continue; }
import json, sys
d = json.load(open(sys.argv[1]))["data"]
w, v = sys.argv[2], sys.argv[3]
open(f"{w}/sudoers-{v}", "w").write(d["sudoers"])
if d.get("helper"):
    open(f"{w}/helper-{v}", "w").write(d["helper"])
    open(f"{w}/helper-{v}.sha256", "w").write(d["helper_sha256"])
    open(f"{w}/helper-{v}.path", "w").write(d["helper_path"])
PY
  podman cp "$WORK/sudoers-$V" "$C:/tmp/sudoers-kk" >/dev/null
  podman exec "$C" sh -c 'install -o root -g root -m 0440 /tmp/sudoers-kk /etc/sudoers.d/kryptkeeper-kkscan && visudo -cf /etc/sudoers.d/kryptkeeper-kkscan' >/dev/null \
    && PASS "[$V] sudoers drop-in validated by visudo" || { FAIL "[$V] visudo rejected the bundle's sudoers"; continue; }
  SHA=""
  if [ "$V" = helper ]; then
    HP="$(cat "$WORK/helper-$V.path")"; SHA="$(cat "$WORK/helper-$V.sha256")"
    podman cp "$WORK/helper-$V" "$C:/tmp/helper" >/dev/null
    podman exec "$C" sh -c "install -o root -g root -m 0755 /tmp/helper '$HP'" && PASS "[$V] helper installed at $HP (sha256 ${SHA:0:12}...)" || { FAIL "[$V] helper install"; continue; }
  fi

  STEP "[$V] privileged scan"
  PW=""; [ "$V" = password ] && PW="$SUDO_PW"
  CRED1="$(mkcred "uat-$V-$MODE" "$MODE" "$PW" "$SHA")"; T1="$(mktarget "t-$V-$MODE" "$C" "$CRED1")"
  [ -n "$CRED1" ] && [ -n "$T1" ] && PASS "[$V] credential $CRED1 (sudo_mode $MODE) target $T1" || { FAIL "[$V] cred/target create"; continue; }
  st="$(scan_job ssh "$T1")"; echo "  scan status: $st"
  # Listener correlation joins the host's sockets to the network endpoints, so
  # scan 443 and 8443 now that the host report exists, then scan the host again.
  scan_job targeted "$C:443" >/dev/null; scan_job targeted "$C:8443" >/dev/null
  scan_job ssh "$T1" >/dev/null
  dump_endpoints "$WORK/ep-$V-$MODE.json"
  python3 - "$WORK/ep-$V-$MODE.json" "$C" "$JKS_FP" "$P12_FP" "$MODE" <<'PY' && PASS "[$V] JKS and PKCS12 certificates read, no INSUFFICIENT_PRIVILEGE, PRIVILEGED_INSTALL_PATH raised" || FAIL "[$V] privileged scan assertions"
import json, sys
eps, host, jks, p12, mode = json.load(open(sys.argv[1])), sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5]
ssh = [e for e in eps if e.get("hostname") == host and e.get("port") == 22]
if not ssh: print("  no ssh endpoint"); sys.exit(1)
ep = ssh[0]
issues = ep.get("issues") or []
print("  issues:", [i[:140] for i in issues][:8])
bad = []
# helper and password modes are root: nothing may be unreadable.
ips = [i for i in issues if i.startswith("INSUFFICIENT_PRIVILEGE")]
if mode == "nopasswd":
    # Deliberate (D-273): the rule is not widened to /etc/ssl/private, so that one
    # root-only keys directory is reported and nothing else is.
    if len(ips) != 1 or "paths=/etc/ssl/private" not in ips[0] or "/opt/ssl" in ips[0] or "/etc/nginx/ssl" in ips[0]:
        bad.append("nopasswd must report exactly /etc/ssl/private as insufficient: " + "; ".join(i[:160] for i in ips))
elif ips:
    bad.append("still INSUFFICIENT_PRIVILEGE: " + ips[0][:200])
fps = {(c.get("fingerprint") or "").replace(":", "").lower(): c for c in ep.get("mapped_certs") or []}
for fp, path, label in ((jks, "/opt/ssl/keystore.jks", "JKS"), (p12, "/opt/ssl/app.p12", "PKCS12")):
    if fp not in fps: bad.append(label + " certificate not discovered")
    elif not (fps[fp].get("source_path") or "").startswith(path): bad.append(label + " source_path " + str(fps[fp].get("source_path")))
if not any(i.startswith("PRIVILEGED_INSTALL_PATH") and "/opt/ssl/keystore.jks" in i for i in issues): bad.append("no PRIVILEGED_INSTALL_PATH on the JKS")
# Noise guard: world-readable system certificates must not turn into findings
# just because the elevated reader is stricter than the account itself.
noise = [i for i in issues if i.startswith("UNREADABLE_PATH")]
if noise: bad.append("unexpected UNREADABLE_PATH findings: " + "; ".join(n[:120] for n in noise[:3]))
for b in bad: print("  BAD:", b)
sys.exit(1 if bad else 0)
PY
  python3 - "$WORK/ep-$V-$MODE.json" "$C" <<'PY' && PASS "[$V] listener correlation: nginx:443 and tomcat:8443 at high confidence" || FAIL "[$V] listener correlation"
import json, sys
eps, host = json.load(open(sys.argv[1])), sys.argv[2]
want = {443: "nginx", 8443: "tomcat"}
bad = []
for port, tech in want.items():
    row = [e for e in eps if e.get("hostname") == host and e.get("port") == port]
    if not row: bad.append(f"{port}: no endpoint"); continue
    r = row[0]
    print(f"  {port}: tech={r.get('tech')} confidence={r.get('tech_confidence')} evidence={[x['signal'] for x in r.get('tech_evidence') or []]}")
    if r.get("tech") != tech or r.get("tech_confidence") != "high": bad.append(f"{port}: {r.get('tech')}/{r.get('tech_confidence')}")
for b in bad: print("  BAD:", b)
sys.exit(1 if bad else 0)
PY

  STEP "[$V] renewal through privexec and rollback on a failed nginx -t"
  OLD_FP="$(served_fp "$C")"
  FP1="$(issue_cert "kk-$V-new")"
  R1="$(renew "$FP1" "$T1" "$C")"; echo "  renew: $(echo "$R1" | cut -c1-300)"
  OUT="$(echo "$R1" | jget 'd["data"]["install_outcome"]')"; NEWFP="$(echo "$R1" | jget 'd["data"]["new_fingerprint"]' | tr -d ':' | tr 'A-F' 'a-f')"
  sleep 1; NOW_FP="$(served_fp "$C")"
  if [ "$OUT" = installed_verified ] && [ "$NOW_FP" = "$NEWFP" ] && [ "$NOW_FP" != "$OLD_FP" ]; then
    PASS "[$V] nginx certificate replaced through privexec (now ${NOW_FP:0:16}...)"
  else
    FAIL "[$V] renewal outcome=$OUT served=${NOW_FP:0:16} want=${NEWFP:0:16}"
  fi
  KEY_AFTER="$(podman exec "$C" stat -c '%U:%a' /etc/nginx/ssl/web.key)"
  [ "$KEY_AFTER" = "root:600" ] && PASS "[$V] key still root:600 after the install" || FAIL "[$V] key is $KEY_AFTER after the install"

  HASH_BEFORE="$(podman exec "$C" sha256sum /etc/nginx/ssl/web.crt | cut -d' ' -f1)"
  FP2="$(issue_cert "kk-$V-bad")"
  podman exec "$C" sh -c 'echo "invalid_directive on;" >> /etc/nginx/nginx.conf'
  R2="$(renew "$FP2" "$T1" "$C")"; echo "  renew with broken config: $(echo "$R2" | cut -c1-300)"
  OUT2="$(echo "$R2" | jget 'd["data"]["install_outcome"]')"
  podman exec "$C" sed -i '/invalid_directive on;/d' /etc/nginx/nginx.conf
  HASH_AFTER="$(podman exec "$C" sha256sum /etc/nginx/ssl/web.crt | cut -d' ' -f1)"
  [ "$OUT2" = config_test_failed ] && PASS "[$V] config_test_failed reported" || FAIL "[$V] outcome=$OUT2 (want config_test_failed)"
  [ "$(served_fp "$C")" = "$NOW_FP" ] && [ "$HASH_BEFORE" = "$HASH_AFTER" ] \
    && PASS "[$V] rolled back: previous certificate still served and the file is byte-identical" || FAIL "[$V] rollback not proven"

  STEP "[$V] secrets never reach hub logs, audit rows or the database"
  podman cp "$(ctr hub):/data" "$WORK/hubdata-$V" >/dev/null 2>&1
  HUBLOG="$(podman logs "$(ctr hub)" 2>&1)"
  AUDIT="$(curlj "${HUB_BASE}/api/v1/audit?limit=1000")"
  KEYLEAK="$( { echo "$HUBLOG"; echo "$AUDIT"; } | grep -c -F -- "$KEY_LINE" || true)"
  KEYDB="$(grep -r -a -l -F -- "$KEY_LINE" "$WORK/hubdata-$V" 2>/dev/null | wc -l | tr -d ' ')"
  [ "$KEYLEAK" = 0 ] && [ "$KEYDB" = 0 ] && PASS "[$V] the nginx key's bytes appear in no hub log, audit row or data file (the scan stats the key, never reads it)" \
    || FAIL "[$V] key material found (log/audit $KEYLEAK, data files $KEYDB)"
  if [ "$V" = password ]; then
    PWLOG="$( { echo "$HUBLOG"; echo "$AUDIT"; } | grep -c -F -- "$SUDO_PW" || true)"
    PWDB="$(grep -r -a -l -F -- "$SUDO_PW" "$WORK/hubdata-$V" 2>/dev/null | wc -l | tr -d ' ')"
    [ "$PWLOG" = 0 ] && [ "$PWDB" = 0 ] && PASS "[$V] the sudo password appears in no hub log, audit row or data file (log/audit $PWLOG, files $PWDB)" \
      || FAIL "[$V] the sudo password leaked (log/audit $PWLOG, data files $PWDB)"
  fi
done

STEP "result"
[ "$FAILED" -eq 0 ] && echo "ALL PASS" || echo "ONE OR MORE STEPS FAILED (hub logs: podman logs $(ctr hub))"
exit "$FAILED"
