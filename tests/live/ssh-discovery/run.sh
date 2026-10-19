#!/usr/bin/env bash
# W24-11: agentless SSH discovery against a REAL sshd host holding PEM certs
# for nginx and apache plus a JKS, as root and as a non-sudo user; host-key
# mismatch imports nothing; the scheduler repeats the scan unattended; the
# credential never reaches the hub log or the audit trail.
#
# Counts are asserted over the planted kk-ssh-* certificates only (the image
# also carries ~140 system CA certs). Expected fingerprints come from the
# container, never from the hub. Podman only; PASS/FAIL per step; trap cleanup.
# KK_EVIDENCE_DIR receives scan-root.json, scan-scanner.json, audit-dump.json.
. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/../lib/podman.sh"
set -u
set -o pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$HERE/../../.." && pwd)"
WORK="$(mktemp -d /tmp/kk-uat-sshd.XXXXXX)"
RUN_ID="$(openssl rand -hex 3)"
free_port() { python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1]); s.close()'; }
HUB_PORT="$(free_port)"
HUB_BASE="http://127.0.0.1:${HUB_PORT}"
TOKEN=uat-token
IMAGE="localhost/kk-uat-sshd:$RUN_ID"
HUB_IMAGE="localhost/kk-uat-sshd-hub:$RUN_ID"
NET="kk-uat-sshd-net-$RUN_ID"
CTR_A="kk-uat-sshd-a-$RUN_ID"
CTR_B="kk-uat-sshd-b-$RUN_ID"
ALIAS_A="kk-scanner-view-$RUN_ID"
HUB_CTR="kk-uat-sshd-hub-$RUN_ID"

FAILED=0
STEP() { echo; echo "== $* =="; }
PASS() { echo "PASS: $*"; }
FAIL() { echo "FAIL: $*"; FAILED=1; }
DIE()  { echo "FAIL: $*"; cleanup; exit 1; }

cleanup() {
  STEP "cleanup"
  kk_rm "$CTR_A" "$CTR_B" "$HUB_CTR"
  podman network rm "$NET" >/dev/null 2>&1 || true
  podman rmi -f "$IMAGE" "$HUB_IMAGE" >/dev/null 2>&1 || true
  rm -rf "$WORK"
}
trap cleanup EXIT

curlj() { curl -sS -H "Authorization: Bearer ${TOKEN}" -H 'Content-Type: application/json' "$@"; }
jget() { python3 -c "import json,sys; d=json.load(sys.stdin); print($1)" 2>/dev/null; }

# ---------------------------------------------------------------------------
STEP "keypair, network, image, containers A and B"
ssh-keygen -t ed25519 -N '' -f "$WORK/id_ed25519" -C kk-uat >/dev/null && PASS "keypair generated" || DIE "ssh-keygen failed"
cp "$WORK/id_ed25519.pub" "$WORK/authorized_keys"
podman build -t "$IMAGE" "$HERE" >"$WORK/build.log" 2>&1 \
  && PASS "image built" || { tail -20 "$WORK/build.log"; DIE "podman build failed"; }
podman network create "$NET" >/dev/null && PASS "network $NET" || DIE "network create failed"
# The per-run public key reaches the container with podman cp (a bind mount of
# a /tmp path is invisible to the podman VM on macOS); the entrypoint installs it.
podman create --name "$CTR_A" --network "$NET" --network-alias "$ALIAS_A" "$IMAGE" >/dev/null || DIE "create A failed"
podman create --name "$CTR_B" --network "$NET" "$IMAGE" >/dev/null || DIE "create B failed"
for c in "$CTR_A" "$CTR_B"; do
  podman cp "$WORK/authorized_keys" "$c:/tmp/authorized_keys" >/dev/null || DIE "cannot copy authorized_keys into $c"
  podman start "$c" >/dev/null || DIE "start $c failed"
done
host_key() { # container -> authorized_keys-format ed25519 host key, retried until sshd generated it
  local c=$1 tries=30 k
  while [ $tries -gt 0 ]; do
    k="$(podman exec "$c" cat /etc/ssh/ssh_host_ed25519_key.pub 2>/dev/null | awk '{print $1" "$2}')"
    [ -n "$k" ] && podman exec "$c" pgrep -x sshd >/dev/null 2>&1 && { echo "$k"; return 0; }
    sleep 1; tries=$((tries - 1))
  done
  return 1
}
HOSTKEY_A="$(host_key "$CTR_A")"; HOSTKEY_B="$(host_key "$CTR_B")"
[ -n "$HOSTKEY_A" ] && [ -n "$HOSTKEY_B" ] || DIE "could not read the sshd host keys"
[ "$HOSTKEY_A" != "$HOSTKEY_B" ] || DIE "A and B share a host key; the mismatch case would prove nothing"
PASS "containers A and B up with distinct host keys"

# ---------------------------------------------------------------------------
STEP "expected fingerprints from the container"
python3 - "$CTR_A" "$WORK/expected.json" <<'PY'
import json, re, subprocess, sys
ctr, out = sys.argv[1:3]
def ex(*a): return subprocess.run(["podman", "exec", ctr, *a], capture_output=True, text=True, check=True).stdout
pem = {
  "kk-ssh-web1": "/etc/nginx/ssl/web1.crt", "kk-ssh-web2": "/etc/nginx/ssl/web2.crt",
  "kk-ssh-site1": "/etc/apache2/ssl/site1.crt",
  "kk-ssh-locked": "/etc/nginx/ssl/locked.crt", "kk-ssh-hidden": "/etc/apache2/ssl/locked/hidden.crt",
}
exp = {}
for cn, path in pem.items():
    fp = ex("openssl", "x509", "-in", path, "-noout", "-fingerprint", "-sha256").split("=", 1)[1]
    exp[cn] = {"path": path, "fp": fp.strip().replace(":", "").lower()}
lst = ex("keytool", "-list", "-storepass", "changeit", "-keystore", "/opt/ssl/app.jks")
for m in re.finditer(r"^(kk-ssh-jks\d),.*\n.*\(SHA-256\): ([0-9A-F:]+)", lst, re.M):
    exp[m.group(1)] = {"path": "/opt/ssl/app.jks", "fp": m.group(2).replace(":", "").lower()}
assert len(exp) == 7, f"expected 7 planted certs, got {sorted(exp)}"
json.dump(exp, open(out, "w"), indent=1)
print("expected:", {k: v["fp"][:12] for k, v in exp.items()})
PY
[ $? -eq 0 ] && PASS "7 planted fingerprints read from the container" || DIE "could not compute expected fingerprints"

# ---------------------------------------------------------------------------
STEP "build and start hub (scheduler interval 1m)"
GOARCH="$(kk_goarch)"
mkdir -p "$WORK/hubctx"
( cd "$REPO_ROOT" && GOOS=linux GOARCH=$GOARCH CGO_ENABLED=0 go build -o "$WORK/hubctx/kryptkeeper" ./cmd/kryptkeeper ) \
  && PASS "hub built (linux/$GOARCH)" || DIE "go build failed"
cp "$REPO_ROOT/tests/live/autopilot/hub.Containerfile" "$WORK/hubctx/Containerfile"
podman build -t "$HUB_IMAGE" "$WORK/hubctx" >"$WORK/build-hub.log" 2>&1 \
  && PASS "hub image built" || DIE "hub image build failed"
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
KRYPTKEEPER_DISCOVERY_SCAN_INTERVAL=1m
ENV
podman run -d --name "$HUB_CTR" --network "$NET" -p "127.0.0.1:${HUB_PORT}:${HUB_PORT}" \
  --env-file "$WORK/hub.env" "$HUB_IMAGE" >/dev/null && PASS "hub container up" || DIE "hub start failed"
tries=40
until curl -sS -f -o /dev/null "${HUB_BASE}/api/v1/cas" -H "Authorization: Bearer ${TOKEN}" 2>/dev/null; do
  tries=$((tries - 1)); [ $tries -le 0 ] && { podman logs "$HUB_CTR" 2>&1 | tail -20; DIE "hub never answered"; }
  sleep 1
done
PASS "hub answering on $HUB_BASE"

# ---------------------------------------------------------------------------
STEP "credentials and targets"
mkcred() { # name user host_key
  python3 - "$WORK/id_ed25519" "$1" "$2" "$3" <<'PY' | curlj -X POST "${HUB_BASE}/api/v1/credentials" -d @- | jget 'd["data"]["id"]'
import json, sys
key, name, user, hk = sys.argv[1:5]
print(json.dumps({"name": name, "credential_type": "ssh_key",
  "payload": {"user": user, "private_key_pem": open(key).read(), "host_public_key": hk, "port": 22}}))
PY
}
mktarget() { # name host cred_id ssh_host_key
  python3 - "$1" "$2" "$3" "$4" <<'PY' | curlj -X POST "${HUB_BASE}/api/v1/targets" -d @- | jget 'd["data"]["id"]'
import json, sys
name, host, cred, hk = sys.argv[1:5]
print(json.dumps({"name": name, "host": host, "discovery_mode": "network", "install_mode": "ssh",
  "credential_ref": cred, "install_server_type": "nginx", "install_cert_path": "/etc/nginx/ssl/web1.crt",
  "install_key_path": "/etc/nginx/ssl/web1.key", "install_reload_method": "binary", "ssh_host_key": hk}))
PY
}
CRED_ROOT="$(mkcred "uat-root-$RUN_ID" root "$HOSTKEY_A")"
CRED_SCAN="$(mkcred "uat-scanner-$RUN_ID" scanner "$HOSTKEY_A")"
[ -n "$CRED_ROOT" ] && [ -n "$CRED_SCAN" ] && PASS "credentials root=$CRED_ROOT scanner=$CRED_SCAN" || DIE "credential create failed"
T_ROOT="$(mktarget "t-root-$RUN_ID" "$CTR_A" "$CRED_ROOT" "$HOSTKEY_A")"
T_SCAN="$(mktarget "t-scanner-$RUN_ID" "$ALIAS_A" "$CRED_SCAN" "$HOSTKEY_A")"
T_MISM="$(mktarget "t-mismatch-$RUN_ID" "$CTR_B" "$CRED_ROOT" "$HOSTKEY_A")"
[ -n "$T_ROOT" ] && [ -n "$T_SCAN" ] && [ -n "$T_MISM" ] && PASS "targets root=$T_ROOT scanner=$T_SCAN mismatch=$T_MISM" || DIE "target create failed"

scan_target() { # target id -> job id
  curlj -X POST "${HUB_BASE}/api/v1/discovery/scans" -d "{\"scan_type\":\"ssh\",\"target\":\"$1\"}" | jget 'd["data"]["scan_job"]["id"]'
}
wait_job() { # job id, timeout -> prints status
  local id=$1 timeout=$2 t0 st
  t0=$(date +%s)
  while [ $(( $(date +%s) - t0 )) -lt "$timeout" ]; do
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

# assert_endpoint <scan.json> <host> <expected cn list...>: exact kk-ssh-* set, fingerprints, source paths.
assert_endpoint() {
  local scan=$1 host=$2; shift 2
  python3 - "$scan" "$host" "$WORK/expected.json" "$@" <<'PY'
import json, re, sys
scan, host, expf, *want = sys.argv[1:]
exp = json.load(open(expf))
eps = [e for e in json.load(open(scan)) if e["hostname"] == host]
if not eps:
    print("  no endpoint row for", host); sys.exit(1)
ep = eps[0]
got = {}
for c in ep.get("mapped_certs") or []:
    if re.match(r"^kk-ssh-", c.get("common_name") or ""):
        got[c["common_name"]] = c
bad = []
if set(got) != set(want):
    bad.append(f"CN set {sorted(got)} != {sorted(want)}")
for cn in want:
    c = got.get(cn)
    if not c: continue
    if (c.get("fingerprint") or "").replace(":", "").lower() != exp[cn]["fp"]:
        bad.append(f"{cn} fingerprint mismatch")
    sp = c.get("source_path") or ""
    if not sp.startswith(exp[cn]["path"]):
        bad.append(f"{cn} source_path {sp!r} does not start with {exp[cn]['path']}")
print(f"  found/expected {len(set(got) & set(want))}/{len(want)}")
for cn in sorted(got): print("   ", cn, got[cn].get("source_path"))
for b in bad: print("  BAD:", b)
issues = ep.get("issues") or []
print("  issues:", issues)
json.dump({"issues": issues}, open(scan + ".issues", "w"))
sys.exit(1 if bad else 0)
PY
}

# ---------------------------------------------------------------------------
STEP "root scan (acceptance 1): 7 planted certs with source paths"
JOB_ROOT="$(scan_target "$T_ROOT")"
[ -n "$JOB_ROOT" ] || DIE "root scan not created"
ST="$(wait_job "$JOB_ROOT" 120)"; echo "  job $JOB_ROOT -> $ST"
dump_endpoints "$WORK/scan-root.json"
if assert_endpoint "$WORK/scan-root.json" "$CTR_A" kk-ssh-web1 kk-ssh-web2 kk-ssh-site1 kk-ssh-jks1 kk-ssh-jks2 kk-ssh-locked kk-ssh-hidden; then
  PASS "root scan found exactly the 7 planted certs with matching fingerprints and paths (7/7)"
else FAIL "root scan did not match the 7 planted certs"; fi

STEP "non-sudo scan (acceptance 2a): 5 readable, 2 unreadable reported"
JOB_SCAN="$(scan_target "$T_SCAN")"
[ -n "$JOB_SCAN" ] || DIE "scanner scan not created"
ST="$(wait_job "$JOB_SCAN" 120)"; echo "  job $JOB_SCAN -> $ST"
dump_endpoints "$WORK/scan-scanner.json"
if assert_endpoint "$WORK/scan-scanner.json" "$ALIAS_A" kk-ssh-web1 kk-ssh-web2 kk-ssh-site1 kk-ssh-jks1 kk-ssh-jks2; then
  PASS "scanner scan found exactly the 5 readable certs (5/5); locked and hidden absent"
else FAIL "scanner scan did not match the 5 readable certs"; fi
python3 - "$WORK/scan-scanner.json.issues" <<'PY'
import json, sys
issues = json.load(open(sys.argv[1]))["issues"]
text = "\n".join(issues)
# D-254 (W34-10): permission-denied unreadable paths fold into ONE
# INSUFFICIENT_PRIVILEGE finding listing them (paths=...), so assert that
# finding, its mode and that each path is listed clean (no stray quote).
ip = [i for i in issues if i.startswith("INSUFFICIENT_PRIVILEGE:")]
text = ip[0] if len(ip) == 1 else ""
paths = text.split("paths=", 1)[-1].split("; fix=", 1)[0]
listed = [p.strip() for p in paths.split(",")]
n = sum(1 for p in ("/etc/nginx/ssl/locked.crt", "/etc/apache2/ssl/locked") if p in listed)
if "mode=none" not in text or "uid=" not in text:
    n = 0
print(f"  unreadable reported {n}/2 (INSUFFICIENT_PRIVILEGE findings: {len(ip)}, listed: {listed})")
sys.exit(0 if n == 2 else 1)
PY
[ $? -eq 0 ] && PASS "one INSUFFICIENT_PRIVILEGE (mode=none) names locked.crt and the locked directory (2/2)" || FAIL "unreadable paths not reported 2/2"

STEP "host-key mismatch (acceptance 2b): job fails, 0 certs imported, audit entry"
JOB_MISM="$(scan_target "$T_MISM")"
[ -n "$JOB_MISM" ] || DIE "mismatch scan not created"
ST="$(wait_job "$JOB_MISM" 120)"; echo "  job $JOB_MISM -> $ST"
python3 - "$HUB_BASE" "$TOKEN" "$JOB_MISM" "$CTR_B" "$T_MISM" <<'PY'
import json, re, sys, urllib.request
hub, token, job, host_b, tid = sys.argv[1:6]
def get(p): return json.load(urllib.request.urlopen(urllib.request.Request(hub + p, headers={"Authorization": "Bearer " + token})))
j = [x for x in get("/api/v1/discovery/scan-jobs?limit=100")["data"]["scan_jobs"] if x["id"] == job][0]
fps = re.findall(r"SHA256:[A-Za-z0-9+/=]+", j.get("error", ""))
ok = j["status"] == "failed" and len(fps) >= 2 and len(set(fps)) == 2
print("  job status:", j["status"], "error fingerprints:", fps)
eps = [e for e in get("/api/v1/discovery/endpoints?limit=100")["data"]["endpoints"] if e["hostname"] == host_b]
print("  endpoint rows for B:", len(eps))
ok = ok and not eps
rows = get("/api/v1/audit?action=target.hostkey.mismatch&limit=20")["data"]
hit = [r for r in rows if r.get("resource_id") == tid and all(f in r.get("change_summary", "") for f in fps)]
print("  audit entries for the target containing both fingerprints:", len(hit))
sys.exit(0 if ok and hit else 1)
PY
[ $? -eq 0 ] && PASS "mismatch: failed job with pinned+observed SHA256, 0 endpoints for B, audit target.hostkey.mismatch" || FAIL "host-key mismatch handling not as specified"

# ---------------------------------------------------------------------------
STEP "scheduled repeat (acceptance 3a): second ssh job for T-root without a POST"
count_jobs() {
  curlj "${HUB_BASE}/api/v1/discovery/scan-jobs?q=${T_ROOT}&limit=100" | python3 -c '
import json,sys
print(sum(1 for j in json.load(sys.stdin)["data"]["scan_jobs"] if j["scan_type"]=="ssh"))' 2>/dev/null
}
t0=$(date +%s); n=0
while [ $(( $(date +%s) - t0 )) -lt 150 ]; do
  n="$(count_jobs)"; [ "${n:-0}" -ge 2 ] && break; sleep 5
done
[ "${n:-0}" -ge 2 ] && PASS "scheduled run repeated unattended ($n ssh jobs for T-root, 1 POSTed)" || FAIL "no scheduled repeat within 150 s (jobs: ${n:-0})"

# ---------------------------------------------------------------------------
STEP "credential hygiene (acceptance 3b)"
podman logs "$HUB_CTR" >"$WORK/hub.log" 2>&1
python3 - "$HUB_BASE" "$TOKEN" "$WORK/audit-dump.json" <<'PY'
import json, sys, urllib.request
hub, token, out = sys.argv[1:4]
rows, cursor = [], ""
while True:
    url = hub + "/api/v1/audit?limit=100" + ("&cursor=" + cursor if cursor else "")
    d = json.load(urllib.request.urlopen(urllib.request.Request(url, headers={"Authorization": "Bearer " + token})))
    rows += d["data"]
    cursor = (d.get("meta") or {}).get("next_cursor") or ""
    if not cursor:
        break
json.dump(rows, open(out, "w"))
sys.exit(0 if rows else 1)
PY
[ $? -eq 0 ] && PASS "audit trail dumped" || FAIL "could not read a non-empty audit trail"
python3 - "$WORK/id_ed25519" "$WORK/hub.log" "$WORK/audit-dump.json" <<'PY'
import sys
lines = [l.strip() for l in open(sys.argv[1]) if l.strip() and "PRIVATE KEY" not in l]
texts = [open(f, errors="ignore").read() for f in sys.argv[2:]]
hits = sum(t.count(l) for l in lines for t in texts) + sum(t.count("PRIVATE KEY") for t in texts)
print("credential string hits:", hits)
sys.exit(0 if hits == 0 and lines else 1)
PY
[ $? -eq 0 ] && PASS "credential string hits: 0 (hub log + audit dump)" || FAIL "credential material found in hub log or audit"
if [ -n "${KK_EVIDENCE_DIR:-}" ]; then
  mkdir -p "$KK_EVIDENCE_DIR"
  cp "$WORK/scan-root.json" "$WORK/scan-scanner.json" "$WORK/audit-dump.json" "$KK_EVIDENCE_DIR/" 2>/dev/null || true
fi

STEP "result"
if [ "$FAILED" -eq 0 ]; then echo "ALL PASS"; exit 0; fi
echo "ONE OR MORE STEPS FAILED (hub logs: podman logs $HUB_CTR)"; exit 1
