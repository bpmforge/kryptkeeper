#!/usr/bin/env bash
# W32-18: live proof of the ITSM connectors (ServiceNow Table API, Jira Cloud
# REST v3), the approval bridge and the CMDB ownership sync, against a REAL hub.
#
#   KK_ITSM_MODE=stub  (default)  the ITSM side is tests/live/itsm/stub_itsm.py,
#                                 a Python STAND-IN written from the documented
#                                 API shapes. It proves the hub's half of the
#                                 conversation. It is NOT ServiceNow and NOT Jira
#                                 and no result printed in this mode says so.
#   KK_ITSM_MODE=real             a human-provided ServiceNow PDI and Jira Cloud
#                                 site. Needs all of these in the environment
#                                 (never echoed, never written to disk/git):
#                                   KK_SNOW_URL KK_SNOW_USER KK_SNOW_PASSWORD
#                                   KK_JIRA_URL KK_JIRA_EMAIL KK_JIRA_TOKEN KK_JIRA_PROJECT
#                                   KK_JIRA_APPROVER_ACCOUNT  (accountId of the human who
#                                                              will set the approved status)
#                                 optional: KK_JIRA_ISSUE_TYPE (Task), KK_JIRA_APPROVED_STATUS
#                                 (Approved), KK_JIRA_DONE_STATUS.
#                                 Real mode status: PENDING-RUN (no instance existed when
#                                 this was written; see README.md).
#
# Legs (each PASS/FAIL/SKIP/PENDING-RUN; non-zero exit on any FAIL):
#   1 setup        credential + connection per system through the real API (event_classes
#                  as [{class, ticket_type}], ServiceNow approval_pending => change_request),
#                  then POST /itsm/connections/{id}/test on each (and a bad credential)
#   2 idempotency  one event id submitted 5x => exactly 1 incident and 1 issue, with
#                  CN/serial/expiry/risk/link; then a crash-after-create replay adopts
#                  the ticket (Find before Create) instead of duplicating it
#   3 approval     approval requests raised through the real API reach ITSM by the hub's
#                  own approval_pending path (see below). Jira: ticket set to the approved
#                  status by a mapped accountId => hub approval approved within 2 poll
#                  intervals, audited; unmapped approver => refused. ServiceNow: the same on
#                  a change_request (approval field + sysapproval_approver row, mapped
#                  sys_user sys_id)
#   4 recovery     a verified renewal driven through the hub (stand-in: F5 push target, TLS
#                  verify) => the incident is Resolved and the issue Done within 300 s, with
#                  the close comment (stub mode only: a push target is customer-side)
#   5 cmdb         100 certificates, 100 CIs => 100 owners populated, 100 audit rows
#   6 outage       ITSM down => queued, alert raised, 0 tickets; ITSM back => all
#                  tickets exist exactly once (stub: accelerated; KK_ITSM_FULL_OUTAGE=1
#                  keeps the outage for a real wall-clock hour)
#
# HOW EVENTS ENTER THE HUB. Legs 2 and 6 (and the ticket that leg 4 resolves) still
# insert the queue row with the same INSERT ... ON CONFLICT DO NOTHING that
# Store.InsertEvent runs: the renewal_failed and expiry_no_owner producers fire from
# the daily renewal sweep. Leg 3 is different: the harness creates one enabled `itsm`
# notification rule through POST /notifications/rules (target = the connection id) and
# then everything is the hub's own code: POST /certificates
# => approval created => approval_pending announced => delivery worker => itsm.Channel =>
# Submit (ticket type from the connection's event_classes) => approval link. The rule is
# deleted through the API again before the tickets are drained. Everything after a queue
# row exists is the real product in every leg: the 60 s drain ticker, the credential
# store, the egress-guarded connectors, the backoff, the approval bridge, auto-resolve,
# the CMDB job and the audit trail.
#
# KK_UAT_KEEP=1 keeps the work dir (credentials are never written there).
# KK_RECORD=1 appends this run to tests/live/itsm/RESULTS.md.
set +x
set -u
set -o pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$HERE/../../.." && pwd)"
MODE="${KK_ITSM_MODE:-stub}"
WORK="$(mktemp -d /tmp/kk-uat-itsm.XXXXXX)"
HUB_DIR="$WORK/hub"
HUB_PORT=8098
STUB_PORT="${KK_ITSM_STUB_PORT:-9098}"
F5_VERIFY_PORT="${KK_ITSM_F5_VERIFY_PORT:-9099}"
HUB_BASE="http://127.0.0.1:${HUB_PORT}"
TOKEN=uat-itsm-bootstrap-token
PEPPER="uat-pepper-32-characters-minimum!!"
RUN_ID="$(date +%s)"
DRAIN_WAIT=150     # drain ticker is 60 s; allow one missed tick
BRIDGE_INTERVAL=60 # approval bridge poll interval (defaultBridgeInterval)
FAILED=0
HUB_PID=""
STUB_PID=""
RESULTS=()
KEEP_PATTERN='^$'

STEP() { echo; echo "== $* =="; }
rec()  { RESULTS+=("$1|$2|$3"); }
PASS() { echo "PASS: $2"; rec "$1" PASS "$2"; }
FAIL() { echo "FAIL: $2"; rec "$1" FAIL "$2"; FAILED=1; }
SKIP() { echo "SKIP: $2"; rec "$1" SKIP "$2"; }
PEND() { echo "PENDING-RUN: $2"; rec "$1" PENDING-RUN "$2"; }
DIE()  { echo "FAIL: $*"; FAILED=1; exit 1; }

case "$MODE" in
  stub|real) ;;
  *) echo "KK_ITSM_MODE must be stub or real" >&2; exit 2 ;;
esac

# --------------------------------------------------------------------------
# environment / prerequisites
# --------------------------------------------------------------------------
if [ "$MODE" = real ]; then
  missing=""
  for v in KK_SNOW_URL KK_SNOW_USER KK_SNOW_PASSWORD KK_JIRA_URL KK_JIRA_EMAIL KK_JIRA_TOKEN KK_JIRA_PROJECT KK_JIRA_APPROVER_ACCOUNT; do
    [ -n "${!v:-}" ] || missing="$missing $v"
  done
  if [ -n "$missing" ]; then echo "real mode refuses to run, unset:$missing" >&2; rmdir "$WORK" 2>/dev/null; exit 2; fi
  SNOW_URL="${KK_SNOW_URL%/}"; JIRA_URL="${KK_JIRA_URL%/}"
  SNOW_USER="$KK_SNOW_USER"; SNOW_PASS="$KK_SNOW_PASSWORD"
  JIRA_EMAIL="$KK_JIRA_EMAIL"; JIRA_TOKEN="$KK_JIRA_TOKEN"; JIRA_PROJECT="$KK_JIRA_PROJECT"
  CN_PREFIX="[kk-live] "
else
  # The hub's egress guard refuses loopback and the connectors accept plain http
  # only for loopback, so the stand-in is HTTPS on a private LAN address.
  STUB_HOST="${KK_ITSM_STUB_HOST:-$(python3 - <<'PY'
import ipaddress, socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
try:
    s.connect(("10.255.255.255", 1)); ip = s.getsockname()[0]
except OSError:
    ip = "127.0.0.1"
a = ipaddress.ip_address(ip)
print(ip if a.is_private and not a.is_loopback else "127.0.0.1")
PY
)}"
  [ "$STUB_HOST" = 127.0.0.1 ] && { echo "no private interface for the stand-in; the hub egress guard would refuse loopback" >&2; rmdir "$WORK" 2>/dev/null; exit 2; }
  SNOW_URL="https://${STUB_HOST}:${STUB_PORT}"; JIRA_URL="$SNOW_URL"
  SNOW_USER=itil-live; SNOW_PASS=stub-not-a-real-password
  JIRA_EMAIL=svc@itsm.test; JIRA_TOKEN=stub-not-a-real-token; JIRA_PROJECT=KK
  CN_PREFIX=""
fi
JIRA_APPROVED_STATUS="${KK_JIRA_APPROVED_STATUS:-Approved}"
JIRA_ISSUE_TYPE="${KK_JIRA_ISSUE_TYPE:-Task}"
JIRA_DONE_STATUS="${KK_JIRA_DONE_STATUS:-}"
APPROVER_ACCT="${KK_JIRA_APPROVER_ACCOUNT:-acct-bob}"
SNOW_APPROVER="${KK_SNOW_APPROVER_SYSID:-}"  # sys_user sys_id of the human who approves the change in ServiceNow (real mode)
[ "$MODE" = stub ] && SNOW_APPROVER="snow-approver-b"

for tool in go python3 curl openssl; do command -v "$tool" >/dev/null || { echo "need $tool" >&2; exit 2; }; done
if lsof -nP -iTCP:"$HUB_PORT" -sTCP:LISTEN >/dev/null 2>&1; then echo "port $HUB_PORT is already in use; refusing to touch it" >&2; rmdir "$WORK" 2>/dev/null; exit 2; fi
if [ "$MODE" = stub ] && lsof -nP -iTCP:"$STUB_PORT" -sTCP:LISTEN >/dev/null 2>&1; then echo "port $STUB_PORT is already in use (set KK_ITSM_STUB_PORT)" >&2; rmdir "$WORK" 2>/dev/null; exit 2; fi
if [ "$MODE" = stub ] && lsof -nP -iTCP:"$F5_VERIFY_PORT" -sTCP:LISTEN >/dev/null 2>&1; then echo "port $F5_VERIFY_PORT is already in use (set KK_ITSM_F5_VERIFY_PORT)" >&2; rmdir "$WORK" 2>/dev/null; exit 2; fi

# --------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------
curlj() { curl -sS -H "Authorization: Bearer ${TOKEN}" -H 'Content-Type: application/json' "$@"; }
jget() { python3 -c "import json,sys; d=json.load(sys.stdin); print(eval(sys.argv[1]))" "$1" 2>/dev/null; }
ctl() { curl -sS --cacert "$WORK/stub.pem" "$@"; }
now_s() { date +%s; }

cleanup() {
  STEP "cleanup"
  if [ "$MODE" = real ] && [ -s "$WORK/created.txt" ]; then
    # real mode creates real tickets: close the ones this run made.
    while read -r sys ref; do
      probe close-"$sys" "$ref" >/dev/null 2>&1 && echo "  closed $sys $ref" || echo "  could not close $sys $ref - close it by hand"
    done < "$WORK/created.txt"
  fi
  [ -n "$HUB_PID" ] && kill "$HUB_PID" 2>/dev/null
  [ -n "$STUB_PID" ] && kill "$STUB_PID" 2>/dev/null
  wait 2>/dev/null
  if [ "$FAILED" = 1 ] && [ -f "$WORK/hub.log" ]; then
    echo "--- hub.log (last 25, credentials scrubbed) ---"
    tail -25 "$WORK/hub.log" | sed -E "s/(password|token|secret)[\"']?[:= ]+[^ ,\"']+/\\1=REDACTED/Ig"
  fi
  if [ -n "${KK_UAT_KEEP:-}" ]; then echo "KK_UAT_KEEP set: leaving $WORK"; else rm -rf "$WORK"; fi
}
trap cleanup EXIT

# probe.py: the harness's own client for the ITSM systems (both modes).
cat > "$WORK/probe.py" <<'PY'
import base64, json, os, ssl, sys, urllib.error, urllib.parse, urllib.request

def ctx():
    c = os.environ.get("PROBE_CACERT")
    return ssl.create_default_context(cafile=c) if c else ssl.create_default_context()

def call(base, user, pw, method, path, q=None, body=None):
    url = base + path + ("?" + urllib.parse.urlencode(q) if q else "")
    req = urllib.request.Request(url, method=method, data=json.dumps(body).encode() if body is not None else None)
    req.add_header("Authorization", "Basic " + base64.b64encode((user + ":" + pw).encode()).decode())
    req.add_header("Accept", "application/json")
    if body is not None:
        req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, context=ctx(), timeout=30) as r:
            raw = r.read()
            return r.status, (json.loads(raw) if raw else {})
    except urllib.error.HTTPError as e:
        return e.code, {}

E = os.environ
snow = lambda m, p, q=None, b=None: call(E["PROBE_SNOW_URL"], E["PROBE_SNOW_USER"], E["PROBE_SNOW_PASS"], m, p, q, b)
jira = lambda m, p, q=None, b=None: call(E["PROBE_JIRA_URL"], E["PROBE_JIRA_EMAIL"], E["PROBE_JIRA_TOKEN"], m, p, q, b)

def adf_text(n):
    if isinstance(n, dict):
        return n.get("text", "") + "\n".join(adf_text(c) for c in n.get("content", []))
    return ""

cmd = sys.argv[1]
if cmd == "ping-snow":
    s, _ = snow("GET", "/api/now/table/incident", {"sysparm_limit": "1", "sysparm_fields": "sys_id"})
    print(s); sys.exit(0 if s == 200 else 1)
elif cmd == "ping-jira":
    s, _ = jira("GET", "/rest/api/3/myself") if os.environ.get("PROBE_REAL") else jira("GET", "/rest/api/3/search/jql", {"jql": 'labels = "kk-ping"', "maxResults": "1"})
    print(s); sys.exit(0 if s == 200 else 1)
elif cmd in ("snow-find", "snow-find-change"):
    table = "change_request" if cmd == "snow-find-change" else "incident"
    s, d = snow("GET", "/api/now/table/" + table, {"sysparm_query": "correlation_id=" + sys.argv[2], "sysparm_limit": "50",
                                                    "sysparm_fields": "sys_id,number,state,short_description,description,urgency,correlation_id,close_notes"})
    r = d.get("result", [])
    print(json.dumps({"status": s, "count": len(r), "items": r}))
elif cmd == "jira-find":
    s, d = jira("GET", "/rest/api/3/search/jql", {"jql": 'project = "%s" AND labels = "%s"' % (os.environ["PROBE_JIRA_PROJECT"], sys.argv[2]),
                                                    "maxResults": "50", "fields": "summary,description,labels,status"})
    items = []
    for i in d.get("issues", []):
        f = i.get("fields", {})
        items.append({"key": i["key"], "summary": f.get("summary", ""), "description": adf_text(f.get("description")),
                      "labels": f.get("labels", []), "status": (f.get("status") or {}).get("name", ""),
                      "status_cat": ((f.get("status") or {}).get("statusCategory") or {}).get("key", "")})
    print(json.dumps({"status": s, "count": len(items), "items": items}))
elif cmd == "jira-comments":
    s, d = jira("GET", "/rest/api/3/issue/%s/comment" % sys.argv[2])
    print(json.dumps({"status": s, "text": "\n".join(adf_text(c.get("body")) for c in d.get("comments", []))}))
elif cmd == "close-snow":
    s, _ = snow("PATCH", "/api/now/table/incident/" + sys.argv[2],
                body={"state": "6", "close_code": "Solved (Permanently)", "close_notes": "kk-live harness cleanup"})
    sys.exit(0 if s < 300 else 1)
elif cmd == "close-snowchg":
    s, _ = snow("PATCH", "/api/now/table/change_request/" + sys.argv[2],
                body={"state": "3", "close_code": "successful", "close_notes": "kk-live harness cleanup"})
    sys.exit(0 if s < 300 else 1)
elif cmd == "close-jira":
    s, d = jira("GET", "/rest/api/3/issue/%s/transitions" % sys.argv[2])
    t = [x["id"] for x in d.get("transitions", []) if x.get("to", {}).get("statusCategory", {}).get("key") == "done"]
    if not t:
        sys.exit(1)
    s, _ = jira("POST", "/rest/api/3/issue/%s/transitions" % sys.argv[2], body={"transition": {"id": t[0]}})
    sys.exit(0 if s < 300 else 1)
PY
probe() {
  PROBE_SNOW_URL="$SNOW_URL" PROBE_SNOW_USER="$SNOW_USER" PROBE_SNOW_PASS="$SNOW_PASS" \
  PROBE_JIRA_URL="$JIRA_URL" PROBE_JIRA_EMAIL="$JIRA_EMAIL" PROBE_JIRA_TOKEN="$JIRA_TOKEN" PROBE_JIRA_PROJECT="$JIRA_PROJECT" \
  PROBE_CACERT="$([ "$MODE" = stub ] && echo "$WORK/stub.pem")" PROBE_REAL="$([ "$MODE" = real ] && echo 1)" \
  python3 "$WORK/probe.py" "$@"
}

# db.py: queue-row access to the hub's own sqlite database (see header).
cat > "$WORK/db.py" <<'PY'
import calendar, json, os, sqlite3, sys, time

def ts(t=None):
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(t if t is not None else time.time()))

db = sqlite3.connect(os.environ["KK_DB"], timeout=30)
db.execute("PRAGMA busy_timeout=30000")
cmd, a = sys.argv[1], sys.argv[2:]
if cmd == "seed":
    conn, eid, cls, cn, serial, risk, link, fp, not_after = a
    payload = json.dumps({"id": eid, "class": cls, "cn": cn, "serial": serial, "risk": risk, "deep_link": link,
                          "fingerprint": fp, "tenant": "default", "not_after": not_after})
    now = ts()
    cur = db.execute("INSERT INTO itsm_events (event_id,connection_id,class,fingerprint,payload,status,ticket_key,ticket_url,attempts,"
                     "next_attempt_at,last_error,recreated,tenant,created_at,updated_at) VALUES (?,?,?,?,?,'pending','','',0,?,'',0,'default',?,?) "
                     "ON CONFLICT(event_id) DO NOTHING", (eid, conn, cls, fp, payload, now, now, now))
    db.commit(); print("inserted" if cur.rowcount else "duplicate")
elif cmd == "state":
    r = db.execute("SELECT status,ticket_key,attempts,last_error,next_attempt_at FROM itsm_events WHERE event_id=?", (a[0],)).fetchone()
    print("|".join(str(x) for x in r) if r else "missing")
elif cmd == "reset":
    db.execute("UPDATE itsm_events SET status='pending',ticket_key='',ticket_url='',attempts=0,next_attempt_at=? WHERE event_id=?", (ts(), a[0]))
    db.commit()
elif cmd == "link":
    db.execute("INSERT INTO itsm_approval_links (event_id,approval_id,created_at) VALUES (?,?,?) ON CONFLICT(event_id) DO NOTHING", (a[0], a[1], ts()))
    db.commit()
elif cmd == "make_due":
    db.execute("UPDATE itsm_events SET next_attempt_at=? WHERE status='pending' AND event_id LIKE ?", (ts(), a[0] + "%")); db.commit()
elif cmd == "count":  # count <prefix> -> JSON of status counts and min attempts
    rows = db.execute("SELECT status,COUNT(*),MIN(attempts) FROM itsm_events WHERE event_id LIKE ? GROUP BY status", (a[0] + "%",)).fetchall()
    print(json.dumps({s: {"n": n, "min_attempts": m} for s, n, m in rows}))
elif cmd == "min_wait":  # seconds until the earliest next attempt among pending rows of a prefix
    r = db.execute("SELECT MIN(next_attempt_at) FROM itsm_events WHERE status='pending' AND event_id LIKE ?", (a[0] + "%",)).fetchone()[0]
    print(int(calendar.timegm(time.strptime(r, "%Y-%m-%dT%H:%M:%SZ")) - time.time()) if r else -1)
elif cmd == "ref":
    r = db.execute("SELECT ticket_key FROM itsm_events WHERE event_id=?", (a[0],)).fetchone()
    print(r[0] if r else "")
elif cmd == "link_event":  # link_event <approval_id> <connection_id> -> the event id the hub linked to the approval
    r = db.execute("SELECT event_id FROM itsm_approval_links WHERE approval_id=? AND event_id LIKE ?", (a[0], "%:" + a[1])).fetchone()
    print(r[0] if r else "")
PY
dbx() { KK_DB="$HUB_DIR/data/kryptkeeper.db" python3 "$WORK/db.py" "$@"; }

mkident() { # name role -> T_<name> token + ENTRIES
  local name="$1" role="$2" secret verifier
  secret="$(openssl rand -hex 24)"
  verifier="$(printf '%s' "$secret" | openssl dgst -sha256 -hmac "$PEPPER" -hex | awk '{print $NF}')"
  eval "T_$name=kk_uat${name}_${secret}"
  ENTRIES="${ENTRIES:+$ENTRIES,}{\"name\":\"$name\",\"kid\":\"uat$name\",\"secret_verifier\":\"$verifier\",\"principal_id\":\"$name\",\"role\":\"$role\",\"active\":true}"
}
ENTRIES=""
mkident alice pki-admin

code() { local tok="$1"; shift; curl -sS -o "$WORK/last.json" -w '%{http_code}' -H "Authorization: Bearer $tok" -H 'Content-Type: application/json' "$@"; }

start_hub() {
  "$HUB_DIR/kryptkeeper" >>"$WORK/hub.log" 2>&1 &
  HUB_PID=$!
  local tries=60
  until curl -sS -f -o /dev/null "${HUB_BASE}/api/v1/cas" -H "Authorization: Bearer ${TOKEN}" 2>/dev/null; do
    tries=$((tries - 1)); [ $tries -le 0 ] && DIE "hub never answered /api/v1/cas, see $WORK/hub.log"
    sleep 1
  done
}
stop_hub() { [ -n "$HUB_PID" ] && kill "$HUB_PID" 2>/dev/null; wait "$HUB_PID" 2>/dev/null; HUB_PID=""; }

# find_tickets <system> <id>  -> JSON {count, items}
find_tickets() {
  case "$1" in
    snow) probe snow-find "$2" ;;
    jira) probe jira-find "kk-$(printf '%s' "$2" | tr -c 'A-Za-z0-9_-' '_')" ;;
  esac
}
find_tickets_change() { probe snow-find-change "$1"; } # ServiceNow change_request by event id
ticket_count() { find_tickets "$1" "$2" | jget 'd["count"]'; }
# wait_status <event_id> <status> <timeout_s>: poll the queue row.
wait_status() {
  local eid=$1 want=$2 tries=$(( $3 / 3 ))
  while [ $tries -gt 0 ]; do
    [ "$(dbx state "$eid" | cut -d'|' -f1)" = "$want" ] && return 0
    sleep 3; tries=$((tries - 1))
  done
  return 1
}
remember() { [ "$MODE" = real ] && echo "$1 $2" >> "$WORK/created.txt"; return 0; }
ISO_NA="$(python3 -c 'import time; print(time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time()+86400*30)))')"

# --------------------------------------------------------------------------
# 1. setup
# --------------------------------------------------------------------------
STEP "1. build hub, start ${MODE} ITSM side, start hub on :${HUB_PORT}"
mkdir -p "$HUB_DIR/data"
( cd "$REPO_ROOT" && go build -o "$HUB_DIR/kryptkeeper" ./cmd/kryptkeeper ) || DIE "go build failed"
PASS setup "hub built"

if [ "$MODE" = stub ]; then
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -keyout "$WORK/stub.key" -out "$WORK/stub.pem" \
    -days 1 -subj "/CN=$STUB_HOST" -addext "subjectAltName=IP:$STUB_HOST" 2>/dev/null || DIE "could not make the stand-in certificate"
  python3 "$HERE/stub_itsm.py" --bind "$STUB_HOST" --port "$STUB_PORT" --cert "$WORK/stub.pem" --key "$WORK/stub.key" \
    --state "$WORK/stub-state.json" --f5-verify-port "$F5_VERIFY_PORT" --snow-user "$SNOW_USER" --snow-pass "$SNOW_PASS" \
    --jira-user "$JIRA_EMAIL" --jira-pass "$JIRA_TOKEN" >"$WORK/stub.log" 2>&1 &
  STUB_PID=$!
  for _ in $(seq 1 30); do ctl -f -o /dev/null "$SNOW_URL/_ctl/health" 2>/dev/null && break; sleep 0.5; done
  ctl -f -o /dev/null "$SNOW_URL/_ctl/health" 2>/dev/null && PASS setup "STAND-IN ITSM up at $SNOW_URL (pid $STUB_PID); NOT a real ServiceNow/Jira" || DIE "stand-in did not start, see $WORK/stub.log"
else
  probe ping-snow >/dev/null && PASS setup "ServiceNow instance answered the Table API (wake a hibernating PDI first)" || DIE "ServiceNow did not answer GET /api/now/table/incident with 200"
  probe ping-jira >/dev/null && PASS setup "Jira Cloud answered /rest/api/3/myself" || DIE "Jira did not answer /rest/api/3/myself with 200"
fi

export APP_BOOTSTRAP_TOKEN="$TOKEN" AUTH_MODE=bootstrap APP_CERTIFICATE_PROVIDER=ca KRYPTKEEPER_TLS_DISABLE=true \
  APP_API_KEY_PEPPER="$PEPPER" APP_API_KEY_AUTH_ENABLED=true APP_API_KEYS_JSON="[$ENTRIES]" \
  APP_DISCOVERY_PROVIDER=db APP_NOTIFICATION_PROVIDER=delivery \
  APP_CREDENTIAL_STORE_PASSPHRASE='uat-cred-passphrase-32-bytes-long!!' \
  KRYPTKEEPER_KEYSTORE_PASSPHRASE='uat-keystore-passphrase-32-bytes!!' \
  KRYPTKEEPER_DATA_DIR="$HUB_DIR/data" APP_CA_FILE="$HUB_DIR/data/cas.json" APP_TEMPLATE_FILE="$HUB_DIR/data/templates.json" \
  APP_CERTIFICATE_FILE="$HUB_DIR/data/certificates.json" APP_AUDIT_FILE="$HUB_DIR/data/audit.json" \
  APP_CERTS_SUMMARY_FILE="$HUB_DIR/data/certs_summary.json" \
  KRYPTKEEPER_BOOTSTRAP_CREATE_ROOT=true KRYPTKEEPER_CA_NAME="UAT Root CA" APP_BIND_ADDR=127.0.0.1 PORT="$HUB_PORT"
# The hub trusts exactly the stand-in's certificate. Linux Go honours SSL_CERT_FILE; on macOS Go 1.27
# only does so with GODEBUG x509sslcertoverrideplatform=1, and go.mod's `go 1.26` otherwise defaults it
# to 0 (found live: without it every connector call fails "certificate signed by unknown authority").
[ "$MODE" = stub ] && export SSL_CERT_FILE="$WORK/stub.pem" GODEBUG="${GODEBUG:+$GODEBUG,}x509sslcertoverrideplatform=1"
start_hub
[ -f "$HUB_DIR/data/kryptkeeper.db" ] && PASS setup "hub up on $HUB_BASE (core db $HUB_DIR/data/kryptkeeper.db)" || DIE "no core sqlite db found"

STEP "1b. credentials and connections through the real API"
mkcred() { # name -> id; CRED_JSON env holds the object (a JSON object payload is stored verbatim, which is what the connector factories parse)
  python3 -c "
import json,os,sys
print(json.dumps({'name':sys.argv[1],'credential_type':'api_token','payload':json.loads(os.environ['CRED_JSON'])}))" "$1" > "$WORK/cred.json"
  chmod 600 "$WORK/cred.json"
  local c; c=$(code "$TOKEN" -X POST "$HUB_BASE/api/v1/credentials" -d @"$WORK/cred.json"); rm -f "$WORK/cred.json"
  [ "$c" = 201 ] || { echo "credential $1 -> HTTP $c" >&2; return 1; }
  jget 'd["data"]["id"]' <"$WORK/last.json"
}
SNOW_CRED="$(U="$SNOW_USER" P="$SNOW_PASS" CRED_JSON="$(U="$SNOW_USER" P="$SNOW_PASS" python3 -c "import json,os; print(json.dumps({'username':os.environ['U'],'password':os.environ['P']}))")" mkcred "kk-live-snow-$RUN_ID")"
JIRA_CRED="$(CRED_JSON="$(E="$JIRA_EMAIL" T="$JIRA_TOKEN" K="$JIRA_PROJECT" IT="$JIRA_ISSUE_TYPE" AS="$JIRA_APPROVED_STATUS" DS="$JIRA_DONE_STATUS" python3 -c "
import json,os
print(json.dumps({'email':os.environ['E'],'api_token':os.environ['T'],'project_key':os.environ['K'],'issue_type':os.environ['IT'],
                  'approved_status':os.environ['AS'],'done_status':os.environ['DS']}))")" mkcred "kk-live-jira-$RUN_ID")"
[ -n "$SNOW_CRED" ] && [ -n "$JIRA_CRED" ] && PASS setup "credentials stored (ids only: $SNOW_CRED, $JIRA_CRED)" || DIE "credential create failed"

mkconn() { # kind name base cred event_classes_json -> id (event_classes: [{class, ticket_type}])
  local c; c=$(code "$TOKEN" -X POST "$HUB_BASE/api/v1/itsm/connections" -d "$(python3 -c "import json,sys; print(json.dumps({'kind':sys.argv[1],'name':sys.argv[2],'base_url':sys.argv[3],'credential_ref':sys.argv[4],'event_classes':json.loads(sys.argv[5])}))" "$1" "$2" "$3" "$4" "$5")")
  [ "$c" = 201 ] || { echo "connection $2 -> HTTP $c $(head -c 200 "$WORK/last.json")" >&2; return 1; }
  jget 'd["data"]["id"]' <"$WORK/last.json"
}
# approval_pending opens a change_request on ServiceNow (a change needs approval; an incident does not) and the
# configured issue type on Jira; renewal_failed opens an incident / a Task.
SNOW_CLASSES='[{"class":"renewal_failed","ticket_type":"incident"},{"class":"approval_pending","ticket_type":"change_request"}]'
JIRA_CLASSES="[{\"class\":\"renewal_failed\",\"ticket_type\":\"$JIRA_ISSUE_TYPE\"},{\"class\":\"approval_pending\",\"ticket_type\":\"$JIRA_ISSUE_TYPE\"}]"
SNOW_CONN="$(mkconn servicenow "kk-live-snow-$RUN_ID" "$SNOW_URL" "$SNOW_CRED" "$SNOW_CLASSES")"
JIRA_CONN="$(mkconn jira "kk-live-jira-$RUN_ID" "$JIRA_URL" "$JIRA_CRED" "$JIRA_CLASSES")"
if [ -n "$SNOW_CONN" ] && [ -n "$JIRA_CONN" ]; then
  PASS setup "connections created: servicenow=$SNOW_CONN jira=$JIRA_CONN"
else
  DIE "connection create failed"
fi
c=$(code "$TOKEN" "$HUB_BASE/api/v1/itsm/connections/$SNOW_CONN"); S="$(jget 'json.dumps(d)' <"$WORK/last.json")"
echo "$S" | grep -q "$SNOW_PASS" && FAIL setup "connection response leaks the credential" || PASS setup "connection response carries the credential reference only"
[ "$(jget 'json.dumps(d["data"]["event_classes"], sort_keys=True)' <"$WORK/last.json")" = "$(python3 -c "import json,sys; print(json.dumps(json.loads(sys.argv[1]), sort_keys=True))" "$SNOW_CLASSES")" ] \
  && PASS setup "event_classes round-trip as [{class, ticket_type}]" || FAIL setup "event_classes did not round-trip: $(head -c 300 "$WORK/last.json")"

STEP "1a. POST /itsm/connections/{id}/test (one read-only Find through the real connector)"
for pair in "servicenow:$SNOW_CONN" "jira:$JIRA_CONN"; do
  kind="${pair%%:*}"; cid="${pair#*:}"
  c=$(code "$TOKEN" -X POST "$HUB_BASE/api/v1/itsm/connections/$cid/test")
  [ "$c" = 200 ] && [ "$(jget 'd["data"]["ok"]' <"$WORK/last.json")" = True ] \
    && PASS setup "$kind: connection test ok (credential, egress guard and connector path proven before any event)" \
    || FAIL setup "$kind: connection test -> HTTP $c $(head -c 200 "$WORK/last.json")"
  grep -q "$SNOW_PASS\|$JIRA_TOKEN" "$WORK/last.json" && FAIL setup "$kind: test response leaks the credential"
done
if [ "$MODE" = stub ]; then
  # a wrong password is only distinguishable where the stand-in enforces it (a real service would lock the account)
  BAD_CRED="$(CRED_JSON='{"username":"itil-live","password":"wrong-on-purpose"}' mkcred "kk-live-bad-$RUN_ID")"
  BAD_CONN="$(mkconn servicenow "kk-live-bad-$RUN_ID" "$SNOW_URL" "$BAD_CRED" '[]')"
  c=$(code "$TOKEN" -X POST "$HUB_BASE/api/v1/itsm/connections/$BAD_CONN/test")
  [ "$c" = 200 ] && [ "$(jget 'd["data"]["ok"]' <"$WORK/last.json")" = False ] \
    && PASS setup "wrong credential: test reports ok=false with a generic detail ($(jget 'd["data"]["detail"]' <"$WORK/last.json"))" \
    || FAIL setup "wrong credential: HTTP $c $(head -c 200 "$WORK/last.json")"
  c=$(code "$TOKEN" -X DELETE "$HUB_BASE/api/v1/itsm/connections/$BAD_CONN"); [ "$c" = 204 ] || echo "  (could not delete the bad-credential connection: HTTP $c)"
fi
code "$TOKEN" "$HUB_BASE/api/v1/audit?action=itsm.connection.test&limit=20" >/dev/null
[ "$(jget 'sum(1 for r in d["data"] if r["action"]=="itsm.connection.test")' <"$WORK/last.json")" -ge 2 ] 2>/dev/null \
  && PASS setup "itsm.connection.test audited" || FAIL setup "no itsm.connection.test audit rows"

csr_body() { # cn template_id out.json: a CSR for cn against the first CA
  openssl ecparam -name prime256v1 -genkey -noout -out "$WORK/a.key" 2>/dev/null
  openssl req -new -key "$WORK/a.key" -subj "/CN=$1" -addext "subjectAltName=DNS:$1" -out "$WORK/a.csr" 2>/dev/null
  python3 -c "import json,sys; json.dump({'ca_id':sys.argv[1],'template_id':sys.argv[2],'csr_pem':open(sys.argv[3]).read()}, open(sys.argv[4],'w'))" "$CA_ID" "$2" "$WORK/a.csr" "$3"
}

STEP "1c. seed 100 certificates and the CI list"
ECHO_CMDB_STUB=""; [ "$MODE" = stub ] && ECHO_CMDB_STUB="$SNOW_URL"
STUB_CACERT="$WORK/stub.pem" bash "$HERE/seed_hosts.sh" "$HUB_BASE" "$TOKEN" "$WORK/seed" "$ECHO_CMDB_STUB" && PASS setup "100 certificates issued for host-001..100.itsm.test" || DIE "seed_hosts.sh failed"
code "$TOKEN" "$HUB_BASE/api/v1/certificates?q=host-001&limit=5" >/dev/null
CERT_SERIAL="$(jget 'd["data"][0]["serial_number"]' <"$WORK/last.json")"; CERT_FP="$(jget 'd["data"][0]["fingerprint_sha256"]' <"$WORK/last.json")"
CERT_NA="$(jget 'd["data"][0].get("valid_until","")' <"$WORK/last.json")"; [ -n "$CERT_NA" ] || CERT_NA="$ISO_NA"
CERT_CN="${CN_PREFIX}host-001.itsm.test"; CERT_LINK="https://hub.itsm.test/certificates/$CERT_FP"

# One more certificate for leg 4: its tickets are resolved when the hub renews it (a fresh cert keeps the CMDB count at 100).
code "$TOKEN" "$HUB_BASE/api/v1/cas" >/dev/null; CA_ID="$(jget 'd["data"][0]["id"]' <"$WORK/last.json")"
c=$(code "$TOKEN" -X POST "$HUB_BASE/api/v1/templates" -d '{"name":"itsm-live-renew","display_name":"W32-18 renew","key_usage":["digitalSignature"],"extended_key_usage":["serverAuth"],"allowed_algorithms":["ECDSA"],"validity_period":"720h","active":true}')
RENEW_TPL="$(jget 'd["data"]["id"]' <"$WORK/last.json")"
RENEW_CN="renew-me.itsm.test"
csr_body "$RENEW_CN" "$RENEW_TPL" "$WORK/r.json"
c=$(code "$TOKEN" -X POST "$HUB_BASE/api/v1/certificates" --data @"$WORK/r.json")
RENEW_FP="$(jget 'd["data"]["fingerprint_sha256"]' <"$WORK/last.json")"
code "$TOKEN" "$HUB_BASE/api/v1/certificates?q=$RENEW_CN&limit=5" >/dev/null
RENEW_SERIAL="$(jget 'd["data"][0]["serial_number"]' <"$WORK/last.json")"; RENEW_NA="$(jget 'd["data"][0].get("valid_until","")' <"$WORK/last.json")"; [ -n "$RENEW_NA" ] || RENEW_NA="$ISO_NA"
[ -n "$RENEW_FP" ] && PASS setup "certificate $RENEW_CN issued for the recovery leg" || DIE "could not issue $RENEW_CN: HTTP $c $(head -c 200 "$WORK/last.json")"

cat > "$WORK/check.py" <<'PY'
import json, sys
cn, serial, link, na = sys.argv[1:5]
d = json.load(sys.stdin)["items"][0]
text = d.get("description", "") + "\n" + (d.get("short_description", "") or d.get("summary", ""))
need = ["CN: " + cn, "Serial: " + serial, "Expires: " + na, "Risk: high", "Link: " + link]
miss = [n for n in need if n not in text]
print("missing: " + "; ".join(miss) if miss else "ok")
sys.exit(1 if miss else 0)
PY
check_fields() { python3 "$WORK/check.py" "$CERT_CN" "$CERT_SERIAL" "$CERT_LINK" "$CERT_NA"; } # stdin: find_tickets output


# --------------------------------------------------------------------------
# 2. idempotency (acceptance 1)
# --------------------------------------------------------------------------
STEP "2. one event id submitted 5x per system => exactly one ticket"
IDEM_SNOW="kklive-$RUN_ID-idem-snow"; IDEM_JIRA="kklive-$RUN_ID-idem-jira"
ins=0
for i in 1 2 3 4 5; do
  r1="$(dbx seed "$SNOW_CONN" "$IDEM_SNOW" renewal_failed "$CERT_CN" "$CERT_SERIAL" high "$CERT_LINK" "$CERT_FP" "$CERT_NA")"
  r2="$(dbx seed "$JIRA_CONN" "$IDEM_JIRA" renewal_failed "$CERT_CN" "$CERT_SERIAL" high "$CERT_LINK" "$CERT_FP" "$CERT_NA")"
  [ "$r1" = inserted ] && [ "$r2" = inserted ] && ins=$((ins + 1))
done
[ "$ins" = 1 ] && PASS idempotency "5 submissions of one id left 1 queue row per system (ON CONFLICT DO NOTHING)" || FAIL idempotency "expected exactly 1 insert per system, got $ins"
# leg 4's tickets are queued now so the same drain tick creates them (resolved later by the hub on a verified renewal)
REC_SNOW="kklive-$RUN_ID-rec-snow"; REC_JIRA="kklive-$RUN_ID-rec-jira"
dbx seed "$SNOW_CONN" "$REC_SNOW" renewal_failed "${CN_PREFIX}$RENEW_CN" "$RENEW_SERIAL" high "https://hub.itsm.test/certificates/$RENEW_FP" "$RENEW_FP" "$RENEW_NA" >/dev/null
dbx seed "$JIRA_CONN" "$REC_JIRA" renewal_failed "${CN_PREFIX}$RENEW_CN" "$RENEW_SERIAL" high "https://hub.itsm.test/certificates/$RENEW_FP" "$RENEW_FP" "$RENEW_NA" >/dev/null
wait_status "$IDEM_SNOW" created "$DRAIN_WAIT" && wait_status "$IDEM_JIRA" created "$DRAIN_WAIT" \
  && PASS idempotency "drain created both tickets (first successful create also proves credential, egress and connector path)" \
  || FAIL idempotency "rows did not reach created in ${DRAIN_WAIT}s: snow=$(dbx state "$IDEM_SNOW") jira=$(dbx state "$IDEM_JIRA")"
for sys in snow jira; do
  eid="$IDEM_SNOW"; [ "$sys" = jira ] && eid="$IDEM_JIRA"
  n="$(ticket_count "$sys" "$eid")"
  [ "$n" = 1 ] && PASS idempotency "$sys: exactly 1 ticket for the event id" || FAIL idempotency "$sys: $n tickets for the event id, want 1"
  out="$(find_tickets "$sys" "$eid" | check_fields "$sys")"
  [ "$out" = ok ] && PASS idempotency "$sys: ticket carries CN, serial, expiry, risk and deep link" || FAIL idempotency "$sys: $out"
  ref="$(dbx ref "$eid")"; remember "$sys" "$ref"
done

STEP "2b. crash-after-create replay: row reset to pending, Find must adopt the ticket"
dbx reset "$IDEM_SNOW"; dbx reset "$IDEM_JIRA"
tries=$(( DRAIN_WAIT / 3 ))
while [ $tries -gt 0 ]; do
  [ "$(dbx state "$IDEM_SNOW" | cut -d'|' -f1)" = created ] && [ "$(dbx state "$IDEM_JIRA" | cut -d'|' -f1)" = created ] && break
  sleep 3; tries=$((tries - 1))
done
[ "$(ticket_count snow "$IDEM_SNOW")" = 1 ] && [ "$(ticket_count jira "$IDEM_JIRA")" = 1 ] \
  && PASS idempotency "replay adopted the existing incident and issue; still exactly 1 each" \
  || FAIL idempotency "replay duplicated a ticket (snow=$(ticket_count snow "$IDEM_SNOW") jira=$(ticket_count jira "$IDEM_JIRA"))"

# --------------------------------------------------------------------------
# 3. approval via ticket (acceptance 2), Jira and ServiceNow
# --------------------------------------------------------------------------
STEP "3. approval via ticket, events entering by the hub's own approval_pending path"
c=$(code "$T_alice" -X POST "$HUB_BASE/api/v1/templates" -d '{"name":"itsm-live-approval","display_name":"W32-18 approval","key_usage":["digitalSignature"],"extended_key_usage":["serverAuth"],"allowed_algorithms":["ECDSA"],"validity_period":"P30D","active":true,"require_approval":true,"approval_roles":["pki-admin"]}')
APP_TPL="$(jget 'd["data"]["id"]' <"$WORK/last.json")"
[ "$c" = 201 ] && PASS approval "approval-required template created" || FAIL approval "template -> $c $(head -c 200 "$WORK/last.json")"
request_approval() { # cn -> approval id (proposer = alice)
  csr_body "$1" "$APP_TPL" "$WORK/a.json"
  local c; c=$(code "$T_alice" -X POST "$HUB_BASE/api/v1/certificates" --data @"$WORK/a.json")
  [ "$c" = 202 ] && jget 'd.get("approval_id","")' <"$WORK/last.json"
}
c=$(code "$TOKEN" -X POST "$HUB_BASE/api/v1/users/invite" -d '{"email":"approver-b@itsm.test","role":"pki-admin"}')
USER_B="$(jget 'd.get("data",d).get("id","")' <"$WORK/last.json")"
if [ -z "$USER_B" ]; then code "$TOKEN" "$HUB_BASE/api/v1/users" >/dev/null; USER_B="$(jget '[u["id"] for u in d["data"]["items"] if u["email"]=="approver-b@itsm.test"][0]' <"$WORK/last.json")"; fi
[ -n "$USER_B" ] && PASS approval "approver user B created ($USER_B)" || DIE "could not create user B: HTTP $c $(head -c 200 "$WORK/last.json")"
c=$(code "$TOKEN" -X POST "$HUB_BASE/api/v1/itsm/principal-map" -d "{\"kind\":\"jira\",\"external_id\":\"$APPROVER_ACCT\",\"user_id\":\"$USER_B\"}")
[ "$c" = 201 ] && PASS approval "Jira accountId $APPROVER_ACCT mapped to user B" || FAIL approval "principal-map jira -> $c $(head -c 200 "$WORK/last.json")"
SNOW_APPR_ON=""
if [ -n "$SNOW_APPROVER" ]; then
  c=$(code "$TOKEN" -X POST "$HUB_BASE/api/v1/itsm/principal-map" -d "{\"kind\":\"servicenow\",\"external_id\":\"$SNOW_APPROVER\",\"user_id\":\"$USER_B\"}")
  if [ "$c" = 201 ]; then PASS approval "ServiceNow sys_user $SNOW_APPROVER mapped to user B"; SNOW_APPR_ON=1; else FAIL approval "principal-map servicenow -> $c $(head -c 200 "$WORK/last.json")"; fi
else
  PEND approval "ServiceNow approval needs KK_SNOW_APPROVER_SYSID (sys_user sys_id of the approver); Jira approval still runs"
fi

# One rule per connection, created through the API only while that connection's approvals are raised; the
# announcement, delivery, Submit and link are the hub's.
raise_approvals() { # conn cn_ok cn_no -> "ok_id no_id"
  local rule ok no
  c=$(code "$TOKEN" -X POST "$HUB_BASE/api/v1/notifications/rules" -d "{\"name\":\"kk-live-itsm\",\"threshold_days\":30,\"channel\":\"itsm\",\"target\":\"$1\"}")
  [ "$c" = 201 ] || DIE "itsm notification rule for connection $1 -> HTTP $c $(head -c 200 "$WORK/last.json")"
  rule="$(jget 'd["data"]["id"]' <"$WORK/last.json")"
  ok="$(request_approval "$2")"; no="$(request_approval "$3")"
  code "$TOKEN" -X DELETE "$HUB_BASE/api/v1/notifications/rules/$rule" >/dev/null
  echo "$ok $no"
}
read -r APR_J_OK APR_J_NO <<<"$(raise_approvals "$JIRA_CONN" approve-me.itsm.test refuse-me.itsm.test)"
[ -n "$APR_J_OK" ] && [ -n "$APR_J_NO" ] && PASS approval "two pending approvals raised by alice for the Jira connection ($APR_J_OK, $APR_J_NO)" || DIE "could not raise pending approvals"
if [ -n "$SNOW_APPR_ON" ]; then
  read -r APR_S_OK APR_S_NO <<<"$(raise_approvals "$SNOW_CONN" approve-me-snow.itsm.test refuse-me-snow.itsm.test)"
  [ -n "$APR_S_OK" ] && [ -n "$APR_S_NO" ] && PASS approval "two pending approvals raised by alice for the ServiceNow connection ($APR_S_OK, $APR_S_NO)" || DIE "could not raise ServiceNow approvals"
fi

wait_link() { # approval conn -> event id (the hub linked the ticket to the approval)
  local tries=30 e
  while [ $tries -gt 0 ]; do e="$(dbx link_event "$1" "$2")"; [ -n "$e" ] && { echo "$e"; return 0; }; sleep 2; tries=$((tries - 1)); done
  return 1
}
EV_J_OK="$(wait_link "$APR_J_OK" "$JIRA_CONN")"; EV_J_NO="$(wait_link "$APR_J_NO" "$JIRA_CONN")"
[ -n "$EV_J_OK" ] && [ -n "$EV_J_NO" ] && PASS approval "Jira: approval_pending events and approval links created by the hub (no direct queue insert): ${EV_J_OK%%:*}" \
  || DIE "the hub produced no approval_pending event/link for the Jira connection (rule not matched? see hub.log)"
if [ -n "$SNOW_APPR_ON" ]; then
  EV_S_OK="$(wait_link "$APR_S_OK" "$SNOW_CONN")"; EV_S_NO="$(wait_link "$APR_S_NO" "$SNOW_CONN")"
  [ -n "$EV_S_OK" ] && [ -n "$EV_S_NO" ] && PASS approval "ServiceNow: approval_pending events and approval links created by the hub" || DIE "the hub produced no approval_pending event/link for the ServiceNow connection"
fi
code "$TOKEN" "$HUB_BASE/api/v1/itsm/events?limit=200" >/dev/null
[ "$(jget 'sum(1 for e in d["data"]["items"] if e["event_id"]=="'"$EV_J_OK"'" and e["class"]=="approval_pending")' <"$WORK/last.json")" = 1 ] \
  && PASS approval "GET /itsm/events lists the event as class approval_pending" || FAIL approval "GET /itsm/events does not list $EV_J_OK as approval_pending"

wait_status "$EV_J_OK" created "$DRAIN_WAIT" && wait_status "$EV_J_NO" created "$DRAIN_WAIT" && PASS approval "Jira approval-pending issues created" || FAIL approval "Jira approval tickets not created: $(dbx state "$EV_J_OK") / $(dbx state "$EV_J_NO")"
KEY_J_OK="$(dbx ref "$EV_J_OK")"; KEY_J_NO="$(dbx ref "$EV_J_NO")"; remember jira "$KEY_J_OK"; remember jira "$KEY_J_NO"
if [ -n "$SNOW_APPR_ON" ]; then
  wait_status "$EV_S_OK" created "$DRAIN_WAIT" && wait_status "$EV_S_NO" created "$DRAIN_WAIT" && PASS approval "ServiceNow approval-pending tickets created" || FAIL approval "ServiceNow approval tickets not created: $(dbx state "$EV_S_OK") / $(dbx state "$EV_S_NO")"
  KEY_S_OK="$(dbx ref "$EV_S_OK")"; KEY_S_NO="$(dbx ref "$EV_S_NO")"; remember snowchg "$KEY_S_OK"; remember snowchg "$KEY_S_NO"
  [ "$(find_tickets_change "$EV_S_OK" | jget 'd["count"]')" = 1 ] && [ "$(ticket_count snow "$EV_S_OK")" = 0 ] \
    && PASS approval "ServiceNow: the approval_pending ticket is a change_request (event_classes ticket_type), not an incident" \
    || FAIL approval "ServiceNow: expected 1 change_request and 0 incidents for $EV_S_OK"
fi

T_APPROVE="$(now_s)"
if [ "$MODE" = stub ]; then
  ctl -X POST "$SNOW_URL/_ctl/approve?system=jira&id=$KEY_J_OK&approver=$APPROVER_ACCT" >/dev/null
  ctl -X POST "$SNOW_URL/_ctl/approve?system=jira&id=$KEY_J_NO&approver=acct-not-mapped" >/dev/null
  if [ -n "$SNOW_APPR_ON" ]; then
    ctl -X POST "$SNOW_URL/_ctl/approve?system=snow&id=$KEY_S_OK&approver=$SNOW_APPROVER" >/dev/null
    ctl -X POST "$SNOW_URL/_ctl/approve?system=snow&id=$KEY_S_NO&approver=snow-not-mapped" >/dev/null
  fi
else
  echo "ACTION NEEDED: in Jira set $KEY_J_OK to status '$JIRA_APPROVED_STATUS' as accountId $APPROVER_ACCT,"
  echo "               and $KEY_J_NO to the same status as a DIFFERENT, unmapped user."
  [ -n "$SNOW_APPR_ON" ] && echo "               In ServiceNow approve change $KEY_S_OK as sys_user $SNOW_APPROVER and $KEY_S_NO as a different, unmapped user."
  echo "               Then press Enter (10 min)."
  if ! read -r -t 600; then PEND approval "no human confirmed the ticket approvals"; fi
  T_APPROVE="$(now_s)"
fi
approval_status() { code "$T_alice" "$HUB_BASE/api/v1/approvals/$1" >/dev/null; jget 'd["data"].get("status", d["data"].get("state",""))' <"$WORK/last.json"; }
LIMIT=$(( 2 * BRIDGE_INTERVAL + 5 )); E_J=""; E_S=""
while [ $(( $(now_s) - T_APPROVE )) -le $((LIMIT + 10)) ]; do
  [ -z "$E_J" ] && [ "$(approval_status "$APR_J_OK")" = approved ] && E_J=$(( $(now_s) - T_APPROVE ))
  if [ -n "$SNOW_APPR_ON" ]; then [ -z "$E_S" ] && [ "$(approval_status "$APR_S_OK")" = approved ] && E_S=$(( $(now_s) - T_APPROVE )); fi
  [ -n "$E_J" ] && { [ -z "$SNOW_APPR_ON" ] || [ -n "$E_S" ]; } && break
  sleep 3
done
approval_result() { # label approval elapsed
  if [ -n "$3" ] && [ "$3" -le "$LIMIT" ]; then PASS approval "$1: approved via the ticket after ${3}s (<= 2 x ${BRIDGE_INTERVAL}s poll + 5s slack)"
  else FAIL approval "$1: approval not approved within ${LIMIT}s (elapsed '${3}', status '$(approval_status "$2")')"; fi
}
approval_result "Jira" "$APR_J_OK" "$E_J"
[ -n "$SNOW_APPR_ON" ] && approval_result "ServiceNow" "$APR_S_OK" "$E_S"
for cn in approve-me.itsm.test $([ -n "$SNOW_APPR_ON" ] && echo approve-me-snow.itsm.test); do
  code "$T_alice" "$HUB_BASE/api/v1/certificates?q=$cn" >/dev/null
  [ "$(jget 'len(d["data"])' <"$WORK/last.json")" = 1 ] && PASS approval "certificate $cn issued once the ticket approved" || FAIL approval "no certificate for $cn after the ticket approval"
done
cat > "$WORK/audit.py" <<'PY'
import json, sys
mode, apr = sys.argv[1], sys.argv[2]
rows = json.load(sys.stdin)["data"]
if mode == "itsm-success":     # bridge applied the approval
    ok = any(r["action"] == "itsm.approval.approve" and r["outcome"] == "success" and "approval=" + apr in r.get("change_summary", "") for r in rows)
elif mode == "itsm-refused":   # bridge refused: approver had no mapping
    ok = any(r["action"] == "itsm.approval.approve" and r["outcome"] != "success" and "approval=" + apr in r.get("change_summary", "")
             and "unmapped_approver" in r.get("change_summary", "") for r in rows)
elif mode == "channel":        # the hub's own approval.approve row names the acting channel
    ok = any(r["action"] == "approval.approve" and apr in (r.get("resource_id", "") + r.get("change_summary", ""))
             and '"channel":"itsm"' in r.get("change_summary", "") for r in rows)
else:
    ok = False
sys.exit(0 if ok else 1)
PY
audit_has() { python3 "$WORK/audit.py" "$1" "$2" <"$WORK/last.json"; } # $WORK/last.json holds an /audit response
code "$TOKEN" "$HUB_BASE/api/v1/audit?action=itsm.approval.approve&limit=100" >/dev/null
audit_has itsm-success "$APR_J_OK" && PASS approval "Jira: audit row itsm.approval.approve (success) for the approved request" || FAIL approval "no success audit row for $APR_J_OK"
[ -n "$SNOW_APPR_ON" ] && { audit_has itsm-success "$APR_S_OK" && PASS approval "ServiceNow: audit row itsm.approval.approve (success) for the approved request" || FAIL approval "no success audit row for $APR_S_OK"; }
code "$TOKEN" "$HUB_BASE/api/v1/audit?action=approval.approve&limit=100" >/dev/null
audit_has channel "$APR_J_OK" && PASS approval "Jira: hub approval.approve audit row records channel itsm (acting identity = mapped accountId)" || FAIL approval "approval.approve audit row for $APR_J_OK does not record channel itsm"
[ -n "$SNOW_APPR_ON" ] && { audit_has channel "$APR_S_OK" && PASS approval "ServiceNow: hub approval.approve audit row records channel itsm (acting identity = mapped sys_user)" || FAIL approval "approval.approve audit row for $APR_S_OK does not record channel itsm"; }
# negative: unmapped approver (the bridge already ticked for the links; allow one more interval)
sleep $(( BRIDGE_INTERVAL + 10 ))
[ "$(approval_status "$APR_J_NO")" = pending ] && PASS approval "unmapped Jira approver: approval still pending" || FAIL approval "unmapped Jira approver changed the approval to '$(approval_status "$APR_J_NO")'"
[ -n "$SNOW_APPR_ON" ] && { [ "$(approval_status "$APR_S_NO")" = pending ] && PASS approval "unmapped ServiceNow approver: approval still pending" || FAIL approval "unmapped ServiceNow approver changed the approval to '$(approval_status "$APR_S_NO")'"; }
code "$TOKEN" "$HUB_BASE/api/v1/audit?action=itsm.approval.approve&limit=100" >/dev/null
audit_has itsm-refused "$APR_J_NO" && PASS approval "unmapped Jira approver audited as refused (unmapped_approver)" || FAIL approval "no refused audit row for the unmapped Jira approver"
[ -n "$SNOW_APPR_ON" ] && { audit_has itsm-refused "$APR_S_NO" && PASS approval "unmapped ServiceNow approver audited as refused (unmapped_approver)" || FAIL approval "no refused audit row for the unmapped ServiceNow approver"; }
SKIP approval "proposer-as-approver negative not driven here: the proposer (an API-key principal) cannot also be a mapped user row; covered by Go unit tests"

# --------------------------------------------------------------------------
# 4. recovery (acceptance 2)
# --------------------------------------------------------------------------
STEP "4. recovery: incident resolved / issue done within 300 s of the verify event"
if [ "$MODE" = real ]; then
  PEND recovery "a verified renewal needs a push target (F5/Citrix/k8s/IIS/SSH/plugin) that only the customer has; the stand-in drives an F5 in stub mode. To prove it against real ServiceNow/Jira, renew the certificate of a ticketed event on a real target and re-run the checks of this leg (state=6 / status category done within 300 s plus the close comment)."
else
  wait_status "$REC_SNOW" created "$DRAIN_WAIT" && wait_status "$REC_JIRA" created "$DRAIN_WAIT" && PASS recovery "renewal_failed tickets exist for $RENEW_CN before the renewal" || FAIL recovery "recovery tickets not created: $(dbx state "$REC_SNOW") / $(dbx state "$REC_JIRA")"
  remember snow "$(dbx ref "$REC_SNOW")"; remember jira "$(dbx ref "$REC_JIRA")"
  [ "$(find_tickets snow "$REC_SNOW" | jget 'd["items"][0]["state"]')" != 6 ] && [ "$(find_tickets jira "$REC_JIRA" | jget 'd["items"][0]["status_cat"]')" != done ] \
    && PASS recovery "both tickets are open before the renewal" || FAIL recovery "a recovery ticket is already closed before the renewal"
  F5_CRED="$(CRED_JSON="$(U=f5-live P=stub-not-a-real-password B="$SNOW_URL" python3 -c "import json,os; print(json.dumps({'base_url':os.environ['B'],'username':os.environ['U'],'password':os.environ['P'],'client_ssl_profile':'kk-live-clientssl'}))")" mkcred "kk-live-f5-$RUN_ID")"
  c=$(code "$TOKEN" -X POST "$HUB_BASE/api/v1/targets" -d "{\"name\":\"kk-live-f5-$RUN_ID\",\"host\":\"$STUB_HOST\",\"install_mode\":\"f5\",\"discovery_mode\":\"none\",\"credential_ref\":\"$F5_CRED\",\"verify_host_port\":\"$STUB_HOST:$F5_VERIFY_PORT\"}")
  F5_TARGET="$(jget 'd["data"]["id"]' <"$WORK/last.json")"
  [ "$c" = 201 ] && [ -n "$F5_TARGET" ] && PASS recovery "STAND-IN F5 push target created ($F5_TARGET), verify dial $STUB_HOST:$F5_VERIFY_PORT" || DIE "could not create the f5 target: HTTP $c $(head -c 300 "$WORK/last.json")"
  c=$(code "$TOKEN" -X POST "$HUB_BASE/api/v1/renewal/execute" -d "{\"fingerprint\":\"$RENEW_FP\",\"target_id\":\"$F5_TARGET\"}")
  T_VERIFY="$(now_s)"
  if [ "$c" = 200 ] && [ "$(jget 'd["data"]["renewed"]' <"$WORK/last.json")" = True ] && [ "$(jget 'd["data"]["verified"]' <"$WORK/last.json")" = True ] \
     && [ "$(jget 'd["data"]["install_outcome"]' <"$WORK/last.json")" = installed_verified ]; then
    NEW_FP="$(jget 'd["data"]["new_fingerprint"]' <"$WORK/last.json")"
    PASS recovery "POST /renewal/execute: renewed, installed and verified through the hub (new fingerprint ${NEW_FP:0:16}...)"
    [ "$(ctl "$SNOW_URL/_ctl/state" | jget 'd["f5_served_fingerprint"]')" = "$NEW_FP" ] \
      && PASS recovery "the stand-in's verify listener serves exactly the renewed certificate (the hub's TLS dial matched it)" || FAIL recovery "stand-in served fingerprint differs from the renewed certificate"
  else
    FAIL recovery "renewal did not verify: HTTP $c $(head -c 400 "$WORK/last.json")"; NEW_FP=""
  fi
  S_ST=""; J_ST=""
  while [ $(( $(now_s) - T_VERIFY )) -le 300 ]; do
    S_ST="$(find_tickets snow "$REC_SNOW" | jget 'd["items"][0]["state"]')"; J_ST="$(find_tickets jira "$REC_JIRA" | jget 'd["items"][0]["status_cat"]')"
    [ "$S_ST" = 6 ] && [ "$J_ST" = done ] && break
    sleep 3
  done
  REC_EL=$(( $(now_s) - T_VERIFY ))
  [ "$S_ST" = 6 ] && [ "$REC_EL" -le 300 ] && PASS recovery "incident state=6 (Resolved) ${REC_EL}s after the verify event (limit 300 s)" || FAIL recovery "incident not resolved within 300 s (state '$S_ST')"
  [ "$J_ST" = done ] && [ "$REC_EL" -le 300 ] && PASS recovery "issue in a done status category ${REC_EL}s after the verify event (limit 300 s)" || FAIL recovery "issue not done within 300 s (category '$J_ST')"
  find_tickets snow "$REC_SNOW" | jget 'd["items"][0].get("close_notes","")' | grep -q "Certificate replaced and verified by Kryptkeeper" \
    && PASS recovery "incident close notes carry the hub's resolve comment" || FAIL recovery "incident close notes lack the resolve comment"
  probe jira-comments "$(dbx ref "$REC_JIRA")" | jget 'd["text"]' | grep -q "Certificate replaced and verified by Kryptkeeper" \
    && PASS recovery "issue carries the resolve comment" || FAIL recovery "issue lacks the resolve comment"
  [ "$(dbx state "$REC_SNOW" | cut -d'|' -f1)" = resolved ] && [ "$(dbx state "$REC_JIRA" | cut -d'|' -f1)" = resolved ] \
    && PASS recovery "both queue rows moved to resolved" || FAIL recovery "queue rows: $(dbx state "$REC_SNOW") / $(dbx state "$REC_JIRA")"
  code "$TOKEN" "$HUB_BASE/api/v1/audit?action=itsm.ticket.resolve&limit=50" >/dev/null
  [ "$(jget 'sum(1 for r in d["data"] if r["outcome"]=="success" and r["resource_id"] in ("'"$REC_SNOW"'","'"$REC_JIRA"'"))' <"$WORK/last.json")" = 2 ] \
    && PASS recovery "2 itsm.ticket.resolve audit rows (success)" || FAIL recovery "itsm.ticket.resolve audit rows missing for the recovery events"
fi

# --------------------------------------------------------------------------
# 5. CMDB sync (acceptance 2)
# --------------------------------------------------------------------------
STEP "5. CMDB ownership sync: 100 certificates, 100 CIs"
stop_hub
start_hub   # the sync job runs immediately at start, then every 24 h (no interval env exists)
cmdb_done=""
for _ in $(seq 1 60); do
  code "$TOKEN" "$HUB_BASE/api/v1/audit?action=certificate.ownership_update&limit=100" >/dev/null
  [ "$(jget 'd["meta"]["total"]' <"$WORK/last.json")" -ge 100 ] 2>/dev/null && { cmdb_done=1; break; }
  sleep 3
done
AUDITN="$(jget 'sum(1 for r in d["data"] if "cmdb" in json.dumps(r))' <"$WORK/last.json")"
[ -n "$cmdb_done" ] && [ "$AUDITN" -ge 100 ] 2>/dev/null && PASS cmdb "certificate.ownership_update audit rows with source cmdb: $AUDITN (total $(jget 'd["meta"]["total"]' <"$WORK/last.json"))" || FAIL cmdb "audit rows: $AUDITN cmdb of total $(jget 'd["meta"]["total"]' <"$WORK/last.json")"
code "$TOKEN" "$HUB_BASE/api/v1/certificates?q=host-&limit=100" >/dev/null
cat > "$WORK/cmdb.py" <<'PY'
import json, sys
items = json.load(sys.stdin)["data"]
host = [i for i in items if i.get("common_name", "").startswith("host-")]
print("hosts=%d" % len(host))
print("cmdb=%d" % sum(1 for i in host if i.get("ownership_source") == "cmdb"))
print("owners=%d" % sum(1 for i in host if i.get("owner_email") and i.get("owner_team")))
PY
python3 "$WORK/cmdb.py" <"$WORK/last.json" >"$WORK/cmdb.txt"
H="$(grep hosts= "$WORK/cmdb.txt" | cut -d= -f2)"; C="$(grep cmdb= "$WORK/cmdb.txt" | cut -d= -f2)"; O="$(grep owners= "$WORK/cmdb.txt" | cut -d= -f2)"
[ "$H" = 100 ] && [ "$C" = 100 ] && [ "$O" = 100 ] && PASS cmdb "100/100 certificates have ownership_source=cmdb with owner_email and owner_team populated" || FAIL cmdb "hosts=$H cmdb-sourced=$C owners-populated=$O (want 100/100/100)"

# --------------------------------------------------------------------------
# 6. outage queue drain (acceptance 3)
# --------------------------------------------------------------------------
STEP "6. outage: queue, alert, drain with 0 loss"
if [ "$MODE" = real ]; then
  SKIP outage "cannot induce an outage on a real ServiceNow/Jira; the 1-hour drain is proven against the stand-in (KK_ITSM_FULL_OUTAGE=1) and by Go test TestDrain_OneHourOutage_ZeroLoss"
else
  OUT="kklive-$RUN_ID-out"
  ctl -X POST "$SNOW_URL/_ctl/outage?on=1" >/dev/null
  for i in $(seq -w 1 20); do
    dbx seed "$SNOW_CONN" "$OUT-snow-$i" renewal_failed "outage-$i.itsm.test" "$CERT_SERIAL" high "$CERT_LINK" "" "$CERT_NA" >/dev/null
    dbx seed "$JIRA_CONN" "$OUT-jira-$i" renewal_failed "outage-$i.itsm.test" "$CERT_SERIAL" high "$CERT_LINK" "" "$CERT_NA" >/dev/null
  done
  T_OUT="$(now_s)"
  tries=$(( DRAIN_WAIT / 3 ))
  while [ $tries -gt 0 ]; do
    [ "$(dbx count "$OUT" | jget 'd.get("pending",{}).get("min_attempts",0)')" -ge 1 ] 2>/dev/null && break
    sleep 3; tries=$((tries - 1))
  done
  CNT="$(dbx count "$OUT")"
  [ "$(jget 'd["pending"]["n"]' <<<"$CNT")" = 40 ] && PASS outage "40 events queued, all still pending after a failed drain (attempts>=1), none dropped" || FAIL outage "queue state: $CNT"
  W="$(dbx min_wait "$OUT")"
  [ "$W" -ge 200 ] 2>/dev/null && PASS outage "next attempt scheduled ${W}s ahead (backoff base 5 min)" || FAIL outage "next attempt only ${W}s ahead"
  grep -q "ALERT itsm: itsm_unreachable" "$WORK/hub.log" && PASS outage "itsm_unreachable alert raised (hub log)" || FAIL outage "no itsm_unreachable alert in hub.log"
  [ "$(ctl "$SNOW_URL/_ctl/state" | jget 'sum(1 for i in d["incidents"].values() if i.get("correlation_id","").startswith("'"$OUT"'"))')" = 0 ] \
    && [ "$(ctl "$SNOW_URL/_ctl/state" | jget 'sum(1 for i in d["issues"].values() if any(l.startswith("kk-'"$OUT"'") for l in i["labels"]))')" = 0 ] \
    && PASS outage "0 tickets created while the ITSM was down" || FAIL outage "tickets were created during the outage"
  if [ -n "${KK_ITSM_FULL_OUTAGE:-}" ]; then
    echo "  FULL mode: holding the outage for 3600 s of wall clock (started $(date -u +%H:%M:%SZ))"
    while [ $(( $(now_s) - T_OUT )) -lt 3600 ]; do sleep 60; done
    MODE_NOTE="wall-clock 1 h outage, natural backoff"
  else
    MODE_NOTE="ACCELERATED: next_attempt_at advanced to now (time compression); backoff schedule itself is proven by Go test TestDrain_OneHourOutage_ZeroLoss"
  fi
  ctl -X POST "$SNOW_URL/_ctl/outage?on=0" >/dev/null
  [ -z "${KK_ITSM_FULL_OUTAGE:-}" ] && dbx make_due "$OUT"
  tries=$(( DRAIN_WAIT / 3 )); [ -n "${KK_ITSM_FULL_OUTAGE:-}" ] && tries=$(( 2400 / 3 ))
  while [ $tries -gt 0 ]; do
    [ "$(dbx count "$OUT" | jget 'd.get("created",{}).get("n",0)')" = 40 ] 2>/dev/null && break
    sleep 3; tries=$((tries - 1))
  done
  CNT="$(dbx count "$OUT")"
  [ "$(jget 'd.get("created",{}).get("n",0)' <<<"$CNT")" = 40 ] && PASS outage "all 40 queued events reached created after recovery (0 loss) [$MODE_NOTE]" || FAIL outage "after recovery: $CNT"
  dup=0
  for i in $(seq -w 1 20); do
    [ "$(ticket_count snow "$OUT-snow-$i")" = 1 ] && [ "$(ticket_count jira "$OUT-jira-$i")" = 1 ] || dup=$((dup + 1))
  done
  [ "$dup" = 0 ] && PASS outage "every one of the 40 events has exactly one ticket (0 dupes)" || FAIL outage "$dup events do not have exactly one ticket"
fi

# --------------------------------------------------------------------------
# summary / record
# --------------------------------------------------------------------------
STEP "summary (${MODE} mode$([ "$MODE" = stub ] && echo ', STAND-IN results, not the real services'))"
for r in "${RESULTS[@]}"; do IFS='|' read -r leg st detail <<<"$r"; printf '%-12s %-12s %s\n' "$leg" "$st" "${detail:0:150}"; done
if [ -n "${KK_RECORD:-}" ]; then
  python3 - "$HERE/RESULTS.md" "$MODE" "$FAILED" "$(git -C "$REPO_ROOT" rev-parse --short HEAD)" <<'PY'
import sys, time
path, mode, failed, sha = sys.argv[1:5]
who = "STAND-IN (tests/live/itsm/stub_itsm.py)" if mode == "stub" else "REAL ServiceNow PDI + Jira Cloud"
with open(path, "a") as f:
    f.write("| %s | %s | %s | %s | %s |\n" % (time.strftime("%Y-%m-%d"), sha, who, "FAIL" if failed == "1" else "PASS (legs below)", "see run output"))
PY
fi
echo
[ "$FAILED" = 0 ] && echo "ALL LEGS EXITED CLEAN (SKIP/PENDING-RUN legs are listed above and are NOT passes)" || echo "FAILED"
exit "$FAILED"
