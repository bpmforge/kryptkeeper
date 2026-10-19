#!/usr/bin/env bash
# W30-23: DR failover drill with measured RPO / RTO on real Postgres 16 async
# streaming replication, podman only. Throwaway: every secret is generated per
# run, nothing is committed, everything is removed on exit.
#
#   bash tests/live/k8s/dr-failover.sh [--record] [--skip-build] [--image REF]
#                                      [--steady SECONDS] [--require-events|--no-events]
#
#   --record          append a result row to docs/ops/DR_DRILL_RESULTS.md (review the diff)
#   --skip-build      do not build; use --image (default localhost/kryptkeeper:kkha-w23)
#   --image REF       hub image for BOTH sites; the row records it verbatim
#   --steady N        seconds of steady marker traffic before the kill (default 120)
#   --require-events  (default) assert ha.failover / scheduler.failover / backup.stale
#   --no-events       skip the event assertions
#
# Topology: site A = hub-a + pg-primary; site B = hub-b (cold, started after the
# kill) + pg-standby. synchronous_commit stays at the default (on) with an ASYNC
# standby, so the RPO is honest for async replication.
#
# KEYSTORE DECISION: CA private keys are not in Postgres. The drill models the
# keystore (and the file-backed template store) being replicated out of band by
# bind-mounting ONE host dir into both sites. The lag of a real replication layer
# (RWX volume, cloud KMS) adds to RPO and is NOT measured here.
#
# Exit: 0 = RPO and RTO within target; 1 = a target missed or a step failed.
. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/../lib/podman.sh"
set -u -o pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$HERE/../../.." && pwd)"
RESULTS="$REPO_ROOT/docs/ops/DR_DRILL_RESULTS.md"

RECORD=0; SKIP_BUILD=0; STEADY=120; EVENTS=1
IMAGE=""
while [ $# -gt 0 ]; do
  case "$1" in
    --record) RECORD=1 ;;
    --skip-build) SKIP_BUILD=1 ;;
    --image) IMAGE="${2:?--image needs a value}"; shift ;;
    --steady) STEADY="${2:?--steady needs a value}"; shift ;;
    --require-events) EVENTS=1 ;;
    --no-events) EVENTS=0 ;;
    *) echo "usage: dr-failover.sh [--record] [--skip-build] [--image REF] [--steady N] [--require-events|--no-events]"; exit 2 ;;
  esac
  shift
done

RPO_TARGET=300   # seconds, 5 min
RTO_TARGET=900   # seconds, 15 min

command -v podman >/dev/null || { echo "FAIL: podman not found"; exit 1; }
command -v openssl >/dev/null || { echo "FAIL: openssl not found"; exit 1; }
command -v python3 >/dev/null || { echo "FAIL: python3 not found"; exit 1; }

rand() { LC_ALL=C tr -dc 'A-Za-z0-9' </dev/urandom | head -c "$1"; }
RUN_ID="$(rand 6 | tr '[:upper:]' '[:lower:]')"
NET="kk-dr-$RUN_ID"
PRIMARY="kk-dr-pg-primary-$RUN_ID"; STANDBY="kk-dr-pg-standby-$RUN_ID"
HUB_A="kk-dr-hub-a-$RUN_ID"; HUB_B="kk-dr-hub-b-$RUN_ID"
PORT_A=18091; PORT_B=18092
URL_A="http://127.0.0.1:$PORT_A"; URL_B="http://127.0.0.1:$PORT_B"
PGPW="$(rand 24)"; TOKEN="$(rand 32)"; PASSPHRASE="$(rand 32)"
# podman machine on macOS only mounts $HOME.
WORK="$(mktemp -d "$HOME/.kk-dr.XXXXXX")"
mkdir -p "$WORK/keys" "$WORK/tpl" "$WORK/data-a" "$WORK/data-b"
chmod -R 0777 "$WORK"   # hub runs as uid 65532; throwaway dirs
: >"$WORK/markers.log"

FAILED=0; WRITER_PID=""
STEP() { echo; echo "== $* =="; }
PASS() { echo "PASS: $*"; }
FAIL() { echo "FAIL: $*"; FAILED=1; }
cleanup() {
  STEP "teardown"
  [ -n "$WRITER_PID" ] && kill "$WRITER_PID" 2>/dev/null || true
  kk_rm "$HUB_A" "$HUB_B" "$PRIMARY" "$STANDBY"
  podman network rm "$NET" >/dev/null 2>&1 || true
  [ -n "${BUILT_IMAGE:-}" ] && podman rmi -f "$BUILT_IMAGE" >/dev/null 2>&1 || true
  rm -rf "$WORK"
}
trap cleanup EXIT
DIE() {
  echo "FAIL: $*"
  for c in "$PRIMARY" "$STANDBY" "$HUB_A" "$HUB_B"; do echo "--- $c"; podman logs --tail 25 "$c" 2>&1 | tail -n 25; done
  exit 1
}

waitfor() { # waitfor <seconds> <description> <cmd...>
  local n="$1" what="$2"; shift 2
  local _
  for _ in $(seq 1 "$n"); do "$@" >/dev/null 2>&1 && return 0; sleep 1; done
  echo "timed out after ${n}s waiting for $what"; return 1
}
readyz200() { [ "$(curl -s -o /dev/null -m 3 -w '%{http_code}' "$1/readyz")" = 200 ]; }
PSQL_P() { podman exec -e PGPASSWORD="$PGPW" "$PRIMARY" psql -U kryptkeeper -d kryptkeeper -tAc "$1"; }
PSQL_S() { podman exec -e PGPASSWORD="$PGPW" "$STANDBY" psql -U kryptkeeper -d kryptkeeper -tAc "$1"; }
api() { # api <base> curl args...
  local base="$1"; shift
  curl -sS -m 10 -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' "$@"
}

# ---------------------------------------------------------------------------
STEP "hub image"
if [ -z "$IMAGE" ]; then
  if [ "$SKIP_BUILD" = 1 ]; then IMAGE="localhost/kryptkeeper:kkha-w23"
  else
    SHA="$(git -C "$REPO_ROOT" rev-parse --short HEAD)"
    IMAGE="localhost/kryptkeeper:kkdr-$SHA"; BUILT_IMAGE="$IMAGE"
    podman build -t "$IMAGE" --build-arg VERSION="dr-$SHA" --build-arg COMMIT="$SHA" "$REPO_ROOT" >"$WORK/build.log" 2>&1 \
      || { tail -20 "$WORK/build.log"; DIE "image build failed"; }
  fi
elif [ "$SKIP_BUILD" = 0 ]; then
  echo "(--image given: not building)"
fi
podman image exists "$IMAGE" || DIE "image $IMAGE not present"
GIT_SHA="$(git -C "$REPO_ROOT" rev-parse --short HEAD)"
echo "hub image: $IMAGE (tree $GIT_SHA)"

# ---------------------------------------------------------------------------
STEP "podman network $NET, pg-primary (wal_level=replica)"
podman network create "$NET" >/dev/null || DIE "network create failed"
podman run -d --name "$PRIMARY" --network "$NET" --network-alias pg-primary \
  -e POSTGRES_USER=kryptkeeper -e POSTGRES_DB=kryptkeeper -e POSTGRES_PASSWORD="$PGPW" \
  docker.io/library/postgres:16 \
  postgres -c wal_level=replica -c max_wal_senders=5 -c max_connections=300 -c listen_addresses='*' >/dev/null \
  || DIE "pg-primary failed to start"
waitfor 60 "pg-primary" PSQL_P "SELECT 1" || DIE "pg-primary not ready"
# the image's pg_hba.conf has no replication rule for non-local peers
podman exec "$PRIMARY" sh -c 'echo "host replication all all scram-sha-256" >> "$PGDATA/pg_hba.conf"' || DIE "pg_hba append failed"
PSQL_P "SELECT pg_reload_conf()" >/dev/null
PG_VERSION="$(PSQL_P 'SHOW server_version' | awk '{print $1}')"
SYNC_COMMIT="$(PSQL_P 'SHOW synchronous_commit')"
echo "postgres $PG_VERSION, synchronous_commit=$SYNC_COMMIT"
if [ "$SYNC_COMMIT" = "on" ]; then PASS "synchronous_commit left at default (on)"; else FAIL "synchronous_commit=$SYNC_COMMIT"; fi

STEP "pg-standby via pg_basebackup -R -X stream"
podman run -d --name "$STANDBY" --network "$NET" --network-alias pg-standby --user postgres \
  -e PGPASSWORD="$PGPW" --entrypoint bash docker.io/library/postgres:16 \
  -c 'set -e; rm -rf /var/lib/postgresql/data/*; pg_basebackup -h pg-primary -U kryptkeeper -D /var/lib/postgresql/data -R -X stream; chmod 700 /var/lib/postgresql/data; exec postgres -c max_connections=300 -c hot_standby=on -c listen_addresses="*"' >/dev/null \
  || DIE "pg-standby failed to start"
waitfor 120 "pg-standby accepting reads" PSQL_S "SELECT pg_is_in_recovery()" || DIE "pg-standby not up"
if [ "$(PSQL_S 'SELECT pg_is_in_recovery()')" = "t" ]; then PASS "standby is in recovery"; else FAIL "standby is not in recovery"; fi
waitfor 30 "replication streaming" bash -c "[ \"\$(podman exec -e PGPASSWORD='$PGPW' '$PRIMARY' psql -U kryptkeeper -d kryptkeeper -tAc 'SELECT state FROM pg_stat_replication')\" = streaming ]" \
  || DIE "pg_stat_replication is not streaming"
PASS "pg_stat_replication state = streaming ($(PSQL_P "SELECT application_name||' '||sync_state FROM pg_stat_replication" | head -1))"

# ---------------------------------------------------------------------------
hub_run() { # hub_run <name> <port> <dbhost> <datadir> [extra -e ...]
  local name="$1" port="$2" dbhost="$3" data="$4"; shift 4
  podman run -d --name "$name" --network "$NET" -p "127.0.0.1:$port:8080" \
    -e AUTH_MODE=bootstrap -e APP_BOOTSTRAP_TOKEN="$TOKEN" \
    -e KRYPTKEEPER_KEYSTORE_PASSPHRASE="$PASSPHRASE" -e KRYPTKEEPER_KEYSTORE_DIR=/shared/keys \
    -e KRYPTKEEPER_DB_MODE=postgres \
    -e "DATABASE_URL=postgres://kryptkeeper:${PGPW}@${dbhost}:5432/kryptkeeper?sslmode=disable" \
    -e APP_CERTIFICATE_PROVIDER=ca -e APP_DISCOVERY_PROVIDER=db -e APP_AUDIT_PROVIDER=db \
    -e APP_NOTIFICATION_PROVIDER=delivery -e APP_BIND_ADDR=0.0.0.0 -e PORT=8080 \
    -e KRYPTKEEPER_TLS_DISABLE=true -e KRYPTKEEPER_BASE_URL=http://localhost:8080 \
    -e RENEWAL_POLL_MINUTES=1 -e APP_TEMPLATE_FILE=/shared/templates/templates.json \
    -e KRYPTKEEPER_DATA_DIR=/var/kryptkeeper/data \
    -v "$WORK/keys:/shared/keys" -v "$WORK/tpl:/shared/templates" -v "$WORK/data-$data:/var/kryptkeeper/data" \
    "$@" "$IMAGE" >/dev/null
}

STEP "site A hub (creates the root; keystore dir bind-mounted)"
hub_run "$HUB_A" "$PORT_A" pg-primary a -e KRYPTKEEPER_BOOTSTRAP_CREATE_ROOT=true || DIE "hub-a failed to start"
waitfor 180 "hub-a /readyz" readyz200 "$URL_A" || DIE "hub-a never ready"
PASS "hub-a ready"
CA_ID="$(api "$URL_A" "$URL_A/api/v1/cas" | python3 -c 'import json,sys; print(json.load(sys.stdin)["data"][0]["id"])')" || true
[ -n "$CA_ID" ] || DIE "no CA on hub-a"
TPL_ID="$(api "$URL_A" -X POST "$URL_A/api/v1/templates" -d '{"name":"dr-drill","display_name":"DR drill","validity_period":"P90D","key_usage":["digitalSignature","keyEncipherment"],"extended_key_usage":["serverAuth"],"allowed_algorithms":["ECDSA"],"active":true}' \
  | python3 -c 'import json,sys; print(json.load(sys.stdin)["data"]["id"])')" || true
[ -n "$TPL_ID" ] || DIE "template create failed on hub-a"
echo "CA $CA_ID template $TPL_ID"

# issue <base> <cn> -> prints http code
issue() {
  local base="$1" cn="$2" d="$WORK/issue.$$.$RANDOM"
  openssl ecparam -name prime256v1 -genkey -noout -out "$d.key" 2>/dev/null
  openssl req -new -key "$d.key" -subj "/CN=$cn" -addext "subjectAltName=DNS:$cn.dr.example" -out "$d.csr" 2>/dev/null
  python3 -c "import json,sys; json.dump({'ca_id':sys.argv[1],'template_id':sys.argv[2],'csr_pem':open(sys.argv[3]).read()}, open(sys.argv[4],'w'))" "$CA_ID" "$TPL_ID" "$d.csr" "$d.json"
  local code
  code="$(api "$base" -o /dev/null -w '%{http_code}' -X POST "$base/api/v1/certificates" --data @"$d.json" 2>/dev/null)"
  rm -f "$d.key" "$d.csr" "$d.json"
  echo "$code"
}

# ---------------------------------------------------------------------------
STEP "marker writer: one certificate per second for ${STEADY}s"
(
  while :; do
    ep="$(date +%s)"
    [ "$(issue "$URL_A" "dr-marker-$ep")" = "201" ] && echo "$ep" >>"$WORK/markers.log"
    # one per second; the issue call itself takes a fraction of it
    now="$(date +%s)"; [ "$now" = "$ep" ] && sleep 1
  done
) &
WRITER_PID=$!
sleep "$STEADY"
N_MARKERS="$(wc -l <"$WORK/markers.log" | tr -d ' ')"
if [ "$N_MARKERS" -gt 0 ]; then PASS "$N_MARKERS markers acknowledged (201) before the kill"; else DIE "no marker was acknowledged"; fi

# ---------------------------------------------------------------------------
STEP "kill site A (hub-a and pg-primary, back to back)"
LAG_ROW="$(PSQL_P "SELECT COALESCE(round(EXTRACT(EPOCH FROM replay_lag)::numeric,3)::text,'n/a')||'s / '||pg_wal_lsn_diff(pg_current_wal_lsn(), replay_lsn)||' bytes' FROM pg_stat_replication LIMIT 1" 2>/dev/null)"
[ -n "$LAG_ROW" ] || LAG_ROW="not sampled"
T_KILL="$(date +%s)"
podman kill "$HUB_A" "$PRIMARY" >/dev/null 2>&1
kill "$WRITER_PID" 2>/dev/null; wait "$WRITER_PID" 2>/dev/null; WRITER_PID=""
echo "T_kill=$T_KILL; replication lag sampled just before kill: $LAG_ROW"

STEP "promote pg-standby, start the DR hub, first issuance"
podman exec -u postgres "$STANDBY" psql -tAc "SELECT pg_promote(true, 60)" >/dev/null 2>&1 \
  || { PSQL_S "SELECT pg_promote(true, 60)" >/dev/null 2>&1; } || DIE "promotion failed"
waitfor 60 "standby left recovery" bash -c "[ \"\$(podman exec -e PGPASSWORD='$PGPW' '$STANDBY' psql -U kryptkeeper -d kryptkeeper -tAc 'SELECT pg_is_in_recovery()')\" = f ]" \
  || DIE "standby still in recovery after promote"
hub_run "$HUB_B" "$PORT_B" pg-standby b || DIE "hub-b failed to start"
waitfor 600 "hub-b /readyz" readyz200 "$URL_B" || DIE "DR hub never became ready"
T_FIRST=""
for _ in $(seq 1 600); do
  ep="$(date +%s)"
  if [ "$(issue "$URL_B" "dr-first-$ep")" = "201" ]; then T_FIRST="$(date +%s)"; break; fi
  sleep 1
done
[ -n "$T_FIRST" ] || DIE "no successful issuance on the DR hub within the deadline"
RTO=$((T_FIRST - T_KILL))

STEP "RPO from surviving markers"
SURV="$(PSQL_S "SELECT substring(common_name from 11) FROM certificates WHERE common_name LIKE 'dr-marker-%'" | sort -u)"
N_SURV="$(printf '%s\n' "$SURV" | grep -c . || true)"
N_ACK="$(sort -u "$WORK/markers.log" | wc -l | tr -d ' ')"
LAST_SURV="$(printf '%s\n' "$SURV" | grep . | sort -n | tail -1)"
if [ -z "$LAST_SURV" ]; then
  FAIL "no marker survived on the DR database"; RPO=-1; LOST=$N_ACK
else
  RPO=$((T_KILL - LAST_SURV)); LOST=$((N_ACK - N_SURV)); [ "$LOST" -lt 0 ] && LOST=0
fi

# ---------------------------------------------------------------------------
EV_STATUS="skipped"
if [ "$EVENTS" = 1 ]; then
  STEP "audit and alert events (acceptance 3)"
  EV_STATUS="ok"
  # W30-27 added the emitters: audit ha.failover (internal/bootstrap/ha_failover.go,
  # on a lease takeover), alert scheduler.failover (same file) and alert
  # backup.stale (internal/bootstrap/backup_stale.go). They are NOT asserted live
  # here because this drill cannot yet observe them correctly: a takeover only
  # fires after the dead hub's scheduler lease lapses (2x the scheduler poll
  # interval, up to 30 min for the SLO scheduler, longer than the RTO window),
  # the alerts need KRYPTKEEPER_HA_NOTIFY_TARGET / KRYPTKEEPER_BACKUP_NOTIFY_TARGET
  # plus a webhook receiver reachable from the hub containers (the host echo
  # receiver is not on the podman network), and backup.stale needs a prior
  # successful backup.create (an approved key_backup grant) older than
  # KRYPTKEEPER_BACKUP_STALE_HOURS. Wiring that unrun would be a guess; the
  # emitters are unit-tested instead. Never faked.
  for ev in ha.failover scheduler.failover backup.stale; do
    echo "BLOCKED: $ev emitter exists (W30-27) but the drill has no live assertion wiring for it yet (lease-lapse timing, echo receiver reachability); see comment above"
    EV_STATUS="BLOCKED: live assertion not wired"
  done
fi

# ---------------------------------------------------------------------------
STEP "result"
TOPO="active hub-a + $PRIMARY (pg $PG_VERSION) -> async streaming standby $STANDBY; cold DR hub-b; keystore bind-mounted out of band"
echo "topology : $TOPO"
echo "image    : $IMAGE (tree $GIT_SHA)"
echo "markers  : acked=$N_ACK surviving=$N_SURV lost=$LOST; replication lag at kill: $LAG_ROW"
echo "RPO      : ${RPO}s (target <= ${RPO_TARGET}s)"
echo "RTO      : ${RTO}s (target <= ${RTO_TARGET}s)"
echo "events   : $EV_STATUS"
VERDICT=PASS
[ "$RPO" -ge 0 ] && [ "$RPO" -le "$RPO_TARGET" ] || VERDICT=FAIL
[ "$RTO" -le "$RTO_TARGET" ] || VERDICT=FAIL
[ "$FAILED" = 0 ] || VERDICT=FAIL
echo "VERDICT  : $VERDICT"

if [ "$RECORD" = 1 ]; then
  ROW="| $(date -u +%Y-%m-%d) | $GIT_SHA | $PG_VERSION | $LAG_ROW | ${RPO}s | ${RTO}s | $LOST of $N_ACK | $VERDICT | image $IMAGE; events: $EV_STATUS |"
  python3 - "$RESULTS" "$ROW" <<'PY'
import sys
path, row = sys.argv[1], sys.argv[2]
lines = open(path).read().split("\n")
marker = "<!-- DR-RESULTS-ROWS -->"
out, done = [], False
for l in lines:
    if l.strip() == marker and not done:
        out.append(row); done = True
    out.append(l)
if not done:
    sys.exit("marker %s not found in %s" % (marker, path))
open(path, "w").write("\n".join(out))
PY
  echo "row appended to $RESULTS (review the diff)"
fi
[ "$VERDICT" = PASS ] && exit 0 || exit 1
