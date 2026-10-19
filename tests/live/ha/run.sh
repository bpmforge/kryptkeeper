#!/usr/bin/env bash
# W23-28 / W23-29: HA chaos harness and soak. Two hub replicas on one Postgres
# and one keystore volume, podman only.
#
#   bash tests/live/ha/run.sh                 chaos: concurrent issuance, lease takeover after SIGKILL, duplicate checks
#   bash tests/live/ha/run.sh --soak          30 min soak (10,000 issuances, kill + Postgres restart + partition)
#   bash tests/live/ha/run.sh --soak --short  60 s plumbing dry-run of the soak (200 issuances)
#   --skip-build   reuse the existing localhost/kryptkeeper:kkha-w23 image
#   --keep         leave the stack running on exit (default: tear down, volumes included)
#
# Exits non-zero on any FAIL. Bounded waits only.
set -u -o pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$HERE/../../.." && pwd)"
PROJECT="kkha"
COMPOSE=(podman compose -p "$PROJECT" -f "$HERE/docker-compose.ha.yml")

SOAK=0; SHORT=0; SKIP_BUILD=0; KEEP=0
for a in "$@"; do
  case "$a" in
    --soak) SOAK=1 ;;
    --short) SHORT=1 ;;
    --skip-build) SKIP_BUILD=1 ;;
    --keep) KEEP=1 ;;
    *) echo "usage: run.sh [--soak [--short]] [--skip-build] [--keep]"; exit 2 ;;
  esac
done

FAILED=0
STEP() { echo; echo "== $* =="; }
PASS() { echo "PASS: $*"; }
FAIL() { echo "FAIL: $*"; FAILED=1; }
cleanup() {
  if [ "$KEEP" = 1 ]; then echo "(--keep: stack left running)"; return; fi
  STEP "teardown"
  "${COMPOSE[@]}" down -v --remove-orphans >/dev/null 2>&1 || true
}
DIE() { echo "FAIL: $*"; "${COMPOSE[@]}" logs --tail 40 2>&1 | tail -n 120; cleanup; exit 1; }
trap cleanup EXIT

rand() { LC_ALL=C tr -dc 'A-Za-z0-9' </dev/urandom | head -c "$1"; }
export KK_HA_PG_PASSWORD="$(rand 24)"
export KK_HA_TOKEN="$(rand 32)"
export KK_HA_KEYSTORE_PASSPHRASE="$(rand 32)"

A_URL="http://127.0.0.1:18081"
B_URL="http://127.0.0.1:18082"
PSQL() { podman exec -e PGPASSWORD="$KK_HA_PG_PASSWORD" kkha_postgres_1 psql -U kryptkeeper -d kryptkeeper -tAc "$1"; }

cd "$REPO_ROOT" || exit 1
command -v podman >/dev/null || { echo "FAIL: podman not found"; exit 1; }

STEP "pre-clean any leftover $PROJECT project"
"${COMPOSE[@]}" down -v --remove-orphans >/dev/null 2>&1 || true

if [ "$SKIP_BUILD" = 0 ]; then
  STEP "build localhost/kryptkeeper:kkha-w23"
  podman build -t localhost/kryptkeeper:kkha-w23 \
    --build-arg VERSION="ha-$(git rev-parse --short HEAD)" --build-arg COMMIT="$(git rev-parse --short HEAD)" \
    . || DIE "image build failed"
fi

waitfor() { # waitfor <seconds> <description> <cmd...>
  local n="$1" what="$2"; shift 2
  local i
  for i in $(seq 1 "$n"); do "$@" >/dev/null 2>&1 && return 0; sleep 1; done
  echo "timed out after ${n}s waiting for $what"; return 1
}
readyz200() { [ "$(curl -s -o /dev/null -m 3 -w '%{http_code}' "$1/readyz")" = 200 ]; }
lock_row()  { [ -n "$(PSQL "SELECT holder_id FROM ha_scheduler_locks WHERE lock_name='renewal-scheduler'")" ]; }

STEP "start postgres, then replica A (creates the root), then replica B"
"${COMPOSE[@]}" up -d postgres || DIE "postgres failed to start"
waitfor 60 postgres PSQL "SELECT 1" || DIE "postgres not ready"
"${COMPOSE[@]}" up -d kk-a || DIE "kk-a failed to start"
waitfor 120 "A /readyz" readyz200 "$A_URL" || DIE "A never became ready"
PASS "A ready"
# A must hold the lease before B exists, so the kill test knows the holder.
waitfor 180 "renewal-scheduler lease row" lock_row || DIE "no renewal-scheduler lease row after A started"
PASS "A holds renewal-scheduler: $(PSQL "SELECT holder_id FROM ha_scheduler_locks WHERE lock_name='renewal-scheduler'")"
"${COMPOSE[@]}" up -d kk-b || DIE "kk-b failed to start"
waitfor 120 "B /readyz" readyz200 "$B_URL" || DIE "B never became ready"
PASS "B ready"

export KK_HA_A_URL="$A_URL" KK_HA_B_URL="$B_URL"
export KK_HA_DSN="postgres://kryptkeeper:${KK_HA_PG_PASSWORD}@127.0.0.1:55432/kryptkeeper?sslmode=disable"
export KK_HA_PROJECT="$PROJECT"
export KK_HA_RESULT_OUT="$HERE/soak-result.json"

if [ "$SOAK" = 1 ]; then
  STEP "soak (go test TestHASoak)"
  export KK_HA_SOAK=1
  [ "$SHORT" = 1 ] && export KK_HA_SOAK_SHORT=1
  rm -f "$KK_HA_RESULT_OUT"
  go test ./tests/live/ha/ -count=1 -v -timeout 50m -run TestHASoak 2>&1 | tee "$HERE/soak.log"
  RC=${PIPESTATUS[0]}
  [ "$RC" = 0 ] && PASS "soak" || FAIL "soak (exit $RC)"
  [ -s "$KK_HA_RESULT_OUT" ] && echo "result: $KK_HA_RESULT_OUT" || FAIL "no soak-result.json written"
else
  STEP "chaos (go test)"
  export KK_LIVE_HA=1
  go test ./tests/live/ha/ -count=1 -v -timeout 20m -run 'TestHA(Concurrent|Lease|No)' 2>&1 | tee "$HERE/chaos.log"
  RC=${PIPESTATUS[0]}
  [ "$RC" = 0 ] && PASS "chaos tests" || FAIL "chaos tests (exit $RC)"

  STEP "restart A (killed by the lease test) and check both replicas"
  podman start kkha_kk-a_1 >/dev/null 2>&1
  if waitfor 120 "A /readyz after restart" readyz200 "$A_URL" && readyz200 "$B_URL"; then
    PASS "both replicas /readyz 200"
  else
    FAIL "a replica is not ready after the restart"
  fi
fi

STEP "result"
if [ "$FAILED" = 0 ]; then echo "ALL CHECKS PASSED"; else echo "ONE OR MORE CHECKS FAILED"; fi
exit "$FAILED"
