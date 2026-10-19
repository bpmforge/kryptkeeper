#!/usr/bin/env bash
# W34-20: fingerprint corpus. Starts one container per technology (compose.yaml),
# runs the real discovery scanner against them in full and deep mode from a
# container on the same network, and reports recall, precision, the confidence
# distribution and the number of high-confidence wrong answers against
# expected.json. Release gate: recall >= 90% and zero high-confidence wrong.
#
# Shared-Mac rules: own compose project (kk-w34-corpus), nothing pruned, only
# this project's containers/network/volumes are removed, background pulls are
# stopped by PID. A service that cannot start (mssql on an arm64 runner, a pull
# that fails) is skipped and named in the report; it is never silently counted.
#
# KK_EVIDENCE_DIR receives full.json and deep.json (default: the work dir).
set -u
set -o pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../../.." && pwd)"
PROJECT=kk-w34-corpus
# podman machine on macOS virtiofs-mounts only $HOME, not /tmp.
WORK="$(mktemp -d "$HOME/.kk-w34-corpus.XXXXXX")"
EVID="${KK_EVIDENCE_DIR:-$WORK/out}"
mkdir -p "$WORK/certs" "$WORK/bin" "$EVID"
NET="${PROJECT}_default"
SCANNER_IMAGE=docker.io/library/alpine:3.20
FAILED=0
STEP() { echo; echo "== $* =="; }
PASS() { echo "PASS: $*"; }
FAIL() { echo "FAIL: $*"; FAILED=1; }

cleanup() {
  STEP "cleanup"
  # Only this project's resources; --volumes removes the anonymous volumes the
  # images create for themselves (mysql, postgres, redis), not anyone else's.
  CORPUS_CERTS="$WORK/certs" CORPUS_BIN="$WORK/bin/scanctl" \
    podman compose -p "$PROJECT" -f "$HERE/compose.yaml" -f "$HERE/compose.mssql.yaml" down --volumes >/dev/null 2>&1 || true
  rm -rf "$WORK"
}
trap cleanup EXIT

STEP "preflight"
command -v podman >/dev/null || { echo "podman is required"; exit 1; }
podman system df || true
case "$(podman info --format '{{.Host.Arch}}' 2>/dev/null)" in arm64|aarch64) GOARCH=arm64 ;; *) GOARCH=amd64 ;; esac

STEP "build scanctl (linux/$GOARCH) and generate certificates"
( cd "$ROOT" && CGO_ENABLED=0 GOOS=linux GOARCH=$GOARCH go build -o "$WORK/bin/scanctl" ./tests/live/fingerprint-corpus/scanctl ) \
  && PASS "scanctl built" || { FAIL "scanctl build failed"; exit 1; }
for n in nginx apache openldap postfix dovecot postgres redis vault k8s winrm; do
  openssl req -x509 -newkey rsa:2048 -nodes -days 7 -subj "/CN=$n" -addext "subjectAltName=DNS:$n" \
    -keyout "$WORK/certs/$n.key" -out "$WORK/certs/$n.crt" >/dev/null 2>&1 || { FAIL "cert for $n"; exit 1; }
  chmod 644 "$WORK/certs/$n.key" # throwaway test keys, read by non-root service users
done
PASS "certificates for the corpus"

STEP "mssql image (SQL Server 2022 on amd64; Azure SQL Edge, the same TDS engine, on arm64)"
COMPOSE_FILES=(-f "$HERE/compose.yaml")
case "$GOARCH" in
  arm64) MSSQL_IMG=mcr.microsoft.com/azure-sql-edge:latest ;; # the amd64 server image segfaults under emulation
  *) MSSQL_IMG=mcr.microsoft.com/mssql/server:2022-latest ;;
esac
export MSSQL_IMAGE="$MSSQL_IMG"
if podman image exists "$MSSQL_IMG"; then
  COMPOSE_FILES=(-f "$HERE/compose.yaml" -f "$HERE/compose.mssql.yaml"); PASS "mssql image present: $MSSQL_IMG"
elif [ "${KK_CORPUS_SKIP_MSSQL:-}" = 1 ]; then
  echo "SKIP: mssql (KK_CORPUS_SKIP_MSSQL=1)"
else
  podman pull -q "$MSSQL_IMG" >"$WORK/mssql-pull.log" 2>&1 &
  PULL_PID=$!
  for _ in $(seq 1 "${KK_CORPUS_MSSQL_PULL_SECONDS:-600}"); do kill -0 "$PULL_PID" 2>/dev/null || break; sleep 1; done
  if kill -0 "$PULL_PID" 2>/dev/null; then kill "$PULL_PID" 2>/dev/null; echo "SKIP: mssql pull did not finish in time"
  elif podman image exists "$MSSQL_IMG"; then COMPOSE_FILES=(-f "$HERE/compose.yaml" -f "$HERE/compose.mssql.yaml"); PASS "mssql image pulled: $MSSQL_IMG"
  else echo "SKIP: mssql image cannot be pulled here ($(tail -1 "$WORK/mssql-pull.log"))"; fi
fi

STEP "start the corpus ($PROJECT)"
export CORPUS_CERTS="$WORK/certs" CORPUS_BIN="$WORK/bin/scanctl"
podman compose -p "$PROJECT" "${COMPOSE_FILES[@]}" up -d >"$WORK/up.log" 2>&1 \
  && PASS "compose up" || { tail -20 "$WORK/up.log"; FAIL "compose up failed"; }

scanctl() { podman run --rm --network "$NET" -v "$WORK/bin/scanctl:/bin/scanctl:ro" -v "$HERE/expected.json:/expected.json:ro" -v "$EVID:/out" "$SCANNER_IMAGE" scanctl "$@"; }

STEP "wait for the services"
WAIT_TARGETS="nginx:443,apache:443,tomcat:8443,openldap:389,openldap:636,postfix:25,dovecot:143,dovecot:993,dovecot:110,dovecot:995,mysql:3306,postgres:5432,redis:6380,vault:8200,k8s:6443,winrm:5986"
[ ${#COMPOSE_FILES[@]} -gt 2 ] && WAIT_TARGETS="$WAIT_TARGETS,mssql:1433"
DOWN="$(scanctl wait -targets "$WAIT_TARGETS" -timeout "${KK_CORPUS_WAIT:-240s}")"
SKIP=""
for t in $DOWN; do SKIP="$SKIP,${t%%:*}"; done
[ ${#COMPOSE_FILES[@]} -le 2 ] && SKIP="$SKIP,mssql"
SKIP="${SKIP#,}"
[ -n "$SKIP" ] && echo "SKIPPED services (did not come up): $SKIP" || PASS "all services are listening"

for mode in full deep; do
  STEP "scan: $mode"
  scanctl scan -mode "$mode" -expected /expected.json -skip "$SKIP" -out "/out/$mode.json" | tee "$EVID/$mode.txt" \
    || FAIL "scan $mode failed to run"
done

STEP "release gate (recall >= 90%, zero high-confidence wrong answers)"
python3 - "$EVID" <<'PY'

import json, sys
bad = False
for mode in ("full", "deep"):
    r = json.load(open(f"{sys.argv[1]}/{mode}.json"))
    ok = r["recall"] >= 0.90 and r["wrong_high"] == 0
    print(f"{mode}: recall={r['recall']:.3f} precision={r['precision']:.3f} wrong_high={r['wrong_high']} -> {'PASS' if ok else 'FAIL'}")
    bad |= not ok
sys.exit(1 if bad else 0)
PY
[ $? -eq 0 ] && PASS "release gate" || FAIL "release gate"

[ "$FAILED" -eq 0 ] && echo "RESULT: PASS" || echo "RESULT: FAIL"
exit "$FAILED"
