#!/usr/bin/env bash
# W23-52: CRL and OCSP load benchmark. Modes:
#   inproc  (default) CRL scale + OCSP open-loop load, no external services.
#   replica           inproc plus the attached-OCSP and revoke-visibility legs;
#                     needs KK_A_URL KK_B_URL KK_B_REVOCATION_URL KK_TOKEN
#                     (and KK_BENCH_OCSP_URL/LEAF_PEM/ISSUER_PEM for the attached leg).
# Writes results/<UTC date>.json and prints a markdown summary. Exit 1 when a
# measured criterion fails; legs that did not run are null, not pass.
set -u -o pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$HERE/../../.." && pwd)"
MODE="${1:-inproc}"
case "$MODE" in inproc|replica) ;; *) echo "usage: run.sh [inproc|replica]"; exit 2 ;; esac
if [ "$MODE" = replica ]; then
  for v in KK_A_URL KK_B_URL KK_B_REVOCATION_URL KK_TOKEN; do
    [ -n "${!v:-}" ] || { echo "FAIL: replica mode needs $v"; exit 2; }
  done
fi

export KK_LIVE_REVBENCH=1
STAMP="$(date -u +%Y-%m-%dT%H%M%SZ)"
mkdir -p "$HERE/results"
export KK_BENCH_OUT="$HERE/results/last.json"
rm -f "$KK_BENCH_OUT"

cd "$REPO_ROOT" || exit 1
go test ./tests/live/revocation-bench/ -count=1 -v -timeout 60m 2>&1 | tee "$HERE/results/last.log"
RC=${PIPESTATUS[0]}
[ -s "$KK_BENCH_OUT" ] || { echo "FAIL: no result JSON written"; exit 1; }
mv "$KK_BENCH_OUT" "$HERE/results/$STAMP.json"
echo "results: $HERE/results/$STAMP.json"

python3 - "$HERE/results/$STAMP.json" <<'PY'
import json, sys
r = json.load(open(sys.argv[1]))
e = r["env"]
print(f"\n{e.get('cpu')} / {e.get('cores')} cores / {e.get('ram_gb')} GB / {e.get('uname')} / {e.get('go')} / {e.get('commit')} / {e.get('utc')}")
print("\n| revocations | DER bytes | gen ms (median) | retained heap MB | allocated MB |\n|---|---|---|---|---|")
for c in r["crl"]:
    print(f"| {c['revocations']} | {c['der_bytes']} | {c['gen_ms_median']} | {c['heap_delta_mb']} | {c['alloc_mb']} |")
print("\n| OCSP run | rps | n | errors | p50 ms | p95 ms | p99 ms | max ms |\n|---|---|---|---|---|---|---|---|")
rows = list(r["ocsp"].items()) + ([("attached", r["ocsp_attached"])] if r["ocsp_attached"] else [])
for k, o in rows:
    print(f"| {k} | {o['rps']} | {o['n']} | {o['errors']} | {o['p50_ms']} | {o['p95_ms']} | {o['p99_ms']} | {o['max_ms']} |")
if r["replica"]:
    p = r["replica"]; print(f"\nreplica: max {p['max_s']} s, median {p['median_s']} s over {p['certs']} certs")
print("\npass:", r["pass"])
PY
python3 - "$HERE/results/$STAMP.json" <<'PY' || RC=1
import json, sys
p = json.load(open(sys.argv[1]))["pass"]
sys.exit(1 if any(v is False for v in p.values()) else 0)
PY
exit "$RC"
