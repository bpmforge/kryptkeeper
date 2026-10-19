#!/usr/bin/env bash
# W26-12: after an appliance run, pull hub-side evidence into evidence/ (gitignored).
# No challenge secret is ever requested or stored: the audit and certificate APIs
# do not carry one.
set -u
set -o pipefail

usage() {
  cat <<'USAGE'
usage: ./collect-evidence.sh <common_name> [--expect-replay-denied] [--expect-expiry-denied]

Checks (exit non-zero if any FAIL):
  1. GET /api/v1/certificates?q=<cn> has a row with source=scep
  2. GET /api/v1/audit?action=scep.enroll has a success row
  3. with --expect-replay-denied / --expect-expiry-denied: a denied scep.enroll row
     whose detail says "challenge already used" / "challenge expired"
Writes evidence/<cn>/{certificates.json,audit-scep-enroll.json,summary.txt}.
Run it after each phase (enroll, replay, expiry). Reads .state/env.sh. Requires curl, python3.
USAGE
}
case "${1:-}" in -h|--help|"") usage; [ -z "${1:-}" ] && exit 2; exit 0 ;; esac
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
[ -f "$HERE/.state/env.sh" ] || { echo "no .state/env.sh: run hub-up.sh first" >&2; exit 2; }
. "$HERE/.state/env.sh"
CN="$1"; shift
WANT_REPLAY=0; WANT_EXPIRY=0
for a in "$@"; do case "$a" in
  --expect-replay-denied) WANT_REPLAY=1 ;; --expect-expiry-denied) WANT_EXPIRY=1 ;;
  *) echo "unknown arg $a" >&2; exit 2 ;; esac; done

OUT="$HERE/evidence/$CN"; mkdir -p "$OUT"
api() { curl -sS --cacert "$HUB_CA_PEM" -H "Authorization: Bearer $HUB_TOKEN" "$HUB_LOCAL_BASE$1"; }
api "/api/v1/certificates?q=$CN&limit=100" >"$OUT/certificates.json"
api "/api/v1/audit?action=scep.enroll&limit=100" >"$OUT/audit-scep-enroll.json"

FAILED=0
CN="$CN" OUT="$OUT" WANT_REPLAY="$WANT_REPLAY" WANT_EXPIRY="$WANT_EXPIRY" python3 - <<'PY' | tee "$OUT/summary.txt"
import json,os,sys
out,cn=os.environ["OUT"],os.environ["CN"]
certs=json.load(open(out+"/certificates.json")).get("data",[])
aud=json.load(open(out+"/audit-scep-enroll.json")).get("data",[])
bad=0
def chk(ok,msg):
    global bad
    print(("PASS " if ok else "FAIL ")+msg)
    if not ok: bad+=1
mine=[c for c in certs if c.get("common_name","").lower()==cn.lower()]
chk(any(c.get("source")=="scep" for c in mine), f"certificate CN={cn} present with source=scep ({len(mine)} row(s))")
for c in mine: print("  serial",c.get("serial_number"),"source",c.get("source"),"valid_until",c.get("valid_until"))
succ=[a for a in aud if a.get("outcome")=="success"]
den=[a for a in aud if a.get("outcome")=="denied"]
chk(len(succ)>=1, f"scep.enroll success rows: {len(succ)}")
def has(word): return any(word in json.dumps(a).lower() for a in den)  # detail lives in change_summary; match the whole row to stay schema-tolerant
if os.environ["WANT_REPLAY"]=="1": chk(has("already used"), "scep.enroll denied row for replay (challenge already used)")
if os.environ["WANT_EXPIRY"]=="1": chk(has("challenge expired"), "scep.enroll denied row for expired challenge")
print("denied rows total:",len(den),"| reasons:",sorted({(a.get("change_summary") or "")[:80] for a in den}))
sys.exit(1 if bad else 0)
PY
RC=${PIPESTATUS[0]}
echo "evidence written to $OUT"
exit "$RC"
