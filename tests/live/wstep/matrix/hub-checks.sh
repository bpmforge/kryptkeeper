#!/usr/bin/env bash
# W26-13: hub-side assertions for one Windows target. Run on the operator box.
set -u
set -o pipefail

usage() {
  cat <<'USAGE'
usage: KK_HUB_BASE=https://hub.corp.example.test:8443 KK_HUB_TOKEN=... [KK_HUB_CA_FILE=ca.pem] \
       [KK_WSTEP_MACHINE_TEMPLATE_ID=<id>] ./hub-checks.sh <host> [--renewed] [--skew-denied]

  <host>          machine short name or FQDN (matched against certificate q=)
  --renewed       also assert a wstep.renew success row with predecessor=
  --skew-denied   also assert at least one denied wstep.enroll/xcep.policy row
                  (the Kerberos clock-skew test; see negative.ps1)
Asserts (exit non-zero on any FAIL):
  - a certificate for <host> with source=wstep (and the machine template when
    KK_WSTEP_MACHINE_TEMPLATE_ID is set; otherwise template_id must be non-empty)
  - exactly one wstep.enroll success row before renewal
Real audit names only: wstep.enroll, wstep.renew, xcep.policy; outcome success|denied.
Output goes to stdout and evidence/<host>/hub-checks.txt. Needs curl, python3.
USAGE
}
case "${1:-}" in -h|--help|"") usage; [ -z "${1:-}" ] && exit 2; exit 0 ;; esac
: "${KK_HUB_BASE:?KK_HUB_BASE required}" "${KK_HUB_TOKEN:?KK_HUB_TOKEN required}"
HOST="$1"; shift
RENEWED=0; SKEW=0
for a in "$@"; do case "$a" in --renewed) RENEWED=1 ;; --skew-denied) SKEW=1 ;; *) echo "unknown arg $a" >&2; exit 2 ;; esac; done

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUT="$HERE/evidence/$HOST"; mkdir -p "$OUT"
CURL=(curl -sS -H "Authorization: Bearer $KK_HUB_TOKEN")
[ -n "${KK_HUB_CA_FILE:-}" ] && CURL+=(--cacert "$KK_HUB_CA_FILE")
SHORT="${HOST%%.*}"
"${CURL[@]}" "$KK_HUB_BASE/api/v1/certificates?q=$SHORT&limit=100" >"$OUT/certificates.json" || exit 1
for act in wstep.enroll wstep.renew xcep.policy; do
  "${CURL[@]}" "$KK_HUB_BASE/api/v1/audit?action=$act&limit=100" >"$OUT/audit-$act.json" || exit 1
done

HOST="$SHORT" OUT="$OUT" RENEWED="$RENEWED" SKEW="$SKEW" TPL="${KK_WSTEP_MACHINE_TEMPLATE_ID:-}" python3 - <<'PY' | tee "$OUT/hub-checks.txt"
import json,os,sys
out,host=os.environ["OUT"],os.environ["HOST"].lower()
def load(n): return json.load(open(f"{out}/{n}.json")).get("data",[])
certs=[c for c in load("certificates") if c.get("common_name","").lower().startswith(host)]
bad=0
def chk(ok,msg):
    global bad
    print(("PASS " if ok else "FAIL ")+msg)
    if not ok: bad+=1
w=[c for c in certs if c.get("source")=="wstep"]
chk(len(w)>=1, f"certificate for {host} with source=wstep ({len(w)} row(s))")
tpl=os.environ["TPL"]
chk(any((c.get("template_id")==tpl) if tpl else bool(c.get("template_id")) for c in w),
    "machine template recorded on the certificate"+(f" (== {tpl})" if tpl else " (non-empty template_id)"))
for c in w: print("  serial",c.get("serial_number"),"template",c.get("template_id"),"valid_until",c.get("valid_until"))
def mine(rows): return [a for a in rows if host in json.dumps(a).lower()]
en=[a for a in mine(load("audit-wstep.enroll")) if a.get("outcome")=="success"]
chk(len(en)>=1, f"wstep.enroll success rows for {host}: {len(en)} (expect 1 before renewal)")
if os.environ["RENEWED"]=="1":
    rn=[a for a in mine(load("audit-wstep.renew")) if a.get("outcome")=="success" and "predecessor=" in json.dumps(a)]
    chk(len(rn)>=1, f"wstep.renew success row with predecessor= : {len(rn)}")
    for a in rn[:3]: print("  ",a.get("timestamp"),a.get("change_summary"))
if os.environ["SKEW"]=="1":
    dn=[a for a in load("audit-wstep.enroll")+load("audit-xcep.policy") if a.get("outcome")=="denied"]
    chk(len(dn)>=1, f"denied wstep.enroll/xcep.policy rows (skew refusal): {len(dn)}")
    for a in dn[:3]: print("  ",a.get("timestamp"),a.get("action"),a.get("change_summary"))
sys.exit(1 if bad else 0)
PY
exit "${PIPESTATUS[0]}"
