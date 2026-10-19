#!/usr/bin/env bash
# W31-11: live PQC wave harness against real TLS endpoints (nginx on OpenSSL >= 3.5).
#
# WHAT IT PROVES TODAY (W31-08 ships unsupportedWaveDeliverer, D-103 generate-without-deliver,
# because ML-DSA PKCS#8 export does not exist): a real hub runs a two-principal wave -- propose,
# separation-of-duties refusal, approve -- issues ML-DSA-65 successors, reports every member
# bound to a target as delivery_unsupported with the reason, and the endpoints keep serving
# their OLD certificate (observed by openssl s_client inside the endpoint container, not by the
# hub). The wave is not reported done and the audit trail carries the approve and per-member rows.
#
# WHAT IT CANNOT PROVE YET (reported PENDING, never PASS): the served serial changing to the
# ML-DSA cert, and the failing-endpoint rollback. Both need a real deliverer (blocked on the
# ML-DSA private-key export follow-up).
#
# PASS/FAIL/PENDING per step; stops at the first FAIL (KK_KEEP_GOING=1 runs on). Writes
# RESULTS.md next to this script. Containers are prefixed kkw31-11-; all removed on exit.
set -u
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FX_PREFIX=kkw31-11
FX_PORT="${HUB_PORT:-18451}"
RECORD="${RECORD:-$HERE/RESULTS.md}"
FX_EXTRA_CONTAINERS="kkw31-11-ep-a kkw31-11-ep-b kkw31-11-ep-fail"
. "$HERE/../ca-revoke/fixture.sh"
IMAGE="localhost/kkw31-11-ep:$(openssl rand -hex 3)"
cleanup() { fx_cleanup; podman rmi -f "$IMAGE" >/dev/null 2>&1; }
trap cleanup EXIT
PENDING() { say "PENDING: $*"; }

fx_header "# W31-11 live test: PQC wave against real TLS endpoints"
say "endpoint image: $IMAGE (alpine:3.22, nginx + sshd)"

mkident alice pki-admin; mkident bob pki-admin
W="$FX_RUN/work"

STEP "0. build endpoint image, check its OpenSSL"
mkdir -p "$FX_RUN/work"
podman build -t "$IMAGE" "$HERE" >"$FX_RUN/build.log" 2>&1 || { tail -20 "$FX_RUN/build.log"; DIE "endpoint image build failed"; }
EP_OSSL="$(podman run --rm --entrypoint openssl "$IMAGE" version | awk '{print $2}')"
say "endpoint openssl: $EP_OSSL"
if [ "$(printf '%s\n3.5.0\n' "$EP_OSSL" | sort -V | head -1)" != "3.5.0" ]; then
  DIE "endpoint image OpenSSL $EP_OSSL < 3.5 (fallback base is ubuntu:25.10; decision needed)"
fi
podman run --rm --entrypoint sh "$IMAGE" -c 'openssl list -signature-algorithms | grep -qi ML-DSA-65' \
  && PASS "endpoint image has OpenSSL $EP_OSSL with ML-DSA-65" || DIE "endpoint OpenSSL lacks ML-DSA-65"
podman run --rm --entrypoint sh "$IMAGE" -c 'ldd /usr/sbin/nginx | grep -q libssl' \
  && PASS "nginx links the system libssl" || FAIL "nginx does not link the system libssl"

STEP "1. build hub, Postgres, start hub"
fx_build_and_db
ssh-keygen -t ed25519 -N '' -f "$FX_RUN/id" -C kkw31-11 >/dev/null
fx_start_hub || DIE "hub did not start"
PASS "hub up at $HUBURL"
code "$T_alice" "$HUBURL/api/v1/cas" >/dev/null
CA_ID="$(jget 'd["data"][0]["id"]' <"$FX_RUN/last.json")"
[ -n "$CA_ID" ] || DIE "no root CA"
check "create template (ECDSA + ML-DSA-65)" 201 "$(code "$T_alice" -X POST "$HUBURL/api/v1/templates" \
  -d '{"name":"wave-tpl","display_name":"wave","validity_period":"P30D","key_usage":["digitalSignature"],"extended_key_usage":["serverAuth"],"allowed_algorithms":["ECDSA","ML-DSA-65"],"active":true}')"
TPL_ID="$(jget 'd["data"]["id"]' <"$FX_RUN/last.json")"

STEP "2. start 3 endpoints (ep-a, ep-b healthy; ep-fail is the would-be failing one)"
AUTHKEY="$(cat "$FX_RUN/id.pub")"
EPS="a b fail"
for e in $EPS; do
  podman run -d --name "kkw31-11-ep-$e" --network "$FX_NET" -e AUTHORIZED_KEY="$AUTHKEY" "$IMAGE" >/dev/null || DIE "start ep-$e"
done
probe() { # ep-name host -> serial (uppercase hex, no leading zeros) served at host:443, probed from inside ep-name
  podman exec "kkw31-11-ep-$1" sh -c "echo | openssl s_client -connect $2:443 -servername $2 2>/dev/null | openssl x509 -noout -serial" 2>/dev/null \
    | cut -d= -f2 | tr 'a-f' 'A-F' | sed 's/^0*//'
}
norm() { tr 'a-f' 'A-F' | sed 's/^0*//'; }
wait_serial() { # ep host want tries -> 0 when served serial == want
  local t=${4:-30} s
  while [ "$t" -gt 0 ]; do s="$(probe "$1" "$2")"; [ -n "$s" ] && [ "$s" = "$3" ] && return 0; sleep 1; t=$((t-1)); done
  return 1
}
for e in $EPS; do
  t=30; until [ -n "$(probe a kkw31-11-ep-$e)" ]; do t=$((t-1)); [ $t -le 0 ] && DIE "ep-$e never served TLS"; sleep 1; done
  # entrypoint.sh starts nginx first and sshd last, so TLS answering does not mean sshd is
  # listening yet; the install step dials :22 straight away.
  t=30; until podman exec "kkw31-11-ep-$e" sh -c 'nc -z 127.0.0.1 22' >/dev/null 2>&1; do t=$((t-1)); [ $t -le 0 ] && DIE "ep-$e sshd never listened"; sleep 1; done
done
PASS "all three endpoints serve TLS (placeholder ECDSA leaf) and sshd listens"

STEP "3. credentials, targets, install a hub-issued ECDSA leaf on each endpoint"
PRIV="$(python3 -c "print(open('$FX_RUN/id').read().replace(chr(10), chr(92)+'n'), end='')")"
declare -A OLD_FP SERIAL_BEFORE TGT
for e in $EPS; do
  host="kkw31-11-ep-$e"
  hk="$(podman exec "$host" cat /etc/ssh/ssh_host_ed25519_key.pub | awk '{print $1" "$2}')"
  python3 - "$PRIV" "$hk" "$e" >"$W/cred-$e.json" <<'PY'
import json, sys
priv = sys.argv[1].replace('\\n', '\n')
print(json.dumps({"name": f"wave-ssh-{sys.argv[3]}", "credential_type": "ssh_key",
  "payload": {"user": "root", "private_key_pem": priv, "host_public_key": sys.argv[2], "port": 22}}))
PY
  check "[ep-$e] create ssh credential" 201 "$(code "$T_alice" -X POST "$HUBURL/api/v1/credentials" --data @"$W/cred-$e.json")"
  CRED="$(jget 'd["data"]["id"]' <"$FX_RUN/last.json")"
  check "[ep-$e] create target" 201 "$(code "$T_alice" -X POST "$HUBURL/api/v1/targets" -d "{\"host\":\"$host\",\"discovery_mode\":\"network\",\"install_mode\":\"ssh\",\"credential_ref\":\"$CRED\",\"install_server_type\":\"nginx\",\"install_cert_path\":\"/etc/ssl/kk/server.crt\",\"install_key_path\":\"/etc/ssl/kk/server.key\",\"install_reload_method\":\"binary\",\"name\":\"$host\"}")"
  TGT[$e]="$(jget 'd["data"]["id"]' <"$FX_RUN/last.json")"
  openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -keyout "$W/$e.key" -out "$W/$e.csr" -subj "/CN=$host" -addext "subjectAltName=DNS:$host" >/dev/null 2>&1
  python3 -c "import json,sys; json.dump({'ca_id':sys.argv[1],'template_id':sys.argv[2],'csr_pem':open(sys.argv[3]).read()}, open(sys.argv[4],'w'))" "$CA_ID" "$TPL_ID" "$W/$e.csr" "$W/$e-issue.json"
  check "[ep-$e] issue ECDSA leaf" 201 "$(code "$T_alice" -X POST "$HUBURL/api/v1/certificates" --data @"$W/$e-issue.json")"
  fp="$(jget 'd["data"]["fingerprint_sha256"]' <"$FX_RUN/last.json")"
  check "[ep-$e] renewal/execute installs it over SSH" 200 "$(code "$T_alice" -X POST "$HUBURL/api/v1/renewal/execute" \
    -d "{\"fingerprint\":\"$fp\",\"target_id\":\"${TGT[$e]}\",\"install\":{\"server_type\":\"nginx\",\"cert_path\":\"/etc/ssl/kk/server.crt\",\"key_path\":\"/etc/ssl/kk/server.key\",\"reload_method\":\"binary\",\"verify_host_port\":\"$host:443\"}}")"
  outcome="$(jget 'd["data"].get("install_outcome","")' <"$FX_RUN/last.json")"
  [ "$outcome" = installed_verified ] || FAIL "[ep-$e] install_outcome=$outcome ($(jget 'd["data"].get("install_detail","")' <"$FX_RUN/last.json" | head -c 600))"
  OLD_FP[$e]="$(jget 'd["data"]["new_fingerprint"]' <"$FX_RUN/last.json")"
  code "$T_alice" "$HUBURL/api/v1/certificates/${OLD_FP[$e]}" >/dev/null
  hubser="$(jget 'format(int(d["data"]["serial_number"]),"X")' <"$FX_RUN/last.json")"
  if wait_serial a "$host" "$hubser" 30; then SERIAL_BEFORE[$e]="$hubser"; PASS "[ep-$e] serves the hub-issued ECDSA leaf (serial ${SERIAL_BEFORE[$e]}), the wave member"
  else FAIL "[ep-$e] served serial $(probe a "$host") != hub serial $hubser"; fi
done

STEP "4. wave: create, add 3 bound members + 1 unbound, accept"
openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -keyout "$W/u.key" -out "$W/u.csr" -subj "/CN=unbound.kk-uat.local" -addext "subjectAltName=DNS:unbound.kk-uat.local" >/dev/null 2>&1
python3 -c "import json,sys; json.dump({'ca_id':sys.argv[1],'template_id':sys.argv[2],'csr_pem':open(sys.argv[3]).read()}, open(sys.argv[4],'w'))" "$CA_ID" "$TPL_ID" "$W/u.csr" "$W/u-issue.json"
check "issue the unbound member (no target names it)" 201 "$(code "$T_alice" -X POST "$HUBURL/api/v1/certificates" --data @"$W/u-issue.json")"
U_FP="$(jget 'd["data"]["fingerprint_sha256"]' <"$FX_RUN/last.json")"
check "create wave" 201 "$(code "$T_alice" -X POST "$HUBURL/api/v1/reports/pqc-waves" -d '{"name":"w31-11-live","owner":"alice"}')"
WAVE="$(jget 'd["data"]["id"]' <"$FX_RUN/last.json")"
for fp in "${OLD_FP[a]}" "${OLD_FP[b]}" "${OLD_FP[fail]}" "$U_FP"; do
  check "add member ${fp:0:12}" 200 "$(code "$T_alice" -X POST "$HUBURL/api/v1/reports/pqc-waves/$WAVE/members" -d "{\"fingerprint\":\"$fp\"}")"
done
check "accept wave" 200 "$(code "$T_alice" -X POST "$HUBURL/api/v1/reports/pqc-waves/$WAVE/accept")"

STEP "5. two-principal execute: alice proposes, alice may not approve, bob approves"
check "alice proposes execute" 201 "$(code "$T_alice" -X POST "$HUBURL/api/v1/reports/pqc-waves/$WAVE/execute" -d "{\"template_id\":\"$TPL_ID\"}")"
ACT="$(jget 'd["data"]["id"]' <"$FX_RUN/last.json")"
check "alice cannot approve her own proposal" 403 "$(code "$T_alice" -X POST "$HUBURL/api/v1/reports/pqc-waves/$WAVE/execute/$ACT/approve")"
check "bob approves and the wave runs" 200 "$(code "$T_bob" -X POST "$HUBURL/api/v1/reports/pqc-waves/$WAVE/execute/$ACT/approve")"
cp "$FX_RUN/last.json" "$W/exec.json"
say "execute result: $(python3 -c "import json;d=json.load(open('$W/exec.json'))['data'];print({k:d.get(k) for k in ('migrated','failed','skipped','unsupported','regressed','wave_status')})")"

STEP "6. per-member outcomes as the real hub reported them"
for e in $EPS; do
  python3 - "$W/exec.json" "${OLD_FP[$e]}" >"$W/m-$e.txt" <<'PY'
import json, sys
for r in json.load(open(sys.argv[1]))["data"]["results"]:
    if r["fingerprint"] == sys.argv[2]:
        print(r.get("status",""), r.get("delivery",""), r.get("new_fingerprint",""), r.get("reason",""), sep="\t")
PY
  IFS=$'\t' read -r st dl nfp why <"$W/m-$e.txt"
  [ "$st" = delivery_unsupported ] && [ "$dl" = unsupported ] && PASS "[ep-$e] member status=delivery_unsupported delivery=unsupported" || FAIL "[ep-$e] member status=$st delivery=$dl reason=$why"
  case "$why" in *D-103*) PASS "[ep-$e] reason cites D-103: $why";; *) FAIL "[ep-$e] reason does not cite D-103: $why";; esac
  code "$T_alice" "$HUBURL/api/v1/certificates/$nfp" >/dev/null
  alg="$(jget 'd["data"].get("key_algorithm_display","")' <"$FX_RUN/last.json")"
  [ "$alg" = ML-DSA-65 ] && PASS "[ep-$e] successor ${nfp:0:12} was issued as ML-DSA-65 (hub inventory)" || FAIL "[ep-$e] successor key algorithm '$alg', want ML-DSA-65"
done
python3 - "$W/exec.json" "$U_FP" >"$W/m-u.txt" <<'PY'
import json, sys
for r in json.load(open(sys.argv[1]))["data"]["results"]:
    if r["fingerprint"] == sys.argv[2]:
        print(r.get("status",""), r.get("delivery",""), r.get("new_fingerprint",""), sep="\t")
PY
IFS=$'\t' read -r ust udl unfp <"$W/m-u.txt"
[ "$ust" = migrated ] && [ "$udl" = none ] && [ -n "$unfp" ] && PASS "unbound member status=migrated delivery=none (no target, nothing to deliver)" || FAIL "unbound member status=$ust delivery=$udl"

STEP "7. endpoints still serve the OLD certificate (no outage), observed by openssl s_client"
for e in $EPS; do
  host="kkw31-11-ep-$e"; now="$(probe a "$host")"
  if [ -n "$now" ] && [ "$now" = "${SERIAL_BEFORE[$e]}" ]; then PASS "[ep-$e] served serial unchanged (${SERIAL_BEFORE[$e]}): old cert still served"; else FAIL "[ep-$e] served serial '$now' != before '${SERIAL_BEFORE[$e]}'"; fi
  podman exec kkw31-11-ep-a sh -c "echo | openssl s_client -connect $host:443 -servername $host 2>/dev/null | openssl x509 -noout -text" | grep -q 'ML-DSA' \
    && FAIL "[ep-$e] endpoint unexpectedly serves an ML-DSA cert" || PASS "[ep-$e] served certificate is not ML-DSA (as expected while delivery is unsupported)"
done

STEP "8. wave status and audit trail"
code "$T_alice" "$HUBURL/api/v1/reports/pqc-waves" >/dev/null
WSTAT="$(python3 -c "import json;d=json.load(open('$FX_RUN/last.json'))['data'];w=[x for x in d if x['id']=='$WAVE'][0];print(w['status'],w['migrated'],w['total'],w.get('leaf_only'))")"
say "wave: status migrated total leaf_only = $WSTAT"
[ "${WSTAT%% *}" != done ] && PASS "wave not reported done (status ${WSTAT%% *})" || FAIL "wave reported done though no endpoint serves a PQC cert"
code "$T_alice" "$HUBURL/api/v1/audit?limit=1000" >/dev/null
AUD="$(cat "$FX_RUN/last.json")"
echo "$AUD" | grep -q 'pqc.wave_execute_approve' && PASS "audit has pqc.wave_execute_approve" || FAIL "audit lacks pqc.wave_execute_approve"
echo "$AUD" | grep -q 'pqc.wave_execute_propose' && PASS "audit has pqc.wave_execute_propose" || FAIL "audit lacks pqc.wave_execute_propose"
N="$(echo "$AUD" | grep -o 'pqc.wave_member_result' | wc -l | tr -d ' ')"
[ "$N" -ge 4 ] && PASS "audit has $N pqc.wave_member_result rows (one per member)" || FAIL "audit has only $N pqc.wave_member_result rows"

STEP "9. legs this harness cannot honestly run yet"
PENDING "[ep-a] served serial changes to the ML-DSA cert -- blocked on the ML-DSA private-key export follow-up (production deliverer is unsupportedWaveDeliverer, D-103)"
PENDING "[ep-b] served serial changes to the ML-DSA cert -- same blocker"
PENDING "[ep-fail] injected verify failure is rolled back and the old serial is still served -- same blocker (no Deliver is ever attempted, so there is nothing to roll back)"

STEP "10. summary"
if [ "$FAILED" = 0 ]; then say "ALL RUN STEPS PASSED (3 legs PENDING, nothing claimed for them)"; else say "ONE OR MORE STEPS FAILED"; fi
exit "$FAILED"
