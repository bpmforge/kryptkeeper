#!/usr/bin/env bash
# W23-37: live proof that revoking an issuing CA works end to end against a
# running hub (linux binary from this checkout, in podman, with Postgres):
# dual-controlled revoke, OCSP "revoked" for a child leaf within 60 s, the
# parent CRL listing the CA, and enrolment through the revoked CA refused on
# ACME (lego), EST (globalsign/est), SCEP (micromdm/scep) and CMP (openssl cmp).
#
# PASS/FAIL per step; exits non-zero on the first FAIL. Writes RESULTS.md next
# to this script (no tokens in it). Not part of `go test`, not wired into CI.
# Podman only. Cleans up every container, the network and the temp dir on exit.
set -u
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FX_PREFIX=kkw23rev
FX_PORT="${HUB_PORT:-18437}"
RECORD="${RECORD:-$HERE/RESULTS$([ "${FX_DB_MODE:-postgres}" = sqlite ] && echo -sqlite).md}"
. "$HERE/fixture.sh"
FX_EXTRA_CONTAINERS="${FX_PREFIX}-lego"
trap fx_cleanup EXIT
CA_PEM_HOST() { echo "$FX_RUN/tls-export/ca.pem"; }

mkident alice pki-admin; mkident bob pki-admin
fx_header "# W23-37 live test: revoke an issuing CA, OCSP on a child leaf, CRL check"

fx_build_and_db
STEP "start hub with the bootstrap root R"
fx_start_hub || DIE "hub did not start"
PASS "hub up at $HUBURL (admins alice and bob from APP_API_KEYS_JSON)"
W="$FX_RUN/work"

R_ID="$(code "$T_alice" "$HUBURL/api/v1/cas" >/dev/null; jget 'd["data"][0]["id"]' <"$FX_RUN/last.json")"
[ -n "$R_ID" ] || DIE "no root CA"
check "create intermediate I (RSA-2048, so SCEP can use it) under R" 201 "$(code "$T_alice" -X POST "$HUBURL/api/v1/cas" \
  -d "{\"name\":\"uat-issuing-I\",\"type\":\"intermediate\",\"algorithm\":\"RSA-2048\",\"validity\":\"5y\",\"subject_cn\":\"UAT Issuing I\",\"parent_ca_id\":\"$R_ID\"}")"
I_ID="$(jget 'd["data"]["id"]' <"$FX_RUN/last.json")"
[ -n "$I_ID" ] || DIE "no intermediate id"
code "$T_alice" "$HUBURL/api/v1/cas/$I_ID/chain?format=pem" >/dev/null; cp "$FX_RUN/last.json" "$W/chain-I.pem"
python3 - "$W/chain-I.pem" "$W/I.pem" "$W/R.pem" <<'PY'
import re,sys
pems=re.findall(r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", open(sys.argv[1]).read(), re.S)
assert len(pems)>=2, "chain has %d certs" % len(pems)
open(sys.argv[2],"w").write(pems[0]+"\n"); open(sys.argv[3],"w").write(pems[1]+"\n")
PY
CHAIN="$W/chain-I.pem"
openssl x509 -in "$W/I.pem" -noout -subject | grep -q "UAT Issuing I" && PASS "I chain split: first cert is I, second is R" || DIE "chain order unexpected"
I_SERIAL="$(openssl x509 -in "$W/I.pem" -noout -serial | cut -d= -f2)"

fx_template "$T_alice" || DIE "template"
c="$(fx_issue "$T_alice" "$I_ID" leaf-l.revoke.test "$W/L")"; check "issue leaf L from I" 201 "$c"
L_FP="$(cat "$W/L.fp")"

STEP "3. baseline: OCSP for L is good"
[ "$(ocsp_status "$W/I.pem" "$W/L.pem" "$CHAIN")" = good ] && PASS "openssl ocsp -issuer I -cert L -> good" || FAIL "baseline OCSP for L is not good"

STEP "step 5a. restart hub so ACME/EST/CMP issue from I and SCEP uses I"
fx_start_hub -e KRYPTKEEPER_DEFAULT_CA_ID="$I_ID" -e KRYPTKEEPER_SCEP_CA_ID="$I_ID" -e KRYPTKEEPER_SCEP_ENABLED=true \
  -e KRYPTKEEPER_CMP_SECRET=uat-cmp-secret -e KRYPTKEEPER_CMP_REFERENCE=kk-uat || DIE "hub restart failed"
podman logs "$FX_HUB" 2>&1 | grep -q "SCEP endpoint: /scep (CA $I_ID)" && PASS "SCEP enabled on I" || FAIL "SCEP not enabled on I"
podman logs "$FX_HUB" 2>&1 | grep -q "CMP endpoint: /cmp" && PASS "CMP enabled" || FAIL "CMP not enabled"
# The hub's TLS listener was issued by the bootstrap root R; clients trust R via the exported bundle.

HUBIN="$FX_HUB:$FX_HUBPORT"
CAPEM_MNT="$FX_RUN/tls-export/ca.pem"
mint_scep() { code "$T_alice" -X POST "$HUBURL/api/v1/scep/challenges" -d "{\"common_name\":\"$1\",\"dns_names\":[\"$1\"],\"ttl\":\"60m\"}" >/dev/null; jget 'd["data"]["challenge"]' <"$FX_RUN/last.json"; }
SC1="$(mint_scep scep1.revoke.test)"; SC2="$(mint_scep scep2.revoke.test)"
[ "${#SC1}" -eq 64 ] && [ "${#SC2}" -eq 64 ] && PASS "minted two one-time SCEP challenges (before the revoke)" || DIE "could not mint SCEP challenges"

# --- protocol clients (each run prints a single RESULT line) -------------------
run_acme() { # label domain
  mkdir -p "$FX_RUN/lego-$1"; kk_rm "${FX_PREFIX}-lego"
  kk_wait_dns "$FX_NET" "$FX_HUB" || DIE "DNS for $FX_HUB did not come back on $FX_NET after the previous container was removed"
  podman run --name "${FX_PREFIX}-lego" --network "$FX_NET" --hostname "$2" -e LEGO_CA_CERTIFICATES=/etc/kk-ca/ca.pem \
    -v "$CAPEM_MNT:/etc/kk-ca/ca.pem:ro" -v "$FX_RUN/lego-$1:/data" docker.io/goacme/lego:latest \
    run --accept-tos --email uat@example.test --server "https://$HUBIN/acme/directory" --path /data \
    --domains "$2" --http --http.address :80 >"$W/acme-$1.log" 2>&1
  local rc=$?; kk_rm "${FX_PREFIX}-lego"; return $rc
}
run_est() { # label
  # est-run.sh runs under set -e with `go get` output hidden, so a transient module-proxy
  # failure leaves an empty log. Retry only that case; a real EST answer is never retried.
  local try
  for try in 1 2 3; do
    podman run --rm --network "$FX_NET" -v "$FX_REPO/tests/live/protocols/estcheck:/src:ro" -v "$FX_REPO/tests/live/protocols/est-run.sh:/est-run.sh:ro" \
      -e EST_HOST="$HUBIN" -e EST_USER=uat-est -e EST_PASS=uat-est-password docker.io/library/golang:1.23-alpine sh /est-run.sh >"$W/est-$1.log" 2>&1
    [ -s "$W/est-$1.log" ] && return 0
    sleep 3
  done
}
cat >"$W/scep-run.sh" <<'EOS'
#!/bin/sh
set -u
apk add --no-cache openssl >/dev/null 2>&1
mkdir -p /work/k && cd /work
go install github.com/micromdm/scep/v2/cmd/scepclient@latest >/tmp/get.log 2>&1 || cat /tmp/get.log
export PATH=$PATH:/root/go/bin
openssl genrsa -traditional -out /work/k/key.pem 3072 >/dev/null 2>&1
scepclient -server-url "$SCEP_URL" -challenge "$SCEP_CHALLENGE" -cn "$SCEP_CN" -certificate /work/out.pem -private-key /work/k/key.pem -keySize 3072 -debug
if [ -s /work/out.pem ] && openssl x509 -in /work/out.pem -noout >/dev/null 2>&1; then
  echo "RESULT issued subject=$(openssl x509 -in /work/out.pem -noout -subject -nameopt RFC2253 | sed 's/^subject=//')"
else
  echo "RESULT refused"
fi
EOS
cat >"$W/cmp-run.sh" <<'EOS'
#!/bin/sh
set -u
apk add --no-cache openssl >/dev/null 2>&1
mkdir -p /work && cd /work
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072 -out newkey.pem >/dev/null 2>&1
openssl cmp -cmd ir -server "$CMP_URL" -tls_used -tls_trusted /ca.pem -recipient "/CN=UAT Issuing I" \
  -subject "/CN=$CMP_CN" -newkey newkey.pem -secret "pass:uat-cmp-secret" -ref kk-uat -certout leaf.pem -verbosity 6
if [ -s leaf.pem ]; then echo "RESULT issued subject=$(openssl x509 -in leaf.pem -noout -subject)"; else echo "RESULT refused"; fi
EOS
run_scep() { # label challenge cn
  podman run --rm --network "$FX_NET" -v "$W/scep-run.sh:/scep-run.sh:ro" -v "$CAPEM_MNT:/ca.pem:ro" \
    -e SCEP_URL="https://$HUBIN/scep" -e SCEP_CHALLENGE="$2" -e SCEP_CN="$3" -e SSL_CERT_FILE=/ca.pem \
    docker.io/library/golang:1.23-alpine sh /scep-run.sh 2>&1 | grep -v "$2" >"$W/scep-$1.log"
}
run_cmp() { # label cn
  podman run --rm --network "$FX_NET" -v "$W/cmp-run.sh:/cmp-run.sh:ro" -v "$CAPEM_MNT:/ca.pem:ro" \
    -e CMP_URL="https://$HUBIN/cmp" -e CMP_CN="$2" docker.io/library/alpine:3 sh /cmp-run.sh >"$W/cmp-$1.log" 2>&1
}

STEP "4. enrolment baseline through I on ACME, EST, SCEP, CMP"
BASE_ACME=FAIL BASE_EST=FAIL BASE_SCEP=FAIL BASE_CMP=FAIL
if run_acme base acme1.revoke.test && grep -q "Server responded with a certificate" "$W/acme-base.log" && [ -s "$FX_RUN/lego-base/certificates/acme1.revoke.test.crt" ]; then
  openssl verify -CAfile "$CHAIN" "$FX_RUN/lego-base/certificates/acme1.revoke.test.crt" >/dev/null 2>&1 && { PASS "ACME (lego) issued a cert that chains to I"; BASE_ACME=PASS; } || FAIL "ACME cert does not chain to I"
else FAIL "ACME baseline: $(tail -3 "$W/acme-base.log" | tr '\n' ' ')"; fi
if run_est base; grep -q "PASS enroll" "$W/est-base.log"; then PASS "EST (globalsign/est) enrolled"; BASE_EST=PASS; else FAIL "EST baseline: $(tail -3 "$W/est-base.log" | tr '\n' ' ')"; fi
run_scep base "$SC1" scep1.revoke.test
if grep -q "^RESULT issued" "$W/scep-base.log"; then PASS "SCEP (micromdm/scep) enrolled"; BASE_SCEP=PASS; else FAIL "SCEP baseline: $(tail -3 "$W/scep-base.log" | tr '\n' ' ')"; fi
run_cmp base cmp1.revoke.test
if grep -q "^RESULT issued" "$W/cmp-base.log"; then PASS "CMP (openssl cmp ir) enrolled"; BASE_CMP=PASS; else FAIL "CMP baseline: $(tail -3 "$W/cmp-base.log" | tr '\n' ' ')"; fi
[ "$FAILED" = 0 ] || DIE "baseline enrolment failed, so the post-revoke refusals would prove nothing"

STEP "5. blast radius, then A proposes the revoke (I must stay active)"
check "GET blast-radius retire_ca target=I" 200 "$(code "$T_alice" "$HUBURL/api/v1/blast-radius?action=retire_ca&target=$I_ID")"
AFF="$(jget 'd["data"].get("total_affected", d["data"].get("affected", -1))' <"$FX_RUN/last.json" 2>/dev/null)"
[ "${AFF:--1}" -ge 1 ] 2>/dev/null && PASS "blast radius reports $AFF affected (>= 1)" || FAIL "blast radius affected=$AFF: $(head -c 300 "$FX_RUN/last.json")"
check "A POST /cas/I/revoke is only proposed" 202 "$(code "$T_alice" -X POST "$HUBURL/api/v1/cas/$I_ID/revoke" -d '{}')"
ACT="$(jget 'd["data"]["action_id"]' <"$FX_RUN/last.json")"; [ -n "$ACT" ] || DIE "no action_id"
check "GET /cas/I" 200 "$(code "$T_alice" "$HUBURL/api/v1/cas/$I_ID")"
ST="$(jget 'd["data"]["status"]' <"$FX_RUN/last.json")"; [ "$ST" = active ] && PASS "I is still active while the revoke is pending" || FAIL "I status=$ST before approval"
[ "$(ocsp_status "$W/I.pem" "$W/L.pem" "$CHAIN")" = good ] && PASS "L still good while pending" || FAIL "L not good while pending"

STEP "6. dual control"
check "A approving own revoke" 403 "$(code "$T_alice" -X POST "$HUBURL/api/v1/pending-actions/$ACT/approve")"
check "B approves" 200 "$(code "$T_bob" -X POST "$HUBURL/api/v1/pending-actions/$ACT/approve")"
REV_AT="$(date +%s)"
check "GET /cas/I" 200 "$(code "$T_alice" "$HUBURL/api/v1/cas/$I_ID")"
ST="$(jget 'd["data"]["status"]' <"$FX_RUN/last.json")"; [ "$ST" = revoked ] && PASS "I status=revoked" || FAIL "I status=$ST after approval"

STEP "7. OCSP for L within 60 s, parent CRL lists I"
if poll_ocsp revoked 60 "$W/I.pem" "$W/L.pem" "$CHAIN"; then PASS "openssl ocsp for child leaf L reports revoked after $(( $(date +%s) - REV_AT )) s (budget 60 s)"; else FAIL "OCSP for L still '$POLL_LAST' after 60 s"; fi
curl -sS --cacert "$CAPEM_MNT" "$HUBURL/crl/$R_ID.crl" -o "$W/R.crl"
if openssl crl -inform DER -in "$W/R.crl" -CAfile "$W/R.pem" -noout 2>"$W/crlv.log"; then PASS "parent CRL (R) signature verifies against R"; else FAIL "parent CRL verify: $(cat "$W/crlv.log")"; fi
CRLTXT="$(openssl crl -inform DER -in "$W/R.crl" -noout -text 2>&1)"
echo "$CRLTXT" | grep -qi "Serial Number: $I_SERIAL" && PASS "parent CRL lists I's serial ($I_SERIAL)" || FAIL "parent CRL does not list I's serial $I_SERIAL"
echo "$CRLTXT" | grep -A5 -i "Serial Number: $I_SERIAL" | grep -qi "CA Compromise" && PASS "the entry carries reason CA Compromise" || FAIL "reason is not CA Compromise: $(echo "$CRLTXT" | grep -A5 -i "Serial Number: $I_SERIAL" | tr '\n' ' ')"
curl -sS --cacert "$CAPEM_MNT" "$HUBURL/crl/$I_ID.crl" -o "$W/I.crl"
if openssl crl -inform DER -in "$W/I.crl" -noout -text 2>/dev/null | grep -qi "Serial Number: $(openssl x509 -in "$W/L.pem" -noout -serial | cut -d= -f2)"; then say "info: I's own CRL lists leaf L (not required by the ticket)"; else say "info: I's own CRL does not list leaf L: a CRL-only relying party learns of the revoke from the parent CRL (R) listing I, as the ticket requires; OCSP answers revoked for L directly"; fi

STEP "8. enrolment through revoked I fails on all four protocols"
SC3="$(mint_scep scep3.revoke.test 2>/dev/null || true)"
if run_acme post acme2.revoke.test; then FAIL "ACME enrolment succeeded through the revoked CA"; elif grep -qi "issuing CA revoked\|revoked" "$W/acme-post.log"; then PASS "ACME refused: $(grep -io 'issuing CA revoked' "$W/acme-post.log" | head -1)"; else FAIL "ACME failed but not for the revoked CA: $(tail -3 "$W/acme-post.log" | tr '\n' ' ')"; fi
run_est post; if grep -q "PASS enroll" "$W/est-post.log"; then FAIL "EST enrolment succeeded through the revoked CA"; elif grep -q "FAIL enroll" "$W/est-post.log"; then PASS "EST refused at enroll: $(grep 'FAIL enroll' "$W/est-post.log" | head -1 | cut -c1-160)"; else FAIL "EST failed before enroll: $(tail -3 "$W/est-post.log" | tr '\n' ' ')"; fi
run_scep post "$SC2" scep2.revoke.test; if grep -q "^RESULT issued" "$W/scep-post.log"; then FAIL "SCEP enrolment succeeded through the revoked CA"; elif grep -q "^RESULT refused" "$W/scep-post.log"; then PASS "SCEP refused (unused one-time challenge minted before the revoke)"; else FAIL "SCEP post-revoke: $(tail -3 "$W/scep-post.log" | tr '\n' ' ')"; fi
run_cmp post cmp2.revoke.test; if grep -q "^RESULT issued" "$W/cmp-post.log"; then FAIL "CMP enrolment succeeded through the revoked CA"; elif grep -q "^RESULT refused" "$W/cmp-post.log"; then PASS "CMP refused: $(grep -i 'revoked\|error\|fail' "$W/cmp-post.log" | head -1 | cut -c1-160)"; else FAIL "CMP post-revoke: $(tail -3 "$W/cmp-post.log" | tr '\n' ' ')"; fi
podman logs "$FX_HUB" 2>&1 | grep -i "revoked" | sed -n '1,8p' | while IFS= read -r l; do say "hub log: $l"; done

STEP "9. summary"
say ""
say "| Check | Result |"
say "|---|---|"
say "| baseline ACME / EST / SCEP / CMP enrol through I | $BASE_ACME / $BASE_EST / $BASE_SCEP / $BASE_CMP |"
say "| A proposes revoke: 202, I stays active; A cannot self-approve (403); B approves | see PASS lines above |"
say "| OCSP for child leaf L: revoked | see step 7 |"
say "| parent CRL lists I with CA Compromise | see step 7 |"
say "| ACME, EST, SCEP, CMP refused after revoke | see step 8 |"
say ""
if [ "$FAILED" = 0 ]; then say "ALL STEPS PASSED"; else say "ONE OR MORE STEPS FAILED"; fi
exit "$FAILED"
