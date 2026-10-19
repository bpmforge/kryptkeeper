#!/usr/bin/env bash
# W31-04: live OpenSSL >= 3.5 interop for ML-DSA and hybrid leaf certificates issued by a
# running hub (linux binary from this checkout, in podman, with Postgres). Host OpenSSL does
# the verifying. Hybrid leaves are verified on the classical path only: the hybrid encoding is
# the project's own (D-104, docs/PQC_HYBRID_ENCODING.md), no LAMPS composite interop is claimed.
#
# PASS/FAIL per step; stops at the first FAIL (KK_KEEP_GOING=1 runs on). Writes RESULTS.md
# next to this script (no tokens in it). Not part of `go test`, not wired into CI.
set -u
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FX_PREFIX=kkw31-04
FX_PORT="${HUB_PORT:-18441}"
RECORD="${RECORD:-$HERE/RESULTS.md}"
. "$HERE/../ca-revoke/fixture.sh"
trap fx_cleanup EXIT

OSSL="${OPENSSL:-openssl}"
fx_header "# W31-04 live test: OpenSSL interop for ML-DSA and hybrid leaves"
say "verifier: $($OSSL version)"

STEP "0. OpenSSL version gate"
OSSL_VER="$($OSSL version | awk '{print $2}')"
if [ "$(printf '%s\n3.5.0\n' "$OSSL_VER" | sort -V | head -1)" != "3.5.0" ]; then
  SKIP "openssl <3.5 ($OSSL_VER): ML-DSA interop not run"
  say ""; say "RESULT: SKIPPED (no step ran, nothing is claimed)"
  trap - EXIT; rm -rf "$FX_RUN"; exit 0
fi
PASS "openssl $OSSL_VER >= 3.5"

mkident alice pki-admin; mkident bob pki-admin
fx_build_and_db
STEP "1. start hub with the bootstrap ECDSA root R"
fx_start_hub || DIE "hub did not start"
PASS "hub up at $HUBURL"
W="$FX_RUN/work"
H="$FX_RUN/hdr"; mkdir -p "$H"

code "$T_alice" "$HUBURL/api/v1/cas" >/dev/null
R_ID="$(jget 'd["data"][0]["id"]' <"$FX_RUN/last.json")"
[ -n "$R_ID" ] || DIE "no root CA"

STEP "2. create ML-DSA-65 intermediate M and ECDSA-P256 intermediate C under R"
mk_ca() { # name algo cn -> prints id
  check "create CA $1 ($2)" 201 "$(code "$T_alice" -X POST "$HUBURL/api/v1/cas" \
    -d "{\"name\":\"$1\",\"type\":\"intermediate\",\"algorithm\":\"$2\",\"validity\":\"5y\",\"subject_cn\":\"$3\",\"parent_ca_id\":\"$R_ID\"}")" >&2
  jget 'd["data"]["id"]' <"$FX_RUN/last.json"
}
M_ID="$(mk_ca pqc-issuing-M ML-DSA-65 "PQC Issuing M")"
C_ID="$(mk_ca pqc-issuing-C ECDSA-P256 "PQC Issuing C")"
[ -n "$M_ID" ] && [ -n "$C_ID" ] || DIE "missing CA ids"
split_chain() { # ca_id name -> $W/NAME.pem (the CA) ; $W/R.pem
  code "$T_alice" "$HUBURL/api/v1/cas/$1/chain?format=pem" >/dev/null; cp "$FX_RUN/last.json" "$W/chain-$2.pem"
  python3 - "$W/chain-$2.pem" "$W/$2.pem" "$W/R.pem" <<'PY'
import re,sys
pems=re.findall(r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", open(sys.argv[1]).read(), re.S)
assert len(pems)>=2, "chain has %d certs" % len(pems)
open(sys.argv[2],"w").write(pems[0]+"\n"); open(sys.argv[3],"w").write(pems[1]+"\n")
PY
}
split_chain "$M_ID" M; split_chain "$C_ID" C
$OSSL x509 -in "$W/M.pem" -noout -text | grep -q "ML-DSA-65" && PASS "M is an ML-DSA-65 certificate (openssl parses it)" || FAIL "M is not ML-DSA-65 per openssl"

STEP "3. templates"
mk_tpl() { # name algos-json -> prints id
  check "create template $1" 201 "$(code "$T_alice" -X POST "$HUBURL/api/v1/templates" \
    -d "{\"name\":\"$1\",\"display_name\":\"$1\",\"validity_period\":\"P30D\",\"key_usage\":[\"digitalSignature\"],\"extended_key_usage\":[\"serverAuth\"],\"allowed_algorithms\":$2,\"active\":true}")" >&2
  jget 'd["data"]["id"]' <"$FX_RUN/last.json"
}
TPL_PQC="$(mk_tpl tpl-pqc '["ML-DSA-44","ML-DSA-65","ML-DSA-87","Hybrid-ECDSA-P256-ML-DSA-65","Hybrid-ECDSA-P384-ML-DSA-87"]')"
TPL_ECDSA="$(mk_tpl tpl-ecdsa-only '["ECDSA"]')"
[ -n "$TPL_PQC" ] && [ -n "$TPL_ECDSA" ] || DIE "missing template ids"

# issue CA TPL CSR OUT -> HTTP code; on 201 writes OUT.pem and OUT.fp
issue() {
  local ca="$1" tpl="$2" csr="$3" out="$4" c
  python3 -c "import json,sys; json.dump({'ca_id':sys.argv[1],'template_id':sys.argv[2],'csr_pem':open(sys.argv[3]).read()}, open(sys.argv[4],'w'))" "$ca" "$tpl" "$csr" "$out.json"
  c="$(code "$T_alice" -X POST "$HUBURL/api/v1/certificates" --data @"$out.json")"
  if [ "$c" = 201 ]; then
    jget 'd["data"]["fingerprint_sha256"]' <"$FX_RUN/last.json" >"$out.fp"
    curl -sS --cacert "$FX_RUN/tls-export/ca.pem" -H "Authorization: Bearer $T_alice" "$HUBURL/api/v1/certificates/$(cat "$out.fp")/download?format=pem" -o "$out.pem"
  fi
  echo "$c"
}
verify_ok() { # label chainfile-with-roots untrusted leaf
  local out; out="$($OSSL verify -CAfile "$W/R.pem" ${3:+-untrusted "$3"} "$4" 2>&1)"
  if echo "$out" | grep -q ': OK$'; then PASS "$1: openssl verify OK"; else FAIL "$1: openssl verify: $(echo "$out" | tr '\n' ' ')"; fi
}

STEP "4. ML-DSA-44/65/87 leaves under classical C and under ML-DSA M"
for N in 44 65 87; do
  CN="mldsa$N.pqc.test"
  $OSSL genpkey -algorithm "ML-DSA-$N" -out "$W/k$N.pem" 2>/dev/null || FAIL "openssl genpkey ML-DSA-$N"
  $OSSL req -new -key "$W/k$N.pem" -subj "/CN=$CN" -addext "subjectAltName=DNS:$CN" -out "$W/k$N.csr" 2>/dev/null || FAIL "openssl req ML-DSA-$N"
  check "issue ML-DSA-$N leaf under C" 201 "$(issue "$C_ID" "$TPL_PQC" "$W/k$N.csr" "$W/L$N-C")"
  verify_ok "ML-DSA-$N leaf, chain R,C" "" "$W/C.pem" "$W/L$N-C.pem"
  check "issue ML-DSA-$N leaf under M" 201 "$(issue "$M_ID" "$TPL_PQC" "$W/k$N.csr" "$W/L$N-M")"
  verify_ok "ML-DSA-$N leaf, chain R,M (ML-DSA signature hop)" "" "$W/M.pem" "$W/L$N-M.pem"
done

STEP "5. hybrid leaves under C (classical path only, D-104)"
for HA in Hybrid-ECDSA-P256-ML-DSA-65 Hybrid-ECDSA-P384-ML-DSA-87; do
  CN="$(echo "$HA" | tr 'A-Z' 'a-z').pqc.test"
  (cd "$FX_REPO" && go run ./tests/live/pqc/hybridcsr -algo "$HA" -cn "$CN" -out "$H/$HA") || DIE "hybridcsr helper failed for $HA"
  check "issue $HA leaf under C" 201 "$(issue "$C_ID" "$TPL_PQC" "$H/$HA.csr" "$W/H-$HA")"
  verify_ok "$HA leaf, chain R,C (classical path)" "" "$W/C.pem" "$W/H-$HA.pem"
  # OpenSSL prints a known extension by name and an unknown one by dotted OID; accept either spelling.
  HTXT="$($OSSL x509 -in "$W/H-$HA.pem" -noout -text 2>&1)"
  if echo "$HTXT" | grep -Eqi '2\.5\.29\.72|Subject Alternative Public Key Info'; then PASS "$HA leaf parses and carries subjectAltPublicKeyInfo (2.5.29.72)"; else FAIL "$HA leaf lacks 2.5.29.72 in openssl -text: $(echo "$HTXT" | grep -A40 'X509v3 extensions' | grep -E '^ {12}\S' | tr '\n' ' ')"; fi
done
say "note: hybrid leaves are checked on the classical ECDSA path only; no LAMPS composite interop is claimed"

STEP "6. negative: allow-list refusal"
c="$(issue "$C_ID" "$TPL_ECDSA" "$W/k65.csr" "$W/neg-allow")"
case "$c" in 4??) PASS "ML-DSA-65 CSR with tpl-ecdsa-only refused: HTTP $c (spec expects 422 policy_violation)"; [ "$c" = 422 ] || say "info: got $c, not the documented 422";; *) FAIL "allow-list refusal: want 4xx, got $c";; esac

STEP "7. negative: bad proof of possession"
python3 - "$W/k65.csr" "$W/bad-mldsa.csr" <<'PY'
import re,sys,base64
src=open(sys.argv[1]).read()
m=re.search(r"-----BEGIN ([A-Z ]+)-----\n(.*?)-----END", src, re.S)
label=m.group(1); der=bytearray(base64.b64decode(m.group(2)))
der[-8]^=0xFF
b=base64.b64encode(bytes(der)).decode()
open(sys.argv[2],"w").write("-----BEGIN %s-----\n%s\n-----END %s-----\n" % (label, "\n".join(b[i:i+64] for i in range(0,len(b),64)), label))
PY
check "bad-PoP ML-DSA-65 CSR rejected" 400 "$(issue "$C_ID" "$TPL_PQC" "$W/bad-mldsa.csr" "$W/neg-pop1")"
check "bad-PoP hybrid CSR rejected" 400 "$(issue "$C_ID" "$TPL_PQC" "$H/Hybrid-ECDSA-P256-ML-DSA-65.bad.csr" "$W/neg-pop2")"

STEP "8. CRL and OCSP signed by the ML-DSA CA M, verified by openssl"
cat "$W/M.pem" "$W/R.pem" >"$W/chain-MR.pem"
[ "$(ocsp_status "$W/M.pem" "$W/L65-M.pem" "$W/chain-MR.pem")" = good ] && PASS "openssl ocsp -issuer M -cert ML-DSA-65 leaf -> good (response verified)" || FAIL "OCSP for the M leaf is not good: $(ocsp_status "$W/M.pem" "$W/L65-M.pem" "$W/chain-MR.pem")"
LSER="$($OSSL x509 -in "$W/L65-M.pem" -noout -serial | cut -d= -f2)"
c="$(code "$T_alice" -X POST "$HUBURL/api/v1/certificates/$(cat "$W/L65-M.fp")/revoke" -d '{"reason_code":1}')"
if [ "$c" = 202 ]; then
  ACT="$(jget 'd["data"]["action_id"]' <"$FX_RUN/last.json")"
  c="$(code "$T_bob" -X POST "$HUBURL/api/v1/pending-actions/$ACT/approve")"
fi
check "revoke the M-issued ML-DSA-65 leaf" 200 "$c"
if poll_ocsp revoked 60 "$W/M.pem" "$W/L65-M.pem" "$W/chain-MR.pem"; then PASS "openssl ocsp -> revoked for the M leaf (ML-DSA-signed response verified by openssl)"; else FAIL "OCSP for the M leaf still '$POLL_LAST'"; fi
ok=0
for _ in $(seq 1 30); do
  curl -sS --cacert "$FX_RUN/tls-export/ca.pem" "$HUBURL/crl/$M_ID.crl" -o "$W/M.crl"
  if $OSSL crl -inform DER -in "$W/M.crl" -noout -text 2>/dev/null | grep -qi "Serial Number: $LSER"; then ok=1; break; fi
  sleep 2
done
[ "$ok" = 1 ] && PASS "M's CRL lists the revoked leaf serial" || FAIL "M's CRL does not list serial $LSER"
if $OSSL crl -inform DER -in "$W/M.crl" -CAfile "$W/M.pem" -noout >"$W/crlv.log" 2>&1; then PASS "openssl verifies M's ML-DSA CRL signature against M"; else FAIL "M CRL signature verify: $(tr '\n' ' ' <"$W/crlv.log")"; fi

STEP "9. summary"
say ""
if [ "$FAILED" = 0 ]; then say "ALL STEPS PASSED"; else say "ONE OR MORE STEPS FAILED"; fi
exit "$FAILED"
