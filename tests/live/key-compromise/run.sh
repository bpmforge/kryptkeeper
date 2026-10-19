#!/usr/bin/env bash
# W23-41: live key-compromise drill against a running hub (linux binary from
# this checkout, in podman, with Postgres and a real sshd/nginx managed
# target). A CA C with key K issues three leaves: L1 on a reachable managed
# ssh target (re-issuable), L2 with no managed target (deferred) and L3 on an
# unreachable managed target (failed). Two humans compromise K under dual
# control; the drill proves rotate-before-revoke, 100% revocation visible in
# OCSP/CRL within 60 s, per-bucket re-issue reporting, the audit trail, and
# that a failed rotation leaves zero side effects.
#
# Shares tests/live/ca-revoke/fixture.sh. PASS/FAIL per step; exits non-zero if
# any step FAILs. Writes RESULTS.md next to this script (no tokens in it).
# Not part of `go test`, not wired into CI. Podman only; cleans up on exit.
set -u
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FX_PREFIX=kkw23cmp
FX_PORT="${HUB_PORT:-18438}"
RECORD="${RECORD:-$HERE/RESULTS$([ "${FX_DB_MODE:-postgres}" = sqlite ] && echo -sqlite).md}"
. "$HERE/../ca-revoke/fixture.sh"
SSH_CTR="${FX_PREFIX}-ssh"
DOWN_HOST="${FX_PREFIX}-down"
SSH_IMG="localhost/${FX_PREFIX}-ssh:latest"
FX_EXTRA_CONTAINERS="$SSH_CTR"
trap fx_cleanup EXIT
W=""

mkident alice pki-admin; mkident bob pki-admin; mkident carol pki-admin
fx_header "# W23-41 live key-compromise drill"

fx_build_and_db
W="$FX_RUN/work"

STEP "managed target: sshd + nginx container (image from tests/live/ssh-install, key injected at run time)"
if ! podman image exists "$SSH_IMG"; then
  rm -rf "$FX_RUN/sshctx"; cp -R "$FX_REPO/tests/live/ssh-install" "$FX_RUN/sshctx"; : >"$FX_RUN/sshctx/authorized_keys"
  podman build -t "$SSH_IMG" "$FX_RUN/sshctx" >"$W/ssh-build.log" 2>&1 || DIE "ssh image build failed: $(tail -3 "$W/ssh-build.log")"
  PASS "built $SSH_IMG"
else PASS "reusing cached $SSH_IMG"; fi
ssh-keygen -q -t ed25519 -N '' -f "$W/id_ed25519" -C kk-uat >/dev/null || DIE "ssh-keygen"
podman run -d --name "$SSH_CTR" --network "$FX_NET" --hostname "$SSH_CTR" -e ROLE=nginx "$SSH_IMG" >/dev/null || DIE "ssh container start"
podman cp "$W/id_ed25519.pub" "$SSH_CTR:/root/.ssh/authorized_keys" && podman exec "$SSH_CTR" sh -c 'chown root:root /root/.ssh/authorized_keys && chmod 600 /root/.ssh/authorized_keys' || DIE "authorized_keys install"
for _ in $(seq 1 30); do podman exec "$SSH_CTR" sh -c 'pgrep sshd >/dev/null && pgrep nginx >/dev/null' 2>/dev/null && break; sleep 1; done
HOSTKEY="$(podman exec "$SSH_CTR" cat /etc/ssh/ssh_host_ed25519_key.pub | awk '{print $1" "$2}')"
[ -n "$HOSTKEY" ] && PASS "sshd and nginx up; host key captured for pinning" || DIE "no ssh host key"

STEP "start hub with alice, bob, carol (all pki-admin)"
fx_start_hub || DIE "hub did not start"
PASS "hub up at $HUBURL"
fx_template "$T_alice" || DIE "template"

# --- credential and targets -------------------------------------------------
PRIV="$(python3 -c "import json;print(json.dumps(open('$W/id_ed25519').read()))")"
code "$T_alice" -X POST "$HUBURL/api/v1/credentials" -d "{\"name\":\"uat-ssh\",\"credential_type\":\"ssh_key\",\"payload\":{\"user\":\"root\",\"private_key_pem\":$PRIV,\"host_public_key\":\"$HOSTKEY\",\"port\":22}}" >/dev/null
CRED_ID="$(jget 'd["data"]["id"]' <"$FX_RUN/last.json" 2>/dev/null)"; [ -n "$CRED_ID" ] && PASS "ssh_key credential stored" || DIE "credential: $(head -c 300 "$FX_RUN/last.json")"
mk_target() { # host name
  code "$T_alice" -X POST "$HUBURL/api/v1/targets" -d "{\"host\":\"$1\",\"discovery_mode\":\"network\",\"install_mode\":\"ssh\",\"credential_ref\":\"$CRED_ID\",\"install_server_type\":\"nginx\",\"install_cert_path\":\"/etc/ssl/kk/server.crt\",\"install_key_path\":\"/etc/ssl/kk/server.key\",\"install_reload_method\":\"binary\",\"name\":\"$2\"}"
}
check "managed target for L1 ($SSH_CTR, reachable)" 201 "$(mk_target "$SSH_CTR" uat-reachable)"
check "managed target for L3 ($DOWN_HOST, no such host)" 201 "$(mk_target "$DOWN_HOST" uat-down)"

# --- 1. CA C with key K, three leaves -----------------------------------------
STEP "1. CA C with key K and leaves L1, L2, L3"
check "create CA C" 201 "$(code "$T_alice" -X POST "$HUBURL/api/v1/cas" -d '{"name":"uat-compromise-C","type":"root","algorithm":"ECDSA-P256","validity":"5y","subject_cn":"UAT Compromise C"}')"
C_ID="$(jget 'd["data"]["id"]' <"$FX_RUN/last.json")"
check "GET /cas/C" 200 "$(code "$T_alice" "$HUBURL/api/v1/cas/$C_ID")"
# Deviation from the spec: GET /cas/{id} exposes no key_id field (CAListItem has none), so K is
# derived from the engine's documented naming (internal/ca/engine.go: "key-<caID>") and then
# proven to exist and to be the CA's key via GET /keys/{K}.
K="key-$C_ID"
check "GET /keys/K (K = key-<C id>; the CA API exposes no key_id)" 200 "$(code "$T_alice" "$HUBURL/api/v1/keys/$K")"
get_chain() { # out_prefix -> C cert PEM (first of chain)
  code "$T_alice" "$HUBURL/api/v1/cas/$C_ID/chain?format=pem" >/dev/null
  python3 - "$FX_RUN/last.json" "$1" <<'PY'
import re,sys
p=re.findall(r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", open(sys.argv[1]).read(), re.S)
open(sys.argv[2],"w").write(p[0]+"\n")
PY
}
get_chain "$W/C0.pem"
c="$(fx_issue "$T_alice" "$C_ID" "$SSH_CTR" "$W/L1")"; check "issue L1 (CN $SSH_CTR, matches the reachable target)" 201 "$c"
c="$(fx_issue "$T_alice" "$C_ID" l2-nomanaged.cmp.test "$W/L2")"; check "issue L2 (no managed target)" 201 "$c"
c="$(fx_issue "$T_alice" "$C_ID" "$DOWN_HOST" "$W/L3")"; check "issue L3 (CN $DOWN_HOST, matches the unreachable target)" 201 "$c"
FP1="$(cat "$W/L1.fp")"; FP2="$(cat "$W/L2.fp")"; FP3="$(cat "$W/L3.fp")"
# Install L1's current cert on the target so a re-issue replaces a hub-issued identity (informational).

# --- 2. policy and ACL ------------------------------------------------------
STEP "2. key policy and ACL"
check "PUT /keys/K/policy" 200 "$(code "$T_alice" -X PUT "$HUBURL/api/v1/keys/$K/policy" -d '{"owner":"alice","acl":["alice","bob"],"max_age_days":365}')"
c="$(code "$T_carol" -X POST "$HUBURL/api/v1/keys/$K/rotate" -d '{}')"; check "third admin (carol, not on the ACL) POST /keys/K/rotate" 403 "$c"

# --- 3. baseline ------------------------------------------------------------
STEP "3. baseline OCSP for L1..L3 (issuer = C's pre-rotation certificate)"
for n in 1 2 3; do
  [ "$(ocsp_status "$W/C0.pem" "$W/L$n.pem" "$W/C0.pem")" = good ] && PASS "L$n -> good" || FAIL "L$n baseline not good: $(ocsp_status "$W/C0.pem" "$W/L$n.pem" "$W/C0.pem")"
done

# --- 4. propose -------------------------------------------------------------
STEP "4. A proposes the compromise; nothing may change before approval"
code "$T_alice" "$HUBURL/api/v1/keys/$K" >/dev/null; cp "$FX_RUN/last.json" "$W/key-before.json"
check "A POST /keys/K/compromise" 202 "$(code "$T_alice" -X POST "$HUBURL/api/v1/keys/$K/compromise" -d '{}')"
ACT="$(jget 'd["data"]["action_id"]' <"$FX_RUN/last.json")"; [ -n "$ACT" ] || DIE "no action_id"
check "GET /keys/K/policy" 200 "$(code "$T_alice" "$HUBURL/api/v1/keys/$K/policy")"
CA0="$(jget 'd["data"].get("compromised_at")' <"$FX_RUN/last.json")"
{ [ "$CA0" = None ] || [ -z "$CA0" ]; } && PASS "no compromised_at before approval" || FAIL "compromised_at already set: $CA0"
code "$T_alice" "$HUBURL/api/v1/keys/$K" >/dev/null
cmp -s "$W/key-before.json" "$FX_RUN/last.json" && PASS "key metadata unchanged (K not rotated)" || FAIL "key metadata changed before approval"

# --- 5. approve -------------------------------------------------------------
STEP "5. dual control"
check "A approving own action" 403 "$(code "$T_alice" -X POST "$HUBURL/api/v1/pending-actions/$ACT/approve")"
APPROVE_AT="$(date +%s)"
check "B approves" 200 "$(code "$T_bob" -X POST "$HUBURL/api/v1/pending-actions/$ACT/approve")"
cp "$FX_RUN/last.json" "$W/approve.json"
echo "result JSON (captured):"; python3 -c "import json;print(json.dumps(json.load(open('$W/approve.json')),indent=1))" | tee -a "$RECORD" | head -60

# --- 6. result assertions -----------------------------------------------------
STEP "6. result"
res() { python3 - "$W/approve.json" "$1" <<'PY'
import json,sys
d=json.load(open(sys.argv[1]))
r=d.get("data",d)
# the executor result may be nested under "result"
for k in ("result",):
    if isinstance(r,dict) and k in r and isinstance(r[k],(dict,str)):
        r=r[k] if isinstance(r[k],dict) else json.loads(r[k])
print(eval(sys.argv[2]))
PY
}
[ "$(res 'r["steps"]')" = "['rotate', 'flag', 'revoke', 'reissue']" ] && PASS "steps == [rotate, flag, revoke, reissue]" || FAIL "steps = $(res 'r.get("steps")')"
REVOKED="$(res '" ".join(r.get("revoked") or [])' | tr 'A-F' 'a-f')"
n=0; for fp in "$FP1" "$FP2" "$FP3"; do echo "$REVOKED" | grep -q "$(echo "$fp" | tr 'A-F' 'a-f')" && n=$((n+1)); done
[ "$n" = 3 ] && PASS "revoked contains all three fingerprints (3/3 = 100%)" || FAIL "revoked contains $n/3 fingerprints: $REVOKED"
res 'r.get("reissued")' | tr 'A-F' 'a-f' | grep -q "$(echo "$FP1" | tr 'A-F' 'a-f')" && PASS "reissued contains L1" || FAIL "reissued: $(res 'r.get("reissued")')"
res 'r.get("deferred")' | tr 'A-F' 'a-f' | grep -q "$(echo "$FP2" | tr 'A-F' 'a-f')" && PASS "deferred contains L2" || FAIL "deferred: $(res 'r.get("deferred")')"
FAILMSG="$(res 'r.get("failed")')"
echo "$FAILMSG" | tr 'A-F' 'a-f' | grep -q "$(echo "$FP3" | tr 'A-F' 'a-f')" && PASS "failed reports L3 with its message: $(echo "$FAILMSG" | cut -c1-200)" || FAIL "failed: $FAILMSG"

# --- 7. OCSP / CRL --------------------------------------------------------------
STEP "7. OCSP and CRL within 60 s of the approval"
get_chain "$W/C1.pem"
if cmp -s "$W/C0.pem" "$W/C1.pem"; then say "note: C's certificate did not change across the rotation"; else say "note: rotation replaced C's certificate (C0 != C1), as the spec expects"; fi
for n in 1 2 3; do
  # Strict: the request names the issuer the leaf actually chains to (C's pre-rotation certificate,
  # whose key signed it) and the response must verify against that same certificate.
  if poll_ocsp revoked 60 "$W/C0.pem" "$W/L$n.pem" "$W/C0.pem"; then PASS "L$n: openssl ocsp (-issuer C0, response verified against C0) -> revoked after $(( $(date +%s) - APPROVE_AT )) s"
  else
    why="$POLL_LAST"
    diag="$(ocsp_status "$W/C1.pem" "$W/L$n.pem" "$W/C1.pem")"
    FAIL "L$n: OCSP for the pre-rotation issuer C0 answers '$why' (diagnostic only: asking about issuer C1, the post-rotation certificate, answers '$diag'). A relying party holding L$n builds its OCSP request from C0, so it never gets 'revoked'."
  fi
done
curl -sS --cacert "$FX_RUN/tls-export/ca.pem" "$HUBURL/crl/$C_ID.crl" -o "$W/C.crl"
CRLTXT="$(openssl crl -inform DER -in "$W/C.crl" -noout -text 2>&1)"
for n in 1 2 3; do
  s="$(openssl x509 -in "$W/L$n.pem" -noout -serial | cut -d= -f2)"
  echo "$CRLTXT" | grep -qi "Serial Number: $s" && PASS "CRL /crl/C.crl lists L$n ($s)" || FAIL "CRL does not list L$n ($s)"
done
if openssl crl -inform DER -in "$W/C.crl" -CAfile "$W/C1.pem" -noout 2>/dev/null; then PASS "CRL signature verifies against C's current certificate"; else FAIL "CRL does not verify against C's current certificate"; fi
if openssl crl -inform DER -in "$W/C.crl" -CAfile "$W/C0.pem" -noout 2>/dev/null; then PASS "CRL signature also verifies against the pre-rotation certificate"; else say "info: CRL does not verify against the pre-rotation certificate C0 (signed by the new key)"; fi

# --- 8. audit ---------------------------------------------------------------------
STEP "8. audit trail"
audit_has() { code "$T_alice" "$HUBURL/api/v1/audit?action=$1&limit=50" >/dev/null; python3 - "$FX_RUN/last.json" "$K" <<'PY'
import json,sys
d=json.load(open(sys.argv[1])); d=d.get("data",d)
rows=d if isinstance(d,list) else d.get("entries",d.get("items",[]))
sys.exit(0 if any(True for r in rows) else 1)
PY
}
for a in key.compromise alert.key.compromised alert.key.reissue_deferred alert.key.reissue_failed; do
  audit_has "$a" && PASS "audit has $a" || FAIL "audit has no $a"
done

# --- 9. rotate-failure leg ----------------------------------------------------------
STEP "9. rotation failure: suspended CA => zero side effects"
check "create CA C2" 201 "$(code "$T_alice" -X POST "$HUBURL/api/v1/cas" -d '{"name":"uat-compromise-C2","type":"root","algorithm":"ECDSA-P256","validity":"5y","subject_cn":"UAT Compromise C2"}')"
C2="$(jget 'd["data"]["id"]' <"$FX_RUN/last.json")"
K2="key-$C2"
code "$T_alice" "$HUBURL/api/v1/cas/$C2/chain?format=pem" >/dev/null
python3 - "$FX_RUN/last.json" "$W/C2.pem" <<'PY'
import re,sys
p=re.findall(r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", open(sys.argv[1]).read(), re.S)
open(sys.argv[2],"w").write(p[0]+"\n")
PY
c="$(fx_issue "$T_alice" "$C2" m.cmp.test "$W/M")"; check "issue leaf M under C2" 201 "$c"
check "PUT /keys/K2/policy" 200 "$(code "$T_alice" -X PUT "$HUBURL/api/v1/keys/$K2/policy" -d '{"owner":"alice","acl":["alice","bob"],"max_age_days":365}')"
check "suspend C2 (rotation refuses non-active CAs)" 200 "$(code "$T_alice" -X POST "$HUBURL/api/v1/cas/$C2/suspend")"
code "$T_alice" "$HUBURL/api/v1/audit?limit=200" >/dev/null; ALERTS_BEFORE="$(python3 -c "import json;d=json.load(open('$FX_RUN/last.json'));d=d.get('data',d);rows=d if isinstance(d,list) else d.get('entries',d.get('items',[]));print(sum(1 for r in rows if r.get('action','').startswith('alert.key.') and r.get('resource_id')=='$K2'))")"
check "A proposes compromise of K2" 202 "$(code "$T_alice" -X POST "$HUBURL/api/v1/keys/$K2/compromise" -d '{}')"
ACT2="$(jget 'd["data"]["action_id"]' <"$FX_RUN/last.json")"
c="$(code "$T_bob" -X POST "$HUBURL/api/v1/pending-actions/$ACT2/approve")"
case "$c" in 2*) FAIL "approve of a compromise whose rotation must fail returned $c: $(head -c 300 "$FX_RUN/last.json")" ;; *) PASS "approve reports failure ($c): $(head -c 200 "$FX_RUN/last.json")" ;; esac
code "$T_alice" "$HUBURL/api/v1/keys/$K2/policy" >/dev/null
CA2="$(jget 'd["data"].get("compromised_at")' <"$FX_RUN/last.json")"
{ [ "$CA2" = None ] || [ -z "$CA2" ]; } && PASS "no compromised_at on K2 (nothing stamped)" || FAIL "K2 stamped compromised_at=$CA2"
[ "$(ocsp_status "$W/C2.pem" "$W/M.pem" "$W/C2.pem")" = good ] && PASS "leaf M still good (nothing revoked)" || FAIL "leaf M is not good after the failed flow"
code "$T_alice" "$HUBURL/api/v1/audit?limit=200" >/dev/null; ALERTS_AFTER="$(python3 -c "import json;d=json.load(open('$FX_RUN/last.json'));d=d.get('data',d);rows=d if isinstance(d,list) else d.get('entries',d.get('items',[]));print(sum(1 for r in rows if r.get('action','').startswith('alert.key.') and r.get('resource_id')=='$K2'))")"
[ "$ALERTS_BEFORE" = "$ALERTS_AFTER" ] && PASS "no alert.key.* rows for K2 ($ALERTS_AFTER before and after)" || FAIL "alert rows for K2 changed: $ALERTS_BEFORE -> $ALERTS_AFTER"

STEP "10. summary"
if [ "$FAILED" = 0 ]; then say "ALL STEPS PASSED"; else say "ONE OR MORE STEPS FAILED"; fi
exit "$FAILED"
