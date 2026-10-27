#!/usr/bin/env bash
# W40-03 end-to-end live run (gap P12): the REAL hub (linux binary from this
# checkout, Postgres in podman by default, FX_DB_MODE=sqlite for SQLite) and
# REAL kryptkeeper-agents in debian:12 and rockylinux:9 containers. Everything
# goes through the hub API: propose a trust bundle, the proposer cannot
# approve, a second principal approves, the agents apply it, the OS verifies a
# leaf, per-host status reads applied, then a removal (with the blast-radius
# warning when the root is a hub CA) and the leaf stops verifying.
#
#   bash tests/live/trust-store/e2e.sh
#
# Phase 1 uses a throwaway external root. Phase 2 pushes the hub's own root R
# and verifies a hub-issued leaf; its removal must carry the warning. Windows
# and macOS hosts are not exercised. Podman only; cleans up what it created.
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FX_PREFIX="kkts2e$(openssl rand -hex 2)"
FX_PORT="${HUB_PORT:-$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1])')}"
RECORD="${RECORD:-/dev/null}"
. "$HERE/../ca-revoke/fixture.sh"
IMAGES=(docker.io/library/debian:12 docker.io/library/rockylinux:9)
FX_EXTRA_CONTAINERS="${FX_PREFIX}-a0 ${FX_PREFIX}-a1"
trap fx_cleanup EXIT

mkident alice pki-admin; mkident bob pki-admin
fx_header "# Trust store push, hub to agent end to end (W40-03, gap P12)"
fx_build_and_db
mkdir -p "$FX_RUN/agent"
(cd "$FX_REPO" && GOOS=linux GOARCH="$(kk_goarch)" CGO_ENABLED=0 go build -o "$FX_RUN/agent/kryptkeeper-agent" ./cmd/kryptkeeper-agent) || DIE "agent build failed"
cp "$HERE/e2e-inner.sh" "$FX_RUN/agent/e2e-inner.sh"

STEP "1. start the real hub, enrol two real agents"
fx_start_hub -e KRYPTKEEPER_AGENT_ENROLLMENT_SECRETS=e2e-enrol-secret || DIE "hub did not start"
PASS "hub up at $HUBURL"
W="$FX_RUN/work"
AIDS=()
for i in 0 1; do
  r="$(curl -sS --cacert "$FX_RUN/tls-export/ca.pem" -X POST "$HUBURL/api/v1/agent/register" -H 'Content-Type: application/json' \
    -d "{\"name\":\"e2e-host-$i\",\"type\":\"linux\",\"enrollment_secret\":\"e2e-enrol-secret\"}")"
  aid="$(echo "$r" | jget 'd["agent_id"]')"; tok="$(echo "$r" | jget 'd["token"]')"
  [ -n "$aid" ] && [ -n "$tok" ] || DIE "register agent $i failed: $r"
  AIDS+=("$aid")
  podman run -d --name "${FX_PREFIX}-a$i" --network "$FX_NET" -v "$FX_RUN/agent:/work:ro" -v "$FX_RUN/tls-export:/hubca:ro" \
    -e HUB_URL="https://$FX_HUB:$FX_HUBPORT" -e AGENT_ID="$aid" -e AGENT_TOKEN="$tok" -e AGENT_NAME="e2e-host-$i" \
    "${IMAGES[$i]}" sh /work/e2e-inner.sh >/dev/null || DIE "start agent container $i"
done
for i in 0 1; do
  for _ in $(seq 1 180); do podman exec "${FX_PREFIX}-a$i" test -f /tmp/ready 2>/dev/null && break; sleep 2; done
  podman exec "${FX_PREFIX}-a$i" test -f /tmp/ready || { podman logs "${FX_PREFIX}-a$i" 2>&1 | tail -20; DIE "agent container $i never became ready"; }
  PASS "agent $i on ${IMAGES[$i]##*/} set up with the opt-in sudoers drop-in, running unprivileged (id ${AIDS[$i]})"
done
for _ in $(seq 1 30); do
  code "$T_alice" "$HUBURL/api/v1/agents" >/dev/null
  [ "$(jget 'len([a for a in d["agents"] if a["status"]=="active"])' <"$FX_RUN/last.json")" = 2 ] && break
  sleep 2
done
[ "$(jget 'len([a for a in d["agents"] if a["status"]=="active"])' <"$FX_RUN/last.json")" = 2 ] && PASS "hub shows both agents active" || FAIL "agents not active: $(head -c 300 "$FX_RUN/last.json")"

R_ID="$(code "$T_alice" "$HUBURL/api/v1/cas" >/dev/null; jget 'd["data"][0]["id"]' <"$FX_RUN/last.json")"
fx_template "$T_alice" || DIE "template"
SELECTOR="{\"agent_ids\":[\"${AIDS[0]}\",\"${AIDS[1]}\"]}"
trusted() { podman exec "${FX_PREFIX}-a$1" openssl verify "/work/$2" >/dev/null 2>&1; }
both() { # leaf want(yes|no)
  local i ok=1
  for i in 0 1; do
    if trusted "$i" "$1"; then [ "$2" = yes ] || ok=0; else [ "$2" = no ] || ok=0; fi
  done
  [ "$ok" = 1 ]
}
wait_both() { local n; for n in $(seq 1 45); do both "$1" "$2" && return 0; sleep 2; done; return 1; }
bundle_id() { # name, reads the list in $FX_RUN/last.json
  jget "[b['id'] for b in d['data'] if b['name']=='$1'][0]" <"$FX_RUN/last.json"
}
all_applied() { # bundle id
  local n
  for n in $(seq 1 45); do
    code "$T_alice" "$HUBURL/api/v1/trust-bundles/$1" >/dev/null
    [ "$(jget 'len([h for h in d["data"]["hosts"] if h["outcome"]=="applied"])' <"$FX_RUN/last.json")" = 2 ] && return 0
    sleep 2
  done
  return 1
}
bundle_body() { # name action root selector
  python3 -c "import json,sys; print(json.dumps({'name':sys.argv[1],'action':sys.argv[2],'cert_pem':open(sys.argv[3]).read(),'selector':json.loads(sys.argv[4]),'rationale':'e2e live'}))" "$@"
}
anchors() { # 0|1 yes|no
  local cmd='ls /usr/local/share/ca-certificates/kryptkeeper-*.crt'
  [ "$1" = 1 ] && cmd='ls /etc/pki/ca-trust/source/anchors/kryptkeeper-*.crt'
  podman exec "${FX_PREFIX}-a$1" sh -c "$cmd" >/dev/null 2>&1
}

# phase LABEL ROOT.pem LEAF.pem EXPECT_WARNING(yes|no)
phase() {
  local label="$1" root="$2" leaf="$3" warn="$4" aid bid nw
  STEP "$label"
  both "$leaf" no && PASS "leaf is untrusted on debian and rocky before the push" || FAIL "leaf already trusted before the push"
  check "alice proposes the add bundle" 202 "$(code "$T_alice" -X POST "$HUBURL/api/v1/trust-bundles" -d "$(bundle_body "$label add" add "$root" "$SELECTOR")")"
  aid="$(jget 'd["data"]["action_id"]' <"$FX_RUN/last.json")"
  [ "$(jget 'd["data"]["targets"]' <"$FX_RUN/last.json")" = 2 ] && PASS "proposal snapshots 2 target hosts" || FAIL "targets != 2"
  check "alice cannot approve her own proposal" 403 "$(code "$T_alice" -X POST "$HUBURL/api/v1/pending-actions/$aid/approve")"
  code "$T_alice" "$HUBURL/api/v1/trust-bundles" >/dev/null
  [ "$(jget 'len([b for b in d["data"] if b["name"]=="'"$label"' add"])' <"$FX_RUN/last.json")" = 0 ] && PASS "no bundle exists while the proposal is pending" || FAIL "bundle offered before approval"
  sleep 6
  both "$leaf" no && PASS "agents applied nothing while pending (leaf still untrusted)" || FAIL "trust changed before approval"
  check "bob approves" 200 "$(code "$T_bob" -X POST "$HUBURL/api/v1/pending-actions/$aid/approve")"
  code "$T_alice" "$HUBURL/api/v1/trust-bundles" >/dev/null; bid="$(bundle_id "$label add")"
  [ -n "$bid" ] && PASS "bundle $bid created after approval" || DIE "no bundle after approval"
  wait_both "$leaf" yes && PASS "openssl verify against the system store accepts the leaf on debian and rocky" || FAIL "leaf not trusted after the push (agent log: $(podman logs --tail 5 "${FX_PREFIX}-a0" 2>&1 | tr '\n' ' '))"
  all_applied "$bid" && PASS "hub per-host status: applied on both hosts" || FAIL "per-host status not applied: $(head -c 400 "$FX_RUN/last.json")"
  anchors 0 && PASS "debian anchor kryptkeeper-<sha256>.crt present" || FAIL "debian anchor missing"
  anchors 1 && PASS "rocky anchor kryptkeeper-<sha256>.crt present" || FAIL "rocky anchor missing"

  check "bob proposes the removal" 202 "$(code "$T_bob" -X POST "$HUBURL/api/v1/trust-bundles" -d "$(bundle_body "$label remove" remove "$root" "$SELECTOR")")"
  aid="$(jget 'd["data"]["action_id"]' <"$FX_RUN/last.json")"
  nw="$(jget 'len(d["data"].get("warnings") or [])' <"$FX_RUN/last.json")"
  if [ "$warn" = yes ]; then
    [ "$nw" -ge 1 ] && PASS "removal response carries the blast-radius warning: $(jget 'd["data"]["warnings"][0]' <"$FX_RUN/last.json")" || FAIL "no removal warning for a hub CA root with live certificates"
  else
    [ "$nw" = 0 ] && PASS "removal of a root no hub CA owns carries no warning" || FAIL "unexpected warning: $(head -c 300 "$FX_RUN/last.json")"
  fi
  check "bob cannot approve his own removal" 403 "$(code "$T_bob" -X POST "$HUBURL/api/v1/pending-actions/$aid/approve")"
  both "$leaf" yes && PASS "root still trusted while the removal is pending" || FAIL "removal took effect before approval"
  check "alice approves the removal" 200 "$(code "$T_alice" -X POST "$HUBURL/api/v1/pending-actions/$aid/approve")"
  code "$T_alice" "$HUBURL/api/v1/trust-bundles" >/dev/null; bid="$(bundle_id "$label remove")"
  wait_both "$leaf" no && PASS "leaf no longer trusted on debian and rocky after removal" || FAIL "leaf still trusted after removal"
  all_applied "$bid" && PASS "hub per-host status for the removal: applied on both hosts" || FAIL "removal status not applied: $(head -c 400 "$FX_RUN/last.json")"
  anchors 0 && FAIL "debian anchor remains" || PASS "debian anchor removed"
  anchors 1 && FAIL "rocky anchor remains" || PASS "rocky anchor removed"
}

# Phase 1: throwaway external root (its key is deleted right after it signs the leaf).
mkdir -p "$W"
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 2 -subj "/CN=KK E2E Throwaway Root" \
  -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign,cRLSign" -keyout "$W/t-root.key" -out "$W/t-root.pem" 2>/dev/null
openssl req -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -subj "/CN=leaf.e2e.test" -keyout "$W/t-leaf.key" -out "$W/t-leaf.csr" 2>/dev/null
printf 'subjectAltName=DNS:leaf.e2e.test\nbasicConstraints=CA:FALSE\n' >"$W/t-leaf.ext"
openssl x509 -req -in "$W/t-leaf.csr" -CA "$W/t-root.pem" -CAkey "$W/t-root.key" -CAcreateserial -days 1 -extfile "$W/t-leaf.ext" -out "$W/t-leaf.pem" 2>/dev/null
rm -f "$W/t-root.key" "$W/t-leaf.key"
cp "$W/t-leaf.pem" "$FX_RUN/agent/t-leaf.pem"
phase "throwaway-root" "$W/t-root.pem" t-leaf.pem no

# Phase 2: the hub's own root R and a leaf the hub issues from it.
code "$T_alice" "$HUBURL/api/v1/cas/$R_ID/chain?format=pem" >/dev/null; cp "$FX_RUN/last.json" "$W/R.pem"
[ "$(grep -c 'BEGIN CERTIFICATE' "$W/R.pem")" = 1 ] || DIE "root chain is not a single certificate"
check "hub issues a leaf from R" 201 "$(fx_issue "$T_alice" "$R_ID" hubleaf.e2e.test "$W/hubleaf")"
cp "$W/hubleaf.pem" "$FX_RUN/agent/hubleaf.pem"
phase "hub-root" "$W/R.pem" hubleaf.pem yes

STEP "summary"
say "windows and macOS legs: NOT RUN (out of scope; no keychain or trust-setting changes on this Mac)"
if [ "$FAILED" = 0 ]; then say "ALL STEPS PASSED"; else say "ONE OR MORE STEPS FAILED"; fi
exit "$FAILED"
