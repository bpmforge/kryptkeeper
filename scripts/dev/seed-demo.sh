#!/usr/bin/env bash
# Demo-data seed for a fresh Kryptkeeper hub, so a screenshot tour of every UI
# page shows realistic data. Public API only (no DB writes, no lab hardware).
#
# Usage:
#   BASE_URL=http://127.0.0.1:8080 TOKEN=<admin token> bash scripts/dev/seed-demo.sh
#
# Optional env:
#   LISTENER_PORTS   space-separated ports for the TLS listeners that discovery
#                    scans (default "18490 18491 18492 18493", bound to 127.0.0.1)
#   PIDFILE          where listener PIDs are recorded
#                    (default ${TMPDIR:-/tmp}/kk-seed-demo-listeners.pids)
#
# Hub settings that give the fullest tour (match docker-compose.yml defaults):
#   APP_NOTIFICATION_PROVIDER=delivery APP_DISCOVERY_PROVIDER=db
#   SPIFFE_TRUST_DOMAIN=<domain>   (enables Machine Identities; skipped otherwise)
# The file notification provider (the bare-binary default) serves three canned
# deliveries dated 2026-04-07, which look like real data in screenshots.
#
# Approval-gated requests (wildcard certs, code signing) stay pending: the
# bootstrap token may not approve. Approve a few as a named admin (signed in
# through /login) to fill the Code Signing page; leave some for the inbox.
#
# Safe to re-run: every create checks for an existing object first (by name,
# common name, key id, ...) and skips it. Private keys are generated in a temp
# dir that is removed on exit and are never written into the repo. Secrets
# returned by the API (API-key tokens, agent tokens, CMP secrets) are discarded.
#
# The openssl s_server listeners are left running on purpose (discovery needs
# something to scan). Their PIDs are printed and written to PIDFILE; stop them
# with: kill $(cat "$PIDFILE")
set -euo pipefail

BASE_URL="${BASE_URL:-http://127.0.0.1:8080}"
: "${TOKEN:?set TOKEN to an admin API token}"
API="$BASE_URL/api/v1"
LISTENER_PORTS="${LISTENER_PORTS:-18490 18491 18492 18493}"
PIDFILE="${PIDFILE:-${TMPDIR:-/tmp}/kk-seed-demo-listeners.pids}"

for bin in curl jq openssl python3 ssh-keygen; do
  command -v "$bin" >/dev/null || { echo "missing required tool: $bin" >&2; exit 2; }
done

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
LOG="$WORK/log"; : >"$LOG"
HTTP=000

say() { printf '\n== %s\n' "$*"; }
# record AREA OUTCOME [DETAIL]; outcomes: created exists failed
record() {
  printf '%s|%s|%s\n' "$1" "$2" "${3:-}" >>"$LOG"
  [ "$2" = created ] && echo "   + $1: ${3:-}" || true
}
SKIPS="$WORK/skips"; : >"$SKIPS"
skip() { printf '%s|%s\n' "$1" "$2" >>"$SKIPS"; }

# req METHOD PATH [JSON]  -> sets HTTP, body in $WORK/body
req() {
  local m="$1" p="$2" d="${3:-}"
  if [ -n "$d" ]; then
    HTTP=$(printf '%s' "$d" | curl -sS -o "$WORK/body" -w '%{http_code}' -X "$m" \
      -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
      --data-binary @- "$API$p") || HTTP=000
  else
    HTTP=$(curl -sS -o "$WORK/body" -w '%{http_code}' -X "$m" \
      -H "Authorization: Bearer $TOKEN" "$API$p") || HTTP=000
  fi
}
ok2xx() { [ "${HTTP:0:1}" = 2 ]; }
# Error text only (never the body of a 2xx, which can carry secrets).
errmsg() { jq -r '.message // .error // empty' "$WORK/body" 2>/dev/null | head -c 220; }
fail() { record "$1" failed "$2: HTTP $HTTP $(errmsg)"; echo "   FAILED $1 ($2): HTTP $HTTP $(errmsg)" >&2; }

# has_name PATH NAME : does any object in the GET PATH response carry .name == NAME
has_name() {
  req GET "$1"
  ok2xx && jq -e --arg n "$2" '[.. | objects | .name? // empty] | index($n) != null' "$WORK/body" >/dev/null 2>&1
}
# has_field PATH FIELD VALUE
has_field() {
  req GET "$1"
  ok2xx && jq -e --arg f "$2" --arg v "$3" '[.. | objects | .[$f]? // empty] | index($v) != null' "$WORK/body" >/dev/null 2>&1
}
# ensure AREA LISTPATH NAME CREATEPATH JSON : create unless a same-named object exists
ensure() {
  local area="$1" list="$2" name="$3" cpath="$4" body="$5"
  if has_name "$list" "$name"; then record "$area" exists "$name"; return 0; fi
  req POST "$cpath" "$body"
  if ok2xx; then record "$area" created "$name"; else fail "$area" "$name"; return 1; fi
}
id_of() { # LISTPATH NAME -> id of first object with that name
  req GET "$1"
  jq -r --arg n "$2" '[.. | objects | select(.name? == $n) | .id // empty][0] // empty' "$WORK/body"
}

# load_certs : snapshot the certificate list so later POSTs (which overwrite
# $WORK/body) do not invalidate lookups.
load_certs() { req GET '/certificates?limit=100'; cp "$WORK/body" "$WORK/certs.json"; }
cert_fp() { jq -r --arg c "$1" '[.data[]|select(.common_name==$c)][0].fingerprint_sha256 // empty' "$WORK/certs.json"; }

req GET /templates
ok2xx || { echo "hub not reachable or token rejected at $API (HTTP $HTTP)" >&2; exit 1; }
echo "seeding $BASE_URL"

# ---------------------------------------------------------------- templates
say "certificate templates"
tpl() { # name display validity eku(json array) algs(json array) [extra json object merged]
  local extra="${6:-{\}}"
  jq -nc --arg n "$1" --arg d "$2" --arg v "$3" --argjson eku "$4" --argjson algs "$5" --argjson x "$extra" \
    '{name:$n,display_name:$d,validity_period:$v,key_usage:["digitalSignature","keyEncipherment"],
      extended_key_usage:$eku,allowed_algorithms:$algs,active:true} + $x'
}
ensure templates /templates web-server-90d /templates "$(tpl web-server-90d 'Web Server (90 day)' 90d '["serverAuth"]' '["ECDSA","RSA"]')" || true
ensure templates /templates client-auth-internal /templates "$(tpl client-auth-internal 'Internal Client Auth (20 day)' 20d '["clientAuth"]' '["ECDSA"]')" || true
ensure templates /templates svc-short-7d /templates "$(tpl svc-short-7d 'Short-lived Service (7 day)' 7d '["serverAuth","clientAuth"]' '["ECDSA"]')" || true
ensure templates /templates code-signing-1y /templates "$(tpl code-signing-1y 'Code Signing (1 year)' 365d '["codeSigning"]' '["ECDSA","RSA"]')" || true
ensure templates /templates ssh-access /templates "$(tpl ssh-access 'SSH Access (user + host)' 1d '["clientAuth"]' '["ECDSA"]' \
  '{"ssh_policy":{"cert_types":["user","host"],"max_ttl_hours":24,"allowed_principals":["deploy","ops"],"host_patterns":["*.acme.test"]}}')" || true
ensure templates /templates prod-wildcard-approval /templates "$(tpl prod-wildcard-approval 'Production Wildcard (needs approval)' 90d '["serverAuth"]' '["ECDSA","RSA"]' \
  '{"require_approval":true,"approval_roles":["approver"]}')" || true

tpl_id() { id_of /templates "$1"; }
T_WEB="$(tpl_id web-server-90d)"; T_CLIENT="$(tpl_id client-auth-internal)"; T_SHORT="$(tpl_id svc-short-7d)"
T_CODE="$(tpl_id code-signing-1y)"; T_SSH="$(tpl_id ssh-access)"; T_APPR="$(tpl_id prod-wildcard-approval)"

# ---------------------------------------------------------------- CAs
say "certificate authorities"
req GET /cas
ROOT_ID="$(jq -r '[.data[] | select(.type=="root" and .status=="active")][0].id // empty' "$WORK/body")"
[ -n "$ROOT_ID" ] || { echo "no active root CA to chain under" >&2; exit 1; }
ensure_ca() { # name algorithm
  if has_name /cas "$1"; then record cas exists "$1"; return 0; fi
  req POST /cas "$(jq -nc --arg n "$1" --arg a "$2" --arg p "$ROOT_ID" \
    '{name:$n,type:"intermediate",algorithm:$a,subject_cn:$n,parent_ca_id:$p}')"
  if ok2xx; then record cas created "$1"; else fail cas "$1"; fi
}
ensure_ca "Acme Issuing CA" ECDSA-P256
ensure_ca "Acme Internal Services CA" ECDSA-P384
CA_ISSUING="$(id_of /cas 'Acme Issuing CA')"; CA_INTERNAL="$(id_of /cas 'Acme Internal Services CA')"

# ---------------------------------------------------------------- policies
say "issuance policy"
# CA-scoped so it cannot disturb issuance from the other CAs.
ensure policies /policies "Internal Services: ECDSA only, 30d max" /policies "$(jq -nc --arg ca "$CA_INTERNAL" \
  '{name:"Internal Services: ECDSA only, 30d max",enabled:true,ca_id:$ca,
    rules:{allowed_algorithms:["ECDSA-P256","ECDSA-P384"],max_validity_days:30}}')" || true

# ---------------------------------------------------------------- managed certs
say "managed certificates (issued via CSR)"
req GET '/certificates?limit=100'
jq -r '.data[].common_name' "$WORK/body" | sort -u >"$WORK/have_cns"
issue_cert() { # cn alg template_id ca_id team [extra_san...]
  local cn="$1" alg="$2" tpl="$3" ca="$4" team="$5"; shift 5
  if grep -qxF "$cn" "$WORK/have_cns"; then record certificates exists "$cn"; return 0; fi
  local san="DNS:$cn" s; for s in "$@"; do san="$san,DNS:$s"; done
  local ks=()
  case "$alg" in
    ec256) ks=(-newkey ec -pkeyopt ec_paramgen_curve:P-256) ;;
    ec384) ks=(-newkey ec -pkeyopt ec_paramgen_curve:P-384) ;;
    rsa3072) ks=(-newkey rsa:3072) ;;
    rsa4096) ks=(-newkey rsa:4096) ;;
  esac
  openssl req -new "${ks[@]}" -nodes -keyout "$WORK/k.pem" -subj "/CN=$cn/O=Acme Corp" \
    -addext "subjectAltName=$san" -out "$WORK/c.csr" 2>/dev/null
  req POST /certificates "$(jq -nc --arg ca "$ca" --arg t "$tpl" --arg team "$team" --rawfile c "$WORK/c.csr" \
    '{ca_id:$ca,template_id:$t,csr_pem:$c} + (if $team=="" then {} else {team_id:$team} end)')"
  rm -f "$WORK/k.pem"
  if ok2xx; then record certificates created "$cn"; echo "$cn" >>"$WORK/have_cns"; else fail certificates "$cn"; fi
}
# Web tier: cn|alg|team|extra SAN. RSA-2048 is not issued: the built-in Baseline
# policy (min_rsa_bits 3072) rejects it, which is the product working as intended.
while IFS='|' read -r cn alg team san; do
  [ -n "$cn" ] || continue
  issue_cert "$cn" "$alg" "$T_WEB" "$CA_ISSUING" "$team" ${san:+"$san"}
done <<'EOF'
api.acme.test|ec256|platform|api-internal.acme.test
payments.acme.test|rsa3072|payments|pay.acme.test
www.acme.test|ec256|web|acme.test
shop.acme.test|ec256|web|
auth.acme.test|rsa4096|identity|login.acme.test
grafana.acme.test|ec256|sre|
vault.acme.test|ec384|security|
git.acme.test|ec256|platform|
jenkins.acme.test|rsa3072|platform|
registry.acme.test|ec256|platform|
docs.acme.test|ec256|web|
status.acme.test|ec256|sre|
cdn-edge.acme.test|ec256|web|assets.acme.test
mail.acme.test|rsa3072|it|smtp.acme.test
search.acme.test|ec256|data|
billing.acme.test|rsa3072|payments|
staging-api.acme.test|ec256|platform|
old-reports.acme.test|rsa3072|data|
EOF
# Internal client-auth (20d -> shows as expiring within 30 days) and 7d services.
while IFS='|' read -r cn alg team; do
  [ -n "$cn" ] || continue
  issue_cert "$cn" "$alg" "$T_CLIENT" "$CA_INTERNAL" "$team"
done <<'EOF'
ledger-sync.svc.acme.test|ec256|payments
etl-runner.svc.acme.test|ec384|data
vpn-gateway.svc.acme.test|ec256|it
build-agent.svc.acme.test|ec256|platform
EOF
while IFS='|' read -r cn alg team; do
  [ -n "$cn" ] || continue
  issue_cert "$cn" "$alg" "$T_SHORT" "$CA_INTERNAL" "$team"
done <<'EOF'
checkout-v2.svc.acme.test|ec256|payments
feature-flags.svc.acme.test|ec256|platform
ml-inference.svc.acme.test|ec384|data
canary.svc.acme.test|ec256|sre
notifier.svc.acme.test|ec256|platform
EOF

# Revoke three, each with a different reason (RFC 5280 reason codes).
say "revocations"
revoke() { # cn code text
  load_certs
  local fp rev
  fp="$(cert_fp "$1")"
  [ -n "$fp" ] || { record revocations failed "$1: not found"; return; }
  rev="$(jq -r --arg c "$1" '[.data[]|select(.common_name==$c)][0] | ((.revoked_at // "") != "")' "$WORK/certs.json")"
  if [ "$rev" = true ]; then record revocations exists "$1"; return; fi
  req POST "/certificates/$fp/revoke" "$(jq -nc --argjson c "$2" --arg t "$3" '{reason_code:$c,reason_text:$t}')"
  if ok2xx; then record revocations created "$1"; else fail revocations "$1"; fi
}
revoke jenkins.acme.test 1 "Private key exposed in a build log"
revoke staging-api.acme.test 4 "Superseded by the production API certificate"
revoke old-reports.acme.test 5 "Reporting service decommissioned"

# ---------------------------------------------------------------- approvals (pending)
say "pending approvals"
# Templates with require_approval (the built-in code-signing rule included) answer
# POST /certificates with 202 and park the request in the approvals inbox. The
# inbox summary carries the template id, so that is what idempotency keys on.
request_approvals() { # template_id label cn...
  local tid="$1" label="$2"; shift 2
  req GET /approvals/inbox
  local have; have="$(jq --arg t "$tid" '[.data[]|select(.type=="certificate_approval" and (.summary|contains($t)))]|length' "$WORK/body")"
  if [ "$have" -ge "$#" ]; then record approvals exists "$label requests ($have pending)"; return 0; fi
  local cn
  for cn in "$@"; do
    openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout /dev/null \
      -subj "/CN=$cn" -addext "subjectAltName=DNS:$cn" -out "$WORK/w.csr" 2>/dev/null
    req POST /certificates "$(jq -nc --arg ca "$CA_ISSUING" --arg t "$tid" --rawfile c "$WORK/w.csr" \
      '{ca_id:$ca,template_id:$t,csr_pem:$c,team_id:"security"}')"
    if [ "$HTTP" = 202 ]; then record approvals created "$label: $cn"; else fail approvals "$label: $cn"; fi
  done
}
request_approvals "$T_APPR" "production wildcard" '*.prod.acme.test' '*.eu.acme.test'
request_approvals "$T_CODE" "code signing" release-signing.acme.test installer-signing.acme.test
req GET /pending-actions
if jq -e '[.data[]|select(.action_type=="codesign.oidc_trust_rule")]|length>0' "$WORK/body" >/dev/null 2>&1; then
  record approvals exists "codesign OIDC trust rule"
else
  req POST /codesign/oidc-trust-rules "$(jq -nc --arg ca "$CA_ISSUING" \
    '{provider:"github",issuer:"https://token.actions.githubusercontent.com",audience:"kryptkeeper",
      repo_pattern:"acme/*",ref_pattern:"refs/tags/v*",ca_id:$ca,rationale:"Release signing from tagged builds"}')"
  [ "$HTTP" = 202 ] && record approvals created "codesign OIDC trust rule" || fail approvals "codesign OIDC trust rule"
fi

# ---------------------------------------------------------------- external certs
say "external certificates (bulk import)"
X="$WORK/x"; mkdir -p "$X"; cd "$X"
gen_ca() {
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout lca.key -out lca.crt \
    -subj "/CN=Legacy Corp Issuing CA/O=Legacy Corp" -days 3650 \
    -addext basicConstraints=critical,CA:TRUE -addext keyUsage=keyCertSign,cRLSign 2>/dev/null
}
# chained NAME BITS NOTBEFORE NOTAFTER : leaf signed by the throwaway Legacy CA
chained() {
  openssl req -newkey "rsa:$2" -nodes -keyout "$1.key" -subj "/CN=$1" -addext "subjectAltName=DNS:$1" -out "$1.csr" 2>/dev/null
  openssl x509 -req -in "$1.csr" -CA lca.crt -CAkey lca.key -CAcreateserial -not_before "$3" -not_after "$4" \
    -copy_extensions copy -out "$1.crt" 2>/dev/null
}
selfsigned() { # CN KEYSPEC... -- extra req args
  local cn="$1"; shift
  openssl req -x509 -nodes -keyout "$cn.key" -out "$cn.crt" -subj "/CN=$cn" -addext "subjectAltName=DNS:$cn" "$@" 2>/dev/null
}
gen_ca
NOW_PLUS_400="$(date -u -v+400d +%Y%m%d%H%M%SZ 2>/dev/null || date -u -d '+400 days' +%Y%m%d%H%M%SZ)"
NOW_MINUS_30="$(date -u -v-30d +%Y%m%d%H%M%SZ 2>/dev/null || date -u -d '-30 days' +%Y%m%d%H%M%SZ)"
chained intranet.legacy.test 2048 20240101000000Z 20250101000000Z      # expired, chained
chained hr-portal.legacy.test 2048 "$NOW_MINUS_30" "$NOW_PLUS_400"
chained erp.legacy.test 3072 "$NOW_MINUS_30" "$NOW_PLUS_400"
selfsigned dev-portal.acme.test -newkey ec -pkeyopt ec_paramgen_curve:P-256 -days 365
selfsigned lab-switch.acme.test -newkey rsa:2048 -days 3650
selfsigned exp-self.legacy.test -newkey rsa:2048 -not_before 20230101000000Z -not_after 20240101000000Z   # expired
selfsigned metrics-sandbox.acme.test -newkey ec -pkeyopt ec_paramgen_curve:P-256 -days 12                  # expiring soon
openssl req -x509 -newkey rsa:1024 -sha1 -nodes -keyout old-printer.legacy.test.key -out old-printer.legacy.test.crt \
  -subj "/CN=old-printer.legacy.test" -days 3650 2>/dev/null                                                # weak: RSA-1024 + SHA-1
# The throwaway Legacy CA is regenerated each run, so fingerprints differ every
# time; idempotency is therefore by common name, checked before importing.
load_certs
import_bundle() { # label owner_team owner_email service files...
  local label="$1" team="$2" email="$3" svc="$4"; shift 4
  local f missing=0
  for f in "$@"; do
    [ "$f" = lca.crt ] && continue
    [ -n "$(cert_fp "${f%.crt}")" ] || missing=1
  done
  if [ "$missing" = 0 ]; then record external exists "$label"; return 0; fi
  cat "$@" >"$WORK/bundle.pem"
  req POST /certificates/bulk-import "$(jq -nc --rawfile b "$WORK/bundle.pem" --arg t "$team" --arg e "$email" --arg s "$svc" \
    '{format:"pem",bundle:$b} + (if $t=="" then {} else {owner_team:$t,owner_email:$e,service_name:$s} end)')"
  if ok2xx; then
    record external created "$label: imported $(jq -r '.data.imported' "$WORK/body"), duplicates $(jq -r '.data.skipped_duplicates' "$WORK/body")"
  else fail external "$label"; fi
}
import_bundle "legacy estate (owned)" legacy-ops legacy-ops@acme.test legacy-intranet \
  intranet.legacy.test.crt hr-portal.legacy.test.crt erp.legacy.test.crt lca.crt old-printer.legacy.test.crt
import_bundle "unowned self-signed" "" "" "" dev-portal.acme.test.crt lab-switch.acme.test.crt \
  exp-self.legacy.test.crt metrics-sandbox.acme.test.crt
cd "$WORK"

# Take over two of the imported certs so the estate shows them as managed.
say "estate takeover"
load_certs
for cn in hr-portal.legacy.test erp.legacy.test; do
  fp="$(cert_fp "$cn")"; [ -n "$fp" ] || continue
  st="$(jq -r --arg c "$cn" '[.data[]|select(.common_name==$c)][0].management_state // ""' "$WORK/certs.json")"
  if [ "$st" != unmanaged ]; then record takeover exists "$cn ($st)"; continue; fi
  req POST /estate/takeover "$(jq -nc --arg f "$fp" --arg s "${cn%%.*}" \
    '{fingerprint:$f,owner_email:"legacy-ops@acme.test",owner_team:"legacy-ops",service_name:$s,renewal_path:{mode:"internal"}}')"
  if ok2xx; then record takeover created "$cn"; else fail takeover "$cn"; fi
done

# ---------------------------------------------------------------- ADCS export -> externally managed
say "inventory source sync (externally-managed certificates)"
# The hub reads export_path from ITS filesystem, so this only works when the hub
# shares this machine's filesystem (local dev). Only public certificates are
# written there, never keys. A run is skipped once the source has synced.
SRC_NAME="ADCS enterprise CA export (demo)"
ADCS_DIR="${SEED_ADCS_DIR:-${TMPDIR:-/tmp}/kk-seed-adcs-export}"
req GET /inventory-sources
if jq -e --arg n "$SRC_NAME" '[.data[]|select(.name==$n and ((.last_sync_at // .last_synced_at // "") != ""))]|length>0' "$WORK/body" >/dev/null; then
  record inventory-sources exists "$SRC_NAME (already synced)"
else
  mkdir -p "$ADCS_DIR"; E="$WORK/adcs"; mkdir -p "$E"; cd "$E"
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-384 -nodes -keyout eca.key -out eca.crt \
    -subj "/CN=Contoso Enterprise CA/O=Contoso" -days 3650 -addext basicConstraints=critical,CA:TRUE \
    -addext keyUsage=keyCertSign,cRLSign 2>/dev/null
  for h in fileserver01 sql-prod-02 exchange-ca1 sharepoint wsus-core; do
    openssl req -newkey rsa:2048 -nodes -keyout "$h.key" -subj "/CN=$h.contoso.test" \
      -addext "subjectAltName=DNS:$h.contoso.test" -out "$h.csr" 2>/dev/null
    days=730; [ "$h" = wsus-core ] && days=9
    openssl x509 -req -in "$h.csr" -CA eca.crt -CAkey eca.key -CAcreateserial -days "$days" \
      -copy_extensions copy -out "$ADCS_DIR/$h.crt" 2>/dev/null
  done
  cd "$WORK"
  req POST /inventory-sources "$(jq -nc --arg n "$SRC_NAME" --arg p "$ADCS_DIR" \
    '{name:$n,type:"adcs_export",config_json:({export_path:$p}|tojson)}')"
  if ok2xx || [ "$HTTP" = 409 ]; then
    sid="$(id_of /inventory-sources "$SRC_NAME")"
    req POST "/inventory-sources/$sid/sync"
    if ok2xx; then record inventory-sources created "$SRC_NAME synced: $(jq -c '.data // .' "$WORK/body" | head -c 120)"
    else fail inventory-sources "sync (hub may not share this filesystem)"; fi
  else fail inventory-sources "$SRC_NAME"; fi
fi

# ---------------------------------------------------------------- listeners + discovery
say "TLS listeners and discovery scans"
read -r -a PORTS <<<"$LISTENER_PORTS"
NEW_LISTENERS=0
port_open() { (exec 3<>"/dev/tcp/127.0.0.1/$1") 2>/dev/null; }
start_listener() { # port certfile keyfile [chainfile] ; leaves the process running
  local port="$1" cert="$2" key="$3" chain="${4:-}"
  local args=(-accept "127.0.0.1:$port" -cert "$cert" -key "$key" -quiet -cipher 'DEFAULT:@SECLEVEL=0')
  [ -n "$chain" ] && args+=(-cert_chain "$chain")
  nohup openssl s_server "${args[@]}" </dev/null >/dev/null 2>&1 &
  local pid=$!; sleep 0.6
  if kill -0 "$pid" 2>/dev/null && port_open "$port"; then
    NEW_LISTENERS=1; echo "$pid" >>"$PIDFILE"; echo "   listener 127.0.0.1:$port pid $pid"; return 0
  fi
  return 1
}
L="$WORK/l"; mkdir -p "$L"; touch "$PIDFILE"
# Each listener is started only if its port is free, so a re-run after one died
# restores just that one.
if ! port_open "${PORTS[0]}"; then
  # 1: hub-issued (managed) cert; the key never leaves this temp dir
  P="${PORTS[0]}"
  openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout "$L/e.key" \
    -subj "/CN=edge-lb.acme.test/O=Acme Corp" -addext "subjectAltName=DNS:edge-lb.acme.test" -out "$L/e.csr" 2>/dev/null
  req POST /certificates "$(jq -nc --arg ca "$CA_ISSUING" --arg t "$T_WEB" --rawfile c "$L/e.csr" '{ca_id:$ca,template_id:$t,csr_pem:$c,team_id:"sre"}')"
  if ok2xx; then
    efp="$(jq -r '.data.fingerprint_sha256' "$WORK/body")"
    curl -fsS -H "Authorization: Bearer $TOKEN" "$API/certificates/$efp/download?format=pem&include_chain=true" -o "$L/e.crt" || true
    if [ -s "$L/e.crt" ] && start_listener "$P" "$L/e.crt" "$L/e.key"; then
      record listeners created "port $P hub-issued edge-lb.acme.test"
    else record listeners failed "port $P: could not download the issued certificate or start s_server"; fi
  else fail listeners "issue edge-lb cert"; fi
fi
if ! port_open "${PORTS[1]}"; then  # 2: expired, chained to a private CA
  start_listener "${PORTS[1]}" "$X/intranet.legacy.test.crt" "$X/intranet.legacy.test.key" "$X/lca.crt" \
    && record listeners created "port ${PORTS[1]} expired (intranet.legacy.test)" || fail listeners "port ${PORTS[1]}"
fi
if ! port_open "${PORTS[2]}"; then  # 3: self-signed, valid
  start_listener "${PORTS[2]}" "$X/dev-portal.acme.test.crt" "$X/dev-portal.acme.test.key" \
    && record listeners created "port ${PORTS[2]} self-signed (dev-portal.acme.test)" || fail listeners "port ${PORTS[2]}"
fi
if ! port_open "${PORTS[3]}"; then  # 4: weak RSA-1024 / SHA-1
  start_listener "${PORTS[3]}" "$X/old-printer.legacy.test.crt" "$X/old-printer.legacy.test.key" \
    && record listeners created "port ${PORTS[3]} weak (old-printer.legacy.test)" || fail listeners "port ${PORTS[3]} (weak cert refused by this openssl build)"
fi
req GET /discovery/endpoints
if [ "$NEW_LISTENERS" = 0 ] && [ "$(jq '[.data.endpoints[]?|select(.hostname=="127.0.0.1")]|length' "$WORK/body")" -ge "${#PORTS[@]}" ] \
   && jq -e '[.data.endpoints[]?.mapped_certs[]?|select(.common_name=="edge-lb.acme.test")]|length>0' "$WORK/body" >/dev/null; then
  record discovery exists "${#PORTS[@]} endpoints already discovered"
else
  portsjson="$(printf '%s\n' "${PORTS[@]}" | jq -sc 'map(tonumber)')"
  req POST /discovery/scans "$(jq -nc --argjson p "$portsjson" '{scan_type:"targeted",target:"127.0.0.1",ports:$p}')"
  if ok2xx; then
    job="$(jq -r '.data.scan_job.id' "$WORK/body")"; st=running
    for _ in $(seq 1 30); do
      req GET /discovery/scan-jobs
      st="$(jq -r --arg j "$job" '[.data.scan_jobs[]|select(.id==$j)][0].status // "unknown"' "$WORK/body")"
      case "$st" in completed|failed|cancelled) break ;; esac; sleep 1
    done
    if [ "$st" = completed ]; then
      req GET /discovery/endpoints
      record discovery created "scan $job completed, $(jq '.data.endpoints|length' "$WORK/body") endpoints"
    else record discovery failed "scan $job ended as $st"; fi
  else fail discovery "targeted scan"; fi
fi

# ---------------------------------------------------------------- everything else
say "users, roles, API keys"
for u in "priya.nair@acme.test|pki-operator" "marcus.webb@acme.test|approver" "lena.okafor@acme.test|auditor" "dev.rao@acme.test|viewer"; do
  e="${u%%|*}"; r="${u##*|}"
  if has_field /users email "$e"; then record users exists "$e"; continue; fi
  req POST /users/invite "$(jq -nc --arg e "$e" --arg r "$r" '{email:$e,role:$r}')"
  ok2xx && record users created "$e" || fail users "$e"
done
req GET /roles
if jq -e '[.data[]|select(.name=="cert-owner-readonly")]|length>0' "$WORK/body" >/dev/null; then record roles exists cert-owner-readonly
else
  req POST /roles '{"name":"cert-owner-readonly","description":"Service owners: view certificates and reports","permissions":["certificate.read","report.read"]}'
  ok2xx && record roles created cert-owner-readonly || fail roles cert-owner-readonly
fi
req GET /api-keys
if jq -e '[.data[]|select(.name=="ci-deploy-bot")]|length>0' "$WORK/body" >/dev/null; then record api-keys exists ci-deploy-bot
else
  req POST /api-keys '{"name":"ci-deploy-bot","principal_id":"svc-ci","role":"service-account","scopes":["certificate.read"]}'
  if ok2xx; then record api-keys created "ci-deploy-bot (token discarded)"
  elif [ "$HTTP" = 503 ] && grep -q APP_API_KEY_PEPPER "$WORK/body"; then
    skip "api-keys ci-deploy-bot" "hub has API-key minting off (set APP_API_KEY_PEPPER + APP_API_KEY_AUTH_ENABLED=true)"
  else fail api-keys ci-deploy-bot; fi
fi

say "notifications, ITSM, reports, ownership"
ensure notifications /notifications/rules "Expiry 30d to PKI team" /notifications/rules \
  '{"name":"Expiry 30d to PKI team","threshold_days":30,"channel":"email","target":"pki-team@acme.test"}' || true
ensure notifications /notifications/rules "Expiry 7d page on-call" /notifications/rules \
  '{"name":"Expiry 7d page on-call","threshold_days":7,"channel":"pagerduty","target":"oncall-pki"}' || true
req GET /notifications/team-routes
if jq -e '[.. | objects | select(.owner_team?=="payments")]|length>0' "$WORK/body" >/dev/null; then record notifications exists "team route payments"
else
  req POST /notifications/team-routes '{"owner_team":"payments","channel":"slack","target":"https://hooks.example.test/payments"}'
  ok2xx && record notifications created "team route payments" || fail notifications "team route payments"
fi
load_certs; FP_SIL="$(cert_fp intranet.legacy.test)"
if [ -n "$FP_SIL" ]; then
  req GET "/notifications/silences?target_type=certificate&target_id=$FP_SIL"
  if jq -e '[.. | objects | select(.id? // "" | startswith("sil-"))]|length>0' "$WORK/body" >/dev/null 2>&1; then record notifications exists "silence intranet.legacy.test"
  else
    req POST /notifications/silences "$(jq -nc --arg f "$FP_SIL" '{target_type:"certificate",target_id:$f}')"
    ok2xx && record notifications created "silence intranet.legacy.test" || fail notifications "silence"
  fi
fi
ensure credentials /credentials demo-jira-token /credentials '{"name":"demo-jira-token","credential_type":"api_token","payload":{"token":"demo-not-a-real-token"}}' || true
CRED_ID="$(id_of /credentials demo-jira-token)"
ensure itsm /itsm/connections "Acme Jira (demo)" /itsm/connections \
  '{"kind":"jira","name":"Acme Jira (demo)","base_url":"https://jira.example.test","credential_ref":"'"$CRED_ID"'","event_classes":[{"class":"renewal_failed","ticket_type":"Incident"},{"class":"approval_pending","ticket_type":"Task"}],"enabled":false}' || true
req GET /reports/schedules
if jq -e '[.. | objects | select(.report?=="executive-summary")]|length>0' "$WORK/body" >/dev/null; then record reports exists "weekly executive summary"
else
  req POST /reports/schedules '{"report":"executive-summary","format":"pdf","cadence":"weekly","recipients":["ciso@acme.test"],"enabled":true}'
  ok2xx && record reports created "weekly executive summary" || fail reports "executive summary schedule"
fi
req GET /team-policies
if jq -e '[.. | objects | select(.team?=="payments")]|length>0' "$WORK/body" >/dev/null; then record team-policies exists payments
else
  req POST /team-policies '{"team":"payments","allowed_dns_suffixes":["acme.test"],"max_validity_days":90,"monthly_quota":50}'
  ok2xx && record team-policies created payments || fail team-policies payments
fi
load_certs
if [ "$(jq -r '[.data[]|select(.common_name=="api.acme.test")][0].owner_team // ""' "$WORK/certs.json")" = platform ]; then
  record ownership exists "CMDB ownership rules"
else
req POST /ownership/cmdb-import '{"rules":[{"match":"host","value":"api.acme.test","owner_team":"platform","owner_email":"platform@acme.test"},{"match":"host","value":"payments.acme.test","owner_team":"payments","owner_email":"payments@acme.test"}]}'
ok2xx && record ownership created "CMDB ownership rules" || fail ownership cmdb-import
fi

say "targets, groups, protocols, connectors, sources"
for t in "web-01|web-01.acme.test|ssh" "web-02|web-02.acme.test|ssh" "lb-edge|lb-edge.acme.test|f5"; do
  IFS='|' read -r n h m <<<"$t"
  ensure targets /targets "$n" /targets "$(jq -nc --arg n "$n" --arg h "$h" --arg m "$m" \
    '{name:$n,host:$h,discovery_mode:"none",install_mode:$m,renewal_method:"manual",renewal_threshold_days:30}')" || true
done
TG_IDS="$(req GET /targets; jq -c '[.data[].id]' "$WORK/body")"
if has_name /target-groups prod-web; then record target-groups exists prod-web
else
  req PUT /target-groups/prod-web "$(jq -nc --argjson ids "$TG_IDS" '{renewal_threshold_days:21,target_ids:$ids}')"
  ok2xx && record target-groups created prod-web || fail target-groups prod-web
fi
ensure acme /acme/provisioners internal-acme /acme/provisioners "$(jq -nc --arg ca "$CA_ISSUING" \
  '{name:"internal-acme",ca_id:$ca,allow_names:["*.acme.test"],challenges:["http-01","dns-01"]}')" || true
req GET /acme/eab-keys
if jq -e '[.. | objects | select(.label?=="cert-manager")]|length>0' "$WORK/body" >/dev/null; then record acme exists "EAB key cert-manager"
else
  req POST /acme/eab-keys '{"label":"cert-manager","provisioner":"internal-acme"}'
  ok2xx && record acme created "EAB key cert-manager (HMAC discarded)" || fail acme "EAB key"
fi
req GET /est/users
if jq -e '[.. | objects | select(.username?=="est-devices")]|length>0' "$WORK/body" >/dev/null; then record est exists est-devices
else
  req POST /est/users '{"username":"est-devices","allowed_dns_suffixes":[".devices.acme.test"]}'
  ok2xx && record est created "est-devices (password discarded)" || fail est est-devices
fi
req GET /cmp/credentials
if jq -e '[.. | objects | select(.label?=="demo-cmp")]|length>0' "$WORK/body" >/dev/null; then record cmp exists demo-cmp
else
  req POST /cmp/credentials '{"kind":"pbm","label":"demo-cmp","allowed_dns_suffixes":[".devices.acme.test"]}'
  ok2xx && record cmp created "demo-cmp (secret discarded)" || fail cmp demo-cmp
fi
ensure connectors /connectors internal-connector /connectors '{"name":"internal-connector","type":"internal"}' || true
req GET /agent/enrollment-tokens
if jq -e '[.. | objects | select(.label?=="datacenter-a")]|length>0' "$WORK/body" >/dev/null; then record agents exists "enrollment token datacenter-a"
else
  req POST /agent/enrollment-tokens '{"label":"datacenter-a","ttl_seconds":604800}'
  ok2xx && record agents created "enrollment token datacenter-a (token discarded)" || fail agents "enrollment token"
fi
req GET /agents
if ! jq -e '[.agents[]?|select(.name=="web-01.acme.test")]|length>0' "$WORK/body" >/dev/null; then
  req POST /agent/enrollment-tokens '{"label":"seed-agent","ttl_seconds":600}'
  tok="$(jq -r '.data.token // empty' "$WORK/body")"
  req POST /agent/register "$(jq -nc --arg t "$tok" '{name:"web-01.acme.test",type:"linux",enrollment_token:$t}')"
  ok2xx && record agents created "agent web-01.acme.test (offline; token discarded)" || fail agents "agent register"
else record agents exists "agent web-01.acme.test"; fi

say "SSH CA certificates"
ssh-keygen -q -t ed25519 -N '' -C demo -f "$WORK/ssh_demo" >/dev/null
req GET /ssh/certificates
for s in "alice@acme.test|user|deploy" "bastion.acme.test|host|bastion.acme.test"; do
  IFS='|' read -r kid ct pr <<<"$s"
  if jq -e --arg k "$kid" '[.data[]|select(.key_id==$k)]|length>0' "$WORK/body" >/dev/null; then record ssh exists "$kid"; continue; fi
  req POST /ssh/certificates "$(jq -nc --arg t "$T_SSH" --arg k "$(cat "$WORK/ssh_demo.pub")" --arg kid "$kid" --arg ct "$ct" --arg p "$pr" \
    '{template_id:$t,public_key:$k,cert_type:$ct,key_id:$kid,principals:[$p],ttl_hours:8}')"
  ok2xx && record ssh created "$kid ($ct)" || fail ssh "$kid"
  req GET /ssh/certificates
done

say "governance: ceremonies, access review, PQC wave, exceptions, keys"
req GET /ceremonies
if jq -e '[.data[]?|select(.ca_name=="Root renewal 2026")]|length>0' "$WORK/body" >/dev/null 2>&1; then record ceremonies exists "Root renewal 2026"
else
  req POST /ceremonies '{"name":"Root renewal 2026","common_name":"Acme Root R2","algorithm":"ECDSA-P384","validity_days":3650,"approvers":["alice","bob","carol"],"quorum":2}'
  ok2xx && record ceremonies created "Root renewal 2026 (pending, 0/2 approvals)" || fail ceremonies "Root renewal 2026"
fi
req GET /admin/access-review/campaigns
if jq -e '[.data.items[]?|select(.name=="Q4 access review")]|length>0' "$WORK/body" >/dev/null 2>&1; then record access-review exists "Q4 access review"
else
  req POST /admin/access-review/campaigns '{"name":"Q4 access review","period_days":30}'
  ok2xx && record access-review created "Q4 access review" || fail access-review campaign
fi
ensure pqc-waves /reports/pqc-waves "Wave 1: edge TLS" /reports/pqc-waves '{"name":"Wave 1: edge TLS","owner":"pki-team","target_date":"2027-03-31"}' || true
WAVE="$(id_of /reports/pqc-waves 'Wave 1: edge TLS')"
if [ -n "$WAVE" ]; then
  load_certs
  for cn in www.acme.test shop.acme.test payments.acme.test; do
    fp="$(cert_fp "$cn")"
    [ -n "$fp" ] || continue
    req GET /reports/pqc-waves
    if jq -e --arg w "$WAVE" --arg f "$fp" '[.data[]|select(.id==$w)|.members[]?|select(.fingerprint==$f)]|length>0' "$WORK/body" >/dev/null; then
      record pqc-waves exists "member $cn"; continue
    fi
    req POST "/reports/pqc-waves/$WAVE/members" "$(jq -nc --arg f "$fp" '{fingerprint:$f}')"
    if ok2xx; then record pqc-waves created "member $cn"; elif [ "$HTTP" = 409 ]; then record pqc-waves exists "member $cn"; else fail pqc-waves "member $cn"; fi
  done
fi
load_certs; FP_PRN="$(cert_fp old-printer.legacy.test)"
req GET /exceptions
if [ -n "$FP_PRN" ] && ! jq -e --arg f "$FP_PRN" '[.. | objects | select(.target_id?==$f)]|length>0' "$WORK/body" >/dev/null 2>&1 \
   && ! { req GET /pending-actions; jq -e '[.data[]|select(.action_type|test("exception"))]|length>0' "$WORK/body" >/dev/null 2>&1; }; then
  req POST /exceptions "$(jq -nc --arg f "$FP_PRN" '{target_type:"certificate",target_id:$f,finding_code:"WEAK_KEY",justification_code:"planned_remediation",justification_note:"Printer firmware is end-of-life; replacement ordered",expires_at:"2027-03-01T00:00:00Z"}')"
  [ "$HTTP" = 202 ] || ok2xx && record exceptions created "weak-key exception (pending approval)" || fail exceptions weak-key
else record exceptions exists "weak-key exception"; fi
req GET /keys
if jq -e '[.data[]|select(.id=="app-signing-key")]|length>0' "$WORK/body" >/dev/null; then record keys exists app-signing-key
else
  req POST /keys '{"id":"app-signing-key","algorithm":"ECDSA-P256"}'
  ok2xx && record keys created app-signing-key || fail keys app-signing-key
fi

# ---------------------------------------------------------------- machine identities (NHI)
# Needs SPIFFE_TRUST_DOMAIN on the hub (503 otherwise); identities are minted
# under spiffe://<trust domain>/nhi/<kind>/<name>.
say "machine identities"
for spec in "ci-deployer:workflow:certificate.renew" "payments-svc:service_account:certificate.issue" "triage-copilot:ai_agent:action.propose"; do
  IFS=: read -r nm kind scope <<<"$spec"
  if has_name /nhi/identities "$nm"; then record nhi exists "$nm"; continue; fi
  req POST /nhi/identities "{\"name\":\"$nm\",\"kind\":\"$kind\",\"scopes\":[\"$scope\",\"certificate.read\"]}"
  if ok2xx; then record nhi created "$nm"
  elif [ "$HTTP" = 503 ]; then skip "NHI / machine identities" "hub has no SPIFFE_TRUST_DOMAIN (POST /nhi/identities 503)"; break
  else fail nhi "$nm"; fi
done

# ---------------------------------------------------------------- not seedable via the API
skip "Tenants" "multi-tenancy flag is off (GET /tenants/context enabled=false); the seed does not change config"
skip "SPIFFE workload entries / SVIDs" "need a workload attesting through a SPIFFE agent; the hub only lists them"
skip "CT findings" "findings come from the CT log monitor polling external logs; there is no create endpoint"
skip "Anomalies" "GET /reports/anomalies is the output of a scheduled issuance-anomaly scan; no create endpoint"
skip "Cloud keys / cloud inventory (AWS ACM, Azure KV, GCP CM, AWS PCA, GCP CAS)" "needs real cloud credentials and accounts"
skip "Discovery schedules" "PUT /discovery/schedules only edits existing scheduled targets (env scan targets or targets with scheduled discovery); none configured and config is not changed"
skip "Agent inventory / live agents" "a real agent process would have to heartbeat; the seed registers one offline agent only"
skip "Break-glass, SIEM, Microsoft/ADCS live, ChatOps, SCIM, OIDC/SAML" "need external identity providers or services"
skip "SCEP challenges" "POST /scep/challenges answers 405 on this build (challenge issuance is not exposed on that path)"
skip "Issued code-signing certs (Code Signing inventory page)" "the code-signing template requires approval and the bootstrap token (and any key minted with it) is forbidden from approving, so the two requests stay pending in the Approvals inbox; approve them as a named admin to populate the page"
skip "Code-signing requests / TSA" "need a CI OIDC token (POST /codesign/issue) or an RFC 3161 client; the OIDC trust rule is seeded as a pending approval and code-signing certs are issued"
skip "Delivery plugins" "need a signed WASM plugin binary"
skip "Migration (import from other CAs)" "needs an external CA export to read"
skip "Per-target install / renewal rollout execution" "needs a reachable host and an agent or SSH credentials; targets and a group are seeded without being run"

# ---------------------------------------------------------------- summary
say "SUMMARY"
printf '%-18s %8s %8s %8s\n' area created exists failed
awk -F'|' '{c[$1,$2]++; a[$1]=1} END{for(k in a) printf "%-18s %8d %8d %8d\n", k, c[k,"created"], c[k,"exists"], c[k,"failed"]}' "$LOG" | sort
echo
if grep -q '|failed|' "$LOG"; then
  echo "Failures:"; grep '|failed|' "$LOG" | sed 's/^/  /'
  echo
fi
echo "Could NOT be seeded (area: why):"
awk -F'|' '{printf "  - %s: %s\n", $1, $2}' "$SKIPS"
if [ -s "$PIDFILE" ]; then
  echo; echo "Listeners left running (127.0.0.1): PIDs $(tr '\n' ' ' <"$PIDFILE") (stop: kill \$(cat $PIDFILE))"
fi
! grep -q '|failed|' "$LOG"
