#!/usr/bin/env bash
# filename: tests/live/ad-ldap/run.sh
#
# W19-06: prove the hub's AD/LDAP inventory pull (internal/bootstrap
# inventory_source_adcs_live.go, "adcs_live" InventorySource, W13-04) against
# a REAL Samba Active Directory domain controller container:
#   - bind over LDAP/LDAPS with a stored credential
#   - pull userCertificate attributes via a paged subtree search
#   - land them in the hub's estate with origin=synced
#   - the advisory gpo-check endpoint (internal/adsync, W17-10) returns a
#     sane pass/fail/warn answer
#   - a wrong bind password produces a clear auth error, not a timeout/500
#
# NOTE ON SCOPE: W17-10's internal/adsync package is a WRITE path only — it
# publishes kryptkeeper's certificate TEMPLATES into AD's Configuration
# naming context (pKICertificateTemplate objects) for Windows
# auto-enrollment. It does not pull users/computers/certificates from AD.
# The read path this ticket actually exercises is W13-04's separate
# "adcs_live" InventorySource (internal/bootstrap/inventory_source_adcs_live.go),
# reached via POST /api/v1/inventory-sources + POST
# /api/v1/inventory-sources/{id}/sync. Read the code before the fixture:
# the ticket text's assumption of one unified "AD sync" surface is wrong.
#
# Idempotent, PASS/FAIL per step, non-zero exit on any FAIL, cleans up its
# own container/volume/hub process on exit (trap). No real secrets
# committed: the domain admin password and LDAP bind password are generated
# fresh into the run's temp dir every run, never written to this repo.
set -u
set -o pipefail

# Samba AD provisioning needs security.* xattrs, which ROOTLESS podman refuses
# even under --privileged (verified 2026-10-06 on native amd64 Ubuntu 24.04:
# rootless denied, rootful allowed). Run with a rootful engine, e.g. a wrapper
# script containing `exec sudo podman "$@"` passed as CONTAINER_ENGINE=/path,
# or CONTAINER_ENGINE=docker. "$CE" is quoted, so it must be a single path.
CE="${CONTAINER_ENGINE:-podman}"

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$HERE/../../.." && pwd)"
WORK="$(mktemp -d /tmp/kk-uat-adldap.XXXXXX)"
HUB_DIR=/tmp/kk-uat-adldap-hub
HUB_PORT=8095
HUB_BASE="http://127.0.0.1:${HUB_PORT}"
TOKEN=uat-token
DC_CTR=kk-uat-samba
DC_VOL=kk-uat-samba-data
DOMAIN=CORP.LOCAL
LDAP_PORT=3389   # high port: 389 needs root on the host
LDAPS_PORT=6636  # high port: 636 needs root on the host
DOMAINPASS="$(openssl rand -base64 24 | tr -d '=+/' | cut -c1-20)Aa1!"
BINDPASS="$(openssl rand -base64 24 | tr -d '=+/' | cut -c1-20)Bb2!"

FAILED=0
STEP() { echo; echo "== $* =="; }
PASS() { echo "PASS: $*"; }
FAIL() { echo "FAIL: $*"; FAILED=1; }
DIE()  { echo "FAIL: $*"; cleanup; exit 1; }

HUB_PID=""
cleanup() {
  [ -n "${KK_KEEP:-}" ] && {  echo "KK_KEEP set: leaving $WORK, $HUB_DIR and $DC_CTR running"; return; }
  STEP "cleanup"
  [ -n "$HUB_PID" ] && kill "$HUB_PID" 2>/dev/null || true
  "$CE" rm -f "$DC_CTR" >/dev/null 2>&1 || true
  "$CE" volume rm -f "$DC_VOL" >/dev/null 2>&1 || true
  rm -rf "$WORK" "$HUB_DIR"
}
trap cleanup EXIT

curlj() { curl -sS -H "Authorization: Bearer ${TOKEN}" -H 'Content-Type: application/json' "$@"; }

# ---------------------------------------------------------------------------
# 1. Arch check + Samba AD DC container (podman only; publish 389/636 on
#    127.0.0.1 via high ports; the hub on the host reaches the DC over
#    those published ports, per the ssh-install fixture's topology notes).
# ---------------------------------------------------------------------------
STEP "podman arch"
if [ "$CE" = podman ]; then
  ARCH="$(podman info --format '{{.Host.Arch}}' 2>/dev/null)"
else
  ARCH="$(uname -m)"
fi
case "$ARCH" in x86_64) ARCH=amd64;; aarch64) ARCH=arm64;; esac

PASS "podman host arch: ${ARCH:-unknown}"
PLATFORM_FLAG=""
IMAGE=docker.io/nowsci/samba-domain:latest
if [ "$ARCH" != "amd64" ]; then
  PLATFORM_FLAG="--platform linux/amd64"
  echo "note: $IMAGE is amd64-only; running under qemu emulation (accepted per ticket)"
fi

STEP "pull Samba AD DC image"
# Docker Hub rate-limits anonymous pulls (429); a cached image avoids that.
{ "$CE" image inspect "$IMAGE" >/dev/null 2>&1 || "$CE" pull $PLATFORM_FLAG "$IMAGE" >"$WORK/pull.log" 2>&1; } \
  && PASS "$("$CE" inspect "$IMAGE" --format '{{.Digest}}' 2>/dev/null || echo pulled)" \
  || DIE "$CE pull failed, see $WORK/pull.log"

STEP "start Samba AD DC ($DOMAIN)"
"$CE" rm -f "$DC_CTR" >/dev/null 2>&1 || true
"$CE" volume rm -f "$DC_VOL" >/dev/null 2>&1 || true
"$CE" volume create "$DC_VOL" >/dev/null
# --privileged: samba-tool domain provision needs to set POSIX ACLs/xattrs
# on sysvol during provisioning; a normal capability set is not enough.
"$CE" run -d --name "$DC_CTR" $PLATFORM_FLAG --privileged \
  -v "${DC_VOL}:/var/lib/samba" \
  -e "DOMAIN=${DOMAIN}" -e "DOMAINPASS=${DOMAINPASS}" -e "DNSFORWARDER=8.8.8.8" \
  -p "127.0.0.1:${LDAP_PORT}:389" -p "127.0.0.1:${LDAPS_PORT}:636" \
  "$IMAGE" >"$WORK/dc-start.log" 2>&1 \
  && PASS "container $DC_CTR started" || DIE "failed to start $DC_CTR, see $WORK/dc-start.log"

STEP "wait for domain provisioning"
# samba-tool domain provision under qemu-user emulation can take minutes;
# poll both for the smbd-up marker and for a crash so we fail fast+clearly
# rather than time out uninformatively.
DC_UP=0
tries=96
while [ $tries -gt 0 ]; do
  STATE="$("$CE" inspect "$DC_CTR" --format '{{.State.Status}}' 2>/dev/null)"
  LOG="$("$CE" logs "$DC_CTR" 2>&1)"
  # The image's logs carry no stable "smbd version" banner on a native host;
  # ask the DC itself instead of grepping for a marker.
  if "$CE" exec "$DC_CTR" samba-tool domain info 127.0.0.1 >/dev/null 2>&1; then DC_UP=1; break; fi
  if [ "$STATE" != "running" ]; then break; fi
  if echo "$LOG" | grep -q "PANIC (pid"; then break; fi
  tries=$((tries - 1)); sleep 5
done

if [ "$DC_UP" != "1" ]; then
  PANIC_LINE="$("$CE" logs "$DC_CTR" 2>&1 | grep -m1 "PANIC (pid" || true)"
  if [ -n "$PANIC_LINE" ]; then
    # Root cause confirmed independently (2026-09-10, this ticket): a
    # plain `setfattr -n security.test ... ` inside a --privileged
    # container on this host fails with "Operation not permitted" even
    # though POSIX file perms are writable. Samba's vfs_acl_xattr module
    # stores NT ACLs as a security.NTACL xattr and the provisioner's
    # try_chown()/set_nt_acl() become_root()/unbecome_root() token-stack
    # bookkeeping assumes that xattr write succeeds; when it silently
    # can't, the stack desyncs and smbd panics with "Security context
    # active token stack underflow" partway through sysvol setup. This is
    # a ROOTLESS-container limitation (security.* xattrs need real root),
    # not a kryptkeeper defect and not fixable with container flags. It was
    # first misattributed to the Mac's podman machine; the identical panic on
    # native amd64 Linux under rootless podman, and a clean run there under
    # rootful podman (2026-10-06), pin it on rootless mode.
    DIE "Samba AD DC provisioning panicked (security.* xattrs refused: run with a ROOTFUL engine, see CONTAINER_ENGINE note at the top of this script): $PANIC_LINE"
  fi
  DIE "Samba AD DC never came up (state=$STATE), see: $CE logs $DC_CTR"
fi
PASS "Samba AD DC provisioned and smbd running"

STEP "wait for LDAP to answer"
tries=20
LDAP_UP=0
while [ $tries -gt 0 ]; do
  if "$CE" exec "$DC_CTR" ldapsearch -x -H "ldap://127.0.0.1" -b "" -s base >/dev/null 2>&1; then LDAP_UP=1; break; fi
  tries=$((tries - 1)); sleep 3
done
[ "$LDAP_UP" = "1" ] && PASS "ldapsearch answered inside the DC container" || DIE "ldapsearch never answered"

# ---------------------------------------------------------------------------
# 2. Seed data: 3 users, 2 computers, attach real certs to two objects'
#    userCertificate attribute, export the DC's TLS cert for LDAPS trust.
# ---------------------------------------------------------------------------
BASE_DN="DC=corp,DC=local"
STEP "seed users and computers"
for u in alice bob carol; do
  "$CE" exec "$DC_CTR" samba-tool user create "$u" "${BINDPASS}x1!" >>"$WORK/seed.log" 2>&1 \
    && PASS "user $u created" || FAIL "user $u create failed, see $WORK/seed.log"
done
for c in WKSTN01 WKSTN02; do
  "$CE" exec "$DC_CTR" samba-tool computer create "$c" >>"$WORK/seed.log" 2>&1 \
    && PASS "computer $c created" || FAIL "computer $c create failed, see $WORK/seed.log"
done

# A dedicated bind account for the hub -- least-privilege read of
# userCertificate rather than binding as Administrator.
STEP "create hub bind account"
"$CE" exec "$DC_CTR" samba-tool user create kkhubsync "${BINDPASS}" >>"$WORK/seed.log" 2>&1 \
  && PASS "bind account kkhubsync created" || FAIL "bind account create failed"

attach_cert() {
  local cn=$1 der_b64
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -days 30 -nodes \
    -subj "/CN=${cn}.${DOMAIN}" -keyout "$WORK/${cn}.key" -out "$WORK/${cn}.pem" >>"$WORK/seed.log" 2>&1
  openssl x509 -in "$WORK/${cn}.pem" -outform der -out "$WORK/${cn}.der" 2>>"$WORK/seed.log"
  der_b64="$(base64 < "$WORK/${cn}.der" | tr -d '\n')"
  cat >"$WORK/${cn}.ldif" <<LDIF
dn: CN=${cn},CN=Users,${BASE_DN}
changetype: modify
add: userCertificate
userCertificate:: ${der_b64}
LDIF
  "$CE" cp "$WORK/${cn}.ldif" "${DC_CTR}:/tmp/${cn}.ldif" >>"$WORK/seed.log" 2>&1
  # Samba refuses simple binds over plain ldap:// ("Transport encryption
  # required"); seed over LDAPS. REQCERT=never is fine here: it is the DC's own
  # loopback, and the hub's trust of the DC CA is asserted separately below.
  "$CE" exec -e LDAPTLS_REQCERT=never "$DC_CTR" ldapmodify -x -H ldaps://127.0.0.1 -D "${DOMAIN%%.*}\\Administrator" -w "${DOMAINPASS}" -f "/tmp/${cn}.ldif" >>"$WORK/seed.log" 2>&1
}

STEP "attach real certificates to alice and bob"
attach_cert alice && PASS "cert attached to alice" || FAIL "attach cert to alice failed, see $WORK/seed.log"
attach_cert bob && PASS "cert attached to bob" || FAIL "attach cert to bob failed, see $WORK/seed.log"

STEP "replace DC LDAPS certificate with a well-formed one"
# Samba's auto-generated LDAPS cert has a NEGATIVE serial number, which Go's
# x509 parser (1.23+) correctly rejects. That is the hub being right, not a
# bug to work around, so give the DC a CA-signed cert with a positive serial
# and SANs for the loopback address the hub dials.
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -days 2 -nodes \
  -subj "/CN=KK UAT DC CA" -keyout "$WORK/dc-ca.key" -out "$WORK/dc-ca.pem" \
  -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign,cRLSign" >>"$WORK/seed.log" 2>&1
openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
  -subj "/CN=dc.${DOMAIN}" -keyout "$WORK/dc.key" -out "$WORK/dc.csr" >>"$WORK/seed.log" 2>&1
printf 'subjectAltName=DNS:dc.%s,DNS:localhost,IP:127.0.0.1\nextendedKeyUsage=serverAuth\nkeyUsage=digitalSignature\n' "$DOMAIN" >"$WORK/dc.ext"
openssl x509 -req -in "$WORK/dc.csr" -CA "$WORK/dc-ca.pem" -CAkey "$WORK/dc-ca.key" -set_serial 0x$(openssl rand -hex 8) \
  -days 2 -extfile "$WORK/dc.ext" -out "$WORK/dc.pem" >>"$WORK/seed.log" 2>&1
TLS_DIR=/var/lib/samba/private/tls
"$CE" cp "$WORK/dc.pem" "${DC_CTR}:${TLS_DIR}/cert.pem" >>"$WORK/seed.log" 2>&1
"$CE" cp "$WORK/dc.key" "${DC_CTR}:${TLS_DIR}/key.pem" >>"$WORK/seed.log" 2>&1
"$CE" cp "$WORK/dc-ca.pem" "${DC_CTR}:${TLS_DIR}/ca.pem" >>"$WORK/seed.log" 2>&1
"$CE" exec "$DC_CTR" supervisorctl restart samba >>"$WORK/seed.log" 2>&1
tries=30
until "$CE" exec -e LDAPTLS_CACERT="${TLS_DIR}/ca.pem" "$DC_CTR" ldapsearch -x -H ldaps://127.0.0.1 -b "" -s base >/dev/null 2>&1; do
  tries=$((tries - 1)); [ $tries -le 0 ] && break; sleep 2
done
[ $tries -gt 0 ] && PASS "DC serving the fixture certificate on LDAPS (CA: $WORK/dc-ca.pem)" || FAIL "DC did not come back on LDAPS with the fixture cert, see $WORK/seed.log"

# ---------------------------------------------------------------------------
# 3. Hub on the host: register the adcs_live inventory source, sync, assert.
# ---------------------------------------------------------------------------
STEP "build hub"
# Start from an empty hub data dir: a previous KK_KEEP run skips cleanup and
# would otherwise leave its synced certificates behind.
rm -rf "$HUB_DIR"
mkdir -p "$HUB_DIR/data"
( cd "$REPO_ROOT" && go build -o "$HUB_DIR/kryptkeeper" ./cmd/kryptkeeper ) \
  && PASS "hub built" || DIE "go build failed"

# W19-31: KRYPTKEEPER_TLS_DISABLE=true -- since W19-14 the hub self-issues a
# TLS listener by default whenever APP_CERTIFICATE_PROVIDER=ca (set below),
# which would otherwise break every plain-HTTP curl call this fixture makes
# to $HUB_BASE. The surface under test here is the LDAP inventory-source
# pull against Samba, not the hub's own TLS listener (already proven by
# tests/live/tls/run.sh), so this fixture stays deliberately plain HTTP.
# adcs_live dials with the system trust store (no per-source CA setting), so
# the hub trusts the DC's fixture CA via SSL_CERT_FILE, as an operator would
# with their enterprise root in the OS store.
export SSL_CERT_FILE="$WORK/dc-ca.pem"
export APP_BOOTSTRAP_TOKEN="$TOKEN" AUTH_MODE=bootstrap APP_CERTIFICATE_PROVIDER=ca \
  APP_DISCOVERY_PROVIDER=db APP_NOTIFICATION_PROVIDER=file \
  KRYPTKEEPER_TLS_DISABLE=true \
  APP_CREDENTIAL_STORE_PASSPHRASE='uat-cred-passphrase-32-bytes-long!!' \
  KRYPTKEEPER_KEYSTORE_PASSPHRASE='uat-keystore-passphrase-32-bytes!!' \
  KRYPTKEEPER_DATA_DIR="$HUB_DIR/data" \
  APP_CA_FILE="$HUB_DIR/data/cas.json" \
  APP_TEMPLATE_FILE="$HUB_DIR/data/templates.json" \
  APP_CERTIFICATE_FILE="$HUB_DIR/data/certificates.json" \
  APP_AUDIT_FILE="$HUB_DIR/data/audit.json" \
  APP_CERTS_SUMMARY_FILE="$HUB_DIR/data/certs_summary.json" \
  KRYPTKEEPER_BOOTSTRAP_CREATE_ROOT=true \
  KRYPTKEEPER_CA_NAME="UAT Root CA" \
  APP_BIND_ADDR=127.0.0.1 PORT="$HUB_PORT"

STEP "start hub"
"$HUB_DIR/kryptkeeper" >"$WORK/hub.log" 2>&1 &
HUB_PID=$!
tries=30
until curl -sS -f -o /dev/null "${HUB_BASE}/api/v1/cas" -H "Authorization: Bearer ${TOKEN}"; do
  tries=$((tries - 1)); [ $tries -le 0 ] && DIE "hub never answered a real /api/v1/cas 200, see $WORK/hub.log"
  sleep 1
done
PASS "hub answering on $HUB_BASE"

STEP "store LDAP bind credential"
# No credential_type in the enum is LDAP-specific (ssh_key|api_token|cloud_iam|
# windows_password, internal/bootstrap/outbound_credential_store.go); Resolve()
# treats the payload as opaque bytes regardless of type, so api_token is the
# correct fit for "one opaque secret string" rather than forcing a mismatched
# windows_password shape that implies WinRM-style preflight semantics.
CRED_RESP="$(curlj -X POST "${HUB_BASE}/api/v1/credentials" -d "$(python3 - "$BINDPASS" <<'PY'
import json, sys
print(json.dumps({"name": "uat-ad-ldap-bind", "credential_type": "api_token", "payload": sys.argv[1]}))
PY
)")"
CRED_ID="$(echo "$CRED_RESP" | python3 -c 'import json,sys; print(json.load(sys.stdin)["data"]["id"])' 2>/dev/null)"
[ -n "$CRED_ID" ] && PASS "credential: $CRED_ID" || DIE "credential create failed: $CRED_RESP"

STEP "register adcs_live inventory source (LDAPS, DC CA trusted)"
SRC_RESP="$(curlj -X POST "${HUB_BASE}/api/v1/inventory-sources" -d "$(python3 - "$CRED_ID" "$LDAPS_PORT" "$BASE_DN" "$DOMAIN" <<'PY'
import json, sys
cred_id, ldaps_port, base_dn, domain = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]
cfg = {
    "ldap_url": f"ldaps://127.0.0.1:{ldaps_port}",
    "bind_dn": f"{domain.split('.')[0]}\\kkhubsync",
    "search_base": f"CN=Users,{base_dn}",
}
print(json.dumps({
    "name": "uat-ad-ldap",
    "type": "adcs_live",
    "config_json": json.dumps(cfg),
    "credential_ref": cred_id,
}))
PY
)")"
SRC_ID="$(echo "$SRC_RESP" | python3 -c 'import json,sys; print(json.load(sys.stdin)["data"]["id"])' 2>/dev/null)"
[ -n "$SRC_ID" ] && PASS "inventory source: $SRC_ID" || DIE "inventory source create failed: $SRC_RESP"

STEP "trigger sync"
SYNC_RESP="$(curlj -X POST "${HUB_BASE}/api/v1/inventory-sources/${SRC_ID}/sync")"
SYNCED="$(echo "$SYNC_RESP" | python3 -c 'import json,sys; print(json.load(sys.stdin).get("data",{}).get("synced","?"))' 2>/dev/null)"
if [ "$SYNCED" = "2" ]; then
  PASS "sync reported synced=2 (alice + bob)"
else
  FAIL "sync did not report the expected 2 certs: $SYNC_RESP"
fi

STEP "verify certificates landed with origin=synced"
CERTS_RESP="$(curlj "${HUB_BASE}/api/v1/certificates?origin=synced")"
SYNCED_COUNT="$(echo "$CERTS_RESP" | python3 -c 'import json,sys; d=json.load(sys.stdin); print(len(d.get("data") or []))' 2>/dev/null)"
[ "$SYNCED_COUNT" = "2" ] && PASS "2 certificates present with origin=synced" || FAIL "expected 2 origin=synced certs, got: $CERTS_RESP"

STEP "gpo-check (advisory, no AD round-trip)"
GPO_RESP="$(curlj -X POST "${HUB_BASE}/api/v1/adsync/gpo-check" -d '{
  "AutoEnrollEnabled": true,
  "EnrollmentPolicyURL": "https://example.invalid/ADPolicyProvider_CEP_Kerberos/service.svc",
  "EnrollmentServiceURL": "https://example.invalid/ADPolicyProvider_CES_Kerberos/service.svc",
  "CACertificateInstalled": true,
  "TemplateNames": ["uat-ssh-server"]
}')"
ALL_PASSING="$(echo "$GPO_RESP" | python3 -c 'import json,sys; print(json.load(sys.stdin).get("data",{}).get("all_passing"))' 2>/dev/null)"
[ "$ALL_PASSING" = "True" ] && PASS "gpo-check: all_passing=true for a correctly-configured GPO" || FAIL "gpo-check did not return all_passing=true: $GPO_RESP"

STEP "negative: wrong bind password yields a clear auth error"
BADCRED_RESP="$(curlj -X POST "${HUB_BASE}/api/v1/credentials" -d '{"name":"uat-ad-ldap-bind-bad","credential_type":"api_token","payload":"definitely-wrong-password"}')"
BADCRED_ID="$(echo "$BADCRED_RESP" | python3 -c 'import json,sys; print(json.load(sys.stdin)["data"]["id"])' 2>/dev/null)"
BADSRC_RESP="$(curlj -X POST "${HUB_BASE}/api/v1/inventory-sources" -d "$(python3 - "$BADCRED_ID" "$LDAPS_PORT" "$BASE_DN" "$DOMAIN" <<'PY'
import json, sys
cred_id, ldaps_port, base_dn, domain = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]
cfg = {"ldap_url": f"ldaps://127.0.0.1:{ldaps_port}", "bind_dn": f"{domain.split('.')[0]}\\kkhubsync", "search_base": f"CN=Users,{base_dn}"}
print(json.dumps({"name": "uat-ad-ldap-bad", "type": "adcs_live", "config_json": json.dumps(cfg), "credential_ref": cred_id}))
PY
)")"
BADSRC_ID="$(echo "$BADSRC_RESP" | python3 -c 'import json,sys; print(json.load(sys.stdin)["data"]["id"])' 2>/dev/null)"
BADSYNC_RESP="$(curlj -o "$WORK/badsync.headers" -w '%{http_code}' -X POST "${HUB_BASE}/api/v1/inventory-sources/${BADSRC_ID}/sync")"
if [ "$BADSYNC_RESP" = "503" ] && grep -qi "bind" "$WORK/badsync.headers"; then
  PASS "wrong password: HTTP 503 with a bind error, not a timeout or a bare 500"
else
  FAIL "wrong password did not yield a clear bind error (HTTP $BADSYNC_RESP): $(cat "$WORK/badsync.headers")"
fi

STEP "result"
if [ "$FAILED" -eq 0 ]; then
  echo "ALL CHECKS PASSED"
  exit 0
else
  echo "ONE OR MORE CHECKS FAILED"
  exit 1
fi
