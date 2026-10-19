# shellcheck shell=bash
# Shared functions for tests/live/acme-dns-providers/run.sh (W27-26).
# Sourced, never executed. See README.md for the per-leg environment.

. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/../lib/podman.sh"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$HERE/../../.." && pwd)"
SSH_FIXTURE="$REPO_ROOT/tests/live/ssh-install"
HUBAPI="$HERE/hubapi.py"
TXTLEFT="$HERE/txtleft.py"

# Pinned local ACME server for the RFC2136 leg (digest of ghcr.io/letsencrypt/pebble as tested).
PEBBLE_IMAGE="${KK_PEBBLE_IMAGE:-ghcr.io/letsencrypt/pebble:2.10.1@sha256:ddf230642b1a584f519f32e347de1b05a6e4c1f6c35c1863b33effeab5f78199}"
STAGING_DIRECTORY="${KK_ACME_DIRECTORY:-https://acme-staging-v02.api.letsencrypt.org/directory}"
STAMP="$(date -u +%Y%m%d%H%M%S)"
RUN_ID="$(openssl rand -hex 3)"
PFX="kk-uat-$STAMP"                     # every resource we create starts with this
FAILED=0
HUB_BOOTED=0
RESULTS=""                              # tab-separated rows, one per leg

STEP() { echo; echo "=== $* ==="; }
PASS() { echo "PASS: $*"; }
INFO() { echo "INFO: $*"; }
FAIL() { echo "FAIL: $*"; FAILED=1; }
DIE()  { echo "FAIL: $*"; FAILED=1; exit 1; }

free_port() { python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1]); s.close()'; }
jget() { python3 -c "import json,sys; d=json.load(sys.stdin); print(eval(sys.argv[1]))" "$1"; }

# ---- infrastructure ---------------------------------------------------------

kk_init() {
  WORK="$(mktemp -d /tmp/kk-uat-dnsprov.XXXXXX)"
  # podman machine only virtiofs-mounts $HOME; bind-mounted files live there.
  MOUNT_DIR="$(mktemp -d "$HOME/.kk-uat-dnsprov.XXXXXX")"
  HUB_PORT="$(free_port)"; SSH_PORT="$(free_port)"; TLS_PORT="$(free_port)"
  HUB="http://127.0.0.1:$HUB_PORT"
  TOKEN="uat-dnsprov-bootstrap-token"
  IMAGE="localhost/$PFX-ssh:$RUN_ID"; HUB_IMAGE="localhost/$PFX-hub:$RUN_ID"; BIND_IMAGE="localhost/$PFX-bind:$RUN_ID"
  NET="$PFX-net-$RUN_ID"
  CTR="$PFX-nginx-$RUN_ID"; HUB_CTR="$PFX-hub-$RUN_ID"; BIND_CTR="$PFX-bind-$RUN_ID"; PEBBLE_CTR="$PFX-pebble-$RUN_ID"
  trap kk_cleanup EXIT
}

# Removes only what this run created (the kk-uat-<stamp> prefix).
kk_cleanup() {
  if [ "$FAILED" = 1 ] && [ "$HUB_BOOTED" = 1 ]; then echo "--- hub log (last 25) ---"; podman logs "$HUB_CTR" 2>&1 | tail -25; fi
  kk_rm "$CTR" "$HUB_CTR" "$BIND_CTR" "$PEBBLE_CTR"
  podman network rm "$NET" >/dev/null 2>&1
  podman rmi -f "$IMAGE" "$HUB_IMAGE" "$BIND_IMAGE" >/dev/null 2>&1
  rm -f "$SSH_FIXTURE/authorized_keys"
  rm -rf "$WORK" "$MOUNT_DIR"
}

code() { curl -sS -m "${CURL_MAX:-30}" -o "$WORK/last.json" -w '%{http_code}' -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' "$@"; }
tls_fp() { echo | openssl s_client -connect "127.0.0.1:$TLS_PORT" 2>/dev/null | openssl x509 -outform DER 2>/dev/null | openssl dgst -sha256 -r | cut -d' ' -f1; }

# Local RFC2136 leg: BIND (TSIG-updatable zone) + Pebble (validates dns-01 by
# asking that BIND). Writes the TSIG credential file the leg then uses exactly
# like an operator-supplied one.
start_local_dns() {
  STEP "local RFC2136 infrastructure: BIND + Pebble"
  LOCAL_ZONE="uat.test"
  LOCAL_TSIG_FILE="$MOUNT_DIR/tsig.json"
  mkdir -p "$MOUNT_DIR/bind" "$MOUNT_DIR/pebble"
  local secret; secret="$(openssl rand -base64 32)"
  cat >"$MOUNT_DIR/bind/named.conf" <<EOF
options { directory "/var/cache/bind"; recursion no; listen-on { any; }; allow-query { any; }; dnssec-validation no; };
key "kk-uat-tsig" { algorithm hmac-sha256; secret "$secret"; };
logging { channel o { stderr; severity info; print-time yes; }; category update { o; }; category security { o; }; };
zone "$LOCAL_ZONE" { type primary; file "/var/cache/bind/$LOCAL_ZONE.zone"; allow-update { key "kk-uat-tsig"; }; };
EOF
  cat >"$MOUNT_DIR/bind/zone.db" <<EOF
\$TTL 60
@ IN SOA ns1.$LOCAL_ZONE. admin.$LOCAL_ZONE. 1 60 60 3600 60
@ IN NS ns1.$LOCAL_ZONE.
ns1 IN A 127.0.0.1
EOF
  python3 - "$LOCAL_TSIG_FILE" "$secret" <<'PY'
import json, os, sys
fd = os.open(sys.argv[1], os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
with os.fdopen(fd, "w") as f:
    json.dump({"tsig_key_name": "kk-uat-tsig", "tsig_secret": sys.argv[2], "tsig_algorithm": "hmac-sha256"}, f)
PY
  podman build -q -f "$HERE/bind.Containerfile" -t "$BIND_IMAGE" "$HERE" >"$WORK/build-bind.log" 2>&1 || DIE "bind image build failed: $(tail -5 "$WORK/build-bind.log")"
  podman run -d --name "$BIND_CTR" --network "$NET" -v "$MOUNT_DIR/bind:/cfg:ro" "$BIND_IMAGE" \
    sh -c "cp /cfg/zone.db /var/cache/bind/$LOCAL_ZONE.zone && chown bind /var/cache/bind/$LOCAL_ZONE.zone && exec named -u bind -g -c /cfg/named.conf" >/dev/null || DIE "bind did not start"
  BIND_IP="$(podman inspect "$BIND_CTR" --format "{{(index .NetworkSettings.Networks \"$NET\").IPAddress}}")"
  local soa=""
  for _ in $(seq 1 20); do soa="$(podman exec "$BIND_CTR" dig +short +time=2 +tries=1 @127.0.0.1 SOA "$LOCAL_ZONE" 2>/dev/null)"; [ -n "$soa" ] && break; sleep 0.5; done
  [ -n "$soa" ] || DIE "bind does not serve $LOCAL_ZONE"
  PASS "BIND serves $LOCAL_ZONE at $BIND_IP (TSIG-updatable)"
  # Negative control for the "no TXT left" check: it must see a record we plant.
  grep '^key ' "$MOUNT_DIR/bind/named.conf" >"$MOUNT_DIR/bind/update.key"
  printf 'server 127.0.0.1\nupdate add _acme-challenge.control.%s. 60 TXT "kk-uat-control"\nsend\n' "$LOCAL_ZONE" \
    | podman exec -i "$BIND_CTR" nsupdate -k /cfg/update.key >/dev/null 2>&1
  leg_txtleft_rfc2136 "_acme-challenge.control.$LOCAL_ZONE" >/dev/null 2>&1; [ $? = 1 ] \
    && PASS "control: the TXT-left check sees a planted record" || DIE "control: the TXT-left check missed a planted record"
  printf 'server 127.0.0.1\nupdate delete _acme-challenge.control.%s. TXT\nsend\n' "$LOCAL_ZONE" | podman exec -i "$BIND_CTR" nsupdate -k /cfg/update.key >/dev/null 2>&1
  leg_txtleft_rfc2136 "_acme-challenge.control.$LOCAL_ZONE" >/dev/null 2>&1 && PASS "control: ...and sees it gone" || DIE "control: planted record not removed"

  # Pebble: its own minica CA; the hub trusts it through SSL_CERT_FILE, a
  # bundle of Pebble's CA plus the hub image's system roots (so LE staging
  # legs in the same run keep working).
  podman pull -q "$PEBBLE_IMAGE" >/dev/null 2>&1
  local tmpc; tmpc="$(podman create "$PEBBLE_IMAGE")" || DIE "cannot create a container from $PEBBLE_IMAGE"
  podman cp "$tmpc:/test/certs/pebble.minica.pem" "$MOUNT_DIR/pebble/minica.pem" >/dev/null 2>&1
  podman cp "$tmpc:/test/certs/localhost/cert.pem" "$MOUNT_DIR/pebble/cert.pem" >/dev/null 2>&1
  podman cp "$tmpc:/test/certs/localhost/key.pem" "$MOUNT_DIR/pebble/key.pem" >/dev/null 2>&1
  podman rm "$tmpc" >/dev/null 2>&1
  [ -s "$MOUNT_DIR/pebble/minica.pem" ] || DIE "no Pebble CA in $PEBBLE_IMAGE"
  podman run --rm --entrypoint cat "$HUB_IMAGE" /etc/ssl/certs/ca-certificates.crt >"$MOUNT_DIR/pebble/ca-bundle.pem" 2>/dev/null
  cat "$MOUNT_DIR/pebble/minica.pem" >>"$MOUNT_DIR/pebble/ca-bundle.pem"
  podman run -d --name "$PEBBLE_CTR" --network "$NET" --network-alias pebble -e PEBBLE_VA_NOSLEEP=1 -e PEBBLE_WFE_NONCEREJECT=0 \
    "$PEBBLE_IMAGE" -config /test/config/pebble-config.json -dnsserver "$BIND_IP:53" >/dev/null || DIE "pebble did not start"
  # Capture, then grep: "grep -q" closing the pipe early fails the pipeline under pipefail.
  local plog=""
  for _ in $(seq 1 30); do plog="$(podman logs "$PEBBLE_CTR" 2>&1)"; case "$plog" in *"Listening on:"*) break ;; esac; sleep 0.5; done
  case "$plog" in
    *"Listening on:"*) PASS "Pebble up, validating dns-01 against $BIND_IP:53" ;;
    *) DIE "pebble not listening: $(echo "$plog" | tail -3)" ;;
  esac
  LOCAL_UP=1
}

build_and_start() {
  STEP "build hub and the nginx+sshd fixture"
  local goarch
  goarch="$(kk_goarch)"
  mkdir -p "$WORK/hubctx"
  (cd "$REPO_ROOT" && GOOS=linux GOARCH=$goarch CGO_ENABLED=0 go build -o "$WORK/hubctx/kryptkeeper" ./cmd/kryptkeeper) || DIE "go build failed"
  cp "$REPO_ROOT/tests/live/autopilot/hub.Containerfile" "$WORK/hubctx/Containerfile"
  podman build -q -t "$HUB_IMAGE" "$WORK/hubctx" >"$WORK/build-hub.log" 2>&1 || DIE "hub image build failed: $(tail -5 "$WORK/build-hub.log")"
  ssh-keygen -q -t ed25519 -N '' -f "$WORK/id_ed25519" -C kk-uat
  cp "$WORK/id_ed25519.pub" "$SSH_FIXTURE/authorized_keys"
  podman build -q -t "$IMAGE" "$SSH_FIXTURE" >"$WORK/build.log" 2>&1 || DIE "ssh fixture build failed: $(tail -5 "$WORK/build.log")"
  rm -f "$SSH_FIXTURE/authorized_keys"
  podman network create "$NET" >/dev/null || DIE "network create failed"
  podman run -d --name "$CTR" --network "$NET" -p "127.0.0.1:$SSH_PORT:22" -p "127.0.0.1:$TLS_PORT:443" -e ROLE=nginx "$IMAGE" >/dev/null || DIE "nginx container did not start"
  for _ in $(seq 1 30); do HOSTKEY="$(ssh-keyscan -p "$SSH_PORT" -t ed25519 127.0.0.1 2>/dev/null | grep -v '^#' | awk '{print $2" "$3}')"; [ -n "$HOSTKEY" ] && break; sleep 1; done
  for _ in $(seq 1 30); do BEFORE="$(tls_fp)"; [ -n "$BEFORE" ] && break; sleep 1; done
  [ -n "$HOSTKEY" ] && [ -n "$BEFORE" ] || DIE "fixture not reachable"
  PASS "fixture up; nginx serves the placeholder ($BEFORE)"
  [ "${KK_NEED_LOCAL:-0}" = 1 ] && start_local_dns
  start_hub
}

# (Re)starts the hub in a fresh container: a clean data dir. Used once at boot
# and before each leg when KK_FRESH_HUB=1.
start_hub() {
  cat >"$WORK/hub.env" <<EOF
APP_BOOTSTRAP_TOKEN=$TOKEN
AUTH_MODE=bootstrap
APP_CERTIFICATE_PROVIDER=ca
APP_API_KEY_PEPPER=uat-pepper-32-characters-minimum!!
APP_API_KEY_AUTH_ENABLED=true
APP_CREDENTIAL_STORE_PASSPHRASE=uat-cred-passphrase-32-bytes-long!!
KRYPTKEEPER_KEYSTORE_PASSPHRASE=uat-keystore-passphrase-32-bytes!!
KRYPTKEEPER_DATA_DIR=/data
APP_CA_FILE=/data/cas.json
APP_TEMPLATE_FILE=/data/templates.json
APP_CERTIFICATE_FILE=/data/certificates.json
APP_AUDIT_FILE=/data/audit.json
APP_CERTS_SUMMARY_FILE=/data/certs_summary.json
KRYPTKEEPER_BOOTSTRAP_CREATE_ROOT=true
KRYPTKEEPER_CA_NAME=UAT Root CA
APP_BIND_ADDR=0.0.0.0
PORT=$HUB_PORT
KRYPTKEEPER_TLS_DISABLE=true
EOF
  kk_rm "$HUB_CTR"
  local extra=""
  [ "${LOCAL_UP:-0}" = 1 ] && extra="-e SSL_CERT_FILE=/pebble/ca-bundle.pem -v $MOUNT_DIR/pebble:/pebble:ro"
  # shellcheck disable=SC2086
  podman run -d --name "$HUB_CTR" --network "$NET" -p "127.0.0.1:$HUB_PORT:$HUB_PORT" --env-file "$WORK/hub.env" $extra "$HUB_IMAGE" >/dev/null || DIE "hub container did not start"
  HUB_BOOTED=1
  for _ in $(seq 1 60); do curl -sf "$HUB/healthz" >/dev/null 2>&1 && break; sleep 0.5; done
  curl -sf "$HUB/healthz" >/dev/null || DIE "hub did not start"
  PASS "hub up"
}

# ---- legs --------------------------------------------------------------------
# A leg is a (label, provider, mode) triple: mode is normal | wildcard | longwait.
# Each provider has leg_need_<p> (prints SKIP + returns 2 when a prerequisite
# is missing), leg_setup_<p> (sets the LEG_* variables) and leg_txtleft_<p>.

need_var() { # leg var...: every var must be set (to a readable file when it ends in _FILE)
  local leg="$1" v; shift
  for v in "$@"; do
    eval "val=\${$v:-}"
    if [ -z "$val" ]; then echo "SKIP: $leg needs $v"; return 2; fi
    case "$v" in *_FILE) [ -s "$val" ] || { echo "SKIP: $leg needs $v (file '$val' missing or empty)"; return 2; } ;; esac
  done
}

use_local_rfc2136() { [ -z "${KK_RFC2136_SERVER:-}" ] && [ "${KK_RFC2136_LOCAL:-0}" = 1 ]; }

leg_need_route53() { need_var "$1" KK_R53_CRED_FILE KK_R53_ZONE; }
leg_need_azure()   { need_var "$1" KK_AZ_CRED_FILE KK_AZ_ZONE KK_AZ_RESOURCE_GROUP; }
leg_need_gcp()     { need_var "$1" KK_GCP_CRED_FILE KK_GCP_ZONE KK_GCP_PROJECT; }
leg_need_cname()   { need_var "$1" KK_CNAME_ZONE KK_CNAME_CRED_FILE; }
leg_need_rfc2136() {
  if use_local_rfc2136; then return 0; fi
  need_var "$1" KK_RFC2136_SERVER KK_RFC2136_TSIG_FILE KK_RFC2136_ZONE
}

# Sets: LEG_ZONE LEG_NAMEBASE(optional fixed name) LEG_CRED_FILE LEG_CRED_ARGS LEG_SECRETS LEG_DIRECTORY LEG_ISSUER_RE LEG_CONF_EXTRA LEG_PROP_NOTE
leg_setup_route53() {
  LEG_ZONE="$KK_R53_ZONE"; LEG_CRED_FILE="$KK_R53_CRED_FILE"; LEG_SECRETS="$KK_R53_CRED_FILE"
  LEG_CRED_ARGS="--wrap dns"; [ -n "${KK_R53_ZONE_ID:-}" ] && LEG_CRED_ARGS="$LEG_CRED_ARGS --set hosted_zone_id=$KK_R53_ZONE_ID"
}
leg_setup_azure() {
  LEG_ZONE="$KK_AZ_ZONE"; LEG_CRED_FILE="$KK_AZ_CRED_FILE"; LEG_SECRETS="$KK_AZ_CRED_FILE"
  LEG_CRED_ARGS="--wrap dns --set resource_group=$KK_AZ_RESOURCE_GROUP"
}
leg_setup_gcp() {
  LEG_ZONE="$KK_GCP_ZONE"; LEG_CRED_FILE="$KK_GCP_CRED_FILE"; LEG_SECRETS="$KK_GCP_CRED_FILE"
  LEG_CRED_ARGS="--wrap dns --raw-key service_account_json --set project_id=$KK_GCP_PROJECT"
}
leg_setup_cname() {
  LEG_ZONE="$KK_CNAME_ZONE"; LEG_CRED_FILE="$KK_CNAME_CRED_FILE"; LEG_SECRETS="$KK_CNAME_CRED_FILE"
  LEG_CRED_ARGS="--wrap dns"
  # acme-dns has no delete and the CNAME is operator-owned and pre-created, so
  # a fixed, pre-delegated name is used instead of a per-run one.
  LEG_NAMEBASE="${KK_CNAME_NAME:-kk-uat-cname.$KK_CNAME_ZONE}"
}
leg_setup_rfc2136() {
  if use_local_rfc2136; then
    LEG_ZONE="$LOCAL_ZONE"; LEG_CRED_FILE="$LOCAL_TSIG_FILE"
    LEG_CRED_ARGS="--wrap dns --set nameserver=$BIND_CTR:53 --set zone=$LOCAL_ZONE"
    LEG_DIRECTORY="https://pebble:14000/dir"; LEG_ISSUER_RE='Pebble'
    LEG_CONF_EXTRA=',"dns_propagation":"resolver","dns_resolver":"'"$BIND_IP"':53"'
    LEG_PROP_NOTE="local BIND $BIND_IP + Pebble; propagation=resolver"
  else
    LEG_ZONE="$KK_RFC2136_ZONE"; LEG_CRED_FILE="$KK_RFC2136_TSIG_FILE"
    LEG_CRED_ARGS="--wrap dns --set nameserver=$KK_RFC2136_SERVER --set zone=$KK_RFC2136_ZONE"
  fi
  LEG_SECRETS="$LEG_CRED_FILE"
}

# 0 = no TXT left, 1 = still there, 2 = could not query (a FAIL, never a PASS)
leg_txtleft_route53() { python3 "$TXTLEFT" --provider route53 --cred "$KK_R53_CRED_FILE" --zone "$KK_R53_ZONE" --fqdn "$1"; }
leg_txtleft_azure()   { python3 "$TXTLEFT" --provider azure --cred "$KK_AZ_CRED_FILE" --zone "$KK_AZ_ZONE" --fqdn "$1" --set "resource_group=$KK_AZ_RESOURCE_GROUP"; }
leg_txtleft_gcp()     { python3 "$TXTLEFT" --provider gcp --cred "$KK_GCP_CRED_FILE" --zone "$KK_GCP_ZONE" --fqdn "$1" --set "project_id=$KK_GCP_PROJECT"; }
dig_txt() { # fqdn: TXT values via the leg's authoritative server, one per line
  if use_local_rfc2136; then podman exec "$BIND_CTR" dig +short +time=3 +tries=2 @127.0.0.1 TXT "$1"
  else
    command -v dig >/dev/null 2>&1 || { echo ";; dig not installed"; return 2; }
    local host="${KK_RFC2136_SERVER%:*}" port="${KK_RFC2136_SERVER##*:}"; [ "$port" = "$KK_RFC2136_SERVER" ] && port=53
    dig +short +time=3 +tries=2 -p "$port" "@$host" TXT "$1"
  fi
}
leg_txtleft_rfc2136() {
  local out; out="$(dig_txt "$1" 2>&1)" || { echo "QUERY-ERROR: $out"; return 2; }
  case "$out" in *";;"*) echo "QUERY-ERROR: $out"; return 2 ;; esac
  [ -z "$out" ] && { echo "0 TXT record(s) at $1"; return 0; }
  echo "$(echo "$out" | wc -l | tr -d ' ') TXT record(s) at $1"; return 1
}
leg_txtleft_cname() {
  # The TXT lives in acme-dns (no delete there, one-time digest). What must hold
  # in the customer zone: no TXT of ours, and the operator's CNAME untouched.
  command -v dig >/dev/null 2>&1 || { echo "QUERY-ERROR: dig not installed"; return 2; }
  local cn; cn="$(dig +short +time=5 +tries=2 CNAME "$1")" || return 2
  [ -n "$cn" ] || { echo "QUERY-ERROR: CNAME at $1 is gone or unreadable"; return 2; }
  echo "0 TXT record(s) in the customer zone; CNAME intact -> $cn"; return 0
}

record() { # leg result seconds txtleft occurrences issuer fpmatch note
  RESULTS="${RESULTS}$1	$2	$3	$4	$5	$6	$7	$8
"
}

# run_leg LABEL PROVIDER MODE
run_leg() {
  local label="$1" prov="$2" mode="$3"
  local result=PASS secs="-" txtleft="-" occ="-" issuer="-" fpmatch="-" note=""
  LEG_ZONE=""; LEG_NAMEBASE=""; LEG_CRED_FILE=""; LEG_CRED_ARGS=""; LEG_SECRETS=""
  LEG_DIRECTORY="$STAGING_DIRECTORY"; LEG_ISSUER_RE='\(STAGING\)'; LEG_CONF_EXTRA=""; LEG_PROP_NOTE=""
  STEP "leg: $label ($prov, $mode)"
  "leg_setup_$prov"
  [ "${KK_FRESH_HUB:-0}" = 1 ] && [ "$HUB_BOOTED" = 1 ] && start_hub

  local cn san_expect challenge_fqdn certname
  if [ "$mode" = wildcard ]; then
    certname="*.wild-$STAMP.$LEG_ZONE"; challenge_fqdn="_acme-challenge.wild-$STAMP.$LEG_ZONE"; san_expect="DNS:$certname"
  else
    certname="${LEG_NAMEBASE:-$PFX-$label.$LEG_ZONE}"; challenge_fqdn="_acme-challenge.$certname"; san_expect="DNS:$certname"
  fi
  # CN and SAN identical so the hub orders exactly this identifier.
  # Propagation: operator legs default to auto (authoritative -> doh); override with KK_DNS_PROPAGATION.
  if [ "$mode" = longwait ]; then
    LEG_CONF_EXTRA=',"dns_propagation":"none","dns_propagation_delay":"'"${KK_PROPAGATION_DELAY:-170s}"'"'
    LEG_PROP_NOTE="propagation=none delay=${KK_PROPAGATION_DELAY:-170s}"
  elif [ -z "$LEG_CONF_EXTRA" ] && [ -n "${KK_DNS_PROPAGATION:-}" ]; then
    LEG_CONF_EXTRA=',"dns_propagation":"'"$KK_DNS_PROPAGATION"'"'
    [ -n "${KK_DNS_DOH_URL:-}" ] && LEG_CONF_EXTRA="$LEG_CONF_EXTRA"',"dns_doh_url":"'"$KK_DNS_DOH_URL"'"'
    LEG_PROP_NOTE="propagation=$KK_DNS_PROPAGATION"
  else
    [ -z "$LEG_PROP_NOTE" ] && LEG_PROP_NOTE="propagation=auto"
  fi
  note="$LEG_PROP_NOTE"
  LDIE() { echo "FAIL: $*"; result=FAIL; FAILED=1; note="$note; $*"; }
  LFAIL() { echo "FAIL: $*"; result=FAIL; FAILED=1; note="$note; $*"; }

  # 1. unmanaged certificate
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 30 \
    -keyout "$WORK/old.key" -out "$WORK/old.crt" -subj "/CN=$certname" -addext "subjectAltName=DNS:$certname" >/dev/null 2>&1
  local c FP
  c=$(code -X POST "$HUB/api/v1/certificates/import" -d "$(python3 -c 'import json,sys; print(json.dumps({"certificate_pem": open(sys.argv[1]).read()}))' "$WORK/old.crt")")
  case "$c" in 20*) ;; *) LDIE "import -> $c $(cat "$WORK/last.json")"; record "$label" FAIL - - - - - "$note"; return ;; esac
  FP="$(jget 'd["data"].get("fingerprint_sha256") or d["data"]["certificate"]["fingerprint_sha256"]' <"$WORK/last.json" 2>/dev/null)"
  [ -n "$FP" ] && PASS "imported unmanaged $certname ($FP)" || { LDIE "no fingerprint in import response"; record "$label" FAIL - - - - - "$note"; return; }

  # 2. provider credential (file -> Python -> hub; never argv), connector, takeover
  local cred conn
  # shellcheck disable=SC2086
  cred="$(python3 "$HUBAPI" cred --hub "$HUB" --bearer "$TOKEN" --name "$PFX-$label-dns" --file "$LEG_CRED_FILE" $LEG_CRED_ARGS)" \
    || { LDIE "provider credential create failed"; record "$label" FAIL - - - - - "$note"; return; }
  PASS "credential $cred (secret not shown)"
  c=$(code -X POST "$HUB/api/v1/connectors" -d "$(python3 -c 'import json,sys; print(json.dumps({"name":sys.argv[4],"type":"acme","credential_ref":sys.argv[2],"config_json":json.dumps(dict({"directory_url":sys.argv[1],"challenge":"dns-01","dns_provider":sys.argv[3]}, **json.loads("{"+sys.argv[5].lstrip(",")+"}")))}))' "$LEG_DIRECTORY" "$cred" "$prov" "$PFX-$label" "$LEG_CONF_EXTRA")")
  [ "$c" = 201 ] || { LDIE "connector -> $c $(cat "$WORK/last.json")"; record "$label" FAIL - - - - - "$note"; return; }
  conn="$(jget 'd["data"]["id"]' <"$WORK/last.json")"
  c=$(code -X POST "$HUB/api/v1/estate/takeover" -d "{\"fingerprint\":\"$FP\",\"owner_team\":\"uat\",\"renewal_path\":{\"mode\":\"connector\",\"connector_id\":\"$conn\"}}")
  [ "$c" = 200 ] && PASS "connector $conn -> $LEG_DIRECTORY; taken over" || { LDIE "takeover -> $c $(cat "$WORK/last.json")"; record "$label" FAIL - - - - - "$note"; return; }

  # 3. SSH credential + nginx target
  local sshcred tgt
  sshcred="$(python3 - "$WORK/id_ed25519" "$HOSTKEY" "$HUB" "$TOKEN" "$PFX-$label-ssh" <<'PY'
import json, sys, urllib.request
key, hostkey, hub, bearer, name = sys.argv[1:6]
body = json.dumps({"name": name, "credential_type": "ssh_key",
                   "payload": {"user": "root", "private_key_pem": open(key).read(), "host_public_key": hostkey, "port": 22}}).encode()
req = urllib.request.Request(hub + "/api/v1/credentials", data=body, method="POST",
                             headers={"Authorization": "Bearer " + bearer, "Content-Type": "application/json"})
print(json.load(urllib.request.urlopen(req))["data"]["id"])
PY
)" || { LDIE "ssh credential failed"; record "$label" FAIL - - - - - "$note"; return; }
  c=$(code -X POST "$HUB/api/v1/targets" -d "{\"name\":\"$PFX-$label\",\"host\":\"$CTR\",\"discovery_mode\":\"network\",\"install_mode\":\"ssh\",\"credential_ref\":\"$sshcred\",\"install_server_type\":\"nginx\",\"install_cert_path\":\"/etc/ssl/kk/server.crt\",\"install_key_path\":\"/etc/ssl/kk/server.key\",\"install_reload_method\":\"binary\"}")
  [ "$c" = 201 ] || { LDIE "target -> $c $(cat "$WORK/last.json")"; record "$label" FAIL - - - - - "$note"; return; }
  tgt="$(jget 'd["data"]["id"]' <"$WORK/last.json")"

  # 4. renew: order at the CA, TXT published and removed, installed, verified
  local start out newfp
  start=$(date +%s)
  c=$(CURL_MAX=900 code -X POST "$HUB/api/v1/renewal/execute" -d "{\"fingerprint\":\"$FP\",\"target_id\":\"$tgt\",\"install\":{\"server_type\":\"nginx\",\"cert_path\":\"/etc/ssl/kk/server.crt\",\"key_path\":\"/etc/ssl/kk/server.key\",\"reload_method\":\"binary\",\"verify_host_port\":\"$CTR:443\"}}")
  secs=$(( $(date +%s) - start ))
  out="$(jget 'str(d["data"].get("install_outcome"))+" verified="+str(d["data"].get("verified"))' <"$WORK/last.json" 2>/dev/null)"
  newfp="$(jget 'd["data"].get("new_fingerprint","")' <"$WORK/last.json" 2>/dev/null | tr -d ':' | tr 'A-F' 'a-f')"
  case "$c:$out" in
    200:installed_verified\ verified=True) PASS "renewed and installed in ${secs}s: $out" ;;
    *) LFAIL "renewal -> $c $(head -c 400 "$WORK/last.json")" ;;
  esac
  if [ -n "${KK_EVIDENCE_DIR:-}" ]; then mkdir -p "$KK_EVIDENCE_DIR"; cp "$WORK/last.json" "$KK_EVIDENCE_DIR/$label-renew-execute-response.json"; fi

  # 5. served certificate: fingerprint, issuer, SAN
  local after; after="$(tls_fp)"
  if [ -n "$newfp" ] && [ "$after" = "$newfp" ]; then fpmatch=yes; PASS "nginx serves the renewed certificate ($after)"; else fpmatch=no; LFAIL "nginx serves $after, renewed ${newfp:-none}"; fi
  echo | openssl s_client -connect "127.0.0.1:$TLS_PORT" 2>/dev/null | openssl x509 -noout -issuer -subject -ext subjectAltName >"$WORK/served.txt" 2>/dev/null
  issuer="$(grep -i '^issuer=' "$WORK/served.txt" | head -1 | sed 's/^issuer= *//I' | tr -d '\t')"
  if grep -qiE "^issuer=.*($LEG_ISSUER_RE)" "$WORK/served.txt"; then PASS "issuer: $issuer"; else LFAIL "unexpected issuer: $issuer"; fi
  if grep -qF "$san_expect" "$WORK/served.txt"; then PASS "SAN contains $san_expect"; else LFAIL "SAN lacks $san_expect: $(grep -i 'DNS:' "$WORK/served.txt")"; fi
  [ -n "${KK_EVIDENCE_DIR:-}" ] && cp "$WORK/served.txt" "$KK_EVIDENCE_DIR/$label-served-cert.txt"

  # 6. cleanup proof from the provider itself (a failed query is a FAIL)
  local q rc
  q="$("leg_txtleft_$prov" "$challenge_fqdn" 2>&1)"; rc=$?
  case $rc in
    0) txtleft=0; PASS "no TXT left: $q" ;;
    1) txtleft=">0"; LFAIL "TXT left behind ($q): remove _acme-challenge records of $challenge_fqdn by hand" ;;
    *) txtleft="QUERY-FAILED"; LFAIL "could not verify TXT cleanup: $q" ;;
  esac

  # Local BIND logs every dynamic update: proof the hub really published and removed the TXT over TSIG.
  if use_local_rfc2136 && [ "$prov" = rfc2136 ]; then
    local blog adds dels
    blog="$(podman logs "$BIND_CTR" 2>&1 | grep -F "$challenge_fqdn")"
    adds="$(echo "$blog" | grep -c 'adding an RR')"; dels="$(echo "$blog" | grep -c 'deleting an RR\|deleting rrset')"
    INFO "BIND update log for $challenge_fqdn: adds=$adds deletes=$dels"
    note="$note; BIND log adds=$adds deletes=$dels"
    [ "$adds" -ge 1 ] && [ "$dels" -ge 1 ] || LFAIL "BIND did not log both the TXT add and delete for $challenge_fqdn"
  fi

  # 7. secret scan across hub log + audit (counts only are printed)
  local sargs="" f
  for f in $LEG_SECRETS; do sargs="$sargs --secret $f"; done
  podman logs "$HUB_CTR" >"$WORK/hub.log" 2>&1
  # shellcheck disable=SC2086
  python3 "$HUBAPI" scan --hub "$HUB" --bearer "$TOKEN" --hublog "$WORK/hub.log" --audit-out "$WORK/audit-dump.json" $sargs >"$WORK/scan.out" 2>&1; rc=$?
  cat "$WORK/scan.out"
  occ="$(sed -n 's/.*total occurrences: \([0-9]*\).*/\1/p' "$WORK/scan.out")"; [ -z "$occ" ] && occ="SCAN-FAILED"
  if [ $rc = 0 ] && [ "$occ" = 0 ]; then PASS "secrets found 0 times in hub log + audit"; else LFAIL "secret scan: occurrences=$occ"; fi
  # Control: the scanner must find a value we plant (a scan that cannot fail proves nothing).
  printf 'kk-uat-canary-%s' "$RUN_ID" >"$WORK/canary.txt"
  { cat "$WORK/hub.log"; cat "$WORK/canary.txt"; } >"$WORK/hub-canary.log"
  if python3 "$HUBAPI" scan --hub "$HUB" --bearer "$TOKEN" --hublog "$WORK/hub-canary.log" --secret "$WORK/canary.txt" >/dev/null 2>&1; then
    LFAIL "scan control: a planted value was not detected"
  else PASS "scan control: a planted value is detected"; fi
  if [ -n "${KK_EVIDENCE_DIR:-}" ] && [ "$occ" = 0 ]; then cp "$WORK/hub.log" "$KK_EVIDENCE_DIR/$label-hub.log"; cp "$WORK/audit-dump.json" "$KK_EVIDENCE_DIR/$label-audit.json"; fi

  # The mode that long-wait covers: a JSON 200 after a wait past the old 180 s write deadline.
  if [ "$mode" = longwait ]; then
    [ "$secs" -ge 150 ] && PASS "request spent ${secs}s in the handler and still returned JSON 200" || LFAIL "long-wait leg returned after only ${secs}s; the propagation wait did not exercise the deadline"
  fi
  record "$label" "$result" "$secs" "$txtleft" "$occ" "$issuer" "$fpmatch" "$note"
}

print_results() {
  echo; echo "=== results ==="
  local md="| Leg | Result | Renewal seconds | TXT left | Secret occurrences (log+audit) | Issuer | Served fp == new_fingerprint | Notes |
|---|---|---|---|---|---|---|---|"
  local l r s t o i f n
  while IFS='	' read -r l r s t o i f n; do
    [ -z "$l" ] && continue
    md="$md
| $l | $r | $s | $t | $o | $i | $f | $n |"
  done <<EOF
$RESULTS
EOF
  echo "$md"
  if [ -n "${KK_EVIDENCE_DIR:-}" ]; then mkdir -p "$KK_EVIDENCE_DIR"; echo "$md" >"$KK_EVIDENCE_DIR/results.md"; fi
}
