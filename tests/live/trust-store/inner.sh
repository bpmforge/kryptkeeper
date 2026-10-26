#!/bin/sh
# Runs INSIDE a distribution container (run.sh bind-mounts /work). Proves, on a
# real Debian-family or RHEL-family system, that the real kryptkeeper-agent:
#   1. refuses a trust bundle when it has not opted in (and trusts nothing new),
#   2. adds the root through the ONE sudoers rule when it has opted in, and the
#      OS then verifies a leaf issued by that root,
#   3. removes exactly what it added, and the leaf stops verifying.
# Exit 0 only if every step held.
set -eu

FAILS=0
pass() { echo "PASS: $*"; }
fail() { echo "FAIL: $*"; FAILS=$((FAILS + 1)); }

. /etc/os-release
echo "== $PRETTY_NAME =="

if command -v apt-get >/dev/null 2>&1; then
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -qq >/dev/null
  apt-get install -y -qq sudo openssl ca-certificates >/dev/null
  FAMILY=debian
else
  dnf install -y -q sudo openssl ca-certificates >/dev/null
  FAMILY=rhel
fi

useradd -r -m kryptkeeper-agent
install -o root -g root -m 0755 /work/kryptkeeper-agent /usr/local/bin/kryptkeeper-agent

# The opt-in drop-in the agent itself prints, validated by visudo.
/usr/local/bin/kryptkeeper-agent --generate-trust-store-sudoers >/etc/sudoers.d/kryptkeeper-agent-truststore
chmod 0440 /etc/sudoers.d/kryptkeeper-agent-truststore
if visudo -cf /etc/sudoers.d/kryptkeeper-agent-truststore >/dev/null; then pass "sudoers drop-in passes visudo"; else fail "sudoers drop-in rejected by visudo"; fi
if grep -v '^#' /etc/sudoers.d/kryptkeeper-agent-truststore | grep -q '\*'; then fail "wildcard in the drop-in"; else pass "drop-in has no wildcard"; fi

# The sudo rule must be exactly the helper: any other command is refused.
if runuser -u kryptkeeper-agent -- sudo -n /bin/true 2>/dev/null; then fail "agent account can run arbitrary commands"; else pass "agent account cannot run anything else as root"; fi

# A throwaway CA, and a leaf issued by it. Test keys are generated here only.
mkdir -p /work/pki && cd /work/pki
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 2 -subj "/CN=KK Live Trust Root" \
  -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign,cRLSign" -keyout root.key -out root.pem 2>/dev/null
openssl req -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -subj "/CN=leaf.live.test" -keyout leaf.key -out leaf.csr 2>/dev/null
printf 'subjectAltName=DNS:leaf.live.test\nbasicConstraints=CA:FALSE\n' >leaf.ext
openssl x509 -req -in leaf.csr -CA root.pem -CAkey root.key -CAcreateserial -days 1 -extfile leaf.ext -out leaf.pem 2>/dev/null
FP=$(openssl x509 -in root.pem -outform DER | sha256sum | cut -d' ' -f1)
rm -f root.key # the root's key never needs to leave this step
chmod 0644 root.pem leaf.pem

trusted() { openssl verify leaf.pem >/dev/null 2>&1; }
if trusted; then fail "leaf trusted before anything was pushed"; else pass "leaf is not trusted before the push"; fi

nc_wait() { # wait for the Nth line of results
  n=$1
  i=0
  while [ "$i" -lt 40 ]; do
    [ -f /work/results.jsonl ] && [ "$(wc -l </work/results.jsonl)" -ge "$n" ] && return 0
    sleep 1
    i=$((i + 1))
  done
  return 1
}

/work/stubhub -addr 127.0.0.1:18080 -bundle /work/pki/root.pem -action-file /work/action -results /work/results.jsonl &
HUB=$!
sleep 1

start_agent() { # $1 = opt-in value or empty
  runuser -u kryptkeeper-agent -- env \
    KRYPTKEEPER_HUB_URL=http://127.0.0.1:18080 KRYPTKEEPER_AGENT_ID=live KRYPTKEEPER_AGENT_TOKEN=live \
    KRYPTKEEPER_POLL_INTERVAL=2 KRYPTKEEPER_SCAN_PATHS=/nonexistent KRYPTKEEPER_CONFIG_PATHS=/nonexistent \
    KRYPTKEEPER_TRUST_STORE_PUSH="$1" KRYPTKEEPER_OPS_ADDR=off \
    /usr/local/bin/kryptkeeper-agent >>/work/agent.log 2>&1 &
  AGENT=$!
}
stop_agent() { kill "$AGENT" 2>/dev/null || true; wait "$AGENT" 2>/dev/null || true; }

# 1. opted out
echo add >/work/action
start_agent ""
if nc_wait 1 && grep -q '"outcome":"refused_not_opted_in"' /work/results.jsonl; then pass "opted-out agent reports refused_not_opted_in"; else fail "no refusal reported"; fi
if trusted; then fail "opted-out agent changed the trust store"; else pass "opted-out agent left the trust store alone"; fi
stop_agent

# 2. opted in
start_agent true
if nc_wait 2 && tail -n1 /work/results.jsonl | grep -q '"outcome":"applied"'; then pass "opted-in agent reports applied"; else fail "add not applied: $(tail -n1 /work/results.jsonl)"; fi
if trusted; then pass "OS verifies a leaf issued by the pushed root"; else fail "leaf still untrusted after the push"; fi
if [ "$FAMILY" = debian ]; then F=/usr/local/share/ca-certificates/kryptkeeper-$FP.crt; else F=/etc/pki/ca-trust/source/anchors/kryptkeeper-$FP.crt; fi
if [ -f "$F" ]; then pass "anchor file $F exists"; else fail "anchor file $F missing"; fi
if grep -q "$FP" /var/lib/kryptkeeper-agent/trust-state.json; then pass "state file tracks the fingerprint"; else fail "state file lacks the fingerprint"; fi

# 3. remove
echo remove >/work/action
if nc_wait 3 && tail -n1 /work/results.jsonl | grep -q '"outcome":"applied"'; then pass "remove reported applied"; else fail "remove not applied: $(tail -n1 /work/results.jsonl)"; fi
if trusted; then fail "leaf still trusted after removal"; else pass "leaf is no longer trusted after removal"; fi
if [ -f "$F" ]; then fail "anchor file left behind"; else pass "anchor file removed"; fi
stop_agent
kill "$HUB" 2>/dev/null || true

echo "---- agent log (tail) ----"
tail -n 15 /work/agent.log || true
if [ "$FAILS" -ne 0 ]; then echo "RESULT: $FAILS failure(s)"; exit 1; fi
echo "RESULT: all steps passed on $PRETTY_NAME"
