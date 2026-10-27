#!/bin/sh
# Runs INSIDE a distribution container for e2e.sh: sets the host up the way an
# operator would (agent account, the opt-in sudoers drop-in the agent prints),
# then runs the REAL agent in the foreground, unprivileged, against the real
# hub. Env: HUB_URL AGENT_ID AGENT_TOKEN AGENT_NAME. Mounts: /work (agent
# binary, read-only), /hubca (the hub's TLS trust export).
set -eu
if command -v apt-get >/dev/null 2>&1; then
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -qq >/dev/null
  apt-get install -y -qq sudo openssl ca-certificates >/dev/null
else
  dnf install -y -q sudo openssl ca-certificates >/dev/null
fi
useradd -r -m kryptkeeper-agent
install -o root -g root -m 0755 /work/kryptkeeper-agent /usr/local/bin/kryptkeeper-agent
/usr/local/bin/kryptkeeper-agent --generate-trust-store-sudoers >/etc/sudoers.d/kryptkeeper-agent-truststore
chmod 0440 /etc/sudoers.d/kryptkeeper-agent-truststore
visudo -cf /etc/sudoers.d/kryptkeeper-agent-truststore >/dev/null
touch /tmp/ready
exec runuser -u kryptkeeper-agent -- env \
  KRYPTKEEPER_HUB_URL="$HUB_URL" KRYPTKEEPER_HUB_CA_CERT_FILE=/hubca/ca.pem \
  KRYPTKEEPER_AGENT_ID="$AGENT_ID" KRYPTKEEPER_AGENT_TOKEN="$AGENT_TOKEN" KRYPTKEEPER_AGENT_NAME="$AGENT_NAME" \
  KRYPTKEEPER_POLL_INTERVAL=2 KRYPTKEEPER_SCAN_PATHS=/nonexistent KRYPTKEEPER_CONFIG_PATHS=/nonexistent \
  KRYPTKEEPER_TRUST_STORE_PUSH=true KRYPTKEEPER_OPS_ADDR=off \
  /usr/local/bin/kryptkeeper-agent
