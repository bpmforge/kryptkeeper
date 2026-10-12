#!/bin/sh
# postinstall for the kryptkeeper deb/rpm package. POSIX sh -- runs under
# dpkg's /bin/sh (dash) as well as rpm's, so no bashisms.
set -e

if ! getent group kryptkeeper >/dev/null 2>&1; then
    groupadd --system kryptkeeper
fi

if ! getent passwd kryptkeeper >/dev/null 2>&1; then
    useradd --system --gid kryptkeeper --shell /sbin/nologin \
        --home-dir /var/lib/kryptkeeper --no-create-home kryptkeeper
fi

mkdir -p /var/lib/kryptkeeper/keys
chown -R kryptkeeper:kryptkeeper /var/lib/kryptkeeper
chmod 0700 /var/lib/kryptkeeper/keys

# Never overwrite an operator's existing config -- only seed it once.
if [ ! -f /etc/kryptkeeper/env ]; then
    cp /etc/kryptkeeper/env.example /etc/kryptkeeper/env
    chown root:kryptkeeper /etc/kryptkeeper/env
    chmod 0640 /etc/kryptkeeper/env
fi

if command -v systemctl >/dev/null 2>&1; then
    systemctl daemon-reload || true
fi

cat <<'EOF'
kryptkeeper installed. Before starting the service:
  1. Edit /etc/kryptkeeper/env (set APP_BOOTSTRAP_TOKEN and
     KRYPTKEEPER_KEYSTORE_PASSPHRASE at minimum).
  2. systemctl enable --now kryptkeeper
See docs/deployment.md in the source repo for the full bare-metal install
procedure.
EOF
