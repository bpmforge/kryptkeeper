#!/bin/sh
# W19-02 fixture entrypoint. ROLE selects which web server this container
# instance actually serves TLS from -- nginx and apache both default to
# :443 so one container can only run one of them; sshd runs in every
# container regardless of ROLE since that's the install transport under test.
set -e

ROLE="${ROLE:-nginx}"

# authorized_keys is bind-mounted in by run.sh at container start (the
# keypair is generated fresh per run, never baked into the image or repo).
mkdir -p /root/.ssh
chmod 700 /root/.ssh

# Host keys generated here (not at image build) so nginx-role and
# apache-role containers -- both from the same image -- get distinct host
# keys, which is what run.sh's per-target FixedHostKey pinning is proving.
# `ssh-keygen -A` only fills in MISSING key types -- and openssh-server's
# own apt postinst already generated one set at image-build time, baking a
# shared key into every container from this image -- so those files are
# removed first to force fresh generation on every container start.
rm -f /etc/ssh/ssh_host_*_key /etc/ssh/ssh_host_*_key.pub
ssh-keygen -A >/dev/null

case "$ROLE" in
  nginx)
    service apache2 stop 2>/dev/null || true
    nginx -t
    nginx -g "daemon off;" &
    ;;
  apache)
    service nginx stop 2>/dev/null || true
    apachectl configtest
    apachectl -D FOREGROUND &
    ;;
  *)
    echo "unknown ROLE: $ROLE" >&2
    exit 1
    ;;
esac

exec /usr/sbin/sshd -D -e
