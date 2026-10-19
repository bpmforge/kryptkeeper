#!/bin/sh
# W31-11 endpoint entrypoint: per-container host keys, root key login from $AUTHORIZED_KEY
# (generated fresh by run.sh, never baked into the image), nginx in the background, sshd in front.
set -e
rm -f /etc/ssh/ssh_host_*_key /etc/ssh/ssh_host_*_key.pub
ssh-keygen -A >/dev/null
printf '%s\n' "${AUTHORIZED_KEY:?}" >/root/.ssh/authorized_keys
chmod 600 /root/.ssh/authorized_keys
# Alpine locks root's password ("!"), which sshd treats as a locked account even for key login.
echo "root:$(head -c 24 /dev/urandom | od -An -tx1 | tr -d ' \n')" | chpasswd >/dev/null 2>&1
nginx -t
nginx -g "daemon off;" &
exec /usr/sbin/sshd -D -e
