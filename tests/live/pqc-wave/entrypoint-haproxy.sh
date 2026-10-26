#!/bin/sh
# W40-01 endpoint entrypoint: as entrypoint.sh, with haproxy (master-worker) instead of nginx.
set -e
rm -f /etc/ssh/ssh_host_*_key /etc/ssh/ssh_host_*_key.pub
ssh-keygen -A >/dev/null
printf '%s\n' "${AUTHORIZED_KEY:?}" >/root/.ssh/authorized_keys
chmod 600 /root/.ssh/authorized_keys
echo "root:$(head -c 24 /dev/urandom | od -An -tx1 | tr -d ' \n')" | chpasswd >/dev/null 2>&1
haproxy -c -f /etc/haproxy/haproxy.cfg
haproxy -W -p /run/haproxy.pid -f /etc/haproxy/haproxy.cfg &
exec /usr/sbin/sshd -D -e
