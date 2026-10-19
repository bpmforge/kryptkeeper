#!/bin/sh
# W24-11 fixture entrypoint: install the per-run public key for root and
# scanner, regenerate host keys, run sshd. nginx/apache are not started:
# discovery reads certificate files, it does not talk to the web servers.
set -e
if [ -f /tmp/authorized_keys ]; then
  cp /tmp/authorized_keys /root/.ssh/authorized_keys
  chmod 600 /root/.ssh/authorized_keys
  cp /tmp/authorized_keys /home/scanner/.ssh/authorized_keys
  chown scanner:scanner /home/scanner/.ssh/authorized_keys
  chmod 600 /home/scanner/.ssh/authorized_keys
fi
rm -f /etc/ssh/ssh_host_*_key /etc/ssh/ssh_host_*_key.pub
ssh-keygen -A >/dev/null
exec /usr/sbin/sshd -D -e
