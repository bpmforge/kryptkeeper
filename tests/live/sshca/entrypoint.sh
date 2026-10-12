#!/bin/sh
# Fresh host keys per container, then wait for run.sh to install the CA line
# and the host certificate (signed over this container's host key) before
# sshd starts, so sshd never runs without them.
set -e
rm -f /etc/ssh/ssh_host_*_key /etc/ssh/ssh_host_*_key.pub
ssh-keygen -A >/dev/null
while [ ! -f /etc/ssh/kk-ready ]; do sleep 0.2; done
exec /usr/sbin/sshd -D -e
