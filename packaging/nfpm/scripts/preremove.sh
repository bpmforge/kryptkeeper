#!/bin/sh
# preremove for the kryptkeeper deb/rpm package. POSIX sh.
set -e

if command -v systemctl >/dev/null 2>&1; then
    systemctl stop kryptkeeper.service 2>/dev/null || true
    systemctl disable kryptkeeper.service 2>/dev/null || true
fi

# Deliberately does not touch /var/lib/kryptkeeper (key material, database)
# or /etc/kryptkeeper (config) -- removal is not destruction. An operator
# who wants those gone deletes them explicitly.
