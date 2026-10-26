#!/usr/bin/env bash
# Unit tests + ansible-test sanity for kryptkeeper.pki.
#   tests/run-checks.sh [python-version]    default 3.12 (CI); locally pass what you have, e.g. 3.14
# Needs ansible-core, pytest and cryptography installed in the active Python.
set -euo pipefail
here="$(cd "$(dirname "$0")/.." && pwd)"
pyver="${1:-3.12}"
python3 -m pytest "$here/tests/unit" -q -p no:cacheprovider
# ansible-test insists on the ansible_collections/<ns>/<name> layout.
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
mkdir -p "$tmp/ansible_collections/kryptkeeper"
cp -R "$here" "$tmp/ansible_collections/kryptkeeper/pki"
cd "$tmp/ansible_collections/kryptkeeper/pki"
ansible-test sanity --python "$pyver" --test validate-modules --test pep8 --test import \
  --test yamllint --test shebang --test compile --test no-assert --test runtime-metadata --test ansible-doc
