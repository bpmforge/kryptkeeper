#!/usr/bin/env bash
# W22-21/22: SSO live harness. Boots Keycloak (podman) and a real hub, then
# drives OIDC login with group-to-role mapping, SAML login and a SCIM
# create-then-deactivate timing check, with curl as the browser.
#
#   bash tests/live/sso/run.sh
#
# Parts are sourced in order if present: oidc.sh, saml.sh, scim.sh. Exits
# non-zero on any FAIL. See README.md.
set -u
set -o pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$HERE/lib.sh"

for tool in curl jq openssl go; do need "$tool"; done
[ -x "$PODMAN" ] || DIE "podman not found (set PODMAN=/path/to/podman)"

start_keycloak
build_hub
start_hub

for part in oidc saml scim; do
  # shellcheck disable=SC1090
  [ -f "$HERE/$part.sh" ] && . "$HERE/$part.sh"
done

echo
echo "=== RESULT: $PASSED passed, $FAILED failed ==="
[ "$FAILED" -eq 0 ]
