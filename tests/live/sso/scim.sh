# shellcheck shell=bash
# W22-22: SCIM create-then-deactivate, timed. Keycloak has no SCIM client, so
# this script plays the IdP. Sourced by run.sh after saml.sh.

STEP "SCIM: create erin, log her in over OIDC, deactivate, time how long access survives"
ensure_saml_fixtures
start_hub

if provision_user erin; then
  eid="$(cat "$WORK/uid-erin")"
  cb="$(kc_login erin "$(fixture_pw erin)")"
  code="$(callback_status erin "$cb")"
  got="$(whoami_role "$WORK/jar-erin-hub")"
  if [ "$code" = 302 ] && [ "$got" = pki-operator ]; then
    PASS "erin: OIDC login 302, whoami role = pki-operator"
    t0="$(date +%s)"
    code="$(scim_patch "/scim/v2/Users/$eid" '{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"replace","path":"active","value":false}]}')"
    if [ "$code" = 200 ] && [ "$(jq -r .active "$WORK/scim-body")" = false ]; then
      PASS "SCIM PATCH active=false: 200 with active:false"
      elapsed=""
      while :; do
        now="$(date +%s)"
        if [ "$(hub_status "$HUB_BASE/api/v1/protected/whoami" "$WORK/jar-erin-hub")" = 401 ]; then
          elapsed=$((now - t0)); break
        fi
        [ $((now - t0)) -ge 900 ] && break
        sleep 5
      done
      if [ -n "$elapsed" ] && [ "$elapsed" -le 900 ]; then
        PASS "erin's old session cookie returned 401 ${elapsed}s after SCIM deactivation (limit 900s)"
      else
        FAIL "erin's old session cookie still worked 900s after SCIM deactivation"
      fi
      cb="$(kc_login erin "$(fixture_pw erin)")"
      code="$(callback_status erin "$cb")"
      [ "$code" = 401 ] && PASS "erin: a fresh OIDC login after deactivation: 401" \
        || FAIL "erin: fresh OIDC login after deactivation returned $code, want 401"
    else
      FAIL "SCIM PATCH active=false returned $code, want 200 with active:false"
    fi
  else
    FAIL "erin: OIDC login returned $code with role '$got', want 302 and pki-operator"
  fi
fi
