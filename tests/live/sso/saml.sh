# shellcheck shell=bash
# W22-22: SAML login through real Keycloak. Sourced by run.sh after oidc.sh.

STEP "SAML: import the SAML clients and point the hub at realm kk"
ensure_saml_fixtures
ensure_users
configure_hub_saml

STEP "SAML: mapped users log in with the right role (control for every rejection below)"
for pair in alice:pki-admin bob:pki-operator; do
  user="${pair%%:*}" want="${pair##*:}"
  if ! saml_login "$user" "$(fixture_pw "$user")" "$user"; then FAIL "$user: could not obtain a SAMLResponse from Keycloak"; continue; fi
  code="$(saml_acs_post "$user" "$user")"
  if [ "$code" = 302 ] && has_session_cookie "$WORK/jar-saml-$user-hub"; then
    PASS "$user: ACS 302 with a kk_token session cookie"
  else
    FAIL "$user: ACS returned $code, want 302 + kk_token"; continue
  fi
  got="$(whoami_role "$WORK/jar-saml-$user-hub")"
  [ "$got" = "$want" ] && PASS "$user via SAML: whoami role = $got" || FAIL "$user via SAML: whoami role = '$got', want $want"
done

STEP "SAML: a replayed assertion is rejected"
code="$(saml_acs_post alice alice)"
[ "$code" = 401 ] && PASS "alice's identical SAMLResponse posted a second time: 401" \
  || FAIL "replayed SAMLResponse returned $code, want 401"

STEP "SAML: an expired assertion is rejected (assertion lifespan 8s)"
if saml_login alice "$(fixture_pw alice)" alice-stale; then
  echo "(request id is still inside its 10 min TTL, so a 401 below is the assertion time check, not the request binding)"
  sleep 20
  code="$(saml_acs_post alice alice-stale)"
  [ "$code" = 401 ] && PASS "SAMLResponse posted 20s after issue (lifespan 8s): 401" \
    || FAIL "expired SAMLResponse returned $code, want 401"
else
  FAIL "alice: could not obtain a fresh SAMLResponse for the expiry check"
fi

STEP "SAML: wrong audience is rejected (IdP-initiated control vs kk-other)"
configure_hub_saml APP_SAML_ALLOW_IDP_INITIATED=true
if saml_idp_initiated alice kk-sp alice-idp-ok; then
  code="$(saml_acs_post alice alice-idp-ok)"
  if [ "$code" = 302 ]; then
    PASS "control: IdP-initiated response from kk-sp (audience kk-saml-sp) accepted: 302"
    if saml_idp_initiated alice kk-other alice-idp-bad; then
      code="$(saml_acs_post alice alice-idp-bad)"
      [ "$code" = 401 ] && PASS "IdP-initiated response from kk-other (audience kk-saml-other): 401" \
        || FAIL "wrong-audience response returned $code, want 401"
    else
      FAIL "could not obtain the kk-other IdP-initiated response"
    fi
  else
    FAIL "control IdP-initiated response returned $code, want 302; wrong-audience result would prove nothing"
  fi
else
  FAIL "could not obtain the kk-sp IdP-initiated response"
fi
configure_hub_saml

STEP "SAML: unmapped group is denied"
if saml_login dave "$(fixture_pw dave)" dave; then
  code="$(saml_acs_post dave dave)"
  if [ "$code" = 403 ] && ! has_session_cookie "$WORK/jar-saml-dave-hub"; then
    PASS "dave (kk-nobody) via SAML: ACS 403 and no kk_token cookie"
  else
    FAIL "dave via SAML: ACS returned $code, want 403 and no cookie"
  fi
else
  FAIL "dave: could not obtain a SAMLResponse from Keycloak"
fi
