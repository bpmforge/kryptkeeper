# shellcheck shell=bash
# W22-21: OIDC login through real Keycloak, group claim -> Kryptkeeper role.
# Sourced by run.sh after lib.sh.

STEP "OIDC: provision the fixture users over SCIM (login never creates accounts)"
ensure_users

STEP "OIDC: three mapped groups log in with the right role"
CB_alice=""
for pair in alice:pki-admin bob:pki-operator carol:auditor; do
  user="${pair%%:*}" want="${pair##*:}"
  cb="$(kc_login "$user" "$(fixture_pw "$user")")"
  case "$cb" in
    "$HUB_BASE"/api/v1/auth/oidc/callback\?*code=*state=*|"$HUB_BASE"/api/v1/auth/oidc/callback\?*state=*code=*) ;;
    *) FAIL "$user: Keycloak did not redirect to the hub callback with code+state (got: ${cb:-<empty>})"; continue ;;
  esac
  if [ "$user" = alice ]; then CB_alice="$cb"; fi
  code="$(callback_status "$user" "$cb")"
  if [ "$code" = 302 ] && has_session_cookie "$WORK/jar-$user-hub"; then
    PASS "$user: callback 302 with a kk_token session cookie"
  else
    FAIL "$user: callback returned $code (cookie present: $(has_session_cookie "$WORK/jar-$user-hub" && echo yes || echo no)), want 302 + kk_token"
    continue
  fi
  got="$(whoami_role "$WORK/jar-$user-hub")"
  [ "$got" = "$want" ] && PASS "$user: whoami role = $got" || FAIL "$user: whoami role = '$got', want $want"
done

STEP "OIDC: unmapped group is denied (default policy)"
cb="$(kc_login dave "$(fixture_pw dave)")"
code="$(callback_status dave "$cb")"
if [ "$code" = 403 ] && ! has_session_cookie "$WORK/jar-dave-hub"; then
  PASS "dave (kk-nobody): callback 403 and no kk_token cookie"
else
  FAIL "dave: callback returned $code (cookie present: $(has_session_cookie "$WORK/jar-dave-hub" && echo yes || echo no)), want 403 and no cookie"
fi

STEP "OIDC: a replayed or tampered state is rejected"
code="$(callback_status alice "$CB_alice")"
[ "$code" = 401 ] && PASS "replayed alice callback URL (state already consumed): 401" \
  || FAIL "replayed callback returned $code, want 401"
cb="$(kc_login alice "$(fixture_pw alice)")"
tampered="$(printf '%s' "$cb" | sed -E 's/([?&]state=)([^&]*)/\1\2x/')"
code="$(callback_status alice "$tampered")"
[ "$code" = 401 ] && PASS "callback with a mutated state value: 401" \
  || FAIL "mutated-state callback returned $code, want 401"

STEP "OIDC: APP_AUTH_UNMAPPED_ROLE=read-only is the explicit opt-in"
start_hub APP_AUTH_UNMAPPED_ROLE=read-only
cb="$(kc_login dave "$(fixture_pw dave)")"
code="$(callback_status dave "$cb")"
if [ "$code" = 302 ] && has_session_cookie "$WORK/jar-dave-hub"; then
  PASS "dave with read-only opt-in: callback 302 with a session cookie"
else
  FAIL "dave with opt-in: callback returned $code, want 302 + cookie"
fi
got="$(whoami_role "$WORK/jar-dave-hub")"
[ "$got" = viewer ] && PASS "dave with opt-in: whoami role = viewer" || FAIL "dave with opt-in: whoami role = '$got', want viewer"
start_hub
