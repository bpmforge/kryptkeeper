#!/usr/bin/env bash
# Runs INSIDE the container (see run.sh). Prints "RES|<step>|PASS|FAIL|<detail>"
# lines; the outer script builds the table from them. Exit 0 always -- the
# outer script decides from the RES lines.
set -u
FAM="$1"                       # deb | rpm
SRC=/src                       # repo checkout, read-only
: "${PKG_REPO_URL:=}" "${PKG_REPO_KEY_URL:=}" "${PKG_OLD_VERSION:=}" "${PKG_NEW_VERSION:=}"
STEP_FAIL=0
STEP_NOTES=""

note() { STEP_NOTES="$STEP_NOTES $*;"; }
check() { # check <desc> <cmd...>
  local d="$1"; shift
  if "$@" >/dev/null 2>&1; then note "ok:$d"; else note "BAD:$d"; STEP_FAIL=1; fi
}
end_step() { # end_step <name>
  local r=PASS; [ "$STEP_FAIL" -eq 0 ] || r=FAIL
  echo "RES|$FAM|$1|$r|${STEP_NOTES# }"
  STEP_FAIL=0; STEP_NOTES=""
}
pkg_version() {
  if [ "$FAM" = deb ]; then dpkg-query -W -f='${Version}' kryptkeeper
  else rpm -q --qf '%{VERSION}' kryptkeeper; fi
}

install_old() {
  if [ "$PKG_SOURCE" = local ]; then
    if [ "$FAM" = deb ]; then apt-get install -y -qq /w/old.deb; else dnf install -y -q /w/old.rpm; fi
  else
    if [ "$FAM" = deb ]; then apt-get install -y -qq "kryptkeeper=$PKG_OLD_VERSION"
    else dnf install -y -q "kryptkeeper-$PKG_OLD_VERSION"; fi
  fi
}
install_new() {
  if [ "$PKG_SOURCE" = local ]; then
    if [ "$FAM" = deb ]; then apt-get install -y -qq /w/new.deb; else dnf upgrade -y -q /w/new.rpm; fi
  else
    if [ "$FAM" = deb ]; then apt-get install -y -qq "kryptkeeper=$PKG_NEW_VERSION"
    else dnf upgrade -y -q "kryptkeeper-$PKG_NEW_VERSION"; fi
  fi
}

# ---- container setup (not part of the package) ----
if [ "$FAM" = deb ]; then
  apt-get update -qq >/dev/null 2>&1
  if [ "$PKG_SOURCE" = repo ]; then
    apt-get install -y -qq curl gnupg ca-certificates >/dev/null 2>&1
    mkdir -p /etc/apt/keyrings
    curl -fsSL "$PKG_REPO_KEY_URL" -o /etc/apt/keyrings/kryptkeeper.gpg
    echo "deb [signed-by=/etc/apt/keyrings/kryptkeeper.gpg] $PKG_REPO_URL/apt stable main" \
      > /etc/apt/sources.list.d/kryptkeeper.list
    apt-get update -qq >/dev/null 2>&1
  fi
else
  # Package scripts need groupadd/useradd. Rocky 9 images ship shadow-utils;
  # install it here (not in the package) if a slimmer image ever lacks it.
  rpm -q shadow-utils >/dev/null 2>&1 || dnf install -y -q shadow-utils >/dev/null 2>&1
  if [ "$PKG_SOURCE" = repo ]; then
    curl -fsSL "$PKG_REPO_URL/kryptkeeper.repo" -o /etc/yum.repos.d/kryptkeeper.repo
  fi
fi

# ---- 1. precondition ----
if getent passwd kryptkeeper >/dev/null 2>&1; then note "user already exists"; STEP_FAIL=1; else note "no user"; fi
end_step precondition_no_user

# ---- 2. install old ----
install_old; rc=$?
check "install_exit_$rc" test "$rc" -eq 0
check "user_exists" getent passwd kryptkeeper
check "shell_nologin" test "$(getent passwd kryptkeeper | cut -d: -f7)" = /sbin/nologin
check "bin" test -x /usr/bin/kryptkeeper
check "unit" test -f /usr/lib/systemd/system/kryptkeeper.service
check "env_640_root:kryptkeeper" test "$(stat -c '%a %U:%G' /etc/kryptkeeper/env)" = "640 root:kryptkeeper"
check "keys_700" test "$(stat -c %a /var/lib/kryptkeeper/keys)" = 700
# ---- 3. no auto-start ----
check "no_process" bash -c '! grep -l "^kryptkeeper$" /proc/[0-9]*/comm 2>/dev/null | grep -q .'
# Only lines that begin with systemctl count; the "systemctl enable --now"
# text in postinstall is inside a heredoc echo and starts with "  2.".
check "postinstall_never_starts" bash -c "! grep -En '^[[:space:]]*systemctl[[:space:]].*(start|enable)' $SRC/packaging/nfpm/scripts/postinstall.sh"
check "systemctl_absent_so_no_start_possible" bash -c '! command -v systemctl'
end_step "${FAM}_install_creates_user_no_start"

# ---- 4. edit env ----
echo 'UAT_MARKER=1' >> /etc/kryptkeeper/env
BEFORE="$(sha256sum /etc/kryptkeeper/env | cut -d' ' -f1)"
echo "INFO|$FAM|env_sha256_before|$BEFORE"

# ---- 5. upgrade ----
install_new; rc=$?
check "upgrade_exit_$rc" test "$rc" -eq 0
want="$([ "$PKG_SOURCE" = local ] && echo 0.0.2 || echo "$PKG_NEW_VERSION")"
check "version_$(pkg_version)_want_$want" test "$(pkg_version)" = "$want"
AFTER="$(sha256sum /etc/kryptkeeper/env | cut -d' ' -f1)"
echo "INFO|$FAM|env_sha256_after|$AFTER"
check "env_sha256_identical" test "$BEFORE" = "$AFTER"
check "marker_kept" grep -q '^UAT_MARKER=1$' /etc/kryptkeeper/env
check "user_still_exists" getent passwd kryptkeeper
end_step "${FAM}_upgrade_env_sha256_identical"

# ---- 6. remove ----
if [ "$FAM" = deb ]; then apt-get remove -y -qq kryptkeeper; else dnf remove -y -q kryptkeeper; fi; rc=$?
check "remove_exit_$rc" test "$rc" -eq 0
check "bin_gone" test ! -e /usr/bin/kryptkeeper
check "unit_gone" test ! -e /usr/lib/systemd/system/kryptkeeper.service
check "env_kept" test -f /etc/kryptkeeper/env
check "env_sha256_still_identical" test "$(sha256sum /etc/kryptkeeper/env | cut -d' ' -f1)" = "$BEFORE"
check "data_dir_kept" test -d /var/lib/kryptkeeper
check "keys_dir_kept" test -d /var/lib/kryptkeeper/keys
end_step "${FAM}_remove_keeps_data"
exit 0
