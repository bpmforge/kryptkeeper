// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package privexec

// HelperScript is the POSIX sh helper the customer installs root:root 0755 at
// DefaultHelperPath. Its verbs are the entire sudo allowlist in helper mode
// (D-114, D-209); the hub pins HelperSHA256() before first use.
const HelperScript = `#!/bin/sh
# kryptkeeper-helper: the only program the scan account may run as root.
# Verbs are the allowlist; keep it in sync with docs. Never prints private keys.
set -u
umask 077
PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH
VERSION=1
MAXSZ=1048576
CERT_EXT="pem crt cer cert der jks p12 pfx keystore truststore"
WRITE_EXT="pem crt cer cert key jks p12 pfx keystore truststore"

die() { printf 'kryptkeeper-helper: %s\n' "$*" >&2; exit 2; }

denied() {
  case $1 in
    /etc/shadow*|/etc/gshadow*|/etc/sudoers*|/root/.ssh|/root/.ssh/*) return 0 ;;
  esac
  return 1
}

# Absolute, no "..", conservative charset, not on the denylist (also after symlink resolution).
check_path() {
  case $1 in /*) ;; *) die "path must be absolute" ;; esac
  case $1 in *..*) die "path must not contain .." ;; esac
  case $1 in *[!A-Za-z0-9._/+@:,=-]*) die "unsupported character in path" ;; esac
  if denied "$1"; then die "path denied"; fi
  real=$(readlink -f "$1" 2>/dev/null) || real=$1
  if denied "$real"; then die "path denied"; fi
}

ext_ok() {
  e=${1##*.}
  [ "$e" != "$1" ] || return 1
  e=$(printf %s "$e" | tr 'A-Z' 'a-z')
  for x in $2; do [ "$e" = "$x" ] && return 0; done
  return 1
}

check_file() {
  check_path "$1"
  [ -f "$real" ] || die "not a regular file"
  sz=$(wc -c < "$real" | tr -d ' ')
  [ "$sz" -le "$MAXSZ" ] || die "file exceeds 1 MiB"
}

owner_uid() { stat -c %u "$1" 2>/dev/null || stat -f %u "$1" 2>/dev/null; }

pem_certs_only() {
  awk '/-----BEGIN CERTIFICATE-----/{p=1} p{print} /-----END CERTIFICATE-----/{p=0}'
}

v_version() { printf 'kryptkeeper-helper %s\n' "$VERSION"; }

v_list() {
  [ $# -eq 1 ] || die "usage: list <root>"
  check_path "$1"
  [ -d "$real" ] || die "not a directory"
  find "$real" -maxdepth 8 -type f 2>/dev/null | head -n 20000 | while IFS= read -r f; do
    ext_ok "$f" "$CERT_EXT" || continue
    denied "$f" && continue
    printf '%s\n' "$f"
  done
}

v_stat() {
  [ $# -eq 1 ] || die "usage: stat <path>"
  check_path "$1"
  [ -e "$real" ] || die "no such path"
  stat -c '%F|%a|%U|%G|%s|%n' "$real" 2>/dev/null || stat -f '%HT|%Lp|%Su|%Sg|%z|%N' "$real"
}

v_read_cert() {
  [ $# -eq 1 ] || die "usage: read-cert <path>"
  ext_ok "$1" "$CERT_EXT" || die "extension not allowed"
  check_file "$1"
  case $(printf %s "${1##*.}" | tr 'A-Z' 'a-z') in
    jks|p12|pfx|keystore|truststore)
      # -list never prints key material. A JKS lists its certificates without a
      # password; a PKCS12 keystore (the default type of current JDKs) needs one,
      # so the same default the hub tries unprivileged comes first.
      out=$(keytool -list -rfc -keystore "$real" -storepass changeit < /dev/null 2>/dev/null | pem_certs_only)
      [ -n "$out" ] || out=$(keytool -list -rfc -keystore "$real" < /dev/null 2>/dev/null | pem_certs_only)
      printf '%s\n' "$out"
      ;;
    der)
      openssl x509 -inform der -in "$real" -outform pem 2>/dev/null | pem_certs_only
      ;;
    *)
      if grep -q 'PRIVATE KEY' "$real"; then
        printf 'kryptkeeper-helper: refusing: file contains a private key\n' >&2
        exit 3
      fi
      pem_certs_only < "$real"
      ;;
  esac
}

v_listeners() {
  ss -ltnp 2>/dev/null || netstat -ltnp 2>/dev/null || die "ss and netstat unavailable"
  for p in $(ss -ltnp 2>/dev/null | grep -o 'pid=[0-9]*' | cut -d= -f2 | sort -u); do
    [ -d "/proc/$p" ] || continue
    printf 'proc pid=%s uid=%s exe=%s\n' "$p" \
      "$(awk '/^Uid:/{print $2}' "/proc/$p/status" 2>/dev/null)" \
      "$(readlink "/proc/$p/exe" 2>/dev/null)"
  done
}

v_install() {
  [ $# -eq 3 ] || [ $# -eq 4 ] || die "usage: install <tmp> <dst> <mode> [owner:group]"
  tmp=$1; dst=$2; mode=$3; og=${4:-}
  case $tmp in /tmp/*|/var/tmp/*) ;; *) die "staging file must be under /tmp or /var/tmp" ;; esac
  check_file "$tmp"
  [ ! -L "$tmp" ] || die "staging file must not be a symlink"
  if [ -n "${SUDO_UID:-}" ]; then
    [ "$(owner_uid "$tmp")" = "$SUDO_UID" ] || die "staging file not owned by caller"
  fi
  ext_ok "$dst" "$WRITE_EXT" || die "destination extension not allowed"
  check_path "$dst"
  [ ! -L "$dst" ] || die "destination must not be a symlink"
  [ ! -e "$dst" ] || [ -f "$dst" ] || die "destination exists and is not a regular file"
  dir=${dst%/*}
  [ -d "$dir" ] || die "destination directory missing"
  check_path "$dir"
  case $mode in [0-7][0-7][0-7]|0[0-7][0-7][0-7]) ;; *) die "bad mode (no setuid/setgid/sticky)" ;; esac
  if [ -z "$og" ]; then
    install -m "$mode" "$tmp" "$dst"
    return
  fi
  case $og in *:*) ;; *) die "owner must be owner:group" ;; esac
  own=${og%%:*}; grp=${og#*:}
  case $own in ""|[!a-z_]*|*[!a-z0-9_-]*) die "bad owner" ;; esac
  case $grp in ""|[!a-z_]*|*[!a-z0-9_-]*) die "bad group" ;; esac
  install -o "$own" -g "$grp" -m "$mode" "$tmp" "$dst"
}

# The rollback copy stays on the host, beside the file, so the hub never has
# to read a private key to be able to restore it.
prev_ok() {
  ext_ok "$1" "$WRITE_EXT" || die "extension not allowed"
  check_file "$1"
  prev="$real.kk-prev"
  [ ! -L "$prev" ] || die "backup path is a symlink"
}

v_backup() {
  [ $# -eq 1 ] || die "usage: backup <path>"
  prev_ok "$1"
  cp -p "$real" "$prev"
}

v_restore() {
  [ $# -eq 1 ] || die "usage: restore <path>"
  prev_ok "$1"
  [ -f "$prev" ] || die "no backup to restore"
  mv -f "$prev" "$real"
}

v_discard() {
  [ $# -eq 1 ] || die "usage: discard <path>"
  prev_ok "$1"
  rm -f "$prev"
}

v_config_test() {
  [ $# -eq 1 ] || die "usage: config-test <server_type>"
  case $1 in
    nginx) exec nginx -t ;;
    apache) exec apachectl configtest ;;
    haproxy) exec haproxy -c -f /etc/haproxy/haproxy.cfg ;;
    tomcat) exec /opt/tomcat/bin/catalina.sh configtest ;;
    *) die "unknown server type" ;;
  esac
}

v_reload() {
  [ $# -eq 1 ] || die "usage: reload <service>"
  case $1 in
    nginx|apache2|httpd|haproxy) exec systemctl reload "$1" ;;
    tomcat) exec systemctl restart tomcat ;;
    *) die "service not in reload table" ;;
  esac
}

[ $# -ge 1 ] || die "usage: kryptkeeper-helper <verb> [args]"
verb=$1; shift
case $verb in
  version) v_version ;;
  list) v_list "$@" ;;
  stat) v_stat "$@" ;;
  read-cert) v_read_cert "$@" ;;
  listeners) v_listeners ;;
  install) v_install "$@" ;;
  backup) v_backup "$@" ;;
  restore) v_restore "$@" ;;
  discard) v_discard "$@" ;;
  config-test) v_config_test "$@" ;;
  reload) v_reload "$@" ;;
  *) die "unknown verb" ;;
esac
`
