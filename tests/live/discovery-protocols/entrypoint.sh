#!/bin/sh
# W24-03 fixture: start every service with its own throwaway cert.
set -e
CERTS=/etc/kk-certs
mkdir -p "$CERTS"
for svc in smtp imap postgres ldap rdp; do
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 30 \
    -subj "/CN=$svc.kk.test" -keyout "$CERTS/$svc.key" -out "$CERTS/$svc.crt" >/dev/null 2>&1
  chmod 644 "$CERTS/$svc.crt"; chmod 600 "$CERTS/$svc.key"
done

# --- postfix: 25 and 587, opportunistic TLS ---------------------------------
postconf -e "myhostname=smtp.kk.test" "inet_interfaces=all" "inet_protocols=ipv4" \
  "smtpd_tls_cert_file=$CERTS/smtp.crt" "smtpd_tls_key_file=$CERTS/smtp.key" \
  "smtpd_tls_security_level=may" "maillog_file=/dev/stdout"
grep -q '^submission' /etc/postfix/master.cf || \
  echo 'submission inet n - n - - smtpd
  -o smtpd_tls_security_level=may' >>/etc/postfix/master.cf
postfix start >/dev/null 2>&1

# --- dovecot: 143 STARTTLS, 110 STLS ----------------------------------------
cat >/etc/dovecot/local.conf <<DOVE
protocols = imap pop3
ssl = yes
ssl_cert = <$CERTS/imap.crt
ssl_key = <$CERTS/imap.key
disable_plaintext_auth = no
listen = *
DOVE
dovecot

# --- postgresql: 5432 with ssl=on -------------------------------------------
chown postgres:postgres "$CERTS/postgres.crt" "$CERTS/postgres.key"
chmod 600 "$CERTS/postgres.key"
PGCONF=$(ls /etc/postgresql/*/main/postgresql.conf)
{
  echo "listen_addresses = '*'"
  echo "ssl = on"
  echo "ssl_cert_file = '$CERTS/postgres.crt'"
  echo "ssl_key_file = '$CERTS/postgres.key'"
} >>"$PGCONF"
PGVER=$(basename "$(dirname "$(dirname "$PGCONF")")")
pg_ctlcluster "$PGVER" main start

# --- openldap: StartTLS on 389 ----------------------------------------------
chown openldap:openldap "$CERTS/ldap.crt" "$CERTS/ldap.key"
mkdir -p /run/slapd && chown openldap:openldap /run/slapd
slapd -h "ldap:/// ldapi:///" -u openldap -g openldap
for _ in $(seq 1 20); do
  ldapsearch -Y EXTERNAL -H ldapi:/// -b cn=config -s base dn >/dev/null 2>&1 && break
  sleep 1
done
ldapmodify -Y EXTERNAL -H ldapi:/// >/dev/null <<LDIF
dn: cn=config
changetype: modify
replace: olcTLSCertificateFile
olcTLSCertificateFile: $CERTS/ldap.crt
-
replace: olcTLSCertificateKeyFile
olcTLSCertificateKeyFile: $CERTS/ldap.key
LDIF

# --- xrdp: 3389 with TLS security layer -------------------------------------
sed -i -e "s|^security_layer=.*|security_layer=tls|" \
       -e "s|^certificate=.*|certificate=$CERTS/rdp.crt|" \
       -e "s|^key_file=.*|key_file=$CERTS/rdp.key|" /etc/xrdp/xrdp.ini
xrdp-sesman >/dev/null 2>&1 || true
xrdp -n >/var/log/xrdp-stdout.log 2>&1 &

# --- sshd: fresh host keys so the expected algorithm list comes from files --
rm -f /etc/ssh/ssh_host_*
ssh-keygen -A >/dev/null
exec /usr/sbin/sshd -D -e
