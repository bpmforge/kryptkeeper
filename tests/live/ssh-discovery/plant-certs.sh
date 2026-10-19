#!/bin/sh
# Plant the W24-11 certificates. Self-signed, 30-day, CN marker kk-ssh-*.
set -e
mkdir -p /etc/nginx/ssl /etc/apache2/ssl/locked /opt/ssl /tmp/plant
mk() { # cn out.crt
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 30 \
    -subj "/CN=$1" -keyout /tmp/plant/k.key -out "$2" >/dev/null 2>&1
}
mk kk-ssh-web1   /etc/nginx/ssl/web1.crt
mk kk-ssh-web2   /etc/nginx/ssl/web2.crt
mk kk-ssh-site1  /etc/apache2/ssl/site1.crt
mk kk-ssh-locked /etc/nginx/ssl/locked.crt
mk kk-ssh-hidden /etc/apache2/ssl/locked/hidden.crt
# JKS with two trusted-certificate entries (certificates only, no key material).
mk kk-ssh-jks1 /tmp/plant/jks1.crt
mk kk-ssh-jks2 /tmp/plant/jks2.crt
for n in 1 2; do
  keytool -importcert -noprompt -alias "kk-ssh-jks$n" -file "/tmp/plant/jks$n.crt" \
    -keystore /opt/ssl/app.jks -storepass changeit -storetype JKS >/dev/null 2>&1
done
chmod 644 /etc/nginx/ssl/web1.crt /etc/nginx/ssl/web2.crt /etc/apache2/ssl/site1.crt /opt/ssl/app.jks
chmod 755 /opt/ssl /etc/nginx/ssl /etc/apache2/ssl
chmod 600 /etc/nginx/ssl/locked.crt /etc/apache2/ssl/locked/hidden.crt
chmod 700 /etc/apache2/ssl/locked
chown root:root /etc/nginx/ssl/locked.crt /etc/apache2/ssl/locked /etc/apache2/ssl/locked/hidden.crt
rm -rf /tmp/plant
