#!/bin/bash
# Entry for the libest estserver container. libest's example CA scripts build
# the demo EST CA; the server certificate is re-issued here so it carries the
# SAN a Go TLS client requires (the example one is CN=127.0.0.1 only).
# The client credential estuser / estpwd is libest's own documented example
# credential for this test server; it is not a Kryptkeeper secret.
set -e
NAME="${EST_SERVER_NAME:-localhost}" # the container name the hub dials; localhost and 127.0.0.1 are always added
cd /src/example/server
echo | ./createCA.sh >/tmp/createCA.log 2>&1
openssl req -new -newkey rsa:2048 -nodes -keyout /tmp/srv.key -out /tmp/srv.csr -subj "/CN=$NAME" 2>/dev/null
printf 'subjectAltName=DNS:%s,DNS:localhost,IP:127.0.0.1\nextendedKeyUsage=serverAuth\n' "$NAME" >/tmp/srv.ext
openssl x509 -req -in /tmp/srv.csr -CA estCA/cacert.crt -CAkey estCA/private/cakey.pem -CAcreateserial -days 30 -extfile /tmp/srv.ext -out /tmp/srv.crt 2>/dev/null
cat /tmp/srv.crt /tmp/srv.key > estCA/private/estservercertandkey.pem
rm -f /tmp/srv.key
[ -d /out ] && cp estCA/cacert.crt /out/est-ca.pem
export EST_TRUSTED_CERTS=./trustedcerts.crt
export EST_CACERTS_RESP=./estCA/cacert.crt
export EST_OPENSSL_CACONFIG=./estExampleCA.cnf
exec ./estserver -c estCA/private/estservercertandkey.pem -k estCA/private/estservercertandkey.pem -r estrealm -b -p 8085 -v
