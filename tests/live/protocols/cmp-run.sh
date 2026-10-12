#!/bin/sh
# Real CMP client: OpenSSL 3's `openssl cmp` app (RFC 4210/6712).
# W19-16: exercises RFC 4210 section 5.1.3.1 PasswordBasedMac protection
# (openssl's -secret/-ref) plus a bad-secret and unprotected-request
# rejection check, then -cmd kur.
#
# W19-31: the hub now serves /cmp over TLS only (self-issued, one listener
# for the whole mux). -tls_used enables openssl cmp's TLS client options;
# the actual trust-anchor flag is -tls_trusted, not -trusted (-trusted is
# for verifying the CMP message *signer*, a separate, orthogonal check --
# confirmed with `openssl cmp -help` in this same alpine image). CMP_CA is
# the CA bundle bind-mounted in by run.sh.
set -u
apk add --no-cache openssl >/dev/null 2>&1
mkdir -p /work
cd /work
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out newkey.pem >/dev/null 2>&1

echo "== cmp -cmd ir (valid -secret/-ref) =="
openssl cmp -cmd ir \
  -server "$CMP_URL" \
  -tls_used -tls_trusted "$CMP_CA" \
  -recipient "/CN=UAT Root CA" \
  -subject "/CN=uat-cmp-leaf" \
  -newkey newkey.pem \
  -secret "pass:$CMP_SECRET" \
  -ref "$CMP_REFERENCE" \
  -certout leaf.pem \
  -verbosity 8
RC=$?
echo "IR_RC=$RC"
if [ -f leaf.pem ]; then
  echo "== leaf.pem (ir succeeded) =="
  openssl x509 -in leaf.pem -noout -subject -issuer
else
  echo "== no leaf.pem: ir did not succeed =="
fi

echo "== cmp -cmd ir (wrong secret -- must be rejected) =="
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out wrongkey.pem >/dev/null 2>&1
openssl cmp -cmd ir \
  -server "$CMP_URL" \
  -tls_used -tls_trusted "$CMP_CA" \
  -recipient "/CN=UAT Root CA" \
  -subject "/CN=uat-cmp-wrongsecret" \
  -newkey wrongkey.pem \
  -secret "pass:not-the-real-secret" \
  -ref "$CMP_REFERENCE" \
  -certout wrong.pem \
  -verbosity 8
if [ -f wrong.pem ]; then
  echo "WRONGSECRET_REJECTED=0"
else
  echo "WRONGSECRET_REJECTED=1"
fi

echo "== cmp -cmd ir (unprotected -- must be rejected) =="
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out unprotkey.pem >/dev/null 2>&1
openssl cmp -cmd ir \
  -server "$CMP_URL" \
  -tls_used -tls_trusted "$CMP_CA" \
  -recipient "/CN=UAT Root CA" \
  -subject "/CN=uat-cmp-unprotected" \
  -newkey unprotkey.pem \
  -unprotected_requests \
  -certout unprot.pem \
  -verbosity 8
if [ -f unprot.pem ]; then
  echo "UNPROTECTED_REJECTED=0"
else
  echo "UNPROTECTED_REJECTED=1"
fi

echo "== cmp -cmd kur (key update, same shared secret) =="
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out kurkey.pem >/dev/null 2>&1
openssl cmp -cmd kur \
  -server "$CMP_URL" \
  -tls_used -tls_trusted "$CMP_CA" \
  -recipient "/CN=UAT Root CA" \
  -oldcert leaf.pem \
  -newkey kurkey.pem \
  -secret "pass:$CMP_SECRET" \
  -ref "$CMP_REFERENCE" \
  -certout kur.pem \
  -verbosity 8
KUR_RC=$?
echo "KUR_RC=$KUR_RC"
if [ -f kur.pem ]; then
  echo "== kur.pem (kur succeeded) =="
  openssl x509 -in kur.pem -noout -subject -issuer
else
  echo "== no kur.pem: kur did not succeed =="
fi
