#!/bin/sh
# Real SCEP client: micromdm/scep (maintained Go reimplementation of the
# sscep protocol handling; builds cleanly with `go install`, unlike sscep's
# autotools build which needs libssl-dev headers not worth vendoring here).
#
# W20-16: enrollment needs a one-time challenge minted by run.sh through
# POST /api/v1/scep/challenges, and the hub issues the names bound to that
# challenge, never the CSR's. Four enrollments, each with a fresh device key:
#   first  - fresh challenge                  -> issued, CN = bound name
#   reuse  - the same challenge again          -> refused
#   wrong  - a challenge the hub never minted  -> refused
#   bound  - fresh challenge, CSR says Administrator -> issued, CN = bound name
# Each prints one "RESULT <label> ..." line for run.sh; issued certificates
# go to /out (a host-mounted volume) so run.sh can chain-verify them.
#
# W26-11 renewal (W26-30): scepclient sends a RenewalReq (type 17) signed by the
# certificate in -certificate when that file already exists, and overwrites it
# with the new certificate on success (cmd/scepclient: msgType = RenewalReq when
# the -certificate file loads). So a refusal leaves the OLD certificate in the
# file; renew() decides by exit status and by the serial changing.
#   renew          - signed by the current cert (first)         -> issued, same CN
#   renew-rogue    - first's cert, an unrelated private key      -> refused
#   renew-foreign  - a self-signed cert the CA never issued      -> refused
#   replay         - first's already-used challenge, after renewal -> refused
set -u
apk add --no-cache openssl >/dev/null 2>&1
mkdir -p /work /out
cd /work
go install github.com/micromdm/scep/v2/cmd/scepclient@latest >/tmp/get.log 2>&1 || cat /tmp/get.log
export PATH=$PATH:/root/go/bin

enroll() {
  label=$1 challenge=$2 cn=$3
  # Each enrollment's key in its own directory: scepclient keeps csr.pem
  # and self.pem next to the private key and reuses them on the next run
  # (cmd/scepclient: dir := filepath.Dir(-private-key)), so a shared
  # directory resends the first run's CSR, old challenge and all.
  mkdir -p "/work/$label"
  # sscep/micromdm-scep require a PKCS#1 ("RSA PRIVATE KEY") self-signer
  # key, not the PKCS#8 default openssl now writes.
  openssl genrsa -traditional -out "/work/$label/key.pem" 3072 >/dev/null 2>&1
  echo "== scepclient enroll ($label, CSR CN=$cn) =="
  scepclient -server-url "$SCEP_URL" -challenge "$challenge" -cn "$cn" \
    -certificate "/work/$label.pem" -private-key "/work/$label/key.pem" -keySize 3072 -debug
  if [ -s "/work/$label.pem" ] && openssl x509 -in "/work/$label.pem" -noout >/dev/null 2>&1; then
    cp "/work/$label.pem" "/out/$label.pem"
    echo "RESULT $label issued subject=$(openssl x509 -in "/work/$label.pem" -noout -subject -nameopt RFC2253 | sed 's/^subject=//') san=$(openssl x509 -in "/work/$label.pem" -noout -ext subjectAltName 2>/dev/null | tail -1 | tr -d ' ')"
  else
    echo "RESULT $label refused"
  fi
}

enroll first "$SCEP_CHALLENGE" "$SCEP_CN"
enroll reuse "$SCEP_CHALLENGE" "$SCEP_CN"
enroll wrong "0000000000000000000000000000000000000000000000000000000000000000" "$SCEP_CN"
enroll bound "$SCEP_CHALLENGE2" Administrator

# renew <label> <cert source> <key source>: renews with the given signer.
renew() {
  label=$1 certsrc=$2 keysrc=$3
  mkdir -p "/work/$label"
  cp "$keysrc" "/work/$label/key.pem"
  cp "$certsrc" "/work/$label.pem"
  old=$(openssl x509 -in "/work/$label.pem" -noout -serial | cut -d= -f2)
  echo "== scepclient renew ($label, signer serial $old) =="
  scepclient -server-url "$SCEP_URL" -cn "$SCEP_CN" \
    -certificate "/work/$label.pem" -private-key "/work/$label/key.pem" -keySize 3072 -debug
  rc=$?
  new=$(openssl x509 -in "/work/$label.pem" -noout -serial 2>/dev/null | cut -d= -f2)
  if [ "$rc" = 0 ] && [ -n "$new" ] && [ "$new" != "$old" ]; then
    cp "/work/$label.pem" "/out/$label.pem"
    echo "RESULT $label issued old_serial=$old new_serial=$new subject=$(openssl x509 -in "/work/$label.pem" -noout -subject -nameopt RFC2253 | sed 's/^subject=//')"
  else
    echo "RESULT $label refused rc=$rc"
  fi
}

if [ -s /work/first.pem ]; then
  renew renew /work/first.pem /work/first/key.pem

  # An unrelated key: the signer certificate is first's, the signature is not.
  mkdir -p /work/rogue
  openssl genrsa -traditional -out /work/rogue/key.pem 3072 >/dev/null 2>&1
  renew renew-rogue /work/first.pem /work/rogue/key.pem

  # A certificate the CA never issued (self-signed): RenewalReq from a
  # self-signed signer is refused, never treated as an enrollment.
  mkdir -p /work/foreign
  openssl genrsa -traditional -out /work/foreign/key.pem 3072 >/dev/null 2>&1
  openssl req -x509 -new -key /work/foreign/key.pem -subj "/CN=$SCEP_CN" -days 30 -out /work/foreign/cert.pem >/dev/null 2>&1
  renew renew-foreign /work/foreign/cert.pem /work/foreign/key.pem

  # The challenge replay still fails after a renewal.
  enroll replay "$SCEP_CHALLENGE" "$SCEP_CN"
else
  echo "RESULT renew skipped: no first.pem (initial enrollment did not issue)"
fi
