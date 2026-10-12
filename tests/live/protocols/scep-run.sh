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
  openssl genrsa -traditional -out "/work/$label/key.pem" 2048 >/dev/null 2>&1
  echo "== scepclient enroll ($label, CSR CN=$cn) =="
  scepclient -server-url "$SCEP_URL" -challenge "$challenge" -cn "$cn" \
    -certificate "/work/$label.pem" -private-key "/work/$label/key.pem" -keySize 2048 -debug
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
