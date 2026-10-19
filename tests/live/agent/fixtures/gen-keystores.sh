#!/bin/sh
# Regenerates the W24-16 keystore fixtures into this directory. Needs openssl
# (3.x) and keytool (any JDK/JRE). Run `sh gen-keystores.sh`, or inside a
# container: podman run --rm -v "$PWD:/out" ubuntu:24.04 sh -c \
#   'apt-get update && apt-get install -y openssl openjdk-17-jre-headless && cd /out && sh gen-keystores.sh'
# Subject CNs are fixed (jks1..3, p12-leaf, p12-ca, kube-client .kryptkeeper.uat.local);
# keys and serials are fresh each run, so regenerating changes the binaries.
# No private key is committed: the P12 leaf key is imported and discarded, and
# the JKS holds trusted certificate entries only.
set -e
cd "$(dirname "$0")"
W=$(mktemp -d)
trap 'rm -rf "$W"' EXIT
DAYS=3650
ec() { # cn key crt [signing opts...]
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days $DAYS \
    -subj "/CN=$1" -keyout "$2" -out "$3" >/dev/null 2>&1
}

rm -f store3.jks store2.p12 kubeconfig
# JKS: 3 trustedCertEntry
for n in 1 2 3; do
  ec "jks$n.kryptkeeper.uat.local" "$W/jks$n.key" "$W/jks$n.pem"
  keytool -importcert -noprompt -alias "a$n" -file "$W/jks$n.pem" \
    -keystore store3.jks -storepass changeit -storetype JKS >/dev/null 2>&1
done

# PKCS#12: CA + leaf signed by it, legacy SHA-1 MAC profile (ParsePKCS12Certs
# uses golang.org/x/crypto/pkcs12, SHA-1 MAC only). Password changeit.
ec "p12-ca.kryptkeeper.uat.local" "$W/ca.key" "$W/ca.pem"
openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
  -subj "/CN=p12-leaf.kryptkeeper.uat.local" -keyout "$W/leaf.key" -out "$W/leaf.csr" >/dev/null 2>&1
openssl x509 -req -in "$W/leaf.csr" -CA "$W/ca.pem" -CAkey "$W/ca.key" -CAcreateserial \
  -days $DAYS -out "$W/leaf.pem" >/dev/null 2>&1
openssl pkcs12 -export -legacy -inkey "$W/leaf.key" -in "$W/leaf.pem" -certfile "$W/ca.pem" \
  -out store2.p12 -passout pass:changeit

# kubeconfig: one client-certificate-data cluster user. The key is a throwaway
# placeholder string, not key material: discovery reads certificates only.
ec "kube-client.kryptkeeper.uat.local" "$W/kube.key" "$W/kube.pem"
CERT_B64=$(base64 <"$W/kube.pem" | tr -d '\n')
cat >kubeconfig <<KC
apiVersion: v1
kind: Config
clusters:
- name: uat
  cluster:
    server: https://127.0.0.1:6443
users:
- name: kube-client
  user:
    client-certificate-data: $CERT_B64
contexts:
- name: uat
  context:
    cluster: uat
    user: kube-client
current-context: uat
KC
echo "wrote store3.jks store2.p12 kubeconfig"
