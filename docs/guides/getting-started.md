# Getting Started with Kryptkeeper

This guide takes you from zero to issuing, verifying and revoking your first
certificate with Docker Compose. On a fresh Ubuntu 24.04 VM with 4 vCPU, the
first `docker compose up` built and started the hub in under 3 minutes
([`DAY_ONE_RUN_v1.1.md`](../release/DAY_ONE_RUN_v1.1.md)).

## Prerequisites

- Docker 24+ with Docker Compose v2 and BuildKit (on Ubuntu:
  `apt install docker.io docker-compose-v2 docker-buildx`)
- `curl`, `openssl` and `jq` in your shell

## 1. Start the Hub

```bash
git clone https://github.com/bpmforge/kryptkeeper.git
cd kryptkeeper
cp env.example .env
```

Edit `.env` and set two values. Compose refuses to start without either, and
they must differ:

```bash
APP_BOOTSTRAP_TOKEN=<openssl rand -hex 32>
KRYPTKEEPER_KEYSTORE_PASSPHRASE=<openssl rand -hex 32>
```

Then start it:

```bash
docker compose up -d
```

The first start builds the images from source and creates a default root CA
(`KRYPTKEEPER_BOOTSTRAP_CREATE_ROOT=true` in `env.example`). The API listens on
**https://localhost:8080** with a certificate from that root; the dashboard is
on **http://localhost:3000**.

### Verify it's running

Export the hub's CA certificate once and use it with every `curl`:

```bash
docker run --rm -v kryptkeeper_tls-trust:/trust:ro alpine cat /trust/ca.pem > ca.pem
curl --cacert ca.pem https://localhost:8080/healthz
# → {"status":"ok"}
```

Set up your shell for the steps below, using the `APP_BOOTSTRAP_TOKEN` from
`.env` as the bearer token:

```bash
export TOKEN=<your APP_BOOTSTRAP_TOKEN>
API=https://localhost:8080/api/v1
auth=(--cacert ca.pem -H "Authorization: Bearer $TOKEN")
```

## 2. Find (or create) a Root CA

```bash
# The default root CA created on first start
CA_ID=$(curl -s "${auth[@]}" $API/cas | jq -r '.data[0].id')

# Optional: create another root CA instead (subject_cn is the only required field)
curl -s "${auth[@]}" -X POST $API/cas -H "Content-Type: application/json" \
  -d '{"name": "My Root CA", "type": "root", "subject_cn": "My Root CA", "algorithm": "ECDSA-P256"}' | jq .
```

## 3. Create a Certificate Template

A fresh install has no templates, and issuance requires one.

```bash
TEMPLATE_ID=$(curl -s "${auth[@]}" -X POST $API/templates -H "Content-Type: application/json" -d '{
  "name": "tls-server",
  "display_name": "TLS Server (90 days)",
  "key_usage": ["digitalSignature"],
  "extended_key_usage": ["serverAuth"],
  "allowed_algorithms": ["ECDSA", "RSA"],
  "validity_period": "P90D",
  "active": true
}' | jq -r '.data.id')
```

## 4. Issue a Certificate

Issuance is CSR-in: you keep the private key, and Kryptkeeper only sees the CSR.

```bash
openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
  -keyout server.key -out server.csr -subj "/CN=app.example.com" \
  -addext "subjectAltName=DNS:app.example.com"

FINGERPRINT=$(jq -n --arg ca "$CA_ID" --arg tpl "$TEMPLATE_ID" --rawfile csr server.csr \
  '{ca_id: $ca, template_id: $tpl, csr_pem: $csr}' |
  curl -s "${auth[@]}" -X POST $API/certificates -H "Content-Type: application/json" -d @- |
  jq -r '.data.fingerprint_sha256')

curl -s "${auth[@]}" "$API/certificates/$FINGERPRINT/download?format=pem" -o leaf.pem
curl -s "${auth[@]}" "$API/cas/$CA_ID/chain?format=pem" -o root.pem
openssl verify -CAfile root.pem leaf.pem
# → leaf.pem: OK
```

## 5. Revoke the Certificate

```bash
curl -s "${auth[@]}" -X POST "$API/certificates/$FINGERPRINT/revoke" \
  -H "Content-Type: application/json" -d '{"reason": "superseded"}' | jq .
```

## 6. Issue a Post-Quantum Certificate

Kryptkeeper issues ML-DSA (FIPS 204) certificates. Create a template that
allows it, then follow
[`pqc-certificate.md`](pqc-certificate.md) to issue one and check it with
OpenSSL 3.5.

```bash
curl -s "${auth[@]}" -X POST $API/templates -H "Content-Type: application/json" -d '{
  "name": "pqc-client",
  "display_name": "PQC Client Certificate",
  "validity_period": "P90D",
  "key_usage": ["digitalSignature"],
  "extended_key_usage": ["clientAuth"],
  "allowed_algorithms": ["ML-DSA-65"]
}' | jq -r '.data.id'
```

## Next steps

- [Day one: a complete estate picture](day-one-estate.md): import, scan and
  sync what you already have, and get a risk-scored report.
- [Connect to Microsoft Intune via BYOCA SCEP](intune-byoca.md)
- [Deploy with Kubernetes and Helm](../deployment.md#kubernetes--helm-production)
- [Use the Terraform provider](../../deploy/terraform/README.md)
- [Set up the cert-manager external issuer](../deployment.md#cert-manager-issuer-k8s-native-certificate-issuance)
