# Getting Started with Kryptkeeper

This guide takes you from zero to issuing your first certificate in under 15 minutes
using Docker Compose.

## Prerequisites

- Docker 24+ and Docker Compose v2
- `curl` and `openssl` in your shell

## 1. Start the Hub

```bash
git clone https://github.com/bpmforge/kryptkeeper.git
cd kryptkeeper

# Generate a random bootstrap token for first-time setup
export KK_TOKEN=$(openssl rand -hex 20)
echo "Bootstrap token: $KK_TOKEN"

docker compose up -d
```

The Hub starts on port **8080** (HTTP) by default.
Set `KRYPTKEEPER_ADDR=:443` and mount TLS certs for production.

### Verify it's running

```bash
curl -s http://localhost:8080/healthz
# → {"status":"ok"}
```

## 2. Create a Root CA

```bash
curl -s -X POST http://localhost:8080/api/v1/cas \
  -H "Authorization: Bearer $KK_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "My Root CA",
    "common_name": "My Organisation Root CA",
    "algorithm": "ECDSA-P384",
    "validity_days": 3650
  }' | jq .
```

Note the `"id"` field — you will need it in the next step.

```bash
export CA_ID="<id from above>"
```

## 3. Create a Certificate Template

```bash
curl -s -X POST http://localhost:8080/api/v1/templates \
  -H "Authorization: Bearer $KK_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "tls-server",
    "display_name": "TLS Server Certificate",
    "validity_period": "P90D",
    "key_usage": ["digitalSignature", "keyEncipherment"],
    "extended_key_usage": ["serverAuth"],
    "allowed_algorithms": ["ECDSA-P256", "ECDSA-P384"],
    "auto_enroll": false,
    "active": true
  }' | jq .

export TEMPLATE_ID="<id from above>"
```

## 4. Issue a Certificate

Generate a key and CSR:

```bash
openssl ecparam -genkey -name prime256v1 -noout -out server.key
openssl req -new -key server.key \
  -subj "/CN=myapp.example.com" \
  -out server.csr
```

Issue the certificate:

```bash
curl -s -X POST http://localhost:8080/api/v1/certificates \
  -H "Authorization: Bearer $KK_TOKEN" \
  -H "Content-Type: application/json" \
  -d "{
    \"ca_id\": \"$CA_ID\",
    \"template_id\": \"$TEMPLATE_ID\",
    \"csr_pem\": \"$(cat server.csr | awk '{printf "%s\\n", $0}')\"
  }" | jq -r '.data.certificate_pem' > server.crt

openssl x509 -in server.crt -noout -subject -dates
```

## 5. Revoke the Certificate

```bash
FINGERPRINT=$(openssl x509 -in server.crt -noout -fingerprint -sha256 \
  | sed 's/.*=//' | tr -d ':' | tr '[:upper:]' '[:lower:]')

curl -s -X POST http://localhost:8080/api/v1/certificates/$FINGERPRINT/revoke \
  -H "Authorization: Bearer $KK_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"reason": "superseded"}'
```

## 6. Issue a Post-Quantum Certificate

Kryptkeeper supports ML-DSA (FIPS 204) out of the box.

```bash
# Create a PQC template
curl -s -X POST http://localhost:8080/api/v1/templates \
  -H "Authorization: Bearer $KK_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "pqc-client",
    "display_name": "PQC Client Certificate",
    "validity_period": "P90D",
    "key_usage": ["digitalSignature"],
    "extended_key_usage": ["clientAuth"],
    "allowed_algorithms": ["ML-DSA-65"]
  }' | jq -r '.data.id'

# Issue via ACME (kryptkeeper-agent handles key gen and enrollment automatically)
KRYPTKEEPER_HUB_URL=http://localhost:8080 \
KRYPTKEEPER_AGENT_NAME=my-laptop \
  kryptkeeper-agent
```

## Next steps

- [Connect to Microsoft Intune via BYOCA SCEP](intune-byoca.md)
- [Deploy with Kubernetes and Helm](../deployment.md#kubernetes--helm-production)
- [Use the Terraform provider](../../deploy/terraform/README.md)
- [Set up the cert-manager external issuer](../deployment.md#cert-manager-issuer-k8s-native-certificate-issuance)
