# Issue Your First Post-Quantum Certificate

Kryptkeeper implements NIST FIPS 204 (ML-DSA) using Cloudflare CIRCL.
This guide walks through creating a PQC CA and issuing your first quantum-safe certificate.

## Background

ML-DSA (Module Lattice Digital Signature Algorithm) is NIST's post-quantum signature standard.
It replaces RSA and ECDSA for long-lived certificates where harvest-now/decrypt-later attacks
are a concern.

| Variant | Security level | Public key | Signature | NIST level |
|---------|---------------|------------|-----------|------------|
| ML-DSA-44 | 128-bit PQC | 1312 bytes | 2420 bytes | 2 |
| ML-DSA-65 | 192-bit PQC | 1952 bytes | 3293 bytes | 3 |
| ML-DSA-87 | 256-bit PQC | 2592 bytes | 4595 bytes | 5 |

For most deployments: use **ML-DSA-65** (best balance of security and size).

## Prerequisites

A running Kryptkeeper Hub (see [Getting Started](getting-started.md)).

## 1. Create a PQC Root CA

```bash
export KK_TOKEN="your-bootstrap-token"

curl -s -X POST http://localhost:8080/api/v1/cas \
  -H "Authorization: Bearer $KK_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "PQC Root CA",
    "common_name": "PQC Root Certificate Authority",
    "algorithm": "ML-DSA-65",
    "validity_days": 3650
  }' | jq .

export PQC_CA_ID="<id from response>"
```

## 2. Create a PQC certificate template

```bash
curl -s -X POST http://localhost:8080/api/v1/templates \
  -H "Authorization: Bearer $KK_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "pqc-tls-server",
    "display_name": "PQC TLS Server Certificate",
    "validity_period": "P90D",
    "key_usage": ["digitalSignature"],
    "extended_key_usage": ["serverAuth"],
    "allowed_algorithms": ["ML-DSA-65"],
    "active": true
  }' | jq .

export PQC_TEMPLATE_ID="<id from response>"
```

Note: `ML-DSA-65` is listed in `allowed_algorithms`. The template policy will reject
any CSR that uses a different algorithm.

## 3. Generate an ML-DSA key pair and CSR

ML-DSA key generation requires the Cloudflare CIRCL library. Use Kryptkeeper's key
generation API rather than openssl (which doesn't support ML-DSA yet):

```bash
# Generate key + CSR via the Kryptkeeper key generation endpoint
curl -s -X POST http://localhost:8080/api/v1/keys/generate-csr \
  -H "Authorization: Bearer $KK_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "algorithm": "ML-DSA-65",
    "common_name": "pqc.example.com",
    "dns_names": ["pqc.example.com"]
  }' | jq -r '.data.csr_pem' > pqc-server.csr

# The private key is stored in Kryptkeeper's key store.
# Export it if needed:
curl -s http://localhost:8080/api/v1/keys/pqc.example.com \
  -H "Authorization: Bearer $KK_TOKEN" | jq -r '.data.private_key_pem' > pqc-server.key
```

## 4. Issue the PQC certificate

```bash
curl -s -X POST http://localhost:8080/api/v1/certificates \
  -H "Authorization: Bearer $KK_TOKEN" \
  -H "Content-Type: application/json" \
  -d "{
    \"ca_id\": \"$PQC_CA_ID\",
    \"template_id\": \"$PQC_TEMPLATE_ID\",
    \"csr_pem\": \"$(cat pqc-server.csr | awk '{printf "%s\\n", $0}')\"
  }" | jq -r '.data.certificate_pem' > pqc-server.crt

echo "Certificate issued:"
# Show algorithm (will be "ML-DSA-65 / id-ml-dsa-65")
openssl x509 -in pqc-server.crt -noout -text | grep -A2 "Public Key Algorithm"
```

## 5. Hybrid certificate (ECDSA + ML-DSA)

For maximum compatibility during the migration period (2025–2028), use a hybrid cert.
Hybrid certs contain both an ECDSA signature (for current TLS stacks) and an ML-DSA
alt-sig extension (for PQC-aware verifiers).

```bash
# Create a hybrid CA (ECDSA P-256 + ML-DSA-65)
curl -s -X POST http://localhost:8080/api/v1/cas \
  -H "Authorization: Bearer $KK_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Hybrid CA",
    "common_name": "Hybrid ECDSA+ML-DSA Certificate Authority",
    "algorithm": "HybridP256MLDSA65",
    "validity_days": 3650
  }' | jq .

# Create hybrid template
curl -s -X POST http://localhost:8080/api/v1/templates \
  -H "Authorization: Bearer $KK_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "hybrid-tls",
    "display_name": "Hybrid TLS Certificate",
    "validity_period": "P90D",
    "key_usage": ["digitalSignature"],
    "extended_key_usage": ["serverAuth"],
    "allowed_algorithms": ["HybridP256MLDSA65"]
  }' | jq .
```

The hybrid cert is fully compatible with existing TLS stacks (they see the ECDSA signature)
and provides forward security against quantum attacks (ML-DSA alt-sig is verified by
PQC-aware clients).

## 6. Verify the PQC readiness score

After issuing PQC certs, the Crypto Posture dashboard (`/crypto-posture`) shows:

- **PQC readiness score**: percentage of certs that are quantum-safe or hybrid
- **Algorithm breakdown**: visual breakdown of RSA/ECDSA/ML-DSA/Hybrid distribution
- **Grade**: certs signed by ML-DSA or Hybrid CA earn grade A on PQC readiness

## Algorithm migration timeline

| Period | Recommended action |
|--------|--------------------|
| 2025–2026 | Issue hybrid certs for new services; inventory legacy RSA/ECDSA |
| 2026–2027 | Migrate server certs to hybrid (ECDSA+ML-DSA) |
| 2027–2028 | Migrate CA hierarchy to ML-DSA-65 or ML-DSA-87 |
| 2028+ | Deprecate classical-only certs per NIST guidance |

NIST formally deprecated RSA, ECDSA, and DH key agreement in 2024 (SP 800-186, SP 800-208).
All new CAs should be ML-DSA or hybrid from 2026 onward.
