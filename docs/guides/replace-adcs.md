# Replace ADCS with Kryptkeeper

This guide walks through migrating from Active Directory Certificate Services (ADCS)
to Kryptkeeper as your enterprise PKI. You keep your existing Windows autoenrollment
workflows while gaining modern automation, post-quantum readiness, and multi-platform support.

## Why replace ADCS?

| Pain point | ADCS | Kryptkeeper |
|------------|------|-------------|
| Platform | Windows Server only | Linux, Docker, Kubernetes |
| Autoenrollment | GPO + NDES required | XCEP/WSTEP built-in, Intune BYOCA |
| Certificate lifetime | Manual tracking | Automated renewal, expiry alerts |
| PQC readiness | No ML-DSA support | ML-DSA-44/65/87 + hybrid certs |
| API/automation | PowerShell only | REST API, Terraform, cert-manager |
| Cost | CAL + Windows Server license | Apache 2.0, free |

## Migration strategy

### Phase 1 — Dual-issue (parallel operation, no disruption)

Run Kryptkeeper alongside ADCS. New enrollments go to Kryptkeeper; existing ADCS certs
expire naturally.

1. Deploy Kryptkeeper (see [Getting Started](getting-started.md))
2. Create matching templates in Kryptkeeper for each ADCS template you use
3. Configure Windows clients to enroll against Kryptkeeper via XCEP/WSTEP (GPO)
4. Monitor Crypto Posture dashboard — track ADCS-issued vs. Kryptkeeper-issued certs

### Phase 2 — ADCS decommission

Once all ADCS-issued certs have been renewed by Kryptkeeper (visible in the Crypto
Posture dashboard), decommission the ADCS CA server.

## Replicating ADCS certificate templates

ADCS templates map to Kryptkeeper templates. The key fields:

```bash
# ADCS "WebServer" template equivalent:
curl -s -X POST http://localhost:8080/api/v1/templates \
  -H "Authorization: Bearer $KK_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "web-server",
    "display_name": "Web Server",
    "validity_period": "P365D",
    "key_usage": ["digitalSignature", "keyEncipherment"],
    "extended_key_usage": ["serverAuth"],
    "allowed_algorithms": ["ECDSA-P256", "ECDSA-P384", "RSA-2048"],
    "auto_enroll": true,
    "active": true
  }'

# ADCS "User" template equivalent:
curl -s -X POST http://localhost:8080/api/v1/templates \
  -H "Authorization: Bearer $KK_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "user",
    "display_name": "User Authentication",
    "validity_period": "P365D",
    "key_usage": ["digitalSignature"],
    "extended_key_usage": ["clientAuth", "emailProtection"],
    "allowed_algorithms": ["ECDSA-P256"],
    "auto_enroll": true,
    "active": true
  }'
```

## Windows autoenrollment via XCEP/WSTEP

Kryptkeeper has built-in XCEP (certificate enrollment policy) and WSTEP (certificate
enrollment) endpoints — the same protocols ADCS uses for GPO-based autoenrollment.

### Configure GPO

In Group Policy Management:

1. Navigate to **Computer Configuration → Windows Settings → Security Settings →
   Public Key Policies → Certificate Services Client – Auto-Enrollment**
2. Set **Configuration Model: Enabled**
3. Enable **Renew expired certificates, update pending certificates, and remove
   revoked certificates**
4. Navigate to **Certificate Enrollment Policy**
5. Add a new policy server:
   - **Enrollment Policy Server URI**: `https://your-kryptkeeper.example.com/xcep`
   - **Authentication type**: Kerberos or Username/Password

Windows clients will now auto-enroll against Kryptkeeper on next Group Policy refresh.

### Verify enrollment

```powershell
# Force GP refresh
gpupdate /force

# Check enrolled certs
Get-ChildItem -Path Cert:\LocalMachine\My | Format-List Subject, Thumbprint, NotAfter
```

## Microsoft Intune devices (BYOCA SCEP)

For Intune-managed devices that can't use GPO, use the SCEP BYOCA integration.
See [Connect Kryptkeeper to Microsoft Intune](intune-byoca.md).

## Syncing ADCS templates (optional)

Kryptkeeper includes an `adsync` package that can read template definitions directly
from Active Directory and create matching Kryptkeeper templates automatically.

```bash
# Coming in v1.1: adsync CLI tool
# kryptkeeper-adsync --ldap-url ldaps://dc.example.com \
#   --bind-dn "CN=svc-kk,OU=Service Accounts,DC=example,DC=com" \
#   --template-ou "CN=Certificate Templates,CN=Public Key Services,..."
```

## Crypto Posture during migration

The Crypto Posture dashboard (`/crypto-posture`) gives you a live view of:

- How many certs were issued by ADCS vs. Kryptkeeper
- Which certs are using weak algorithms (RSA-2048) vs. strong (ECDSA-P384, ML-DSA)
- Expiry buckets — which ADCS certs need renewal soonest
- Automation coverage — are renewals happening automatically?

Use the CSV export to feed the migration status into your SIEM or ticketing system.
