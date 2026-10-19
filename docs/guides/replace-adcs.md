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
2. Import the ADCS templates (`/migration`, see the cutover playbook below) or create
   matching ones by hand
3. Configure Windows clients to enroll against Kryptkeeper via XCEP/WSTEP (GPO)
4. Monitor Crypto Posture dashboard — track ADCS-issued vs. Kryptkeeper-issued certs

### Phase 2 — ADCS decommission

Once all ADCS-issued certs have been renewed by Kryptkeeper (visible in the Crypto
Posture dashboard), decommission the ADCS CA server.

## Cutover playbook: inventory, migrate, run in parallel, cut over, roll back

This is the sequence the v0.21 lab rehearsal ran against a Windows Server 2025
Enterprise CA (`docs/release/ADCS_CUTOVER_REHEARSAL_v0.21.md`). Every step is
reversible until ADCS is decommissioned. `$KK` is the hub API base
(`https://hub.example.com/api/v1`), `$KK_TOKEN` an admin API key. Steps marked
**two people** go through the pending-action queue: one admin proposes, a
second approves (`POST /pending-actions/{id}/approve`); self-approval and the
bootstrap token are refused.

### 1. Inventory the ADCS estate

Store the LDAP bind password once; only its id is ever referenced again.

```bash
curl -s -X POST "$KK/credentials" -H "Authorization: Bearer $KK_TOKEN" -H "Content-Type: application/json" \
  -d '{"name":"adcs-ldap-read","credential_type":"windows_password","payload":{"password":"<bind password>"}}'
# -> data.id, e.g. cred-... ; a bare JSON string payload works too

curl -s -X POST "$KK/inventory-sources" -H "Authorization: Bearer $KK_TOKEN" -H "Content-Type: application/json" \
  -d '{"name":"adcs","type":"adcs_live","credential_ref":"cred-...",
       "config_json":"{\"ldap_url\":\"ldaps://dc01.corp.example:636\",\"bind_dn\":\"svc-kk-read@corp.example\",\"search_base\":\"DC=corp,DC=example\"}"}'
curl -s -X POST "$KK/inventory-sources/<id>/sync" -H "Authorization: Bearer $KK_TOKEN"
# -> {"synced":N,"skipped":0,"revoked_marked":0}
```

Synced certificates enter the estate as `origin=synced`, `management_state=external`
(ADCS still manages them). Re-syncs are idempotent and never undo a takeover.
Build a manifest of the source fingerprints **on the DC side** (SHA-256 of each
`userCertificate`, one lowercase hex value per line) and check the hub saw all of
them:

```bash
KK_TOKEN=... scripts/migration-verify.sh --hub https://hub.example.com --manifest adcs.sha256 --origin synced
# last line: total=N mapped=N unmatched=0 percent=100.0 (exit 0)
```

### 2. Map the ADCS templates (dry run)

The dry run reads the `pKICertificateTemplate` objects live (same stored
credential) or from a JSON export of them (`"content": "<export>"`, 48 KiB max
to apply), and writes nothing:

```bash
curl -s -X POST "$KK/migration/dryrun" -H "Authorization: Bearer $KK_TOKEN" -H "Content-Type: application/json" \
  -d '{"source":"adcs","credential_ref":"cred-...","options":{
        "ldap_url":"ldaps://dc01.corp.example:636","bind_dn":"svc-kk-read@corp.example",
        "base_dn":"CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=corp,DC=example"}}'
```

Each entry is `create`, `update`, `skip` or `conflict`, with a per-field
mapped/partial/unmapped report. ADCS v1 (built-in schema) templates and templates
with no mappable EKU are skipped. Read the `notes` of each entry:

- **Key size raised to the policy floor.** ADCS templates are often RSA-2048; the
  default `Baseline` issuance policy requires RSA ≥ 3072. The migration never
  weakens the policy: it raises the template's `min_key_size` and says so, e.g.
  `key size raised from 2048 to 3072 to meet policy "Baseline"`. XCEP then
  advertises 3072, so Windows clients generate a compliant key. Check that any
  non-Windows consumer of the template can use 3072-bit keys.
- **DC, Kerberos and RAS templates are not offered to workstations.** Templates
  whose EKUs mark them for domain controllers, Kerberos or IPsec/RAS servers
  (KDC authentication, smart-card logon on a machine template, IKE intermediate,
  DS email replication) and the built-in `DomainController*`,
  `KerberosAuthentication` and `RASAndIASServer` are created with
  `auto_enroll=false` and
  `enrollment_permissions.enroll=["pki-admin","protocol:wstep:restricted"]`,
  because the import cannot read the ADCS enrollment ACLs. XCEP/WSTEP enforce an
  enroll list only when it has a `protocol:wstep` entry (lists of API roles alone,
  such as `["pki-operator"]`, leave Windows enrollment unchanged); the
  `restricted` entry matches no client. To offer such a template, add
  `protocol:wstep:<host fqdn>` (one machine, e.g. `protocol:wstep:dc01.corp.example`)
  or `protocol:wstep` (every Windows client) with
  `PATCH /templates/{id}` `{"enrollment_permissions":{"enroll":[...]}}`.

### 3. Apply (two people)

```bash
curl -s -X POST "$KK/migration/apply" -H "Authorization: Bearer $ALICE" -H "Content-Type: application/json" -d @same-body.json
# -> 202 {"status":"pending_approval","pending_action_id":"act-..."}
curl -s -X POST "$KK/pending-actions/act-.../approve" -H "Authorization: Bearer $BOB"
# -> batch mb_... ; GET /migration/{batch}/report shows every template and field
```

Migrated templates keep their ADCS OIDs, so certificates name the same template.
The approval is refused if the export or the template set changed since the
proposal (propose again). Re-applying later (a changed ADCS template, a raised
policy floor, or a template a rollback left disabled) plans an `update`: the
existing template is updated in place and reactivated, through the same
two-person approval. Re-applying an unchanged export is `nothing_to_apply`.

### 4. Parallel run

Issue from a migrated template and from ADCS for the same test endpoint and
check both chains verify (`openssl s_client -verify_return_error`). ADCS keeps
issuing everywhere else.

### 5. Cut over one group

Link a GPO that sets the enrollment policy server to
`https://hub.example.com/xcep` (Kerberos) to an OU holding only the pilot group;
it takes precedence over a domain-wide policy. After `gpupdate /force` and an
autoenrollment pulse (`certutil -pulse`), the clients enroll from the hub
(`wstep.enroll` audit rows, inventory `source=wstep`, `internal/managed`).
A client is offered only templates of its own kind (machine or user) that it is
permitted to enroll.

Take over the pilot group's ADCS-issued certificates so the hub renews them:

```bash
curl -s -X POST "$KK/estate/takeover" -H "Authorization: Bearer $KK_TOKEN" -H "Content-Type: application/json" \
  -d '{"fingerprint":"<sha256>","owner_team":"pilot","renewal_path":{"mode":"internal"}}'
# many at once: POST /estate/takeover/bulk {"items":[...]} (500 max)
```

They become `management_state=managed`; inventory re-syncs leave them managed.

### 6. Roll back

In this order:

1. **GPO**: remove the link and the GPO (`Remove-GPLink`, `Remove-GPO`), move the
   pilot machines back, `gpupdate /force`. Clients return to the previous policy
   server; revoke the hub-issued pilot certificates if they must not remain.
2. **Takeover**: `POST /estate/revert {"fingerprint":"<sha256>"}` for each
   taken-over certificate. It returns to its pre-takeover state: `external` for a
   certificate an inventory source synced, `unmanaged` otherwise; the
   `estate.takeover.revert` audit row records from/to.
3. **Templates**: `POST /migration/{batch}/rollback` disables (never deletes) the
   batch's templates; templates with pending certificate approvals stay active and
   are reported as `kept`. A second call is a no-op (`already_rolled_back`).
   Templates you created outside the batch must be deactivated by hand.
4. **Verify**: run `scripts/migration-verify.sh` again with the same manifest;
   expect `unmatched=0` and every certificate back at `synced/external`. A
   fingerprint the hub does not hold is listed as `UNMATCHED` and exits 1.

## Replicating ADCS certificate templates by hand

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
    "allowed_algorithms": ["ECDSA-P256", "ECDSA-P384", "RSA-3072"],
    "min_key_size": 3072,
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

## Syncing ADCS templates

Template import from Active Directory is the `/migration` API in step 2 of the
cutover playbook above (live LDAP read or JSON export, dry run, two-person apply,
rollback by batch).

## Crypto Posture during migration

The Crypto Posture dashboard (`/crypto-posture`) gives you a live view of:

- How many certs were issued by ADCS vs. Kryptkeeper
- Which certs are using weak algorithms (RSA-2048) vs. strong (ECDSA-P384, ML-DSA)
- Expiry buckets — which ADCS certs need renewal soonest
- Automation coverage — are renewals happening automatically?

Use the CSV export to feed the migration status into your SIEM or ticketing system.
